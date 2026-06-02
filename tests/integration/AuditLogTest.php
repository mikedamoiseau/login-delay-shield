<?php
/**
 * Integration tests for the admin/security action audit log (F-2-7).
 *
 * Exercises table creation, the deferred-write path (via the queue flush),
 * filtering/pagination, and the settings-change + manual-unlock capture points
 * against the bundled WordPress test database.
 */

class AuditLogTest extends WP_UnitTestCase {

    /**
     * Ensure a clean audit table before each test.
     */
    public function setUp(): void {
        parent::setUp();

        global $wpdb;
        wldelay_create_audit_table();
        $table = wldelay_get_audit_table_name();
        $wpdb->query( "TRUNCATE TABLE $table" );

        if ( function_exists( 'wldelay_reset_deferred_tasks' ) ) {
            wldelay_reset_deferred_tasks();
        }

        // Clear any audit-integrity marker left by a prior test so the
        // degraded-state assertions start from a healthy baseline.
        delete_option( 'wldelay_audit_health' );
        delete_option( 'wldelay_audit_ack' );
        delete_option( 'wldelay_audit_recovery' );
    }

    /**
     * Helper: flush the deferred queue so enqueued audit writes hit the DB.
     */
    private function flush() {
        wldelay_flush_deferred_tasks();
    }

    /**
     * The audit table is created with the expected columns and indexes.
     */
    public function test_table_created_with_structure() {
        global $wpdb;

        $table   = wldelay_get_audit_table_name();
        $columns = array_column( $wpdb->get_results( "DESCRIBE $table" ), 'Field' );

        foreach ( array( 'id', 'actor_id', 'actor_login', 'action', 'object', 'old_value', 'new_value', 'ip_address', 'created_at' ) as $column ) {
            $this->assertContains( $column, $columns, "Missing column {$column}" );
        }

        $index_names = array_unique( array_column( $wpdb->get_results( "SHOW INDEX FROM $table" ), 'Key_name' ) );
        $this->assertContains( 'created_at', $index_names );
        $this->assertContains( 'action', $index_names );
        $this->assertContains( 'actor_id', $index_names );
    }

    /**
     * The audit table is provisioned on the DB upgrade path.
     */
    public function test_table_created_on_upgrade() {
        global $wpdb;

        $table = wldelay_get_audit_table_name();
        $wpdb->query( "DROP TABLE IF EXISTS $table" );

        update_option( 'wldelay_db_version', '1' );
        wldelay_maybe_upgrade_db();

        $exists = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) );
        $this->assertSame( $table, $exists );

        delete_option( 'wldelay_db_version' );
    }

    /**
     * wldelay_audit_log() inserts a row (after flush) with the resolved actor,
     * action, and values.
     */
    public function test_audit_log_inserts_row() {
        global $wpdb;

        $user_id = self::factory()->user->create( array( 'user_login' => 'auditor', 'role' => 'administrator' ) );
        wp_set_current_user( $user_id );
        $_SERVER['REMOTE_ADDR'] = '203.0.113.7';

        wldelay_audit_log( 'settings_changed', array(
            'object'    => 'wldelay_delay',
            'new_value' => array( 'wldelay_delay' => array( 'old' => 3, 'new' => 5 ) ),
        ) );

        // Audit writes are synchronous (a compliance trail must not be lossy),
        // so the row is present immediately — no queue flush required.
        $table = wldelay_get_audit_table_name();
        $this->assertSame( 1, (int) $wpdb->get_var( "SELECT COUNT(*) FROM $table" ) );

        $row = $wpdb->get_row( "SELECT * FROM $table ORDER BY id DESC LIMIT 1" );
        $this->assertNotNull( $row );
        $this->assertSame( 'settings_changed', $row->action );
        $this->assertSame( 'auditor', $row->actor_login );
        $this->assertSame( $user_id, (int) $row->actor_id );
        $this->assertSame( 'wldelay_delay', $row->object );
        $this->assertSame( '203.0.113.7', $row->ip_address );

        $decoded = json_decode( $row->new_value, true );
        $this->assertSame( 5, $decoded['wldelay_delay']['new'] );

        wp_set_current_user( 0 );
        unset( $_SERVER['REMOTE_ADDR'] );
    }

    /**
     * A system action (no logged-in user) records actor_id 0 and empty login.
     */
    public function test_system_actor_recorded_as_zero() {
        global $wpdb;

        wp_set_current_user( 0 );

        wldelay_audit_log( 'lockout_cleared', array( 'object' => '198.51.100.1' ) );
        $this->flush();

        $table = wldelay_get_audit_table_name();
        $row   = $wpdb->get_row( "SELECT * FROM $table ORDER BY id DESC LIMIT 1" );
        $this->assertSame( 0, (int) $row->actor_id );
        $this->assertSame( '', $row->actor_login );
    }

    /**
     * Querying filters by action and paginates.
     */
    public function test_query_filters_by_action_and_paginates() {
        // Seed mixed actions directly through the writer.
        for ( $i = 0; $i < 30; $i++ ) {
            wldelay_audit_write_row( array(
                'action'     => 'settings_changed',
                'actor_id'   => 1,
                'created_at' => current_time( 'mysql', true ),
            ) );
        }
        for ( $i = 0; $i < 5; $i++ ) {
            wldelay_audit_write_row( array(
                'action'     => 'lockout_cleared',
                'actor_id'   => 1,
                'created_at' => current_time( 'mysql', true ),
            ) );
        }

        $this->assertSame( 30, wldelay_count_audit_log( array( 'action' => 'settings_changed' ) ) );
        $this->assertSame( 5, wldelay_count_audit_log( array( 'action' => 'lockout_cleared' ) ) );
        $this->assertSame( 35, wldelay_count_audit_log() );

        $page1 = wldelay_query_audit_log( array( 'action' => 'settings_changed' ), 1, 25 );
        $page2 = wldelay_query_audit_log( array( 'action' => 'settings_changed' ), 2, 25 );
        $this->assertCount( 25, $page1 );
        $this->assertCount( 5, $page2 );

        foreach ( $page1 as $row ) {
            $this->assertSame( 'settings_changed', $row->action );
        }
    }

    /**
     * Querying filters by date range.
     */
    public function test_query_filters_by_date() {
        global $wpdb;
        $table = wldelay_get_audit_table_name();

        // Old row (well in the past) + a current row.
        $wpdb->insert( $table, array(
            'action'     => 'settings_changed',
            'actor_id'   => 1,
            'created_at' => '2000-01-01 12:00:00',
        ) );
        wldelay_audit_write_row( array(
            'action'     => 'settings_changed',
            'actor_id'   => 1,
            'created_at' => current_time( 'mysql', true ),
        ) );

        $this->assertSame( 2, wldelay_count_audit_log() );

        $only_old = wldelay_query_audit_log( array( 'from' => '1999-12-31', 'to' => '2000-01-02' ), 1, 25 );
        $this->assertCount( 1, $only_old );
        $this->assertSame( '2000-01-01 12:00:00', $only_old[0]->created_at );
    }

    /**
     * A settings change records a settings_changed row with a diff of changed keys.
     */
    public function test_settings_change_records_diff() {
        global $wpdb;

        $user_id = self::factory()->user->create( array( 'role' => 'administrator' ) );
        wp_set_current_user( $user_id );

        // Establish a baseline, then change one key. update_option fires
        // update_option_wldelay_options, which the capture point hooks.
        update_option( WLDELAY_OPTION_NAME, array( 'wldelay_delay' => 3, 'wldelay_lockout_enabled' => true ) );
        $this->flush();

        $table = wldelay_get_audit_table_name();
        $wpdb->query( "TRUNCATE TABLE $table" );
        wldelay_reset_deferred_tasks();

        update_option( WLDELAY_OPTION_NAME, array( 'wldelay_delay' => 7, 'wldelay_lockout_enabled' => true ) );
        $this->flush();

        $row = $wpdb->get_row( "SELECT * FROM $table WHERE action = 'settings_changed' ORDER BY id DESC LIMIT 1" );
        $this->assertNotNull( $row, 'Expected a settings_changed audit row' );

        $diff = json_decode( $row->new_value, true );
        $this->assertArrayHasKey( 'wldelay_delay', $diff );
        $this->assertArrayNotHasKey( 'wldelay_lockout_enabled', $diff );
        $this->assertSame( 7, $diff['wldelay_delay']['new'] );

        wp_set_current_user( 0 );
    }

    /**
     * A manual unlock records a lockout_cleared row naming the target.
     */
    public function test_manual_unlock_records_lockout_cleared() {
        global $wpdb;

        wldelay_audit_lockout_cleared( '192.0.2.55', 'bob', 1 );
        $this->flush();

        $table = wldelay_get_audit_table_name();
        $row   = $wpdb->get_row( "SELECT * FROM $table WHERE action = 'lockout_cleared' ORDER BY id DESC LIMIT 1" );
        $this->assertNotNull( $row );
        $this->assertSame( '192.0.2.55 / bob', $row->object );

        $detail = json_decode( $row->new_value, true );
        $this->assertSame( 1, $detail['removed_rows'] );
    }

    /**
     * Audit writes are synchronous, so two identical actions in the same second
     * each produce their own row instead of collapsing to one. Guards against
     * the deferred-queue dedupe (id + args hash, second-resolution timestamp)
     * that would silently drop a repeated action (review fix).
     */
    public function test_identical_rapid_actions_are_each_recorded() {
        global $wpdb;
        $table = wldelay_get_audit_table_name();

        wldelay_audit_log( 'settings_changed', array(
            'object'    => 'wldelay_delay',
            'new_value' => array( 'wldelay_delay' => array( 'old' => 3, 'new' => 5 ) ),
        ) );
        wldelay_audit_log( 'settings_changed', array(
            'object'    => 'wldelay_delay',
            'new_value' => array( 'wldelay_delay' => array( 'old' => 3, 'new' => 5 ) ),
        ) );

        $this->assertSame(
            2,
            (int) $wpdb->get_var( "SELECT COUNT(*) FROM $table" ),
            'Two identical actions must each be recorded, not deduplicated'
        );
    }

    /**
     * A failed INSERT returns false and is not silently swallowed. With the
     * table dropped the write cannot succeed, exercising the failure path
     * (review fix — surfaces invisible audit gaps).
     */
    public function test_write_row_failure_returns_false() {
        global $wpdb;

        $table = wldelay_get_audit_table_name();

        // Force the audit INSERT to fail deterministically by mangling it into
        // invalid SQL via the `query` filter. (DROP TABLE does not persist
        // inside the per-test transaction in this harness, so a missing table
        // cannot be relied on to trigger the failure path.)
        $break = static function ( $query ) use ( $table ) {
            if ( 0 === stripos( ltrim( $query ), 'INSERT' ) && false !== strpos( $query, $table ) ) {
                return 'INSERT INTO'; // Syntax error -> $wpdb->query returns false.
            }
            return $query;
        };
        add_filter( 'query', $break );

        $suppress = $wpdb->suppress_errors( true );
        $result   = wldelay_audit_write_row( array(
            'action'     => 'settings_changed',
            'actor_id'   => 1,
            'created_at' => current_time( 'mysql', true ),
        ) );
        $wpdb->suppress_errors( $suppress );

        remove_filter( 'query', $break );

        $this->assertFalse( $result, 'A failed audit INSERT must return false' );

        // The mangled write must not have left a row behind.
        $this->assertSame( 0, (int) $wpdb->get_var( "SELECT COUNT(*) FROM $table" ) );

        // The failure must raise the admin-visible integrity marker so the
        // read-only UI can warn that the trail is incomplete (review fix).
        $this->assertTrue(
            wldelay_audit_log_is_degraded(),
            'A failed audit write must set the integrity marker'
        );
        $health = wldelay_get_audit_health();
        $this->assertSame( 'settings_changed', $health['last_action'] );
        $this->assertSame( 1, (int) $health['count'] );
    }

    /**
     * A later successful write records RECOVERY but must NOT erase the gap
     * warning: the rows lost during the outage are permanently gone, so the
     * trail-incomplete signal has to persist (review fix — a successful write
     * proves pipeline health, not trail integrity). recovered_at is annotated;
     * is_degraded stays true.
     */
    public function test_successful_write_records_recovery_but_keeps_gap_warning() {
        // Seed a failure marker directly (as a prior failed write would).
        wldelay_record_audit_write_failure( 'settings_changed', 'simulated outage' );
        $this->assertTrue( wldelay_audit_log_is_degraded(), 'Precondition: marker is set' );

        // A successful write proves the pipeline is healthy again.
        $id = wldelay_audit_write_row( array(
            'action'     => 'settings_changed',
            'actor_id'   => 1,
            'created_at' => current_time( 'mysql', true ),
        ) );

        $this->assertNotFalse( $id, 'The recovery write must succeed' );

        // The gap warning MUST still be raised — the lost row never came back.
        $this->assertTrue(
            wldelay_audit_log_is_degraded(),
            'A successful write must NOT clear the gap warning'
        );

        // Recovery is tracked separately so the operator can see the pipeline
        // is working again even though the trail stays flagged.
        $health = wldelay_get_audit_health();
        $this->assertNotEmpty( $health['recovered_at'], 'Recovery time must be recorded' );
        $this->assertSame( 1, (int) $health['count'], 'Failure count is preserved as forensic evidence' );
    }

    /**
     * A recovery note that completes AFTER a fresh failure has landed must not
     * silence that newer, unacknowledged gap, nor revert the failure count.
     * Guards the round-6 race: recovery used to read-modify-write the SAME
     * health option as the failure recorder, so a stale recovery could overwrite
     * a newer failure (count 2 -> 1) and — if the older generation was
     * acknowledged — flip is_degraded() to false. Recovery now writes its own
     * option and is generation-tagged, so it can never clobber the health marker
     * (review fix).
     */
    public function test_recovery_cannot_clobber_a_concurrent_failure() {
        // Generation 1: a failure the admin sees and acknowledges.
        wldelay_record_audit_write_failure( 'settings_changed', 'outage one' );
        $this->assertTrue( wldelay_acknowledge_audit_gap( 1, 1 ) );
        $this->assertFalse( wldelay_audit_log_is_degraded(), 'Precondition: generation 1 acknowledged' );

        // Generation 2: a fresh, unacknowledged failure lands (the "concurrent"
        // failure). The warning must reopen.
        wldelay_record_audit_write_failure( 'lockout_cleared', 'outage two' );
        $this->assertTrue( wldelay_audit_log_is_degraded(), 'A fresh failure reopens the warning' );

        // A recovery write now completes — modelling the recovery whose stale
        // read raced the generation-2 failure. Under the old shared-option
        // design this reverted count to 1 and silenced the gap.
        wldelay_note_audit_write_recovered();

        // The newer gap must remain raised and the count must not regress.
        $this->assertTrue(
            wldelay_audit_log_is_degraded(),
            'Recovery must NOT silence the newer, unacknowledged gap'
        );
        $health = wldelay_get_audit_health();
        $this->assertSame( 2, (int) $health['count'], 'Recovery must not revert the failure count' );

        // Recovery DID correspond to generation 2 here, so its stamp may surface;
        // what matters is the gap stays open until generation 2 is acknowledged.
        $this->assertTrue( wldelay_acknowledge_audit_gap( 1, 2 ) );
        $this->assertFalse( wldelay_audit_log_is_degraded(), 'Acknowledging the current generation clears it' );
    }

    /**
     * A recovery recorded for an OLD generation is suppressed once a newer
     * failure supersedes it: the merged health record must not present a stale
     * "recovered" stamp on a still-open, never-recovered newer gap (review fix —
     * generation-gated recovery merge).
     */
    public function test_stale_recovery_stamp_is_suppressed_after_newer_failure() {
        // Generation 1 fails, then recovers — recovered_count = 1.
        wldelay_record_audit_write_failure( 'settings_changed', 'outage one' );
        wldelay_note_audit_write_recovered();
        $health = wldelay_get_audit_health();
        $this->assertNotEmpty( $health['recovered_at'], 'Recovery for generation 1 is recorded' );

        // Generation 2 fails and never recovers.
        wldelay_record_audit_write_failure( 'lockout_cleared', 'outage two' );

        // The generation-1 recovery is now stale (recovered_count 1 < count 2)
        // and must not surface as if the generation-2 gap had healed.
        $health = wldelay_get_audit_health();
        $this->assertSame( 2, (int) $health['count'] );
        $this->assertArrayNotHasKey(
            'recovered_at',
            $health,
            'A stale recovery stamp must be suppressed after a newer failure'
        );
    }

    /**
     * The gap warning clears ONLY through an explicit administrator
     * acknowledgement, and that acknowledgement retains the forensic metadata
     * (gap_since/count) rather than discarding it (review fix).
     */
    public function test_gap_clears_only_on_explicit_acknowledgement() {
        wldelay_record_audit_write_failure( 'settings_changed', 'simulated outage' );
        $this->assertTrue( wldelay_audit_log_is_degraded(), 'Precondition: marker is set' );

        $acknowledged = wldelay_acknowledge_audit_gap( 42 );
        $this->assertTrue( $acknowledged, 'An outstanding gap must be acknowledgeable' );

        // Warning is now dismissed...
        $this->assertFalse(
            wldelay_audit_log_is_degraded(),
            'Acknowledgement must dismiss the warning'
        );

        // ...but the forensic record is RETAINED, not deleted.
        $health = wldelay_get_audit_health();
        $this->assertIsArray( $health, 'The marker must be retained after acknowledgement' );
        $this->assertNotEmpty( $health['acknowledged_at'], 'acknowledged_at must be stamped' );
        $this->assertSame( 42, (int) $health['acknowledged_by'] );
        $this->assertSame( 1, (int) $health['count'], 'The historical failure count is preserved' );
        $this->assertNotEmpty( $health['gap_since'], 'The gap-open time is preserved' );
    }

    /**
     * A NEW write failure after an acknowledgement reopens the gap: the warning
     * returns and the original gap-open time is preserved (review fix — an
     * acknowledged gap must not mask a fresh, distinct failure).
     */
    public function test_new_failure_after_acknowledgement_reopens_gap() {
        wldelay_record_audit_write_failure( 'settings_changed', 'outage one' );
        $first       = wldelay_get_audit_health();
        $first_since = $first['gap_since'];

        wldelay_acknowledge_audit_gap( 1 );
        $this->assertFalse( wldelay_audit_log_is_degraded(), 'Precondition: acknowledged' );

        // A second, distinct failure.
        wldelay_record_audit_write_failure( 'lockout_cleared', 'outage two' );

        $this->assertTrue(
            wldelay_audit_log_is_degraded(),
            'A fresh failure after acknowledgement must reopen the warning'
        );
        $health = wldelay_get_audit_health();
        $this->assertSame( 2, (int) $health['count'], 'The cumulative failure count keeps climbing' );
        $this->assertSame( $first_since, $health['gap_since'], 'gap_since stays anchored to the first failure' );
    }

    /**
     * A failure that lands AFTER the acknowledge link was rendered (a concurrent
     * request) must not be silenced by that acknowledgement, and its count must
     * not be lost. Guards the read-modify-write clobber between the failure
     * recorder and the acknowledgement: the two now write separate options and
     * the ack only covers the generation the admin actually saw (review fix).
     */
    public function test_concurrent_failure_is_not_overwritten_by_acknowledgement() {
        // Generation 1 — the gap the admin sees and is about to acknowledge.
        wldelay_record_audit_write_failure( 'settings_changed', 'outage one' );
        $observed = (int) wldelay_get_audit_health()['count'];
        $this->assertSame( 1, $observed );

        // A SECOND failure lands before the acknowledgement completes (the
        // concurrent-request interleaving), bumping the generation to 2.
        wldelay_record_audit_write_failure( 'lockout_cleared', 'outage two' );

        // The admin acknowledges only the generation they actually saw (1).
        $this->assertTrue( wldelay_acknowledge_audit_gap( 7, $observed ) );

        // The newer, unseen failure must keep the warning raised...
        $this->assertTrue(
            wldelay_audit_log_is_degraded(),
            'A failure newer than the acknowledged generation must keep the gap open'
        );

        // ...and its count must survive (the prior single-option design lost it).
        $health = wldelay_get_audit_health();
        $this->assertSame( 2, (int) $health['count'], 'The concurrent failure count must not be lost' );

        // Acknowledging the current generation (2) finally clears it.
        $this->assertTrue( wldelay_acknowledge_audit_gap( 7, 2 ) );
        $this->assertFalse( wldelay_audit_log_is_degraded(), 'Acknowledging the current generation clears the warning' );
    }

    /**
     * A privileged settings change made while the audit table is unwritable must
     * still complete (fail-open: a DB hiccup must not lock an admin out of their
     * own settings), but it must leave the admin-visible integrity marker set so
     * the gap is detectable from the UI rather than silent (review fix).
     */
    public function test_settings_change_during_audit_failure_is_flagged() {
        $user_id = self::factory()->user->create( array( 'role' => 'administrator' ) );
        wp_set_current_user( $user_id );

        $table = wldelay_get_audit_table_name();
        $break = static function ( $query ) use ( $table ) {
            if ( 0 === stripos( ltrim( $query ), 'INSERT' ) && false !== strpos( $query, $table ) ) {
                return 'INSERT INTO'; // Syntax error -> the audit write fails.
            }
            return $query;
        };
        add_filter( 'query', $break );

        global $wpdb;
        $suppress = $wpdb->suppress_errors( true );

        // The mutation itself must succeed even though its audit row cannot be
        // written.
        $changed = update_option( WLDELAY_OPTION_NAME, array( 'wldelay_delay' => 9 ) );

        $wpdb->suppress_errors( $suppress );
        remove_filter( 'query', $break );

        $this->assertTrue( $changed, 'The settings mutation must complete (fail-open)' );
        $this->assertTrue(
            wldelay_audit_log_is_degraded(),
            'A failed audit write during a settings change must flag the trail as incomplete'
        );

        wp_set_current_user( 0 );
    }

    /**
     * A non-numeric actor filter matches only by login and must NOT return
     * system rows (actor_id 0). Guards the OR actor_id = 0 fold-in (review fix).
     */
    public function test_text_actor_filter_excludes_system_rows() {
        // One human actor row + several system rows (actor_id 0).
        wldelay_audit_write_row( array(
            'action'      => 'settings_changed',
            'actor_id'    => 7,
            'actor_login' => 'alice',
            'created_at'  => current_time( 'mysql', true ),
        ) );
        for ( $i = 0; $i < 3; $i++ ) {
            wldelay_audit_write_row( array(
                'action'      => 'lockout_cleared',
                'actor_id'    => 0,
                'actor_login' => '',
                'created_at'  => current_time( 'mysql', true ),
            ) );
        }

        // Text search for "alice" must return only her row, not the 3 system rows.
        $this->assertSame( 1, wldelay_count_audit_log( array( 'actor' => 'alice' ) ) );
        $rows = wldelay_query_audit_log( array( 'actor' => 'alice' ), 1, 25 );
        $this->assertCount( 1, $rows );
        $this->assertSame( 'alice', $rows[0]->actor_login );

        // A numeric actor filter still matches the exact id.
        $this->assertSame( 1, wldelay_count_audit_log( array( 'actor' => '7' ) ) );
    }

    /**
     * The bulk-flush action carries its own label so it is distinguishable from
     * a single-IP unlock in the trail (review fix — CLI flush-lockouts).
     */
    public function test_lockouts_flushed_action_has_distinct_label() {
        $flushed = wldelay_get_audit_action_label( 'lockouts_flushed' );
        $cleared = wldelay_get_audit_action_label( 'lockout_cleared' );

        $this->assertNotSame( 'lockouts_flushed', $flushed, 'Bulk-flush action should have a human label' );
        $this->assertNotSame( $flushed, $cleared, 'Bulk flush must be distinct from single-IP unlock' );
    }

    /**
     * The FIRST settings save on a fresh install — where wldelay_options does
     * not yet exist, so WordPress takes the add-option path and fires
     * add_option_{$option} rather than update_option_{$option} — must still be
     * audited. Guards the add_option capture point (review fix): the initial
     * security configuration needs a forensic baseline.
     */
    public function test_first_settings_save_on_fresh_install_is_audited() {
        global $wpdb;

        $user_id = self::factory()->user->create( array( 'role' => 'administrator' ) );
        wp_set_current_user( $user_id );

        // Fresh-install precondition: the option is absent, so the next save
        // goes through add_option (not update_option).
        delete_option( WLDELAY_OPTION_NAME );

        $table = wldelay_get_audit_table_name();
        $wpdb->query( "TRUNCATE TABLE $table" );

        add_option( WLDELAY_OPTION_NAME, array( 'wldelay_delay' => 5, 'wldelay_lockout_enabled' => true ) );
        $this->flush();

        $rows = $wpdb->get_results( "SELECT * FROM $table WHERE action = 'settings_changed'" );
        $this->assertCount( 1, $rows, 'First settings save must produce exactly one audit row' );

        $diff = json_decode( $rows[0]->new_value, true );
        $this->assertArrayHasKey( 'wldelay_delay', $diff, 'The added keys must appear in the diff' );
        $this->assertNull( $diff['wldelay_delay']['old'], 'No prior value on a fresh add' );
        $this->assertSame( 5, $diff['wldelay_delay']['new'] );

        wp_set_current_user( 0 );
    }

    /**
     * On a non-UTC site, UTC-stored rows must display in site-local time and
     * date filters must convert local boundaries to UTC before comparing.
     * Guards the timezone handling (review fix) — without it the trail shows
     * the wrong time and omits events near day boundaries.
     */
    public function test_non_utc_timezone_display_and_filter() {
        global $wpdb;

        $original_tz = get_option( 'timezone_string' );
        update_option( 'timezone_string', 'America/New_York' ); // UTC-5 (or -4 DST).

        $table = wldelay_get_audit_table_name();

        // A row stored at 02:00 UTC on Jan 2 falls on Jan 1 (21:00/22:00) in
        // New York. A local-date filter for Jan 1 must therefore include it,
        // and a filter for Jan 2 must exclude it.
        $wpdb->insert( $table, array(
            'action'     => 'settings_changed',
            'actor_id'   => 1,
            'created_at' => '2020-01-02 02:00:00', // UTC
        ) );

        // Filter on the LOCAL date the event actually occurred (Jan 1).
        $local_day = wldelay_query_audit_log( array( 'from' => '2020-01-01', 'to' => '2020-01-01' ), 1, 25 );
        $this->assertCount( 1, $local_day, 'A UTC row must match the local calendar day it falls on' );

        // The UTC calendar day (Jan 2) must NOT match — the event is Jan 1 local.
        $utc_day = wldelay_query_audit_log( array( 'from' => '2020-01-02', 'to' => '2020-01-02' ), 1, 25 );
        $this->assertCount( 0, $utc_day, 'A UTC row must not match the following local day' );

        // Display: the rendered time must be the site-local conversion of the
        // UTC value, not the raw UTC value.
        $local_display = mysql2date( 'Y-m-d H:i', get_date_from_gmt( '2020-01-02 02:00:00' ) );
        $this->assertStringStartsWith( '2020-01-01', $local_display, 'Display must convert UTC to site-local time' );

        if ( false === $original_tz ) {
            delete_option( 'timezone_string' );
        } else {
            update_option( 'timezone_string', $original_tz );
        }
    }
}
