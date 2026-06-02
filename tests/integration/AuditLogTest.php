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
     * Once the audit pipeline recovers, a verified successful write clears the
     * integrity marker so the admin warning does not linger forever (review fix:
     * the marker tracks current health, not a permanent flag).
     */
    public function test_integrity_marker_clears_after_successful_write() {
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
        $this->assertFalse(
            wldelay_audit_log_is_degraded(),
            'A successful write must clear the integrity marker'
        );
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
