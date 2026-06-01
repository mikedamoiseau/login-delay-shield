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

        // Nothing written until the deferred queue flushes.
        $table = wldelay_get_audit_table_name();
        $this->assertSame( 0, (int) $wpdb->get_var( "SELECT COUNT(*) FROM $table" ) );

        $this->flush();

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
}
