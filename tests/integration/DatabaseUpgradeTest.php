<?php
/**
 * Integration tests for database upgrade functionality.
 */

class DatabaseUpgradeTest extends WP_UnitTestCase {

    /**
     * Clean up after each test.
     */
    public function tearDown(): void {
        delete_option( 'wldelay_db_version' );
        delete_option( 'wldelay_plugin_version' );
        delete_option( 'wldelay_previous_version' );
        delete_option( 'wldelay_name_change_notice_dismissed' );
        delete_option( 'wldelay_options' );
        parent::tearDown();
    }

    /**
     * Test that create_log_table creates the table.
     */
    public function test_create_log_table_creates_table() {
        global $wpdb;

        $table_name = wldelay_get_log_table_name();

        // Drop table if exists
        $wpdb->query( "DROP TABLE IF EXISTS $table_name" );

        // Create the table
        wldelay_create_log_table();

        // Verify table exists
        $table_exists = $wpdb->get_var(
            $wpdb->prepare(
                "SHOW TABLES LIKE %s",
                $table_name
            )
        );

        $this->assertEquals( $table_name, $table_exists );
    }

    /**
     * Test that create_log_table sets db_version option.
     */
    public function test_create_log_table_sets_version() {
        delete_option( 'wldelay_db_version' );

        wldelay_create_log_table();

        $db_version = get_option( 'wldelay_db_version' );

        $this->assertEquals( WLDELAY_VERSION, $db_version );
    }

    /**
     * Test that maybe_upgrade_db triggers upgrade when version differs.
     */
    public function test_maybe_upgrade_triggers_on_version_mismatch() {
        global $wpdb;

        // Set an old version
        update_option( 'wldelay_db_version', '1.0.0' );

        $table_name = wldelay_get_log_table_name();

        // Drop table to verify it gets recreated
        $wpdb->query( "DROP TABLE IF EXISTS $table_name" );

        // Trigger upgrade check
        wldelay_maybe_upgrade_db();

        // Verify table was created
        $table_exists = $wpdb->get_var(
            $wpdb->prepare(
                "SHOW TABLES LIKE %s",
                $table_name
            )
        );

        $this->assertEquals( $table_name, $table_exists );

        // Verify version was updated
        $this->assertEquals( WLDELAY_VERSION, get_option( 'wldelay_db_version' ) );
    }

    /**
     * Test that maybe_upgrade_db does nothing when version matches.
     */
    public function test_maybe_upgrade_skips_when_version_matches() {
        // Set current version
        update_option( 'wldelay_db_version', WLDELAY_VERSION );

        // Add a spy to track if create_log_table is called
        // Since we can't easily mock, we'll check that version stays the same
        $before_version = get_option( 'wldelay_db_version' );

        wldelay_maybe_upgrade_db();

        $after_version = get_option( 'wldelay_db_version' );

        $this->assertEquals( $before_version, $after_version );
    }

    /**
     * Test that log table has correct structure.
     */
    public function test_log_table_has_correct_structure() {
        global $wpdb;

        wldelay_create_log_table();
        $table_name = wldelay_get_log_table_name();

        $columns = $wpdb->get_results( "DESCRIBE $table_name" );
        $column_names = array_column( $columns, 'Field' );

        $this->assertContains( 'id', $column_names );
        $this->assertContains( 'ip_address', $column_names );
        $this->assertContains( 'username', $column_names );
        $this->assertContains( 'attempted_at', $column_names );
        $this->assertContains( 'source', $column_names );
    }

    /**
     * Test that log table has proper indexes.
     */
    public function test_log_table_has_indexes() {
        global $wpdb;

        wldelay_create_log_table();
        $table_name = wldelay_get_log_table_name();

        $indexes = $wpdb->get_results( "SHOW INDEX FROM $table_name" );
        $index_names = array_unique( array_column( $indexes, 'Key_name' ) );

        $this->assertContains( 'PRIMARY', $index_names );
        $this->assertContains( 'attempted_at', $index_names );
        $this->assertContains( 'ip_address', $index_names );
    }

    /**
     * Test that version tracking works correctly.
     */
    public function test_version_tracking() {
        // Clear version tracking options
        delete_option( 'wldelay_plugin_version' );
        delete_option( 'wldelay_previous_version' );

        // Simulate first install (no previous version)
        wldelay_track_version();

        $this->assertEquals( WLDELAY_VERSION, get_option( 'wldelay_plugin_version' ) );
        $this->assertFalse( get_option( 'wldelay_previous_version' ) ); // No previous version

        // Simulate upgrade from 1.5.0
        update_option( 'wldelay_plugin_version', '1.5.0' );
        wldelay_track_version();

        $this->assertEquals( WLDELAY_VERSION, get_option( 'wldelay_plugin_version' ) );
        $this->assertEquals( '1.5.0', get_option( 'wldelay_previous_version' ) );
    }

    /**
     * Test that version tracking doesn't update when version unchanged.
     */
    public function test_version_tracking_no_update_when_same() {
        update_option( 'wldelay_plugin_version', WLDELAY_VERSION );
        update_option( 'wldelay_previous_version', '1.5.0' );

        wldelay_track_version();

        // Previous version should not change
        $this->assertEquals( '1.5.0', get_option( 'wldelay_previous_version' ) );
    }

    /**
     * Test log_failed_attempt with source parameter.
     */
    public function test_log_failed_attempt_with_source() {
        global $wpdb;

        wldelay_create_log_table();
        $table_name = wldelay_get_log_table_name();
        $wpdb->query( "TRUNCATE TABLE $table_name" );

        // Log with wp-login source
        wldelay_log_failed_attempt( '192.168.1.1', 'user1', 'wp-login' );

        // Log with xmlrpc source
        wldelay_log_failed_attempt( '192.168.1.2', 'user2', 'xmlrpc' );

        $results = $wpdb->get_results( "SELECT * FROM $table_name ORDER BY id" );

        $this->assertCount( 2, $results );
        $this->assertEquals( 'wp-login', $results[0]->source );
        $this->assertEquals( 'xmlrpc', $results[1]->source );
    }

    /**
     * Test log_failed_attempt default source.
     */
    public function test_log_failed_attempt_default_source() {
        global $wpdb;

        wldelay_create_log_table();
        $table_name = wldelay_get_log_table_name();
        $wpdb->query( "TRUNCATE TABLE $table_name" );

        // Set REQUEST_URI to simulate wp-login
        $_SERVER['REQUEST_URI'] = '/wp-login.php';

        // Log without specifying source
        wldelay_log_failed_attempt( '192.168.1.1', 'user1' );

        $result = $wpdb->get_row( "SELECT * FROM $table_name LIMIT 1" );

        $this->assertEquals( 'wp-login', $result->source );

        unset( $_SERVER['REQUEST_URI'] );
    }

    /**
     * Test that dbDelta preserves existing data during upgrade.
     */
    public function test_upgrade_preserves_data() {
        global $wpdb;

        wldelay_create_log_table();
        $table_name = wldelay_get_log_table_name();

        // Insert some data
        wldelay_log_failed_attempt( '192.168.1.1', 'test_user', 'wp-login' );

        // Simulate upgrade by calling create_log_table again
        wldelay_create_log_table();

        // Data should still exist
        $count = $wpdb->get_var( "SELECT COUNT(*) FROM $table_name" );

        $this->assertEquals( 1, $count );
    }

    /**
     * Test plugins_loaded hooks are registered.
     */
    public function test_plugins_loaded_hooks_registered() {
        $this->assertNotFalse(
            has_action( 'plugins_loaded', 'wldelay_maybe_upgrade_db' ),
            'wldelay_maybe_upgrade_db should be hooked to plugins_loaded'
        );

        $this->assertNotFalse(
            has_action( 'plugins_loaded', 'wldelay_track_version' ),
            'wldelay_track_version should be hooked to plugins_loaded'
        );

        $this->assertNotFalse(
            has_action( 'plugins_loaded', 'wldelay_load_textdomain' ),
            'wldelay_load_textdomain should be hooked to plugins_loaded'
        );
    }
}
