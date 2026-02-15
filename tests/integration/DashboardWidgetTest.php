<?php
/**
 * Integration tests for dashboard widget functionality.
 */

class DashboardWidgetTest extends WP_UnitTestCase {

    /**
     * Clean up after each test.
     */
    public function tearDown(): void {
        global $wpdb;

        // Clear log table
        $table_name = wldelay_get_log_table_name();
        $wpdb->query( "TRUNCATE TABLE $table_name" );

        // Clear dashboard widget cache
        delete_transient( 'wldelay_dashboard_attempts' );

        parent::tearDown();
    }

    /**
     * Test that dashboard widget action is registered.
     */
    public function test_dashboard_widget_action_registered() {
        $this->assertNotFalse(
            has_action( 'wp_dashboard_setup', 'wldelay_add_dashboard_widget' ),
            'wldelay_add_dashboard_widget should be hooked to wp_dashboard_setup'
        );
    }

    /**
     * Test that widget shows empty message when no attempts.
     */
    public function test_widget_shows_empty_message() {
        // Ensure log table is empty
        global $wpdb;
        $table_name = wldelay_get_log_table_name();
        $wpdb->query( "TRUNCATE TABLE $table_name" );

        ob_start();
        wldelay_dashboard_widget_content();
        $output = ob_get_clean();

        $this->assertStringContainsString( 'No failed login attempts recorded', $output );
    }

    /**
     * Test that widget displays failed attempts.
     */
    public function test_widget_displays_failed_attempts() {
        // Make sure log table exists
        wldelay_create_log_table();

        // Add a failed attempt
        wldelay_log_failed_attempt( '192.168.1.100', 'attacker', 'wp-login' );

        ob_start();
        wldelay_dashboard_widget_content();
        $output = ob_get_clean();

        $this->assertStringContainsString( '192.168.1.100', $output );
        $this->assertStringContainsString( 'attacker', $output );
        $this->assertStringContainsString( 'Login', $output ); // Source badge
    }

    /**
     * Test that widget displays XMLRPC source correctly.
     */
    public function test_widget_displays_xmlrpc_source() {
        wldelay_create_log_table();
        wldelay_log_failed_attempt( '10.0.0.50', 'xmlrpc_attacker', 'xmlrpc' );

        ob_start();
        wldelay_dashboard_widget_content();
        $output = ob_get_clean();

        $this->assertStringContainsString( '10.0.0.50', $output );
        $this->assertStringContainsString( 'xmlrpc_attacker', $output );
        $this->assertStringContainsString( 'XML-RPC', $output ); // Source badge
    }

    /**
     * Test that widget limits displayed attempts.
     */
    public function test_widget_limits_displayed_attempts() {
        wldelay_create_log_table();

        // Add 15 failed attempts
        for ( $i = 1; $i <= 15; $i++ ) {
            wldelay_log_failed_attempt( "192.168.1.{$i}", "user{$i}", 'wp-login' );
        }

        ob_start();
        wldelay_dashboard_widget_content();
        $output = ob_get_clean();

        // Widget should show 10 attempts (default limit)
        // Count table rows (excluding header)
        preg_match_all( '/<tr>/', $output, $matches );
        // Header row + 10 data rows = 11 total <tr> tags
        $this->assertCount( 11, $matches[0] );
    }

    /**
     * Test that widget contains settings link.
     */
    public function test_widget_contains_settings_link() {
        wldelay_create_log_table();
        wldelay_log_failed_attempt( '192.168.1.1', 'test', 'wp-login' );

        ob_start();
        wldelay_dashboard_widget_content();
        $output = ob_get_clean();

        $this->assertStringContainsString( 'login-delay-shield-admin', $output );
        $this->assertStringContainsString( 'Settings', $output );
    }

    /**
     * Test that widget has proper table structure.
     */
    public function test_widget_has_proper_table_structure() {
        wldelay_create_log_table();
        wldelay_log_failed_attempt( '192.168.1.1', 'test', 'wp-login' );

        ob_start();
        wldelay_dashboard_widget_content();
        $output = ob_get_clean();

        // Check for table headers
        $this->assertStringContainsString( '<table', $output );
        $this->assertStringContainsString( 'Time', $output );
        $this->assertStringContainsString( 'Username', $output );
        $this->assertStringContainsString( 'IP Address', $output );
        $this->assertStringContainsString( 'Source', $output );
    }

    /**
     * Test that recent attempts are fetched in correct order.
     */
    public function test_recent_attempts_order() {
        global $wpdb;

        wldelay_create_log_table();
        $table_name = wldelay_get_log_table_name();

        // Insert with explicit timestamps to ensure correct ordering
        $wpdb->insert( $table_name, [
            'ip_address' => '192.168.1.1',
            'username' => 'first',
            'attempted_at' => '2025-01-01 10:00:00',
            'source' => 'wp-login',
        ] );
        $wpdb->insert( $table_name, [
            'ip_address' => '192.168.1.2',
            'username' => 'second',
            'attempted_at' => '2025-01-01 11:00:00',
            'source' => 'wp-login',
        ] );
        $wpdb->insert( $table_name, [
            'ip_address' => '192.168.1.3',
            'username' => 'third',
            'attempted_at' => '2025-01-01 12:00:00',
            'source' => 'wp-login',
        ] );

        $attempts = wldelay_get_recent_failed_attempts( 10 );

        // Most recent should be first (ORDER BY attempted_at DESC)
        $this->assertEquals( 'third', $attempts[0]->username );
        $this->assertEquals( 'second', $attempts[1]->username );
        $this->assertEquals( 'first', $attempts[2]->username );
    }

    /**
     * Test wldelay_get_recent_failed_attempts respects limit.
     */
    public function test_get_recent_failed_attempts_respects_limit() {
        wldelay_create_log_table();

        // Add 10 attempts
        for ( $i = 1; $i <= 10; $i++ ) {
            wldelay_log_failed_attempt( "192.168.1.{$i}", "user{$i}", 'wp-login' );
        }

        $attempts = wldelay_get_recent_failed_attempts( 5 );

        $this->assertCount( 5, $attempts );
    }

    /**
     * Test log table name function.
     */
    public function test_get_log_table_name() {
        global $wpdb;

        $expected = $wpdb->prefix . 'wldelay_login_log';
        $actual = wldelay_get_log_table_name();

        $this->assertEquals( $expected, $actual );
    }
}
