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

        // Clear dashboard widget sub-caches
        delete_transient( WLDELAY_DASH_RECENT_CACHE );
        delete_transient( WLDELAY_DASH_TRENDS_CACHE );

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

        // Drop any sub-caches a prior test primed so the widget rebuilds from the
        // now-empty table rather than serving a stale recent-attempts list.
        delete_transient( WLDELAY_DASH_RECENT_CACHE );
        delete_transient( WLDELAY_DASH_TRENDS_CACHE );

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
        $this->assertStringContainsString( 'Failed login trends: last 7 days', $output );
        $this->assertStringContainsString( 'Daily activity', $output );
        $this->assertStringContainsString( 'Top sources', $output );
        $this->assertStringContainsString( 'Top IPs', $output );
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
     * Test that widget displays REST source correctly.
     */
    public function test_widget_displays_rest_source() {
        wldelay_create_log_table();
        wldelay_log_failed_attempt( '10.0.0.51', 'rest_attacker', 'rest' );

        ob_start();
        wldelay_dashboard_widget_content();
        $output = ob_get_clean();

        $this->assertStringContainsString( 'REST API', $output );
    }

    /**
     * Test that widget displays application-password source correctly.
     */
    public function test_widget_displays_application_password_source() {
        wldelay_create_log_table();
        wldelay_log_failed_attempt( '10.0.0.52', 'app_attacker', 'application-password' );

        ob_start();
        wldelay_dashboard_widget_content();
        $output = ob_get_clean();

        $this->assertStringContainsString( 'Application Password', $output );
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
     * Test failed login trend aggregation for recent data.
     */
    public function test_get_failed_login_trends_aggregates_recent_data() {
        global $wpdb;

        wldelay_create_log_table();
        $table_name = wldelay_get_log_table_name();

        $wpdb->insert(
            $table_name,
            array(
                'ip_address'   => '203.0.113.10',
                'username'     => 'first-user',
                'attempted_at' => gmdate( 'Y-m-d H:i:s', current_time( 'timestamp' ) - HOUR_IN_SECONDS ),
                'source'       => 'wp-login',
            )
        );
        $wpdb->insert(
            $table_name,
            array(
                'ip_address'   => '203.0.113.10',
                'username'     => 'second-user',
                'attempted_at' => gmdate( 'Y-m-d H:i:s', current_time( 'timestamp' ) - ( 2 * HOUR_IN_SECONDS ) ),
                'source'       => 'xmlrpc',
            )
        );
        $wpdb->insert(
            $table_name,
            array(
                'ip_address'   => '198.51.100.8',
                'username'     => 'third-user',
                'attempted_at' => gmdate( 'Y-m-d H:i:s', current_time( 'timestamp' ) - DAY_IN_SECONDS ),
                'source'       => 'wp-login',
            )
        );
        $wpdb->insert(
            $table_name,
            array(
                'ip_address'   => '192.0.2.99',
                'username'     => 'old-user',
                'attempted_at' => gmdate( 'Y-m-d H:i:s', current_time( 'timestamp' ) - ( 10 * DAY_IN_SECONDS ) ),
                'source'       => 'rest',
            )
        );

        $trends = wldelay_get_failed_login_trends( 7 );

        $this->assertSame( 7, $trends['window_days'] );
        $this->assertSame( 3, $trends['total_attempts'] );
        $this->assertCount( 7, $trends['daily_counts'] );
        $this->assertSame( 2, $trends['peak_day']['count'] );
        $this->assertSame( '203.0.113.10', $trends['top_ips'][0]['ip_address'] );
        $this->assertSame( 2, $trends['top_ips'][0]['count'] );
        $this->assertSame( 'wp-login', $trends['source_counts'][0]['source'] );
        $this->assertSame( 2, $trends['source_counts'][0]['count'] );
    }

    /**
     * Test widget rebuilds the recent sub-cache when only the trends cache is primed.
     */
    public function test_widget_rebuilds_recent_when_only_trends_cached() {
        wldelay_create_log_table();
        wldelay_log_failed_attempt( '192.168.1.210', 'cached-user', 'wp-login' );

        // Prime only the trends sub-cache; leave recent unset so the widget must
        // rebuild it independently.
        set_transient( WLDELAY_DASH_TRENDS_CACHE, wldelay_get_failed_login_trends( 7 ), WLDELAY_DASH_TRENDS_TTL );
        delete_transient( WLDELAY_DASH_RECENT_CACHE );

        ob_start();
        wldelay_dashboard_widget_content();
        $output = ob_get_clean();

        $this->assertStringContainsString( 'Failed login trends: last 7 days', $output );
        $this->assertStringContainsString( 'cached-user', $output );
        $this->assertNotFalse( get_transient( WLDELAY_DASH_RECENT_CACHE ), 'Recent sub-cache should be rebuilt on miss' );
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
