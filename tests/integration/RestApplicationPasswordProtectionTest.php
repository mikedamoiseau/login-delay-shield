<?php
/**
 * Integration tests for REST and application-password protection.
 */

class RestApplicationPasswordProtectionTest extends WP_UnitTestCase {

    public function setUp(): void {
        parent::setUp();
        wldelay_create_log_table();
        $this->truncate_log_table();

        $_SERVER['REMOTE_ADDR'] = '203.0.113.10';
        unset( $_SERVER['REQUEST_URI'] );
        unset( $_SERVER['PHP_AUTH_USER'] );
        unset( $_SERVER['PHP_AUTH_PW'] );

        delete_option( 'wldelay_options' );
        wldelay_clear_options_cache();

        // Keep app-password behavior deterministic in tests.
        add_filter( 'wp_is_application_passwords_available', '__return_true' );
    }

    public function tearDown(): void {
        unset( $_SERVER['REMOTE_ADDR'] );
        unset( $_SERVER['REQUEST_URI'] );
        unset( $_SERVER['PHP_AUTH_USER'] );
        unset( $_SERVER['PHP_AUTH_PW'] );

        remove_all_filters( 'wp_is_application_passwords_available' );

        delete_option( 'wldelay_options' );
        wldelay_clear_options_cache();
        $this->truncate_log_table();
        parent::tearDown();
    }

    public function test_rest_authentication_filter_registered() {
        $this->assertNotFalse( has_filter( 'rest_authentication_errors', 'wldelay_handle_rest_authentication' ) );
    }

    public function test_application_password_filter_registered() {
        $this->assertNotFalse( has_filter( 'authenticate', 'wldelay_handle_application_password_auth' ) );
    }

    public function test_rest_protection_defaults_to_disabled_when_flag_missing() {
        update_option( 'wldelay_options', array(
            'wldelay_delay' => 0,
        ) );
        wldelay_clear_options_cache();
        $_SERVER['REQUEST_URI'] = '/wp-json/wp/v2/posts';

        $incoming = new WP_Error( 'rest_invalid', 'Invalid credentials' );
        $result = wldelay_handle_rest_authentication( $incoming );

        $this->assertSame( $incoming, $result );
        $this->assertCount( 0, wldelay_get_recent_failed_attempts( 10 ) );
    }

    public function test_rest_protection_disabled_passthrough() {
        update_option( 'wldelay_options', array(
            'wldelay_rest_enabled' => false,
            'wldelay_delay' => 0,
        ) );
        wldelay_clear_options_cache();
        $_SERVER['REQUEST_URI'] = '/wp-json/wp/v2/posts';

        $incoming = new WP_Error( 'rest_invalid', 'Invalid credentials' );
        $result = wldelay_handle_rest_authentication( $incoming );

        $this->assertSame( $incoming, $result );
        $this->assertCount( 0, wldelay_get_recent_failed_attempts( 10 ) );
    }

    public function test_rest_protection_logs_failed_attempt_with_rest_source() {
        update_option( 'wldelay_options', array(
            'wldelay_rest_enabled' => true,
            'wldelay_delay' => 0,
            'wldelay_delay_random' => false,
            'wldelay_progressive_enabled' => true,
        ) );
        wldelay_clear_options_cache();

        $_SERVER['REQUEST_URI'] = '/wp-json/wp/v2/posts';
        $_SERVER['PHP_AUTH_USER'] = 'RestUser';
        $_SERVER['PHP_AUTH_PW'] = 'bad-pass';

        $incoming = new WP_Error( 'rest_invalid', 'Invalid credentials' );
        $result = wldelay_handle_rest_authentication( $incoming );

        $this->assertSame( $incoming, $result );
        $logs = wldelay_get_recent_failed_attempts( 10 );
        $this->assertCount( 1, $logs );
        $this->assertEquals( 'rest', $logs[0]->source );
        $this->assertEquals( 'restuser', $logs[0]->username );
    }

    public function test_rest_protection_blocks_locked_ip() {
        update_option( 'wldelay_options', array(
            'wldelay_rest_enabled' => true,
            'wldelay_lockout_enabled' => true,
            'wldelay_lockout_duration' => 60,
            'wldelay_delay' => 0,
        ) );
        wldelay_clear_options_cache();

        $_SERVER['REQUEST_URI'] = '/wp-json/wp/v2/posts';
        $_SERVER['PHP_AUTH_USER'] = 'locked-user';
        $_SERVER['PHP_AUTH_PW'] = 'bad-pass';
        wldelay_lock_ip( '203.0.113.10', 'locked-user' );

        $result = wldelay_handle_rest_authentication( new WP_Error( 'rest_invalid', 'Invalid credentials' ) );

        $this->assertInstanceOf( WP_Error::class, $result );
        $this->assertEquals( 'wldelay_ip_locked', $result->get_error_code() );
    }

    public function test_rest_protection_respects_whitelist() {
        update_option( 'wldelay_options', array(
            'wldelay_rest_enabled' => true,
            'wldelay_whitelist_enabled' => true,
            'wldelay_whitelist_ips' => '203.0.113.10',
            'wldelay_delay' => 0,
        ) );
        wldelay_clear_options_cache();
        $_SERVER['REQUEST_URI'] = '/wp-json/wp/v2/posts';

        $incoming = new WP_Error( 'rest_invalid', 'Invalid credentials' );
        $result = wldelay_handle_rest_authentication( $incoming );

        $this->assertSame( $incoming, $result );
        $this->assertCount( 0, wldelay_get_recent_failed_attempts( 10 ) );
    }

    public function test_application_password_protection_defaults_to_disabled_when_flag_missing() {
        update_option( 'wldelay_options', array(
            'wldelay_delay' => 0,
        ) );
        wldelay_clear_options_cache();
        $_SERVER['PHP_AUTH_USER'] = 'api-user';
        $_SERVER['PHP_AUTH_PW'] = 'app-pass';

        $incoming = new WP_Error( 'invalid_application_password', 'Bad app password' );
        $result = wldelay_handle_application_password_auth( $incoming, 'api-user', 'app-pass' );

        $this->assertSame( $incoming, $result );
        $this->assertCount( 0, wldelay_get_recent_failed_attempts( 10 ) );
    }

    public function test_application_password_protection_disabled_passthrough() {
        update_option( 'wldelay_options', array(
            'wldelay_application_password_enabled' => false,
            'wldelay_delay' => 0,
        ) );
        wldelay_clear_options_cache();
        $_SERVER['PHP_AUTH_USER'] = 'api-user';
        $_SERVER['PHP_AUTH_PW'] = 'app-pass';

        $incoming = new WP_Error( 'invalid_application_password', 'Bad app password' );
        $result = wldelay_handle_application_password_auth( $incoming, 'api-user', 'app-pass' );

        $this->assertSame( $incoming, $result );
        $this->assertCount( 0, wldelay_get_recent_failed_attempts( 10 ) );
    }

    public function test_application_password_failed_attempt_logs_source() {
        update_option( 'wldelay_options', array(
            'wldelay_application_password_enabled' => true,
            'wldelay_delay' => 0,
            'wldelay_delay_random' => false,
            'wldelay_progressive_enabled' => true,
        ) );
        wldelay_clear_options_cache();
        $_SERVER['PHP_AUTH_USER'] = 'app-user';
        $_SERVER['PHP_AUTH_PW'] = 'wrong';

        $incoming = new WP_Error( 'invalid_application_password', 'Bad app password' );
        $result = wldelay_handle_application_password_auth( $incoming, 'app-user', 'wrong' );

        $this->assertSame( $incoming, $result );
        $logs = wldelay_get_recent_failed_attempts( 10 );
        $this->assertCount( 1, $logs );
        $this->assertEquals( 'application-password', $logs[0]->source );
        $this->assertEquals( 'app-user', $logs[0]->username );
    }

    public function test_application_password_blocks_locked_ip() {
        update_option( 'wldelay_options', array(
            'wldelay_application_password_enabled' => true,
            'wldelay_lockout_enabled' => true,
            'wldelay_lockout_duration' => 60,
            'wldelay_delay' => 0,
        ) );
        wldelay_clear_options_cache();

        $_SERVER['PHP_AUTH_USER'] = 'locked-app-user';
        $_SERVER['PHP_AUTH_PW'] = 'bad';
        wldelay_lock_ip( '203.0.113.10', 'locked-app-user' );

        $result = wldelay_handle_application_password_auth(
            new WP_Error( 'invalid_application_password', 'Bad app password' ),
            'locked-app-user',
            'bad'
        );

        $this->assertInstanceOf( WP_Error::class, $result );
        $this->assertEquals( 'wldelay_ip_locked', $result->get_error_code() );
    }

    public function test_application_password_respects_whitelist() {
        update_option( 'wldelay_options', array(
            'wldelay_application_password_enabled' => true,
            'wldelay_whitelist_enabled' => true,
            'wldelay_whitelist_ips' => '203.0.113.10',
            'wldelay_delay' => 0,
        ) );
        wldelay_clear_options_cache();

        $_SERVER['PHP_AUTH_USER'] = 'app-user';
        $_SERVER['PHP_AUTH_PW'] = 'wrong';
        $incoming = new WP_Error( 'invalid_application_password', 'Bad app password' );
        $result = wldelay_handle_application_password_auth( $incoming, 'app-user', 'wrong' );

        $this->assertSame( $incoming, $result );
        $this->assertCount( 0, wldelay_get_recent_failed_attempts( 10 ) );
    }

    public function test_rest_handler_skips_application_password_when_app_protection_enabled() {
        update_option( 'wldelay_options', array(
            'wldelay_rest_enabled' => true,
            'wldelay_application_password_enabled' => true,
            'wldelay_progressive_enabled' => true,
            'wldelay_delay' => 0,
            'wldelay_delay_random' => false,
        ) );
        wldelay_clear_options_cache();

        $_SERVER['REQUEST_URI'] = '/wp-json/wp/v2/posts';
        $_SERVER['PHP_AUTH_USER'] = 'app-user';
        $_SERVER['PHP_AUTH_PW'] = 'bad';

        $incoming = new WP_Error( 'invalid_application_password', 'Bad app password' );
        $result = wldelay_handle_rest_authentication( $incoming );

        $this->assertSame( $incoming, $result );
        $this->assertCount( 0, wldelay_get_recent_failed_attempts( 10 ) );
    }

    private function truncate_log_table() {
        global $wpdb;
        $table_name = wldelay_get_log_table_name();
        $wpdb->query( "TRUNCATE TABLE $table_name" );
    }
}
