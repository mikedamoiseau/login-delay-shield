<?php
/**
 * Integration tests for recovery tools (unlock current IP + CLI helpers).
 */

if ( ! class_exists( 'WLD_RecoveryTools_WPDieException' ) ) {
    class WLD_RecoveryTools_WPDieException extends Exception {}
}

class RecoveryToolsTest extends WP_UnitTestCase {

    /**
     * @var array
     */
    private $old_get = array();

    /**
     * @var array
     */
    private $old_request = array();

    /**
     * @var string|null
     */
    private static $redirect_location = null;

    public function setUp(): void {
        parent::setUp();

        delete_option( 'wldelay_options' );
        delete_option( wldelay_get_transient_registry_option_name() );
        wldelay_clear_options_cache();

        $this->old_get     = $_GET;
        $this->old_request = $_REQUEST;

        $_SERVER['REMOTE_ADDR'] = '192.168.50.10';
        self::$redirect_location = null;
    }

    public function tearDown(): void {
        unset( $_SERVER['REMOTE_ADDR'] );

        $_GET     = $this->old_get;
        $_REQUEST = $this->old_request;

        delete_option( 'wldelay_options' );
        delete_option( wldelay_get_transient_registry_option_name() );
        wldelay_clear_options_cache();
        remove_all_filters( 'wp_die_handler' );
        remove_all_filters( 'wp_redirect' );
        // wldelay_handle_unlock_current_ip() now checks WP_TESTS_DOMAIN constant.
        wp_set_current_user( 0 );

        parent::tearDown();
    }

    public function test_delete_lockout_for_ip_removes_lockout_and_failure_keys() {
        $ip = '192.168.50.10';

        $lockout_key = wldelay_get_lockout_transient_key( $ip );
        $fails_key = wldelay_get_failure_transient_key( $ip );

        set_transient( $lockout_key, time(), 10 * MINUTE_IN_SECONDS );
        set_transient( $fails_key, 5, HOUR_IN_SECONDS );

        wldelay_register_transient_key( $lockout_key );
        wldelay_register_transient_key( $fails_key );

        $deleted = wldelay_delete_lockout_for_ip( $ip );

        $this->assertSame( 2, $deleted );
        $this->assertFalse( get_transient( $lockout_key ) );
        $this->assertFalse( get_transient( $fails_key ) );
    }

    public function test_delete_lockout_for_ip_removes_ip_username_keys_when_username_provided() {
        $ip = '192.168.50.20';
        $username = 'admin';
        $pair_options = [ 'wldelay_lockout_attempt_strategy' => 'ip_username' ];

        $lockout_key = wldelay_get_lockout_transient_key( $ip, $username, $pair_options );
        $fails_key = wldelay_get_failure_transient_key( $ip, $username, $pair_options );

        set_transient( $lockout_key, time(), 10 * MINUTE_IN_SECONDS );
        set_transient( $fails_key, 3, HOUR_IN_SECONDS );

        wldelay_register_transient_key( $lockout_key );
        wldelay_register_transient_key( $fails_key );

        $deleted = wldelay_delete_lockout_for_ip( $ip, $username );

        $this->assertSame( 2, $deleted );
        $this->assertFalse( get_transient( $lockout_key ) );
        $this->assertFalse( get_transient( $fails_key ) );
    }

    public function test_flush_lockout_transients_removes_lockouts_and_failure_counters() {
        $ip_one = '192.168.50.30';
        $ip_two = '192.168.50.31';

        $lockout_one = wldelay_get_lockout_transient_key( $ip_one );
        $lockout_two = wldelay_get_lockout_transient_key( $ip_two );
        $fails_one = wldelay_get_failure_transient_key( $ip_one );
        $fails_two = wldelay_get_failure_transient_key( $ip_two );

        set_transient( $lockout_one, time(), 10 * MINUTE_IN_SECONDS );
        set_transient( $lockout_two, time(), 10 * MINUTE_IN_SECONDS );
        set_transient( $fails_one, 2, HOUR_IN_SECONDS );
        set_transient( $fails_two, 4, HOUR_IN_SECONDS );

        wldelay_register_transient_key( $lockout_one );
        wldelay_register_transient_key( $lockout_two );
        wldelay_register_transient_key( $fails_one );
        wldelay_register_transient_key( $fails_two );

        $deleted = wldelay_flush_lockout_transients();

        $this->assertGreaterThanOrEqual( 4, $deleted );
        $this->assertFalse( get_transient( $lockout_one ) );
        $this->assertFalse( get_transient( $lockout_two ) );
        $this->assertFalse( get_transient( $fails_one ) );
        $this->assertFalse( get_transient( $fails_two ) );
    }

    public function test_unlock_current_ip_url_contains_expected_action_and_nonce() {
        $url = wldelay_get_unlock_current_ip_url();

        $this->assertStringContainsString( 'action=wldelay_unlock_current_ip', $url );
        $this->assertStringContainsString( '_wpnonce=', $url );
    }

    public function test_unlock_current_ip_action_is_registered() {
        $this->assertNotFalse(
            has_action( 'admin_post_wldelay_unlock_current_ip', 'wldelay_handle_unlock_current_ip' ),
            'wldelay_handle_unlock_current_ip should be hooked to admin_post_wldelay_unlock_current_ip'
        );
    }

    public function test_unlock_current_ip_action_removes_lockout_and_redirects_with_success_notice() {
        $admin_id = $this->factory->user->create( array( 'role' => 'administrator' ) );
        wp_set_current_user( $admin_id );

        $ip = '192.168.50.10';
        $lockout_key = wldelay_get_lockout_transient_key( $ip );
        $fails_key   = wldelay_get_failure_transient_key( $ip );

        set_transient( $lockout_key, time(), 10 * MINUTE_IN_SECONDS );
        set_transient( $fails_key, 5, HOUR_IN_SECONDS );

        wldelay_register_transient_key( $lockout_key );
        wldelay_register_transient_key( $fails_key );

        $nonce = wp_create_nonce( 'wldelay_unlock_current_ip' );
        $_GET['_wpnonce']     = $nonce;
        $_REQUEST['_wpnonce'] = $nonce;

        add_filter( 'wp_redirect', array( __CLASS__, 'capture_redirect_location' ), 10, 2 );

        do_action( 'admin_post_wldelay_unlock_current_ip' );

        $this->assertFalse( get_transient( $lockout_key ) );
        $this->assertFalse( get_transient( $fails_key ) );
        $this->assertNotNull( self::$redirect_location );
        $this->assertStringContainsString( 'page=login-delay-shield-admin', self::$redirect_location );
        $this->assertStringContainsString( 'wldelay_unlock_ip=success', self::$redirect_location );
    }

    public function test_unlock_current_ip_action_requires_capability() {
        $user_id = $this->factory->user->create( array( 'role' => 'subscriber' ) );
        wp_set_current_user( $user_id );

        add_filter( 'wp_die_handler', array( __CLASS__, 'filter_wp_die_handler' ) );

        $this->expectException( WLD_RecoveryTools_WPDieException::class );

        do_action( 'admin_post_wldelay_unlock_current_ip' );
    }

    public function test_unlock_current_ip_action_requires_nonce() {
        $admin_id = $this->factory->user->create( array( 'role' => 'administrator' ) );
        wp_set_current_user( $admin_id );

        add_filter( 'wp_die_handler', array( __CLASS__, 'filter_wp_die_handler' ) );

        $this->expectException( WLD_RecoveryTools_WPDieException::class );

        do_action( 'admin_post_wldelay_unlock_current_ip' );
    }

    public static function capture_redirect_location( $location, $status ) {
        self::$redirect_location = $location;

        return false;
    }

    public static function filter_wp_die_handler( $handler ) {
        return array( __CLASS__, 'throw_wp_die' );
    }

    public static function throw_wp_die( $message, $title = '', $args = array() ) {
        throw new WLD_RecoveryTools_WPDieException( wp_strip_all_tags( (string) $message ) );
    }
}
