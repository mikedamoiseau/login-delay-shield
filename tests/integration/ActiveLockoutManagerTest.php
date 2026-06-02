<?php
/**
 * Integration tests for the Active Lockout Manager (F-1-1).
 *
 * Covers the admin card render, the per-subject unlock handler (scoped to a
 * single (ip,username) so a co-tenant on a shared NAT IP stays locked), the
 * clear-all handler, audit recording, and the durable-delete failure path.
 */

if ( ! class_exists( 'WLD_ActiveLockout_WPDieException' ) ) {
    class WLD_ActiveLockout_WPDieException extends Exception {}
}

class ActiveLockoutManagerTest extends WP_UnitTestCase {

    /**
     * @var array
     */
    private $old_get = array();

    /**
     * @var array
     */
    private $old_post = array();

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

        WLDelay_Test_Fixture::reset();

        $this->old_get     = $_GET;
        $this->old_post    = $_POST;
        $this->old_request = $_REQUEST;

        self::$redirect_location = null;
    }

    public function tearDown(): void {
        $_GET     = $this->old_get;
        $_POST    = $this->old_post;
        $_REQUEST = $this->old_request;

        remove_all_filters( 'wp_die_handler' );
        remove_all_filters( 'wp_redirect' );
        remove_all_filters( 'query' );

        wp_set_current_user( 0 );

        WLDelay_Test_Fixture::reset();

        parent::tearDown();
    }

    /**
     * Seed two co-tenant lockouts on a shared IP plus a separate IP, all active.
     */
    private function seed_lockouts() {
        WLDelay_Test_Fixture::make()
            ->with_option( 'wldelay_lockout_enabled', true )
            ->with_option( 'wldelay_lockout_attempt_strategy', 'ip_username' )
            ->with_lockout( '203.0.113.10', 'alice', 900 )
            ->with_lockout( '203.0.113.10', 'bob', 900 )
            ->with_lockout( '198.51.100.20', 'carol', 900 )
            ->apply();
    }

    public function test_render_lists_active_lockouts_and_excludes_expired() {
        $admin_id = $this->factory->user->create( array( 'role' => 'administrator' ) );
        wp_set_current_user( $admin_id );

        $this->seed_lockouts();

        // Add an already-expired lockout directly to the store; it must not show.
        wldelay_get_persistence_store()->add_lockout(
            '198.51.100.99',
            'expired-user',
            -60,
            'login',
            'wp-login',
            wldelay_get_lockout_transient_key( '198.51.100.99', 'expired-user' )
        );

        $view = new LDS_Settings_View();
        $method = new ReflectionMethod( LDS_Settings_View::class, 'render_active_lockouts' );
        $method->setAccessible( true );

        ob_start();
        $method->invoke( $view );
        $html = ob_get_clean();

        $this->assertStringContainsString( '203.0.113.10', $html );
        $this->assertStringContainsString( 'alice', $html );
        $this->assertStringContainsString( 'bob', $html );
        $this->assertStringContainsString( '198.51.100.20', $html );
        $this->assertStringContainsString( 'carol', $html );
        $this->assertStringContainsString( 'left', $html, 'Time remaining should be rendered' );
        $this->assertStringContainsString( 'wldelay_unlock_lockout', $html, 'Per-row unlock form should be present' );
        $this->assertStringContainsString( 'wldelay_clear_all_lockouts', $html, 'Clear-all form should be present' );

        $this->assertStringNotContainsString( 'expired-user', $html, 'Expired lockouts must be excluded' );
    }

    public function test_render_empty_state_when_no_active_lockouts() {
        $admin_id = $this->factory->user->create( array( 'role' => 'administrator' ) );
        wp_set_current_user( $admin_id );

        $view = new LDS_Settings_View();
        $method = new ReflectionMethod( LDS_Settings_View::class, 'render_active_lockouts' );
        $method->setAccessible( true );

        ob_start();
        $method->invoke( $view );
        $html = ob_get_clean();

        $this->assertStringContainsString( 'No active lockouts', $html );
    }

    public function test_unlock_action_is_registered() {
        $this->assertSame(
            10,
            has_action( 'admin_post_wldelay_unlock_lockout', 'wldelay_handle_unlock_lockout' )
        );
        $this->assertSame(
            10,
            has_action( 'admin_post_wldelay_clear_all_lockouts', 'wldelay_handle_clear_all_lockouts' )
        );
    }

    public function test_unlock_removes_only_targeted_subject_and_leaves_cotenant_locked() {
        $admin_id = $this->factory->user->create( array( 'role' => 'administrator' ) );
        wp_set_current_user( $admin_id );

        $this->seed_lockouts();

        $alice_key = wldelay_get_lockout_transient_key( '203.0.113.10', 'alice', array( 'wldelay_lockout_attempt_strategy' => 'ip_username' ) );
        $bob_key   = wldelay_get_lockout_transient_key( '203.0.113.10', 'bob', array( 'wldelay_lockout_attempt_strategy' => 'ip_username' ) );

        $this->assertNotFalse( get_transient( $alice_key ) );
        $this->assertNotFalse( get_transient( $bob_key ) );

        $nonce = wp_create_nonce( 'wldelay_unlock_lockout' );
        $_REQUEST['_wpnonce'] = $nonce;
        $_POST['_wpnonce']    = $nonce;
        $_POST['wldelay_lockout_ip']       = '203.0.113.10';
        $_POST['wldelay_lockout_username'] = 'alice';
        $_POST['wldelay_lockout_type']     = 'login';

        add_filter( 'wp_redirect', array( __CLASS__, 'capture_redirect_location' ), 10, 2 );

        do_action( 'admin_post_wldelay_unlock_lockout' );

        // Alice is gone, Bob (co-tenant on the same NAT IP) remains locked.
        $this->assertFalse( get_transient( $alice_key ) );
        $this->assertNotFalse( get_transient( $bob_key ), 'Co-tenant lockout must survive a scoped unlock' );

        $active = wldelay_get_persistence_store()->get_active_lockouts( PHP_INT_MAX );
        $usernames = wp_list_pluck( $active, 'username' );
        $this->assertNotContains( 'alice', $usernames );
        $this->assertContains( 'bob', $usernames );

        $this->assertNotNull( self::$redirect_location );
        $this->assertStringContainsString( 'wldelay_unlock_subject=success', self::$redirect_location );
    }

    public function test_unlock_records_audit_lockout_cleared_row() {
        global $wpdb;

        $admin_id = $this->factory->user->create( array( 'role' => 'administrator' ) );
        wp_set_current_user( $admin_id );

        $this->seed_lockouts();

        $table  = wldelay_get_audit_table_name();
        $before = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM $table WHERE action = %s", 'lockout_cleared' ) );

        $nonce = wp_create_nonce( 'wldelay_unlock_lockout' );
        $_REQUEST['_wpnonce'] = $nonce;
        $_POST['_wpnonce']    = $nonce;
        $_POST['wldelay_lockout_ip']       = '198.51.100.20';
        $_POST['wldelay_lockout_username'] = 'carol';
        $_POST['wldelay_lockout_type']     = 'login';

        add_filter( 'wp_redirect', array( __CLASS__, 'capture_redirect_location' ), 10, 2 );

        do_action( 'admin_post_wldelay_unlock_lockout' );

        $after = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM $table WHERE action = %s", 'lockout_cleared' ) );
        $this->assertSame( $before + 1, $after, 'A scoped unlock must record a lockout_cleared audit row' );
    }

    public function test_clear_all_removes_every_active_lockout() {
        $admin_id = $this->factory->user->create( array( 'role' => 'administrator' ) );
        wp_set_current_user( $admin_id );

        $this->seed_lockouts();

        $this->assertNotEmpty( wldelay_get_persistence_store()->get_active_lockouts( PHP_INT_MAX ) );

        $nonce = wp_create_nonce( 'wldelay_clear_all_lockouts' );
        $_REQUEST['_wpnonce'] = $nonce;
        $_POST['_wpnonce']    = $nonce;

        add_filter( 'wp_redirect', array( __CLASS__, 'capture_redirect_location' ), 10, 2 );

        do_action( 'admin_post_wldelay_clear_all_lockouts' );

        $this->assertEmpty(
            wldelay_get_persistence_store()->get_active_lockouts( PHP_INT_MAX ),
            'Clear-all must remove every active lockout'
        );
        $this->assertNotNull( self::$redirect_location );
        $this->assertStringContainsString( 'wldelay_clear_all=success', self::$redirect_location );
    }

    public function test_unlock_durable_delete_failure_yields_failed_status() {
        global $wpdb;

        $admin_id = $this->factory->user->create( array( 'role' => 'administrator' ) );
        wp_set_current_user( $admin_id );

        $this->seed_lockouts();

        $table = wldelay_get_lockout_table_name();

        // Force the durable conditional DELETE to fail at the DB layer by mangling
        // it into invalid SQL via the `query` filter, so $wpdb->delete() returns
        // FALSE (distinct from "0 rows"). The handler must surface this as a hard
        // failure rather than reporting a clean removal.
        $break = static function ( $query ) use ( $table ) {
            if ( 0 === stripos( ltrim( $query ), 'DELETE' ) && false !== strpos( $query, $table ) ) {
                return 'DELETE FROM'; // Syntax error -> $wpdb->query returns false.
            }
            return $query;
        };
        add_filter( 'query', $break );

        $suppress = $wpdb->suppress_errors( true );

        $nonce = wp_create_nonce( 'wldelay_unlock_lockout' );
        $_REQUEST['_wpnonce'] = $nonce;
        $_POST['_wpnonce']    = $nonce;
        $_POST['wldelay_lockout_ip']       = '198.51.100.20';
        $_POST['wldelay_lockout_username'] = 'carol';
        $_POST['wldelay_lockout_type']     = 'login';

        add_filter( 'wp_redirect', array( __CLASS__, 'capture_redirect_location' ), 10, 2 );

        do_action( 'admin_post_wldelay_unlock_lockout' );

        $wpdb->suppress_errors( $suppress );
        remove_filter( 'query', $break );

        $this->assertNotNull( self::$redirect_location );
        $this->assertStringContainsString( 'wldelay_unlock_subject=failed', self::$redirect_location );
    }

    public function test_unlock_requires_capability() {
        $user_id = $this->factory->user->create( array( 'role' => 'subscriber' ) );
        wp_set_current_user( $user_id );

        add_filter( 'wp_die_handler', array( __CLASS__, 'filter_wp_die_handler' ) );

        $this->expectException( WLD_ActiveLockout_WPDieException::class );

        do_action( 'admin_post_wldelay_unlock_lockout' );
    }

    public function test_unlock_requires_nonce() {
        $admin_id = $this->factory->user->create( array( 'role' => 'administrator' ) );
        wp_set_current_user( $admin_id );

        add_filter( 'wp_die_handler', array( __CLASS__, 'filter_wp_die_handler' ) );

        // No nonce set -> check_admin_referer() must wp_die().
        $this->expectException( WLD_ActiveLockout_WPDieException::class );

        do_action( 'admin_post_wldelay_unlock_lockout' );
    }

    public function test_clear_all_requires_capability() {
        $user_id = $this->factory->user->create( array( 'role' => 'subscriber' ) );
        wp_set_current_user( $user_id );

        add_filter( 'wp_die_handler', array( __CLASS__, 'filter_wp_die_handler' ) );

        $this->expectException( WLD_ActiveLockout_WPDieException::class );

        do_action( 'admin_post_wldelay_clear_all_lockouts' );
    }

    public static function capture_redirect_location( $location, $status ) {
        self::$redirect_location = $location;

        return false;
    }

    public static function filter_wp_die_handler( $handler ) {
        return array( __CLASS__, 'throw_wp_die' );
    }

    public static function throw_wp_die( $message, $title = '', $args = array() ) {
        throw new WLD_ActiveLockout_WPDieException( wp_strip_all_tags( (string) $message ) );
    }
}
