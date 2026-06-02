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

    /**
     * Resolve the durable lockout_key for an (ip, username) subject. The per-row
     * Unlock form POSTs this lossless key, never the truncated display username.
     */
    private function lockout_key_for( $ip, $username ) {
        $active = wldelay_get_persistence_store()->get_active_lockouts( PHP_INT_MAX );
        foreach ( $active as $row ) {
            if ( (string) $row['ip_address'] === (string) $ip && (string) $row['username'] === (string) $username ) {
                return (string) $row['lockout_key'];
            }
        }
        return '';
    }

    /**
     * Read the durable lockout_key values currently stored for an IP, directly
     * from the table (bypasses the active/expired filter).
     */
    private function lockout_keys_for_ip( $ip ) {
        global $wpdb;
        $table = wldelay_get_lockout_table_name();
        return array_map(
            'strval',
            (array) $wpdb->get_col(
                $wpdb->prepare( "SELECT lockout_key FROM $table WHERE ip_address = %s", (string) $ip )
            )
        );
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
        $_POST['wldelay_lockout_key']      = $this->lockout_key_for( '203.0.113.10', 'alice' );
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
        $_POST['wldelay_lockout_key']      = $this->lockout_key_for( '198.51.100.20', 'carol' );
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

        // Resolve the key BEFORE breaking DELETE (the read SELECT still works).
        $carol_key = $this->lockout_key_for( '198.51.100.20', 'carol' );

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
        $_POST['wldelay_lockout_key']      = $carol_key;
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

    /**
     * F-1-1 SECURITY regression: two subjects on one IP that share an identical
     * 255-char username prefix must be unlocked independently. Matching on the
     * truncated username column would release both; matching on the lossless
     * lockout_key releases only the targeted one.
     */
    public function test_unlock_by_key_does_not_release_prefix_colliding_cotenant() {
        $admin_id = $this->factory->user->create( array( 'role' => 'administrator' ) );
        wp_set_current_user( $admin_id );

        $ip     = '203.0.113.55';
        $prefix = str_repeat( 'a', 255 );
        $user_a = $prefix . 'AAAA';
        $user_b = $prefix . 'BBBB';

        $store = wldelay_get_persistence_store();
        $store->add_lockout( $ip, $user_a, 900, 'login', 'wp-login', wldelay_get_lockout_transient_key( $ip, $user_a ) );
        $store->add_lockout( $ip, $user_b, 900, 'login', 'wp-login', wldelay_get_lockout_transient_key( $ip, $user_b ) );

        $key_a = wldelay_get_lockout_storage_key( $ip, $user_a, 'login' );
        $key_b = wldelay_get_lockout_storage_key( $ip, $user_b, 'login' );
        $this->assertNotSame( $key_a, $key_b, 'Distinct full identifiers must hash to distinct lockout keys' );

        $nonce = wp_create_nonce( 'wldelay_unlock_lockout' );
        $_REQUEST['_wpnonce'] = $nonce;
        $_POST['_wpnonce']    = $nonce;
        $_POST['wldelay_lockout_ip']  = $ip;
        $_POST['wldelay_lockout_key'] = $key_a;

        add_filter( 'wp_redirect', array( __CLASS__, 'capture_redirect_location' ), 10, 2 );

        do_action( 'admin_post_wldelay_unlock_lockout' );

        // Exactly one durable row removed; the prefix-colliding co-tenant remains.
        $remaining = $this->lockout_keys_for_ip( $ip );
        $this->assertNotContains( $key_a, $remaining, 'Targeted subject must be removed' );
        $this->assertContains( $key_b, $remaining, 'Prefix-colliding co-tenant must stay locked' );
        $this->assertStringContainsString( 'wldelay_unlock_subject=success', self::$redirect_location );
    }

    /**
     * F-1-1 review: clearing exactly one subject must report exactly 1 in the
     * notice count and the audit removed_rows — not transient+durable inflated.
     */
    public function test_clear_all_reports_durable_subject_count_not_inflated() {
        global $wpdb;

        $admin_id = $this->factory->user->create( array( 'role' => 'administrator' ) );
        wp_set_current_user( $admin_id );

        WLDelay_Test_Fixture::make()
            ->with_option( 'wldelay_lockout_enabled', true )
            ->with_option( 'wldelay_lockout_attempt_strategy', 'ip_username' )
            ->with_lockout( '198.51.100.77', 'solo', 900 )
            ->apply();

        $table  = wldelay_get_audit_table_name();

        $nonce = wp_create_nonce( 'wldelay_clear_all_lockouts' );
        $_REQUEST['_wpnonce'] = $nonce;
        $_POST['_wpnonce']    = $nonce;

        add_filter( 'wp_redirect', array( __CLASS__, 'capture_redirect_location' ), 10, 2 );

        do_action( 'admin_post_wldelay_clear_all_lockouts' );

        $this->assertStringContainsString( 'wldelay_clear_count=1', self::$redirect_location, 'One subject must report a count of 1' );

        $row = $wpdb->get_row( $wpdb->prepare( "SELECT new_value FROM $table WHERE action = %s ORDER BY id DESC LIMIT 1", 'lockout_cleared' ) );
        $this->assertNotNull( $row );
        $decoded = json_decode( $row->new_value, true );
        $this->assertSame( 1, (int) $decoded['removed_rows'], 'Audit removed_rows must be the durable subject count (1), not inflated' );
    }

    /**
     * F-3-1: a failed durable READ (broken SELECT) must surface as `failed`, not
     * a clean "none", for the per-row unlock handler.
     */
    public function test_unlock_read_failure_yields_failed_status() {
        global $wpdb;

        $admin_id = $this->factory->user->create( array( 'role' => 'administrator' ) );
        wp_set_current_user( $admin_id );

        $this->seed_lockouts();
        $carol_key = $this->lockout_key_for( '198.51.100.20', 'carol' );

        $table = wldelay_get_lockout_table_name();

        // Break the IP snapshot SELECT so get_lockouts_for_ip() returns FALSE.
        $break = static function ( $query ) use ( $table ) {
            if ( 0 === stripos( ltrim( $query ), 'SELECT' ) && false !== strpos( $query, 'ip_address' ) && false !== strpos( $query, $table ) ) {
                return 'SELECT * FROM'; // Syntax error -> get_results returns null/last_error set.
            }
            return $query;
        };
        add_filter( 'query', $break );
        $suppress = $wpdb->suppress_errors( true );

        $nonce = wp_create_nonce( 'wldelay_unlock_lockout' );
        $_REQUEST['_wpnonce'] = $nonce;
        $_POST['_wpnonce']    = $nonce;
        $_POST['wldelay_lockout_ip']  = '198.51.100.20';
        $_POST['wldelay_lockout_key'] = $carol_key;

        add_filter( 'wp_redirect', array( __CLASS__, 'capture_redirect_location' ), 10, 2 );

        do_action( 'admin_post_wldelay_unlock_lockout' );

        $wpdb->suppress_errors( $suppress );
        remove_filter( 'query', $break );

        $this->assertStringContainsString( 'wldelay_unlock_subject=failed', self::$redirect_location );
    }

    /**
     * F-3-1: a failed durable READ on the active-lockouts enumeration must make
     * clear-all report `failed`, not a clean "none".
     */
    public function test_clear_all_read_failure_yields_failed_status() {
        global $wpdb;

        $admin_id = $this->factory->user->create( array( 'role' => 'administrator' ) );
        wp_set_current_user( $admin_id );

        $this->seed_lockouts();

        $table = wldelay_get_lockout_table_name();

        // Break the active-lockouts SELECT (filters on expires_at) so
        // get_active_lockouts() returns FALSE.
        $break = static function ( $query ) use ( $table ) {
            if ( 0 === stripos( ltrim( $query ), 'SELECT' ) && false !== strpos( $query, 'expires_at >' ) && false !== strpos( $query, $table ) ) {
                return 'SELECT * FROM'; // Syntax error.
            }
            return $query;
        };
        add_filter( 'query', $break );
        $suppress = $wpdb->suppress_errors( true );

        $nonce = wp_create_nonce( 'wldelay_clear_all_lockouts' );
        $_REQUEST['_wpnonce'] = $nonce;
        $_POST['_wpnonce']    = $nonce;

        add_filter( 'wp_redirect', array( __CLASS__, 'capture_redirect_location' ), 10, 2 );

        do_action( 'admin_post_wldelay_clear_all_lockouts' );

        $wpdb->suppress_errors( $suppress );
        remove_filter( 'query', $break );

        $this->assertStringContainsString( 'wldelay_clear_all=failed', self::$redirect_location );
    }

    /**
     * F-3-1: the renderer must show a DB-error notice (not the empty state) when
     * the active-lockouts read fails.
     */
    public function test_render_shows_error_notice_on_read_failure() {
        global $wpdb;

        $admin_id = $this->factory->user->create( array( 'role' => 'administrator' ) );
        wp_set_current_user( $admin_id );

        $this->seed_lockouts();

        $table = wldelay_get_lockout_table_name();
        $break = static function ( $query ) use ( $table ) {
            if ( 0 === stripos( ltrim( $query ), 'SELECT' ) && false !== strpos( $query, 'expires_at >' ) && false !== strpos( $query, $table ) ) {
                return 'SELECT * FROM';
            }
            return $query;
        };
        add_filter( 'query', $break );
        $suppress = $wpdb->suppress_errors( true );

        $view = new LDS_Settings_View();
        $method = new ReflectionMethod( LDS_Settings_View::class, 'render_active_lockouts' );
        $method->setAccessible( true );

        ob_start();
        $method->invoke( $view );
        $html = ob_get_clean();

        $wpdb->suppress_errors( $suppress );
        remove_filter( 'query', $break );

        $this->assertStringContainsString( 'notice-error', $html, 'A read failure must render an error notice' );
        $this->assertStringNotContainsString( 'No active lockouts', $html, 'A read failure must NOT render the empty state' );
    }

    /**
     * F-1-1: clear-all must release a registry-only (no durable row) lockout — the
     * wldelay_lock_ip() fail-open path where the durable add failed but the
     * registry write succeeded.
     */
    public function test_clear_all_sweeps_registry_only_lockout() {
        $admin_id = $this->factory->user->create( array( 'role' => 'administrator' ) );
        wp_set_current_user( $admin_id );

        // Simulate the fail-open outcome directly: a lockout transient + its
        // registry record, with NO durable row.
        $ip            = '203.0.113.88';
        $transient_key = wldelay_get_lockout_transient_key( $ip, '' );
        set_transient( $transient_key, time(), 900 );
        wldelay_register_transient_key( $transient_key, time() + 900 );

        $this->assertNotFalse( get_transient( $transient_key ) );
        // No durable row exists for it.
        $this->assertEmpty( $this->lockout_keys_for_ip( $ip ) );

        $nonce = wp_create_nonce( 'wldelay_clear_all_lockouts' );
        $_REQUEST['_wpnonce'] = $nonce;
        $_POST['_wpnonce']    = $nonce;

        add_filter( 'wp_redirect', array( __CLASS__, 'capture_redirect_location' ), 10, 2 );

        do_action( 'admin_post_wldelay_clear_all_lockouts' );

        $this->assertFalse( get_transient( $transient_key ), 'Clear-all must sweep the registry-only transient lockout' );
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
