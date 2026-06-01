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

    public function test_delete_lockout_for_ip_removes_password_reset_keys_when_username_provided() {
        $ip = '192.168.50.25';
        $username = 'admin';
        $pair_options = [ 'wldelay_lockout_attempt_strategy' => 'ip_username' ];

        $lockout_key = wldelay_get_password_reset_lockout_transient_key( $ip, $username, $pair_options );
        $fails_key = wldelay_get_password_reset_failure_transient_key( $ip, $username, $pair_options );

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

    /**
     * A registered key survives a clobber of the legacy shared-array registry.
     *
     * The old registry was one option holding an array, updated with a
     * non-atomic read-modify-write: two concurrent registrations could
     * overwrite each other's entry, losing a key. The per-key record format
     * stores each key in its own option, so a lost/overwritten shared array no
     * longer drops registered keys (F-2-1 review).
     */
    public function test_registry_keys_survive_shared_array_clobber() {
        $a = wldelay_get_lockout_transient_key( '192.168.60.1' );
        $b = wldelay_get_lockout_transient_key( '192.168.60.2' );

        wldelay_register_transient_key( $a );
        wldelay_register_transient_key( $b );

        // Simulate a concurrent read-modify-write that clobbered the shared
        // array down to a single (or no) entry.
        update_option( wldelay_get_transient_registry_option_name(), array( $a ), false );

        $keys = wldelay_get_registered_transient_keys();

        $this->assertContains( $a, $keys );
        $this->assertContains(
            $b,
            $keys,
            'A per-key registry record must survive a shared-array clobber'
        );
    }

    /**
     * Flush still clears a transient whose legacy shared-array entry was lost,
     * because the per-key registry record remains discoverable (F-2-1 review).
     */
    public function test_flush_clears_transient_whose_shared_array_entry_was_lost() {
        $lockout = wldelay_get_lockout_transient_key( '192.168.60.10' );
        $fails   = wldelay_get_failure_transient_key( '192.168.60.10' );

        set_transient( $lockout, time(), HOUR_IN_SECONDS );
        set_transient( $fails, 3, HOUR_IN_SECONDS );
        wldelay_register_transient_key( $lockout );
        wldelay_register_transient_key( $fails );

        // The shared-array registry entry is lost to a concurrent clobber.
        update_option( wldelay_get_transient_registry_option_name(), array(), false );

        wldelay_flush_lockout_transients();

        $this->assertFalse( get_transient( $lockout ) );
        $this->assertFalse( get_transient( $fails ) );
    }

    /**
     * wldelay_register_transient_key() reports whether the record is actually
     * persisted, not whether update_option() returned true (which is false both
     * on failure and on an unchanged write). When the record cannot be read back
     * — the DB-outage case where set_transient() hit an external object cache but
     * the registry write failed — it returns false so callers can drop the
     * orphan (Codex round-3 review).
     */
    public function test_register_transient_key_reports_unverifiable_write_as_failure() {
        $key    = wldelay_get_lockout_transient_key( '192.168.51.10' );
        $record = wldelay_get_transient_registry_key_prefix() . md5( $key );

        // Force the readback to miss, simulating a write that did not persist.
        add_filter( "option_{$record}", '__return_false' );
        $this->assertFalse(
            wldelay_register_transient_key( $key, time() + HOUR_IN_SECONDS ),
            'An unverifiable registry write must report failure'
        );
        remove_filter( "option_{$record}", '__return_false' );

        // With the readback intact the same call reports success.
        $this->assertTrue(
            wldelay_register_transient_key( $key, time() + HOUR_IN_SECONDS ),
            'A persisted registry record must report success'
        );
    }

    /**
     * A failure counter has no durable backing, so when its registry write is
     * unverifiable the cache-only transient would be invisible to recovery.
     * wldelay_track_failed_attempt() must fail open and drop the orphan rather
     * than leave a counter that flush can never clear (Codex round-3 review).
     */
    public function test_failure_counter_orphan_dropped_when_registry_unverifiable() {
        $ip = '192.168.51.20';
        $_SERVER['REMOTE_ADDR'] = $ip;

        // Lockout enabled (so the counter is tracked) with a threshold high
        // enough that the single attempt never trips an actual lockout.
        update_option( 'wldelay_options', array(
            'wldelay_lockout_enabled'   => true,
            'wldelay_lockout_threshold' => 99,
        ) );
        wldelay_clear_options_cache();

        $key    = wldelay_get_failure_transient_key( $ip );
        $record = wldelay_get_transient_registry_key_prefix() . md5( $key );

        add_filter( "option_{$record}", '__return_false' );
        wldelay_track_failed_attempt( '' );
        remove_filter( "option_{$record}", '__return_false' );

        $this->assertFalse(
            get_transient( $key ),
            'An undiscoverable failure-counter transient must be dropped, not orphaned'
        );
    }

    /**
     * Per-key registry records carry the transient's expiry and are reaped by
     * the daily cleanup once elapsed, so a rotating-IP/username attack cannot
     * grow wp_options without bound. A live record is left untouched; no manual
     * flush is required (Codex-2 round-3 review).
     */
    public function test_expired_registry_record_is_purged_by_cleanup() {
        $live_key    = wldelay_get_failure_transient_key( '192.168.51.30' );
        $expired_key = wldelay_get_failure_transient_key( '192.168.51.31' );

        wldelay_register_transient_key( $live_key, time() + HOUR_IN_SECONDS );
        wldelay_register_transient_key( $expired_key, time() - 10 );

        $live_record    = wldelay_get_transient_registry_key_prefix() . md5( $live_key );
        $expired_record = wldelay_get_transient_registry_key_prefix() . md5( $expired_key );

        $this->assertIsArray( get_option( $live_record, false ) );
        $this->assertIsArray( get_option( $expired_record, false ) );

        $removed = wldelay_purge_expired_transient_registry_records();

        $this->assertGreaterThanOrEqual( 1, $removed );
        $this->assertFalse(
            get_option( $expired_record, false ),
            'An expired registry record must be reaped without a manual flush'
        );
        $this->assertIsArray(
            get_option( $live_record, false ),
            'A still-live registry record must survive the reaper'
        );
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
