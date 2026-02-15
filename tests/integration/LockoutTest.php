<?php
/**
 * Integration tests for IP lockout functionality.
 */

class LockoutTest extends WP_UnitTestCase {

    /**
     * Set up before each test.
     */
    public function setUp(): void {
        parent::setUp();

        // Clear any existing options to ensure clean slate
        delete_option( 'wldelay_options' );

        // Clear all IP-related SERVER variables to ensure consistent IP detection
        unset( $_SERVER['HTTP_CLIENT_IP'], $_SERVER['HTTP_X_FORWARDED_FOR'] );

        // Set up a test IP
        $_SERVER['REMOTE_ADDR'] = '192.168.1.100';

        // Clear any existing transients for this IP
        $this->clear_test_ip_transients();

        // Clear options cache
        wldelay_clear_options_cache();
    }

    /**
     * Tear down after each test.
     */
    public function tearDown(): void {
        unset( $_SERVER['REMOTE_ADDR'] );
        unset( $_POST['log'] );
        $this->clear_test_ip_transients();
        delete_option( 'wldelay_options' );
        wldelay_clear_options_cache();
        parent::tearDown();
    }

    /**
     * Clear transients used by lockout/failure tracking in tests.
     */
    private function clear_test_ip_transients() {
        $ip = '192.168.1.100';
        $pair_options = [ 'wldelay_lockout_attempt_strategy' => 'ip_username' ];

        delete_transient( wldelay_get_failure_transient_key( $ip ) );
        delete_transient( wldelay_get_lockout_transient_key( $ip ) );

        delete_transient( wldelay_get_failure_transient_key( $ip, 'alice', $pair_options ) );
        delete_transient( wldelay_get_failure_transient_key( $ip, 'bob', $pair_options ) );
        delete_transient( wldelay_get_failure_transient_key( $ip, 'testuser', $pair_options ) );
        delete_transient( wldelay_get_lockout_transient_key( $ip, 'alice', $pair_options ) );
        delete_transient( wldelay_get_lockout_transient_key( $ip, 'bob', $pair_options ) );
        delete_transient( wldelay_get_lockout_transient_key( $ip, 'testuser', $pair_options ) );
    }

    /**
     * Test that lockout is not triggered below threshold.
     */
    public function test_lockout_not_triggered_below_threshold() {
        update_option( 'wldelay_options', [
            'wldelay_lockout_enabled' => true,
            'wldelay_lockout_threshold' => 5,
            'wldelay_lockout_duration' => 60,
        ] );
        wldelay_clear_options_cache();

        // Simulate 4 failed attempts (below threshold of 5)
        for ( $i = 0; $i < 4; $i++ ) {
            wldelay_track_failed_attempt( 'testuser' );
        }

        $this->assertFalse( wldelay_is_ip_locked() );
    }

    /**
     * Test that lockout is triggered at threshold.
     */
    public function test_lockout_triggered_at_threshold() {
        update_option( 'wldelay_options', [
            'wldelay_lockout_enabled' => true,
            'wldelay_lockout_threshold' => 3,
            'wldelay_lockout_duration' => 60,
        ] );
        wldelay_clear_options_cache();

        // Simulate 3 failed attempts (at threshold)
        for ( $i = 0; $i < 3; $i++ ) {
            wldelay_track_failed_attempt( 'testuser' );
        }

        $this->assertTrue( wldelay_is_ip_locked() );
    }

    /**
     * Test that lockout is triggered above threshold.
     */
    public function test_lockout_triggered_above_threshold() {
        update_option( 'wldelay_options', [
            'wldelay_lockout_enabled' => true,
            'wldelay_lockout_threshold' => 3,
            'wldelay_lockout_duration' => 60,
        ] );
        wldelay_clear_options_cache();

        // Simulate 5 failed attempts (above threshold of 3)
        for ( $i = 0; $i < 5; $i++ ) {
            wldelay_track_failed_attempt( 'testuser' );
        }

        $this->assertTrue( wldelay_is_ip_locked() );
    }

    /**
     * Test that locked IP returns WP_Error.
     */
    public function test_locked_ip_returns_wp_error() {
        update_option( 'wldelay_options', [
            'wldelay_lockout_enabled' => true,
            'wldelay_lockout_threshold' => 2,
            'wldelay_lockout_duration' => 60,
        ] );
        wldelay_clear_options_cache();

        // Lock the IP
        wldelay_lock_ip( '192.168.1.100' );

        // Create a valid user
        $user = $this->factory->user->create_and_get( [
            'user_login' => 'testuser',
            'user_pass' => 'testpassword',
        ] );

        // Try to authenticate - should be blocked even with valid credentials
        $result = wldelay_auth_login( $user, 'testpassword' );

        $this->assertInstanceOf( WP_Error::class, $result );
        $this->assertEquals( 'wldelay_ip_locked', $result->get_error_code() );
    }

    /**
     * Test that lockout check happens before password validation.
     */
    public function test_lockout_check_before_delay() {
        update_option( 'wldelay_options', [
            'wldelay_lockout_enabled' => true,
            'wldelay_lockout_threshold' => 2,
            'wldelay_lockout_duration' => 60,
            'wldelay_delay' => 3, // 3 second delay
        ] );
        wldelay_clear_options_cache();

        // Lock the IP
        wldelay_lock_ip( '192.168.1.100' );

        $error = new WP_Error( 'invalid_password', 'Invalid password' );

        $start = microtime( true );
        $result = wldelay_auth_login( $error, 'wrongpassword' );
        $elapsed = microtime( true ) - $start;

        // Should return immediately without delay (locked)
        $this->assertInstanceOf( WP_Error::class, $result );
        $this->assertEquals( 'wldelay_ip_locked', $result->get_error_code() );
        $this->assertLessThan( 1.0, $elapsed, 'Should not apply delay when IP is locked' );
    }

    /**
     * Test that unlocked IP is not blocked.
     */
    public function test_unlocked_ip_not_blocked() {
        update_option( 'wldelay_options', [
            'wldelay_lockout_enabled' => true,
            'wldelay_lockout_threshold' => 10,
            'wldelay_lockout_duration' => 60,
        ] );
        wldelay_clear_options_cache();

        // Create a valid user
        $user = $this->factory->user->create_and_get( [
            'user_login' => 'testuser',
            'user_pass' => 'testpassword',
        ] );

        // Should return user (not locked)
        $result = wldelay_auth_login( $user, 'testpassword' );

        $this->assertInstanceOf( WP_User::class, $result );
    }

    /**
     * Test that lockout does not trigger when disabled.
     */
    public function test_lockout_not_triggered_when_disabled() {
        update_option( 'wldelay_options', [
            'wldelay_lockout_enabled' => false,
            'wldelay_lockout_threshold' => 2,
            'wldelay_lockout_duration' => 60,
            'wldelay_email_enabled' => true, // Enable email to still track attempts
            'wldelay_email_threshold' => 100,
        ] );
        wldelay_clear_options_cache();

        // Simulate 5 failed attempts (above threshold of 2)
        for ( $i = 0; $i < 5; $i++ ) {
            wldelay_track_failed_attempt( 'testuser' );
        }

        // Should not be locked since lockout is disabled
        $this->assertFalse( wldelay_is_ip_locked() );
    }

    /**
     * Test that lockout transient is set correctly.
     */
    public function test_lockout_transient_set() {
        update_option( 'wldelay_options', [
            'wldelay_lockout_duration' => 30, // 30 minutes
        ] );
        wldelay_clear_options_cache();

        wldelay_lock_ip( '192.168.1.100' );

        $transient_key = 'wldelay_lockout_' . md5( '192.168.1.100' );
        $lockout_time = get_transient( $transient_key );

        $this->assertNotFalse( $lockout_time );
        $this->assertIsInt( $lockout_time );
    }

    /**
     * Test that shared counter works for both email and lockout.
     */
    public function test_shared_counter_for_email_and_lockout() {
        update_option( 'wldelay_options', [
            'wldelay_email_enabled' => true,
            'wldelay_email_threshold' => 3,
            'wldelay_lockout_enabled' => true,
            'wldelay_lockout_threshold' => 5,
            'wldelay_lockout_duration' => 60,
        ] );
        wldelay_clear_options_cache();

        // Simulate 4 failed attempts
        for ( $i = 0; $i < 4; $i++ ) {
            wldelay_track_failed_attempt( 'testuser' );
        }

        // Counter should be 4
        $transient_key = 'wldelay_fails_' . md5( '192.168.1.100' );
        $count = get_transient( $transient_key );
        $this->assertEquals( 4, $count );

        // Should not be locked yet (threshold is 5)
        $this->assertFalse( wldelay_is_ip_locked() );

        // One more attempt should trigger lockout
        wldelay_track_failed_attempt( 'testuser' );

        $this->assertTrue( wldelay_is_ip_locked() );
    }

    /**
     * Test that empty IP does not cause lockout check to fail.
     */
    public function test_empty_ip_skips_lockout_check() {
        update_option( 'wldelay_options', [
            'wldelay_lockout_enabled' => true,
            'wldelay_lockout_threshold' => 2,
            'wldelay_lockout_duration' => 60,
        ] );
        wldelay_clear_options_cache();

        // Clear the IP
        unset( $_SERVER['REMOTE_ADDR'], $_SERVER['HTTP_CLIENT_IP'], $_SERVER['HTTP_X_FORWARDED_FOR'] );

        // Should return false when IP is empty
        $this->assertFalse( wldelay_is_ip_locked() );
    }

    /**
     * Test that different IPs have separate lockouts.
     */
    public function test_separate_lockouts_per_ip() {
        update_option( 'wldelay_options', [
            'wldelay_lockout_enabled' => true,
            'wldelay_lockout_threshold' => 2,
            'wldelay_lockout_duration' => 60,
        ] );
        wldelay_clear_options_cache();

        // Lock IP 1
        $_SERVER['REMOTE_ADDR'] = '192.168.1.100';
        wldelay_lock_ip( '192.168.1.100' );

        $this->assertTrue( wldelay_is_ip_locked() );

        // Check IP 2 - should not be locked
        $_SERVER['REMOTE_ADDR'] = '192.168.1.101';
        $this->assertFalse( wldelay_is_ip_locked() );
    }

    /**
     * Test lockout error message content.
     */
    public function test_lockout_error_message() {
        update_option( 'wldelay_options', [
            'wldelay_lockout_enabled' => true,
            'wldelay_lockout_threshold' => 2,
            'wldelay_lockout_duration' => 60,
        ] );
        wldelay_clear_options_cache();

        wldelay_lock_ip( '192.168.1.100' );

        $user = new WP_User();
        $result = wldelay_auth_login( $user, 'password' );

        $this->assertInstanceOf( WP_Error::class, $result );
        $this->assertStringContainsString( 'Too many failed login attempts', $result->get_error_message() );
    }

    /**
     * Test lockout error message includes countdown feedback.
     */
    public function test_lockout_error_message_includes_countdown() {
        update_option( 'wldelay_options', [
            'wldelay_lockout_enabled' => true,
            'wldelay_lockout_threshold' => 2,
            'wldelay_lockout_duration' => 1,
        ] );
        wldelay_clear_options_cache();
        $_POST['log'] = 'testuser';

        wldelay_lock_ip( '192.168.1.100', 'testuser' );

        $user = new WP_User();
        $result = wldelay_auth_login( $user, 'password' );

        $this->assertInstanceOf( WP_Error::class, $result );
        $this->assertStringContainsString( 'Please try again in', $result->get_error_message() );
    }

    /**
     * Test tracking works when only lockout is enabled (email disabled).
     */
    public function test_tracking_with_only_lockout_enabled() {
        update_option( 'wldelay_options', [
            'wldelay_email_enabled' => false,
            'wldelay_lockout_enabled' => true,
            'wldelay_lockout_threshold' => 3,
            'wldelay_lockout_duration' => 60,
        ] );
        wldelay_clear_options_cache();

        // Simulate 3 failed attempts
        for ( $i = 0; $i < 3; $i++ ) {
            wldelay_track_failed_attempt( 'testuser' );
        }

        // Should be locked
        $this->assertTrue( wldelay_is_ip_locked() );

        // Counter should still be tracked
        $transient_key = 'wldelay_fails_' . md5( '192.168.1.100' );
        $count = get_transient( $transient_key );
        $this->assertEquals( 3, $count );
    }

    /**
     * Test IP+username strategy keeps lockouts isolated per username.
     */
    public function test_lockout_strategy_ip_username_isolates_usernames() {
        update_option( 'wldelay_options', [
            'wldelay_lockout_enabled' => true,
            'wldelay_lockout_threshold' => 2,
            'wldelay_lockout_duration' => 60,
            'wldelay_lockout_attempt_strategy' => 'ip_username',
        ] );
        wldelay_clear_options_cache();

        wldelay_track_failed_attempt( 'alice' );
        $this->assertFalse( wldelay_is_ip_locked( '192.168.1.100', 'alice' ) );

        wldelay_track_failed_attempt( 'alice' );

        $this->assertTrue( wldelay_is_ip_locked( '192.168.1.100', 'alice' ) );
        $this->assertFalse( wldelay_is_ip_locked( '192.168.1.100', 'bob' ) );
    }

    /**
     * Test auth lockout check uses username in IP+username strategy.
     */
    public function test_auth_lockout_check_uses_requested_username_for_ip_username_strategy() {
        update_option( 'wldelay_options', [
            'wldelay_lockout_enabled' => true,
            'wldelay_lockout_threshold' => 2,
            'wldelay_lockout_duration' => 60,
            'wldelay_lockout_attempt_strategy' => 'ip_username',
        ] );
        wldelay_clear_options_cache();

        wldelay_lock_ip( '192.168.1.100', 'alice' );

        $user = $this->factory->user->create_and_get( [
            'user_login' => 'testuser',
            'user_pass' => 'testpassword',
        ] );

        $_POST['log'] = 'alice';
        $blocked = wldelay_auth_login( $user, 'testpassword' );
        $this->assertInstanceOf( WP_Error::class, $blocked );
        $this->assertEquals( 'wldelay_ip_locked', $blocked->get_error_code() );

        $_POST['log'] = 'bob';
        $allowed = wldelay_auth_login( $user, 'testpassword' );
        $this->assertInstanceOf( WP_User::class, $allowed );
    }

    /**
     * Test failure counters are isolated by username in IP+username strategy.
     */
    public function test_failure_count_isolated_by_username_for_ip_username_strategy() {
        update_option( 'wldelay_options', [
            'wldelay_email_enabled' => true,
            'wldelay_email_threshold' => 99,
            'wldelay_lockout_enabled' => false,
            'wldelay_lockout_attempt_strategy' => 'ip_username',
        ] );
        wldelay_clear_options_cache();

        wldelay_track_failed_attempt( 'alice' );
        wldelay_track_failed_attempt( 'alice' );
        wldelay_track_failed_attempt( 'bob' );

        $this->assertEquals( 2, wldelay_get_failure_count( '192.168.1.100', 'alice' ) );
        $this->assertEquals( 1, wldelay_get_failure_count( '192.168.1.100', 'bob' ) );
    }

    /**
     * Test no tracking when both email and lockout are disabled.
     */
    public function test_no_tracking_when_all_disabled() {
        update_option( 'wldelay_options', [
            'wldelay_email_enabled' => false,
            'wldelay_lockout_enabled' => false,
        ] );
        wldelay_clear_options_cache();

        wldelay_track_failed_attempt( 'testuser' );

        // No transient should be set
        $transient_key = 'wldelay_fails_' . md5( '192.168.1.100' );
        $count = get_transient( $transient_key );

        $this->assertFalse( $count );
    }
}
