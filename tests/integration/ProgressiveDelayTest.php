<?php
/**
 * Integration tests for progressive delay functionality.
 */

class ProgressiveDelayTest extends WP_UnitTestCase {

    /**
     * Set up before each test.
     */
    public function setUp(): void {
        parent::setUp();
        // Clear any existing options
        delete_option( 'wldelay_options' );
        // Clear options cache
        wldelay_clear_options_cache();
        // Clear any existing failed attempt transients
        $this->clear_failure_transients();
    }

    /**
     * Tear down after each test.
     */
    public function tearDown(): void {
        delete_option( 'wldelay_options' );
        wldelay_clear_options_cache();
        $this->clear_failure_transients();
        unset( $_SERVER['REMOTE_ADDR'] );
        parent::tearDown();
    }

    /**
     * Clear failure tracking transients.
     */
    private function clear_failure_transients() {
        global $wpdb;
        $wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_wldelay_fails_%'" );
        $wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_timeout_wldelay_fails_%'" );
    }

    /**
     * Test that progressive delay is disabled by default.
     */
    public function test_progressive_delay_disabled_by_default() {
        $_SERVER['REMOTE_ADDR'] = '192.168.1.1';

        update_option( 'wldelay_options', [
            'wldelay_delay' => 1,
            'wldelay_delay_random' => false,
        ] );

        // Get delay with failure count - should just return base
        $delay = wldelay_get_delay_value( 5 );

        $this->assertEquals( 1, $delay );
    }

    /**
     * Test that progressive delay increases with failures.
     */
    public function test_progressive_delay_increases() {
        update_option( 'wldelay_options', [
            'wldelay_delay' => 1,
            'wldelay_delay_random' => false,
            'wldelay_progressive_enabled' => true,
            'wldelay_progressive_increment' => 2,
            'wldelay_progressive_max' => 30,
        ] );

        // 0 failures: base only = 1
        $this->assertEquals( 1, wldelay_get_delay_value( 0 ) );

        // 1 failure: 1 + (2 * 1) = 3
        $this->assertEquals( 3, wldelay_get_delay_value( 1 ) );

        // 3 failures: 1 + (2 * 3) = 7
        $this->assertEquals( 7, wldelay_get_delay_value( 3 ) );

        // 5 failures: 1 + (2 * 5) = 11
        $this->assertEquals( 11, wldelay_get_delay_value( 5 ) );
    }

    /**
     * Test that progressive delay respects maximum cap.
     */
    public function test_progressive_delay_respects_max() {
        update_option( 'wldelay_options', [
            'wldelay_delay' => 5,
            'wldelay_delay_random' => false,
            'wldelay_progressive_enabled' => true,
            'wldelay_progressive_increment' => 5,
            'wldelay_progressive_max' => 20,
        ] );

        // 5 failures: 5 + (5 * 5) = 30, but capped at 20
        $this->assertEquals( 20, wldelay_get_delay_value( 5 ) );

        // 10 failures: would be 55, but still capped at 20
        $this->assertEquals( 20, wldelay_get_delay_value( 10 ) );
    }

    /**
     * Test that failure count is correctly retrieved.
     */
    public function test_get_failure_count() {
        $_SERVER['REMOTE_ADDR'] = '192.168.1.1';

        // Initially should be 0
        $this->assertEquals( 0, wldelay_get_failure_count() );

        // Set a transient manually
        $transient_key = 'wldelay_fails_' . md5( '192.168.1.1' );
        set_transient( $transient_key, 5, HOUR_IN_SECONDS );

        $this->assertEquals( 5, wldelay_get_failure_count() );
    }

    /**
     * Test that progressive delay is applied during actual login.
     */
    public function test_progressive_delay_applied_on_login() {
        $_SERVER['REMOTE_ADDR'] = '192.168.1.1';
        $_POST['log'] = 'testuser';

        update_option( 'wldelay_options', [
            'wldelay_delay' => 1,
            'wldelay_delay_random' => false,
            'wldelay_progressive_enabled' => true,
            'wldelay_progressive_increment' => 1,
            'wldelay_progressive_max' => 30,
            'wldelay_email_enabled' => false,
            'wldelay_lockout_enabled' => false,
        ] );

        // Simulate 2 previous failures
        $transient_key = 'wldelay_fails_' . md5( '192.168.1.1' );
        set_transient( $transient_key, 2, HOUR_IN_SECONDS );

        $error = new WP_Error( 'invalid_password', 'Invalid password' );

        $start = microtime( true );
        wldelay_auth_login( $error, 'wrongpassword' );
        $elapsed = microtime( true ) - $start;

        // Expected delay: 1 + (1 * 2) = 3 seconds
        $this->assertGreaterThanOrEqual( 2.9, $elapsed, 'Progressive delay should be applied' );
        $this->assertLessThan( 4.5, $elapsed, 'Should not exceed expected delay by much' );
    }

    /**
     * Test that first failure uses base delay only.
     */
    public function test_first_failure_uses_base_delay() {
        $_SERVER['REMOTE_ADDR'] = '192.168.1.1';
        $_POST['log'] = 'testuser';

        update_option( 'wldelay_options', [
            'wldelay_delay' => 1,
            'wldelay_delay_random' => false,
            'wldelay_progressive_enabled' => true,
            'wldelay_progressive_increment' => 2,
            'wldelay_progressive_max' => 30,
            'wldelay_email_enabled' => false,
            'wldelay_lockout_enabled' => false,
        ] );

        $error = new WP_Error( 'invalid_password', 'Invalid password' );

        $start = microtime( true );
        wldelay_auth_login( $error, 'wrongpassword' );
        $elapsed = microtime( true ) - $start;

        // First failure, no previous attempts, should be base delay = 1
        $this->assertGreaterThanOrEqual( 0.9, $elapsed );
        $this->assertLessThan( 2.5, $elapsed, 'First failure should only have base delay' );
    }

    /**
     * Test progressive delay works with random base delay.
     */
    public function test_progressive_with_random_base() {
        update_option( 'wldelay_options', [
            'wldelay_delay_random' => true,
            'wldelay_delay_random_min' => 2,
            'wldelay_delay_random_max' => 2, // Fixed for testing
            'wldelay_progressive_enabled' => true,
            'wldelay_progressive_increment' => 3,
            'wldelay_progressive_max' => 30,
        ] );

        // 2 failures: 2 (random base) + (3 * 2) = 8
        $delay = wldelay_get_delay_value( 2 );

        $this->assertEquals( 8, $delay );
    }

    /**
     * Test default progressive increment value.
     */
    public function test_default_progressive_increment() {
        update_option( 'wldelay_options', [
            'wldelay_delay' => 1,
            'wldelay_delay_random' => false,
            'wldelay_progressive_enabled' => true,
            // Don't set increment - should use default
            'wldelay_progressive_max' => 30,
        ] );

        // Default increment is 1
        // 5 failures: 1 + (1 * 5) = 6
        $this->assertEquals( 6, wldelay_get_delay_value( 5 ) );
    }

    /**
     * Test default progressive max value.
     */
    public function test_default_progressive_max() {
        update_option( 'wldelay_options', [
            'wldelay_delay' => 5,
            'wldelay_delay_random' => false,
            'wldelay_progressive_enabled' => true,
            'wldelay_progressive_increment' => 10,
            // Don't set max - should use default (30)
        ] );

        // 10 failures: 5 + (10 * 10) = 105, but capped at default max (30)
        $this->assertEquals( 30, wldelay_get_delay_value( 10 ) );
    }

    /**
     * Test successful login doesn't trigger progressive delay.
     */
    public function test_successful_login_no_progressive_delay() {
        $_SERVER['REMOTE_ADDR'] = '192.168.1.1';

        update_option( 'wldelay_options', [
            'wldelay_delay' => 2,
            'wldelay_delay_random' => false,
            'wldelay_progressive_enabled' => true,
            'wldelay_progressive_increment' => 5,
            'wldelay_progressive_max' => 60,
        ] );

        // Simulate previous failures
        $transient_key = 'wldelay_fails_' . md5( '192.168.1.1' );
        set_transient( $transient_key, 5, HOUR_IN_SECONDS );

        $user = $this->factory->user->create_and_get( [
            'user_login' => 'testuser',
            'user_pass' => 'testpassword',
        ] );

        $start = microtime( true );
        $result = wldelay_auth_login( $user, 'testpassword' );
        $elapsed = microtime( true ) - $start;

        // Successful login should not have delay
        $this->assertInstanceOf( WP_User::class, $result );
        $this->assertLessThan( 0.5, $elapsed, 'Successful login should not have delay' );
    }

    /**
     * Test that failure tracking increments count.
     */
    public function test_failure_tracking_increments_count() {
        $_SERVER['REMOTE_ADDR'] = '192.168.1.1';
        $_POST['log'] = 'testuser';

        update_option( 'wldelay_options', [
            'wldelay_delay' => 0, // No delay for faster test
            'wldelay_delay_random' => false,
            'wldelay_email_enabled' => true, // Enable tracking
            'wldelay_email_threshold' => 100, // High threshold to not trigger email
            'wldelay_lockout_enabled' => false,
        ] );

        // Initially 0
        $this->assertEquals( 0, wldelay_get_failure_count() );

        // Trigger a failed login
        $error = new WP_Error( 'invalid_password', 'Invalid password' );
        wldelay_auth_login( $error, 'wrongpassword' );

        // Should now be 1
        $this->assertEquals( 1, wldelay_get_failure_count() );
    }

    /**
     * Test progressive mode tracks failures without email or lockout enabled.
     */
    public function test_progressive_mode_tracks_failures_without_email_or_lockout() {
        $_SERVER['REMOTE_ADDR'] = '192.168.1.1';
        $_POST['log'] = 'testuser';

        update_option( 'wldelay_options', [
            'wldelay_delay' => 0,
            'wldelay_delay_random' => false,
            'wldelay_progressive_enabled' => true,
            'wldelay_email_enabled' => false,
            'wldelay_lockout_enabled' => false,
        ] );
        wldelay_clear_options_cache();

        wldelay_track_failed_attempt( 'testuser' );
        wldelay_track_failed_attempt( 'testuser' );

        $this->assertEquals( 2, wldelay_get_failure_count() );
    }

    /**
     * Test challenge mode tracks failures without email, lockout, or progressive delay enabled.
     */
    public function test_challenge_mode_tracks_failures_without_other_counter_features() {
        $_SERVER['REMOTE_ADDR'] = '192.168.1.1';
        $_POST['log'] = 'testuser';

        update_option( 'wldelay_options', [
            'wldelay_delay' => 0,
            'wldelay_delay_random' => false,
            'wldelay_progressive_enabled' => false,
            'wldelay_email_enabled' => false,
            'wldelay_lockout_enabled' => false,
            'wldelay_challenge_mode_enabled' => true,
            'wldelay_challenge_mode_threshold' => 2,
        ] );
        wldelay_clear_options_cache();

        wldelay_track_failed_attempt( 'testuser' );
        wldelay_track_failed_attempt( 'testuser' );

        $this->assertEquals( 2, wldelay_get_failure_count() );
        $this->assertTrue( wldelay_is_challenge_required( 'testuser' ) );
    }
}
