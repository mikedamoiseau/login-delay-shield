<?php
/**
 * Integration tests for authentication login delay.
 */

class AuthLoginTest extends WP_UnitTestCase {
    public function setUp(): void {
        parent::setUp();
        unset( $_POST['log'] );
        $_SERVER['REMOTE_ADDR'] = '192.168.1.210';
        delete_option( 'wldelay_options' );
        wldelay_clear_options_cache();
    }

    public function tearDown(): void {
        unset( $_POST['log'] );
        unset( $_SERVER['REMOTE_ADDR'] );
        delete_option( 'wldelay_options' );
        wldelay_clear_options_cache();
        parent::tearDown();
    }

    /**
     * Test that the filter is properly registered.
     */
    public function test_filter_is_registered() {
        $this->assertNotFalse(
            has_filter( 'wp_authenticate_user', 'wldelay_auth_login' ),
            'wldelay_auth_login should be hooked to wp_authenticate_user'
        );
    }

    /**
     * Test that successful login returns user without modification.
     */
    public function test_successful_login_returns_user() {
        $user = $this->factory->user->create_and_get( [
            'user_login' => 'testuser',
            'user_pass' => 'testpassword',
        ] );

        $result = wldelay_auth_login( $user, 'testpassword' );

        $this->assertInstanceOf( WP_User::class, $result );
        $this->assertEquals( $user->ID, $result->ID );
    }

    /**
     * Test that failed login returns WP_Error.
     */
    public function test_failed_login_returns_wp_error() {
        $error = new WP_Error( 'invalid_username', 'Invalid username' );

        $start = microtime( true );
        $result = wldelay_auth_login( $error, 'wrongpassword' );
        $elapsed = microtime( true ) - $start;

        $this->assertInstanceOf( WP_Error::class, $result );
        // Delay should have been applied (at least default of 1 second)
        $this->assertGreaterThanOrEqual( 0.9, $elapsed, 'Delay should be applied on failed login' );
    }

    /**
     * Test that delay value comes from options.
     */
    public function test_delay_uses_configured_value() {
        // Set a 2 second delay
        update_option( 'wldelay_options', [
            'wldelay_delay' => 2,
            'wldelay_delay_random' => false,
        ] );

        // Clear static cache
        $this->clear_options_cache();

        $error = new WP_Error( 'invalid_password', 'Invalid password' );

        $start = microtime( true );
        wldelay_auth_login( $error, 'wrongpassword' );
        $elapsed = microtime( true ) - $start;

        $this->assertGreaterThanOrEqual( 1.9, $elapsed, 'Should use 2 second delay from options' );
        $this->assertLessThan( 3.0, $elapsed, 'Should not exceed expected delay by much' );
    }

    /**
     * Test that random delay is within configured bounds.
     */
    public function test_random_delay_within_bounds() {
        update_option( 'wldelay_options', [
            'wldelay_delay_random' => true,
            'wldelay_delay_random_min' => 1,
            'wldelay_delay_random_max' => 2,
        ] );

        $this->clear_options_cache();

        $error = new WP_Error( 'invalid_password', 'Invalid password' );

        $start = microtime( true );
        wldelay_auth_login( $error, 'wrongpassword' );
        $elapsed = microtime( true ) - $start;

        // Should be between 1 and 2 seconds (with some tolerance)
        $this->assertGreaterThanOrEqual( 0.9, $elapsed );
        $this->assertLessThanOrEqual( 2.5, $elapsed );
    }

    /**
     * Test wldelay_get_delay_value returns correct fixed delay.
     */
    public function test_get_delay_value_returns_fixed() {
        update_option( 'wldelay_options', [
            'wldelay_delay' => 5,
            'wldelay_delay_random' => false,
        ] );

        $this->clear_options_cache();

        $delay = wldelay_get_delay_value();

        $this->assertEquals( 5, $delay );
    }

    /**
     * Test wldelay_get_delay_value returns random within bounds.
     */
    public function test_get_delay_value_returns_random_in_bounds() {
        update_option( 'wldelay_options', [
            'wldelay_delay_random' => true,
            'wldelay_delay_random_min' => 3,
            'wldelay_delay_random_max' => 7,
        ] );

        $this->clear_options_cache();

        // Test multiple times
        for ( $i = 0; $i < 10; $i++ ) {
            $this->clear_options_cache();
            $delay = wldelay_get_delay_value();
            $this->assertGreaterThanOrEqual( 3, $delay );
            $this->assertLessThanOrEqual( 7, $delay );
        }
    }

    /**
     * Test default delay when options are not set.
     */
    public function test_default_delay_when_no_options() {
        delete_option( 'wldelay_options' );
        $this->clear_options_cache();

        $delay = wldelay_get_delay_value();

        $this->assertEquals( LDS_Settings::_DEFAULT_DELAY_IN_SECONDS, $delay );
    }

    /**
     * Test failed login includes remaining-attempts feedback before lockout.
     */
    public function test_failed_login_adds_remaining_attempts_message() {
        update_option( 'wldelay_options', [
            'wldelay_delay' => 1,
            'wldelay_delay_random' => false,
            'wldelay_lockout_enabled' => true,
            'wldelay_lockout_threshold' => 3,
            'wldelay_lockout_duration' => 60,
        ] );
        $this->clear_options_cache();
        $_POST['log'] = 'testuser';

        $error = new WP_Error( 'invalid_password', 'Invalid password' );
        $result = wldelay_auth_login( $error, 'wrongpassword' );

        $this->assertInstanceOf( WP_Error::class, $result );
        $messages = $result->get_error_messages( 'wldelay_attempts_remaining' );
        $this->assertNotEmpty( $messages );
        $this->assertStringContainsString( '2', $messages[0] );
        $this->assertStringContainsString( 'remaining', strtolower( $messages[0] ) );
    }

    /**
     * Clear the static options cache in wldelay_get_options().
     */
    private function clear_options_cache() {
        wldelay_clear_options_cache();
    }
}
