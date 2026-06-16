<?php
/**
 * Unit tests for lockout settings sanitization.
 */

use Brain\Monkey\Functions;

class LockoutTest extends LDS_Unit_Test_Case {

    /**
     * @var LDS_Settings
     */
    private $settings;

    protected function setUp(): void {
        parent::setUp();

        Functions\when( 'get_option' )->justReturn( false );

        // Mock WordPress functions used by the settings class
        Functions\when( 'absint' )->alias( function( $value ) {
            return abs( (int) $value );
        });

        Functions\when( 'sanitize_email' )->alias( function( $email ) {
            return filter_var( $email, FILTER_SANITIZE_EMAIL );
        });

        // Create settings instance
        $this->settings = new LDS_Settings();
    }

    /**
     * Test that lockout threshold is bounded between 1 and 100.
     */
    public function test_lockout_threshold_bounded() {
        // Test lower bound
        $input = [ 'wldelay_lockout_threshold' => 0 ];
        $result = $this->settings->sanitize( $input );
        $this->assertEquals( 1, $result['wldelay_lockout_threshold'] );

        // Test upper bound
        $input = [ 'wldelay_lockout_threshold' => 150 ];
        $result = $this->settings->sanitize( $input );
        $this->assertEquals( 100, $result['wldelay_lockout_threshold'] );

        // Test valid value
        $input = [ 'wldelay_lockout_threshold' => 25 ];
        $result = $this->settings->sanitize( $input );
        $this->assertEquals( 25, $result['wldelay_lockout_threshold'] );
    }

    /**
     * Test that lockout duration is bounded between 1 and 1440 minutes.
     */
    public function test_lockout_duration_bounded() {
        // Test lower bound
        $input = [ 'wldelay_lockout_duration' => 0 ];
        $result = $this->settings->sanitize( $input );
        $this->assertEquals( 1, $result['wldelay_lockout_duration'] );

        // Test upper bound
        $input = [ 'wldelay_lockout_duration' => 2000 ];
        $result = $this->settings->sanitize( $input );
        $this->assertEquals( 1440, $result['wldelay_lockout_duration'] );

        // Test valid value
        $input = [ 'wldelay_lockout_duration' => 120 ];
        $result = $this->settings->sanitize( $input );
        $this->assertEquals( 120, $result['wldelay_lockout_duration'] );
    }

    /**
     * Test that negative values are handled correctly (absint behavior).
     */
    public function test_negative_values_converted() {
        $input = [
            'wldelay_lockout_threshold' => -5,
            'wldelay_lockout_duration' => -30,
        ];

        $result = $this->settings->sanitize( $input );

        // absint() converts negative to positive
        $this->assertEquals( 5, $result['wldelay_lockout_threshold'] );
        $this->assertEquals( 30, $result['wldelay_lockout_duration'] );
    }

    /**
     * Test that lockout enabled is properly cast to boolean.
     */
    public function test_lockout_enabled_cast_correctly() {
        // Test truthy values
        $input = [ 'wldelay_lockout_enabled' => '1' ];
        $result = $this->settings->sanitize( $input );
        $this->assertTrue( $result['wldelay_lockout_enabled'] );

        $input = [ 'wldelay_lockout_enabled' => 'yes' ];
        $result = $this->settings->sanitize( $input );
        $this->assertTrue( $result['wldelay_lockout_enabled'] );

        // Test falsy values
        $input = [ 'wldelay_lockout_enabled' => '' ];
        $result = $this->settings->sanitize( $input );
        $this->assertFalse( $result['wldelay_lockout_enabled'] );

        $input = [ 'wldelay_lockout_enabled' => null ];
        $result = $this->settings->sanitize( $input );
        $this->assertFalse( $result['wldelay_lockout_enabled'] );
    }

    /**
     * Test default values are used when lockout fields are missing.
     */
    public function test_defaults_used_for_missing_lockout_fields() {
        $input = [];

        $result = $this->settings->sanitize( $input );

        $this->assertEquals( LDS_Settings::_DEFAULT_LOCKOUT_THRESHOLD, $result['wldelay_lockout_threshold'] );
        $this->assertEquals( LDS_Settings::_DEFAULT_LOCKOUT_DURATION, $result['wldelay_lockout_duration'] );
        $this->assertFalse( $result['wldelay_lockout_enabled'] );
    }

    /**
     * Test lockout threshold edge cases at bounds.
     */
    public function test_lockout_threshold_at_bounds() {
        // Test exactly at lower bound
        $input = [ 'wldelay_lockout_threshold' => 1 ];
        $result = $this->settings->sanitize( $input );
        $this->assertEquals( 1, $result['wldelay_lockout_threshold'] );

        // Test exactly at upper bound
        $input = [ 'wldelay_lockout_threshold' => 100 ];
        $result = $this->settings->sanitize( $input );
        $this->assertEquals( 100, $result['wldelay_lockout_threshold'] );
    }

    /**
     * Test lockout duration edge cases at bounds.
     */
    public function test_lockout_duration_at_bounds() {
        // Test exactly at lower bound
        $input = [ 'wldelay_lockout_duration' => 1 ];
        $result = $this->settings->sanitize( $input );
        $this->assertEquals( 1, $result['wldelay_lockout_duration'] );

        // Test exactly at upper bound (24 hours)
        $input = [ 'wldelay_lockout_duration' => 1440 ];
        $result = $this->settings->sanitize( $input );
        $this->assertEquals( 1440, $result['wldelay_lockout_duration'] );
    }

    /**
     * Test lockout attempt strategy sanitization.
     */
    public function test_lockout_attempt_strategy_sanitization() {
        $input = [ 'wldelay_lockout_attempt_strategy' => 'ip_username' ];
        $result = $this->settings->sanitize( $input );
        $this->assertEquals( 'ip_username', $result['wldelay_lockout_attempt_strategy'] );

        $input = [ 'wldelay_lockout_attempt_strategy' => 'invalid_value' ];
        $result = $this->settings->sanitize( $input );
        $this->assertEquals( LDS_Settings::_DEFAULT_LOCKOUT_ATTEMPT_STRATEGY, $result['wldelay_lockout_attempt_strategy'] );
    }

    /**
     * Test default lockout attempt strategy.
     */
    public function test_lockout_attempt_strategy_default() {
        $result = $this->settings->sanitize( [] );
        $this->assertEquals( LDS_Settings::_DEFAULT_LOCKOUT_ATTEMPT_STRATEGY, $result['wldelay_lockout_attempt_strategy'] );
    }
}
