<?php
/**
 * Unit tests for progressive delay functionality.
 */

use Brain\Monkey\Functions;

class ProgressiveDelayTest extends LDS_Unit_Test_Case {

    /**
     * @var LDS_Settings
     */
    private $settings;

    protected function setUp(): void {
        parent::setUp();

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
     * Test progressive increment is bounded between 1 and 10.
     */
    public function test_progressive_increment_bounded() {
        // Test lower bound
        $input = [ 'wldelay_progressive_increment' => 0 ];
        $result = $this->settings->sanitize( $input );
        $this->assertEquals( 1, $result['wldelay_progressive_increment'] );

        // Test upper bound
        $input = [ 'wldelay_progressive_increment' => 15 ];
        $result = $this->settings->sanitize( $input );
        $this->assertEquals( 10, $result['wldelay_progressive_increment'] );

        // Test valid value
        $input = [ 'wldelay_progressive_increment' => 5 ];
        $result = $this->settings->sanitize( $input );
        $this->assertEquals( 5, $result['wldelay_progressive_increment'] );
    }

    /**
     * Test progressive max is bounded between 5 and 60.
     */
    public function test_progressive_max_bounded() {
        // Test lower bound
        $input = [ 'wldelay_progressive_max' => 2 ];
        $result = $this->settings->sanitize( $input );
        $this->assertEquals( 5, $result['wldelay_progressive_max'] );

        // Test upper bound
        $input = [ 'wldelay_progressive_max' => 100 ];
        $result = $this->settings->sanitize( $input );
        $this->assertEquals( 60, $result['wldelay_progressive_max'] );

        // Test valid value
        $input = [ 'wldelay_progressive_max' => 30 ];
        $result = $this->settings->sanitize( $input );
        $this->assertEquals( 30, $result['wldelay_progressive_max'] );
    }

    /**
     * Test progressive enabled is cast to boolean.
     */
    public function test_progressive_enabled_boolean_cast() {
        // Test truthy value
        $input = [ 'wldelay_progressive_enabled' => '1' ];
        $result = $this->settings->sanitize( $input );
        $this->assertTrue( $result['wldelay_progressive_enabled'] );

        // Test falsy value
        $input = [ 'wldelay_progressive_enabled' => '' ];
        $result = $this->settings->sanitize( $input );
        $this->assertFalse( $result['wldelay_progressive_enabled'] );
    }

    /**
     * Test defaults are used for missing progressive delay fields.
     */
    public function test_progressive_defaults_used() {
        $input = [];

        $result = $this->settings->sanitize( $input );

        $this->assertEquals( LDS_Settings::_DEFAULT_PROGRESSIVE_INCREMENT, $result['wldelay_progressive_increment'] );
        $this->assertEquals( LDS_Settings::_DEFAULT_PROGRESSIVE_MAX, $result['wldelay_progressive_max'] );
        $this->assertFalse( $result['wldelay_progressive_enabled'] );
    }

    /**
     * Test progressive delay calculation with zero failures.
     */
    public function test_progressive_delay_zero_failures() {
        $options = [
            'wldelay_delay' => 2,
            'wldelay_delay_random' => false,
            'wldelay_progressive_enabled' => true,
            'wldelay_progressive_increment' => 1,
            'wldelay_progressive_max' => 30,
        ];

        $delay = $this->get_delay_value_from_options( $options, 0 );

        // With zero failures, should just be base delay
        $this->assertEquals( 2, $delay );
    }

    /**
     * Test progressive delay calculation with failures.
     */
    public function test_progressive_delay_with_failures() {
        $options = [
            'wldelay_delay' => 2,
            'wldelay_delay_random' => false,
            'wldelay_progressive_enabled' => true,
            'wldelay_progressive_increment' => 1,
            'wldelay_progressive_max' => 30,
        ];

        // 1 failure: 2 + (1 * 1) = 3
        $delay = $this->get_delay_value_from_options( $options, 1 );
        $this->assertEquals( 3, $delay );

        // 5 failures: 2 + (1 * 5) = 7
        $delay = $this->get_delay_value_from_options( $options, 5 );
        $this->assertEquals( 7, $delay );

        // 10 failures: 2 + (1 * 10) = 12
        $delay = $this->get_delay_value_from_options( $options, 10 );
        $this->assertEquals( 12, $delay );
    }

    /**
     * Test progressive delay respects maximum cap.
     */
    public function test_progressive_delay_capped_at_max() {
        $options = [
            'wldelay_delay' => 5,
            'wldelay_delay_random' => false,
            'wldelay_progressive_enabled' => true,
            'wldelay_progressive_increment' => 3,
            'wldelay_progressive_max' => 15,
        ];

        // 10 failures would be: 5 + (3 * 10) = 35, but capped at 15
        $delay = $this->get_delay_value_from_options( $options, 10 );
        $this->assertEquals( 15, $delay );
    }

    /**
     * Test progressive delay disabled uses base delay only.
     */
    public function test_progressive_disabled_uses_base_delay() {
        $options = [
            'wldelay_delay' => 2,
            'wldelay_delay_random' => false,
            'wldelay_progressive_enabled' => false,
            'wldelay_progressive_increment' => 5,
            'wldelay_progressive_max' => 30,
        ];

        // Even with 10 failures, should just be base delay
        $delay = $this->get_delay_value_from_options( $options, 10 );
        $this->assertEquals( 2, $delay );
    }

    /**
     * Test progressive delay with random base delay.
     */
    public function test_progressive_delay_with_random_base() {
        $options = [
            'wldelay_delay_random' => true,
            'wldelay_delay_random_min' => 2,
            'wldelay_delay_random_max' => 2, // Fixed for testing
            'wldelay_progressive_enabled' => true,
            'wldelay_progressive_increment' => 2,
            'wldelay_progressive_max' => 30,
        ];

        Functions\when( 'wp_rand' )->justReturn( 2 );

        // 3 failures: 2 (random base) + (2 * 3) = 8
        $delay = $this->get_delay_value_from_options( $options, 3 );
        $this->assertEquals( 8, $delay );
    }

    /**
     * Test progressive delay with higher increment.
     */
    public function test_progressive_delay_higher_increment() {
        $options = [
            'wldelay_delay' => 1,
            'wldelay_delay_random' => false,
            'wldelay_progressive_enabled' => true,
            'wldelay_progressive_increment' => 5,
            'wldelay_progressive_max' => 60,
        ];

        // 4 failures: 1 + (5 * 4) = 21
        $delay = $this->get_delay_value_from_options( $options, 4 );
        $this->assertEquals( 21, $delay );
    }

    /**
     * Helper to simulate wldelay_get_delay_value() logic with progressive delay.
     *
     * @param array $options The options array.
     * @param int $failure_count Number of previous failures.
     * @return int The delay value.
     */
    private function get_delay_value_from_options( array $options, int $failure_count = 0 ): int {
        // Get base delay (random or fixed)
        $useRandomDelay = ! empty( $options['wldelay_delay_random'] );

        if ( $useRandomDelay ) {
            $min = isset( $options['wldelay_delay_random_min'] )
                ? (int) $options['wldelay_delay_random_min']
                : LDS_Settings::_DEFAULT_RANDOM_MIN;
            $max = isset( $options['wldelay_delay_random_max'] )
                ? (int) $options['wldelay_delay_random_max']
                : LDS_Settings::_DEFAULT_RANDOM_MAX;

            if ( function_exists( 'wp_rand' ) ) {
                $base_delay = wp_rand( $min, $max );
            } else {
                $base_delay = rand( $min, $max );
            }
        } else {
            $base_delay = isset( $options['wldelay_delay'] )
                ? (int) $options['wldelay_delay']
                : LDS_Settings::_DEFAULT_DELAY_IN_SECONDS;
        }

        // Apply progressive delay if enabled
        $progressive_enabled = ! empty( $options['wldelay_progressive_enabled'] );
        if ( $progressive_enabled && $failure_count > 0 ) {
            $increment = isset( $options['wldelay_progressive_increment'] )
                ? (int) $options['wldelay_progressive_increment']
                : LDS_Settings::_DEFAULT_PROGRESSIVE_INCREMENT;
            $max_delay = isset( $options['wldelay_progressive_max'] )
                ? (int) $options['wldelay_progressive_max']
                : LDS_Settings::_DEFAULT_PROGRESSIVE_MAX;

            $progressive_delay = $base_delay + ( $increment * $failure_count );
            $delay = min( $progressive_delay, $max_delay );
        } else {
            $delay = $base_delay;
        }

        return $delay;
    }
}
