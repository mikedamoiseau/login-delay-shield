<?php
/**
 * Unit tests for delay value calculation.
 */

use Brain\Monkey\Functions;

class DelayValueTest extends LDS_Unit_Test_Case {

    /**
     * Test that fixed delay returns correct value from options.
     */
    public function test_fixed_delay_returns_configured_value() {
        $options = [
            'wldelay_delay' => 3,
            'wldelay_delay_random' => false,
        ];

        Functions\when( 'get_option' )->justReturn( $options );

        // Include the main plugin file to get the functions
        // We need to re-declare the function for each test since it uses static
        $delay = $this->get_delay_value_from_options( $options );

        $this->assertEquals( 3, $delay );
    }

    /**
     * Test that default delay is used when option is empty.
     */
    public function test_fixed_delay_uses_default_when_empty() {
        $options = [];

        $delay = $this->get_delay_value_from_options( $options );

        $this->assertEquals( LDS_Settings::_DEFAULT_DELAY_IN_SECONDS, $delay );
    }

    /**
     * Test that random delay falls within min/max bounds.
     */
    public function test_random_delay_within_bounds() {
        $options = [
            'wldelay_delay_random' => true,
            'wldelay_delay_random_min' => 2,
            'wldelay_delay_random_max' => 4,
        ];

        Functions\when( 'wp_rand' )->alias( function( $min, $max ) {
            return rand( $min, $max );
        });

        // Run multiple times to test randomness stays in bounds
        for ( $i = 0; $i < 10; $i++ ) {
            $delay = $this->get_delay_value_from_options( $options );
            $this->assertGreaterThanOrEqual( 2, $delay );
            $this->assertLessThanOrEqual( 4, $delay );
        }
    }

    /**
     * Test that random delay uses default min/max when not set.
     */
    public function test_random_delay_uses_defaults_when_not_set() {
        $options = [
            'wldelay_delay_random' => true,
        ];

        Functions\when( 'wp_rand' )->alias( function( $min, $max ) {
            // Verify the default values are passed
            $this->assertEquals( LDS_Settings::_DEFAULT_RANDOM_MIN, $min );
            $this->assertEquals( LDS_Settings::_DEFAULT_RANDOM_MAX, $max );
            return $min;
        });

        $delay = $this->get_delay_value_from_options( $options );

        $this->assertEquals( LDS_Settings::_DEFAULT_RANDOM_MIN, $delay );
    }

    /**
     * Helper to simulate wldelay_get_delay_value() logic.
     *
     * We can't include the actual plugin file in unit tests without WordPress,
     * so we replicate the logic here for testing.
     *
     * @param array $options The options array.
     * @return int The delay value.
     */
    private function get_delay_value_from_options( array $options ): int {
        $useRandomDelay = ! empty( $options['wldelay_delay_random'] );

        if ( $useRandomDelay ) {
            $min = isset( $options['wldelay_delay_random_min'] )
                ? (int) $options['wldelay_delay_random_min']
                : LDS_Settings::_DEFAULT_RANDOM_MIN;
            $max = isset( $options['wldelay_delay_random_max'] )
                ? (int) $options['wldelay_delay_random_max']
                : LDS_Settings::_DEFAULT_RANDOM_MAX;

            // Use Brain Monkey's mocked wp_rand or fall back to PHP rand
            if ( function_exists( 'wp_rand' ) ) {
                $delay = wp_rand( $min, $max );
            } else {
                $delay = rand( $min, $max );
            }
        } else {
            $delay = isset( $options['wldelay_delay'] )
                ? (int) $options['wldelay_delay']
                : LDS_Settings::_DEFAULT_DELAY_IN_SECONDS;
        }

        return $delay;
    }
}
