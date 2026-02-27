<?php
/**
 * Unit tests for settings sanitization.
 */

use Brain\Monkey\Functions;

class SanitizationTest extends LDS_Unit_Test_Case {

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
     * Test that delay is capped at 10 seconds.
     */
    public function test_delay_capped_at_10_seconds() {
        $input = [ 'wldelay_delay' => 15 ];

        $result = $this->settings->sanitize( $input );

        $this->assertEquals( 10, $result['wldelay_delay'] );
    }

    /**
     * Test that negative delay is converted to positive (absint behavior).
     */
    public function test_negative_delay_converted_to_positive() {
        $input = [ 'wldelay_delay' => -5 ];

        $result = $this->settings->sanitize( $input );

        // absint() converts -5 to 5, which is within bounds
        $this->assertEquals( 5, $result['wldelay_delay'] );
    }

    /**
     * Test that valid delay is preserved.
     */
    public function test_valid_delay_preserved() {
        $input = [ 'wldelay_delay' => 5 ];

        $result = $this->settings->sanitize( $input );

        $this->assertEquals( 5, $result['wldelay_delay'] );
    }

    /**
     * Test that random min cannot exceed random max.
     */
    public function test_random_min_cannot_exceed_max() {
        $input = [
            'wldelay_delay_random_min' => 8,
            'wldelay_delay_random_max' => 3,
        ];

        $result = $this->settings->sanitize( $input );

        // min should be set to max when min > max
        $this->assertEquals( 3, $result['wldelay_delay_random_min'] );
        $this->assertEquals( 3, $result['wldelay_delay_random_max'] );
    }

    /**
     * Test that random min/max are clamped to 1-10 range.
     */
    public function test_random_values_clamped_to_range() {
        $input = [
            'wldelay_delay_random_min' => 0,
            'wldelay_delay_random_max' => 20,
        ];

        $result = $this->settings->sanitize( $input );

        $this->assertEquals( 1, $result['wldelay_delay_random_min'] );
        $this->assertEquals( 10, $result['wldelay_delay_random_max'] );
    }

    /**
     * Test that email threshold is bounded between 1 and 100.
     */
    public function test_email_threshold_bounded() {
        // Test lower bound
        $input = [ 'wldelay_email_threshold' => 0 ];
        $result = $this->settings->sanitize( $input );
        $this->assertEquals( 1, $result['wldelay_email_threshold'] );

        // Test upper bound
        $input = [ 'wldelay_email_threshold' => 150 ];
        $result = $this->settings->sanitize( $input );
        $this->assertEquals( 100, $result['wldelay_email_threshold'] );

        // Test valid value
        $input = [ 'wldelay_email_threshold' => 25 ];
        $result = $this->settings->sanitize( $input );
        $this->assertEquals( 25, $result['wldelay_email_threshold'] );
    }

    /**
     * Test that email address is sanitized.
     */
    public function test_email_address_sanitized() {
        $input = [ 'wldelay_email_address' => 'valid@example.com' ];

        $result = $this->settings->sanitize( $input );

        $this->assertEquals( 'valid@example.com', $result['wldelay_email_address'] );
    }

    /**
     * Test that invalid email is cleaned.
     */
    public function test_invalid_email_sanitized() {
        $input = [ 'wldelay_email_address' => 'not-an-email<script>' ];

        $result = $this->settings->sanitize( $input );

        // sanitize_email strips invalid characters
        $this->assertStringNotContainsString( '<script>', $result['wldelay_email_address'] );
    }

    /**
     * Test that empty email address is allowed (fallback to admin email).
     */
    public function test_empty_email_allowed() {
        $input = [ 'wldelay_email_address' => '' ];

        $result = $this->settings->sanitize( $input );

        $this->assertEquals( '', $result['wldelay_email_address'] );
    }

    /**
     * Test boolean fields are properly cast.
     */
    public function test_boolean_fields_cast_correctly() {
        // Test truthy values
        $input = [
            'wldelay_delay_random' => '1',
            'wldelay_email_enabled' => 'yes',
            'wldelay_rest_enabled' => '1',
            'wldelay_application_password_enabled' => '1',
        ];
        $result = $this->settings->sanitize( $input );
        $this->assertTrue( $result['wldelay_delay_random'] );
        $this->assertTrue( $result['wldelay_email_enabled'] );
        $this->assertTrue( $result['wldelay_rest_enabled'] );
        $this->assertTrue( $result['wldelay_application_password_enabled'] );

        // Test falsy values
        $input = [
            'wldelay_delay_random' => '',
            'wldelay_email_enabled' => null,
            'wldelay_rest_enabled' => '',
            'wldelay_application_password_enabled' => null,
        ];
        $result = $this->settings->sanitize( $input );
        $this->assertFalse( $result['wldelay_delay_random'] );
        $this->assertFalse( $result['wldelay_email_enabled'] );
        $this->assertFalse( $result['wldelay_rest_enabled'] );
        $this->assertFalse( $result['wldelay_application_password_enabled'] );
    }

    /**
     * Test default values are used when fields are missing.
     */
    public function test_defaults_used_for_missing_fields() {
        $input = [];

        $result = $this->settings->sanitize( $input );

        $this->assertEquals( LDS_Settings::_DEFAULT_RANDOM_MIN, $result['wldelay_delay_random_min'] );
        $this->assertEquals( LDS_Settings::_DEFAULT_RANDOM_MAX, $result['wldelay_delay_random_max'] );
        $this->assertEquals( LDS_Settings::_DEFAULT_EMAIL_THRESHOLD, $result['wldelay_email_threshold'] );
        $this->assertEquals( LDS_Settings::_DEFAULT_EMAIL_COOLDOWN, $result['wldelay_email_cooldown'] );
        $this->assertFalse( $result['wldelay_rest_enabled'] );
        $this->assertFalse( $result['wldelay_application_password_enabled'] );
    }

    /**
     * Test email cooldown sanitization bounds
     */
    public function test_email_cooldown_sanitization() {
        // Test minimum (0 is allowed - disables cooldown)
        $input = [ 'wldelay_email_cooldown' => 0 ];
        $result = $this->settings->sanitize( $input );
        $this->assertEquals( 0, $result['wldelay_email_cooldown'] );

        // Test maximum (capped at 60)
        $input = [ 'wldelay_email_cooldown' => 120 ];
        $result = $this->settings->sanitize( $input );
        $this->assertEquals( 60, $result['wldelay_email_cooldown'] );

        // Test valid value in range
        $input = [ 'wldelay_email_cooldown' => 15 ];
        $result = $this->settings->sanitize( $input );
        $this->assertEquals( 15, $result['wldelay_email_cooldown'] );

        // Test negative values become positive via absint
        $input = [ 'wldelay_email_cooldown' => -5 ];
        $result = $this->settings->sanitize( $input );
        $this->assertEquals( 5, $result['wldelay_email_cooldown'] );
    }
}
