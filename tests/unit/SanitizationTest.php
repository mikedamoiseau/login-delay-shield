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

        Functions\when( 'get_option' )->justReturn( false );
        Functions\when( 'update_option' )->justReturn( true );
        Functions\when( 'wp_generate_password' )->alias( function( $length = 12 ) {
            return substr( str_repeat( 'abcdefghijklmnop', 2 ), 0, $length );
        } );

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
            'wldelay_fail2ban_enabled' => '1',
            'wldelay_fail2ban_include_lockouts' => '1',
            'wldelay_challenge_mode_enabled' => '1',
            'wldelay_country_blocking_enabled' => '1',
        ];
        $result = $this->settings->sanitize( $input );
        $this->assertTrue( $result['wldelay_delay_random'] );
        $this->assertTrue( $result['wldelay_email_enabled'] );
        $this->assertTrue( $result['wldelay_rest_enabled'] );
        $this->assertTrue( $result['wldelay_application_password_enabled'] );
        $this->assertTrue( $result['wldelay_fail2ban_enabled'] );
        $this->assertTrue( $result['wldelay_fail2ban_include_lockouts'] );
        $this->assertTrue( $result['wldelay_challenge_mode_enabled'] );
        $this->assertTrue( $result['wldelay_country_blocking_enabled'] );

        // Test falsy values
        $input = [
            'wldelay_delay_random' => '',
            'wldelay_email_enabled' => null,
            'wldelay_rest_enabled' => '',
            'wldelay_application_password_enabled' => null,
            'wldelay_fail2ban_enabled' => '',
            'wldelay_fail2ban_include_lockouts' => '',
            'wldelay_challenge_mode_enabled' => '',
            'wldelay_country_blocking_enabled' => '',
        ];
        $result = $this->settings->sanitize( $input );
        $this->assertFalse( $result['wldelay_delay_random'] );
        $this->assertFalse( $result['wldelay_email_enabled'] );
        $this->assertFalse( $result['wldelay_rest_enabled'] );
        $this->assertFalse( $result['wldelay_application_password_enabled'] );
        $this->assertFalse( $result['wldelay_fail2ban_enabled'] );
        $this->assertFalse( $result['wldelay_fail2ban_include_lockouts'] );
        $this->assertFalse( $result['wldelay_challenge_mode_enabled'] );
        $this->assertFalse( $result['wldelay_country_blocking_enabled'] );
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
        $this->assertFalse( $result['wldelay_fail2ban_enabled'] );
        $this->assertEquals( '', $result['wldelay_fail2ban_log_path'] );
        $this->assertFalse( $result['wldelay_fail2ban_include_lockouts'] );
        $this->assertFalse( $result['wldelay_challenge_mode_enabled'] );
        $this->assertEquals( LDS_Settings::_DEFAULT_CHALLENGE_MODE_THRESHOLD, $result['wldelay_challenge_mode_threshold'] );
        $this->assertFalse( $result['wldelay_country_blocking_enabled'] );
        $this->assertEquals( '', $result['wldelay_country_blocking_countries'] );
    }

    /**
     * Challenge provider is whitelisted against the registered ids, else math.
     */
    public function test_challenge_provider_whitelisted_else_math() {
        Functions\when( 'sanitize_key' )->alias( function ( $k ) {
            return strtolower( preg_replace( '/[^a-z0-9_\-]/', '', (string) $k ) );
        } );
        Functions\when( 'apply_filters' )->alias( function ( $tag, $value ) {
            return $value;
        } );

        $result = $this->settings->sanitize( array( 'wldelay_challenge_mode_provider' => 'bogus-provider' ) );
        $this->assertSame( 'math', $result['wldelay_challenge_mode_provider'] );

        $result2 = $this->settings->sanitize( array( 'wldelay_challenge_mode_provider' => 'email' ) );
        $this->assertSame( 'email', $result2['wldelay_challenge_mode_provider'] );
    }

    /**
     * Test challenge-mode threshold sanitization bounds.
     */
    public function test_challenge_mode_threshold_bounded() {
        $input = [ 'wldelay_challenge_mode_threshold' => 0 ];
        $result = $this->settings->sanitize( $input );
        $this->assertEquals( 1, $result['wldelay_challenge_mode_threshold'] );

        $input = [ 'wldelay_challenge_mode_threshold' => 150 ];
        $result = $this->settings->sanitize( $input );
        $this->assertEquals( 100, $result['wldelay_challenge_mode_threshold'] );

        $input = [ 'wldelay_challenge_mode_threshold' => 7 ];
        $result = $this->settings->sanitize( $input );
        $this->assertEquals( 7, $result['wldelay_challenge_mode_threshold'] );
    }

    /**
     * Test country-code sanitization.
     */
    public function test_country_codes_are_uppercase_unique_iso_shapes() {
        $input = [
            'wldelay_country_blocking_countries' => "us, ca\nDE;usa\nc1\nbr\nus",
        ];

        $result = $this->settings->sanitize( $input );

        $this->assertSame( "US\nCA\nDE\nBR", $result['wldelay_country_blocking_countries'] );
    }

    /**
     * Test fail2ban log path sanitization in settings.
     */
    public function test_fail2ban_log_path_sanitization() {
        $input = [ 'wldelay_fail2ban_log_path' => 'security/fail2ban.log' ];
        $result = $this->settings->sanitize( $input );

        $this->assertEquals( dirname( wldelay_fail2ban_get_default_log_path() ) . '/security/fail2ban.log', $result['wldelay_fail2ban_log_path'] );

        $input = [
            'wldelay_fail2ban_enabled' => '1',
            'wldelay_fail2ban_log_path' => '/var/log/auth.log',
        ];
        $result = $this->settings->sanitize( $input );

        $this->assertEquals( '', $result['wldelay_fail2ban_log_path'] );
        $this->assertFalse( $result['wldelay_fail2ban_enabled'] );
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
