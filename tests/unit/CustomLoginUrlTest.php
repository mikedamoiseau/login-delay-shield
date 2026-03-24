<?php
/**
 * Unit tests for Custom Login URL slug sanitization.
 */

use Brain\Monkey\Functions;

class CustomLoginUrlTest extends LDS_Unit_Test_Case {

    /**
     * @var LDS_Settings
     */
    private $settings;

    protected function setUp(): void {
        parent::setUp();

        Functions\when( 'absint' )->alias( function( $value ) {
            return abs( (int) $value );
        } );

        Functions\when( 'sanitize_email' )->alias( function( $email ) {
            return filter_var( $email, FILTER_SANITIZE_EMAIL );
        } );

        $this->settings = new LDS_Settings();
    }

    // -------------------------------------------------------------------------
    // sanitize_login_slug() unit tests
    // -------------------------------------------------------------------------

    /**
     * A clean lowercase slug passes through unchanged.
     */
    public function test_valid_slug_passes_through() {
        $result = $this->settings->sanitize_login_slug( 'my-login' );
        $this->assertEquals( 'my-login', $result );
    }

    /**
     * Uppercase letters are lowercased.
     */
    public function test_uppercase_is_lowercased() {
        $result = $this->settings->sanitize_login_slug( 'My-Login' );
        $this->assertEquals( 'my-login', $result );
    }

    /**
     * Spaces and special characters are stripped.
     */
    public function test_special_characters_stripped() {
        $result = $this->settings->sanitize_login_slug( 'my login!' );
        $this->assertEquals( 'mylogin', $result );
    }

    /**
     * Numbers are allowed in slugs.
     */
    public function test_numbers_allowed() {
        $result = $this->settings->sanitize_login_slug( 'login2024' );
        $this->assertEquals( 'login2024', $result );
    }

    /**
     * Leading and trailing hyphens are trimmed.
     */
    public function test_leading_trailing_hyphens_trimmed() {
        $result = $this->settings->sanitize_login_slug( '-my-login-' );
        $this->assertEquals( 'my-login', $result );
    }

    /**
     * Empty input returns the default fallback slug.
     */
    public function test_empty_slug_returns_default() {
        $result = $this->settings->sanitize_login_slug( '' );
        $this->assertEquals( 'my-login', $result );
    }

    /**
     * A slug consisting only of invalid characters returns the default.
     */
    public function test_all_invalid_chars_returns_default() {
        $result = $this->settings->sanitize_login_slug( '!!!@@@###' );
        $this->assertEquals( 'my-login', $result );
    }

    /**
     * Reserved slug 'wp-admin' is rejected.
     */
    public function test_reserved_slug_wp_admin_rejected() {
        $result = $this->settings->sanitize_login_slug( 'wp-admin' );
        $this->assertEquals( 'my-login', $result );
    }

    /**
     * Reserved slug 'wp-login' is rejected.
     */
    public function test_reserved_slug_wp_login_rejected() {
        $result = $this->settings->sanitize_login_slug( 'wp-login' );
        $this->assertEquals( 'my-login', $result );
    }

    /**
     * Reserved slug 'admin' is rejected.
     */
    public function test_reserved_slug_admin_rejected() {
        $result = $this->settings->sanitize_login_slug( 'admin' );
        $this->assertEquals( 'my-login', $result );
    }

    /**
     * Reserved slug 'login' is rejected.
     */
    public function test_reserved_slug_login_rejected() {
        $result = $this->settings->sanitize_login_slug( 'login' );
        $this->assertEquals( 'my-login', $result );
    }

    /**
     * Reserved slug 'wp-cron' is rejected.
     */
    public function test_reserved_slug_wp_cron_rejected() {
        $result = $this->settings->sanitize_login_slug( 'wp-cron' );
        $this->assertEquals( 'my-login', $result );
    }

    /**
     * Input 'wp-login.php' is sanitized (dot stripped) to 'wp-loginphp',
     * which is safe to use and passes through.
     *
     * The reserved list is checked after sanitization, so only post-sanitization
     * slugs (containing only a-z0-9-) can be reserved. 'wp-login.php' contains
     * a dot that gets stripped, producing 'wp-loginphp' — a valid custom slug.
     */
    public function test_wp_login_php_sanitized_to_safe_slug() {
        $result = $this->settings->sanitize_login_slug( 'wp-login.php' );
        $this->assertEquals( 'wp-loginphp', $result );
    }

    /**
     * Hyphens in the middle of a slug are preserved.
     */
    public function test_hyphens_in_middle_preserved() {
        $result = $this->settings->sanitize_login_slug( 'secure-access-2024' );
        $this->assertEquals( 'secure-access-2024', $result );
    }

    // -------------------------------------------------------------------------
    // sanitize() integration: custom login fields go through the full method
    // -------------------------------------------------------------------------

    /**
     * Full sanitize() passes through a valid custom login configuration.
     */
    public function test_sanitize_custom_login_enabled_and_slug() {
        $input = array(
            'wldelay_custom_login_enabled' => '1',
            'wldelay_custom_login_slug'    => 'secure-login',
        );

        $result = $this->settings->sanitize( $input );

        $this->assertTrue( $result['wldelay_custom_login_enabled'] );
        $this->assertEquals( 'secure-login', $result['wldelay_custom_login_slug'] );
    }

    /**
     * Full sanitize() defaults custom login to disabled when key is absent.
     */
    public function test_sanitize_custom_login_disabled_by_default() {
        $result = $this->settings->sanitize( array() );

        $this->assertFalse( $result['wldelay_custom_login_enabled'] );
    }

    /**
     * Full sanitize() rejects a reserved slug and substitutes the fallback.
     */
    public function test_sanitize_rejects_reserved_slug() {
        $input = array(
            'wldelay_custom_login_enabled' => '1',
            'wldelay_custom_login_slug'    => 'wp-admin',
        );

        $result = $this->settings->sanitize( $input );

        $this->assertEquals( 'my-login', $result['wldelay_custom_login_slug'] );
    }
}
