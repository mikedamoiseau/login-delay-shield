<?php
/**
 * Integration tests for the Custom Login URL feature.
 *
 * These tests require a full WordPress test environment (Docker + DB).
 * Run with: composer test:integration
 */

class CustomLoginUrlTest extends WP_UnitTestCase {

    protected function setUp(): void {
        parent::setUp();
        delete_option( 'wldelay_options' );
        wldelay_clear_options_cache();

        // Remove any constants that might be set by a previous test run.
        // (Constants can't be undefined in PHP, but we handle the case in code.)
    }

    protected function tearDown(): void {
        delete_option( 'wldelay_options' );
        wldelay_clear_options_cache();
        parent::tearDown();
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private function enable_custom_login( $slug = 'my-login' ) {
        update_option( 'wldelay_options', array(
            'wldelay_custom_login_enabled' => true,
            'wldelay_custom_login_slug'    => $slug,
        ) );
        wldelay_clear_options_cache();
    }

    private function disable_custom_login() {
        update_option( 'wldelay_options', array(
            'wldelay_custom_login_enabled' => false,
        ) );
        wldelay_clear_options_cache();
    }

    // -------------------------------------------------------------------------
    // wldelay_custom_login_is_active()
    // -------------------------------------------------------------------------

    /**
     * Feature is inactive when disabled in options.
     */
    public function test_is_active_returns_false_when_disabled() {
        $this->disable_custom_login();

        $this->assertFalse( wldelay_custom_login_is_active() );
    }

    /**
     * Feature is active when enabled with a valid slug.
     */
    public function test_is_active_returns_true_when_enabled() {
        $this->enable_custom_login( 'my-login' );

        $this->assertTrue( wldelay_custom_login_is_active() );
    }

    /**
     * Feature is inactive when the slug is empty (even if enabled checkbox is on).
     */
    public function test_is_active_returns_false_when_slug_empty() {
        update_option( 'wldelay_options', array(
            'wldelay_custom_login_enabled' => true,
            'wldelay_custom_login_slug'    => '',
        ) );
        wldelay_clear_options_cache();

        $this->assertFalse( wldelay_custom_login_is_active() );
    }

    // -------------------------------------------------------------------------
    // wldelay_filter_login_url()
    // -------------------------------------------------------------------------

    /**
     * wp_login_url() returns the custom slug URL when feature is enabled.
     */
    public function test_login_url_uses_custom_slug() {
        $this->enable_custom_login( 'secure-access' );

        $login_url = wp_login_url();

        $this->assertStringContainsString( 'secure-access', $login_url );
        $this->assertStringNotContainsString( 'wp-login.php', $login_url );
    }

    /**
     * wp_login_url() returns standard URL when feature is disabled.
     */
    public function test_login_url_unchanged_when_disabled() {
        $this->disable_custom_login();

        $login_url = wp_login_url();

        $this->assertStringContainsString( 'wp-login.php', $login_url );
    }

    /**
     * redirect_to parameter is preserved in the filtered login URL.
     */
    public function test_login_url_preserves_redirect_to() {
        $this->enable_custom_login( 'my-login' );

        $login_url = wp_login_url( home_url( '/dashboard/' ) );

        $this->assertStringContainsString( 'redirect_to', $login_url );
    }

    // -------------------------------------------------------------------------
    // wldelay_filter_logout_url()
    // -------------------------------------------------------------------------

    /**
     * logout_url() returns the custom slug URL when feature is enabled.
     */
    public function test_logout_url_uses_custom_slug() {
        $this->enable_custom_login( 'my-login' );

        $logout_url = wp_logout_url();

        $this->assertStringContainsString( 'my-login', $logout_url );
        $this->assertStringNotContainsString( 'wp-login.php', $logout_url );
    }

    /**
     * logout_url() contains the logout action parameter.
     */
    public function test_logout_url_contains_action_logout() {
        $this->enable_custom_login( 'my-login' );

        $logout_url = wp_logout_url();

        $this->assertStringContainsString( 'action=logout', $logout_url );
    }

    // -------------------------------------------------------------------------
    // wldelay_filter_lostpassword_url()
    // -------------------------------------------------------------------------

    /**
     * lostpassword_url() returns the custom slug URL when feature is enabled.
     */
    public function test_lostpassword_url_uses_custom_slug() {
        $this->enable_custom_login( 'my-login' );

        $lp_url = wp_lostpassword_url();

        $this->assertStringContainsString( 'my-login', $lp_url );
        $this->assertStringNotContainsString( 'wp-login.php', $lp_url );
        $this->assertStringContainsString( 'action=lostpassword', $lp_url );
    }

    // -------------------------------------------------------------------------
    // wldelay_custom_login_block_direct_access()
    // -------------------------------------------------------------------------

    /**
     * Block function does nothing when feature is disabled.
     */
    public function test_block_direct_access_noop_when_disabled() {
        $this->disable_custom_login();

        // Simulate a REQUEST_URI pointing at wp-login.php — should not redirect.
        $_SERVER['REQUEST_URI'] = '/wp-login.php';

        // The function should return without calling wp_safe_redirect / exit.
        // We verify indirectly: no exception/exit is thrown.
        ob_start();
        wldelay_custom_login_block_direct_access();
        ob_end_clean();

        // If we reach this line the function returned normally (no exit).
        $this->assertTrue( true );

        unset( $_SERVER['REQUEST_URI'] );
    }

    /**
     * Block function allows slug-based requests through (REQUEST_URI has slug).
     */
    public function test_block_direct_access_allows_slug_request() {
        $this->enable_custom_login( 'my-login' );

        $_SERVER['REQUEST_URI'] = '/my-login/';

        ob_start();
        wldelay_custom_login_block_direct_access();
        ob_end_clean();

        // No exit/redirect = function returned normally.
        $this->assertTrue( true );

        unset( $_SERVER['REQUEST_URI'] );
    }

    // -------------------------------------------------------------------------
    // wldelay_filter_retrieve_password_message()
    // -------------------------------------------------------------------------

    /**
     * Password reset message has wp-login.php URL replaced with custom slug.
     */
    public function test_password_reset_message_uses_custom_slug() {
        $this->enable_custom_login( 'my-login' );

        $old_url = network_site_url( 'wp-login.php', 'login' );
        $message = "Reset your password here: {$old_url}?action=rp&key=abc123";

        // Create a minimal WP_User stub.
        $user = new stdClass();

        $filtered = wldelay_filter_retrieve_password_message( $message, 'abc123', 'testuser', $user );

        $this->assertStringNotContainsString( 'wp-login.php', $filtered );
        $this->assertStringContainsString( 'my-login', $filtered );
    }

    /**
     * Password reset message is unchanged when feature is disabled.
     */
    public function test_password_reset_message_unchanged_when_disabled() {
        $this->disable_custom_login();

        $old_url = network_site_url( 'wp-login.php', 'login' );
        $message = "Reset link: {$old_url}?action=rp&key=abc123";

        $user     = new stdClass();
        $filtered = wldelay_filter_retrieve_password_message( $message, 'abc123', 'testuser', $user );

        $this->assertEquals( $message, $filtered );
    }

    // -------------------------------------------------------------------------
    // Recovery bypass constant
    // -------------------------------------------------------------------------

    /**
     * When WLDELAY_DISABLE_CUSTOM_LOGIN is true, the feature is inactive.
     *
     * Note: PHP constants cannot be undefined once set, so this test relies on
     * the constant already being defined in a way that enables the bypass, or
     * it documents expected behaviour for code review purposes. In CI, this
     * constant is not defined and the feature behaves normally.
     *
     * If WLDELAY_DISABLE_CUSTOM_LOGIN is defined as true in the test bootstrap,
     * wldelay_custom_login_is_active() must return false regardless of options.
     */
    public function test_bypass_constant_overrides_enabled_setting() {
        if ( ! defined( 'WLDELAY_DISABLE_CUSTOM_LOGIN' ) ) {
            $this->markTestSkipped( 'WLDELAY_DISABLE_CUSTOM_LOGIN constant not defined in this environment.' );
        }

        $this->enable_custom_login( 'my-login' );

        if ( WLDELAY_DISABLE_CUSTOM_LOGIN ) {
            $this->assertFalse( wldelay_custom_login_is_active() );
        } else {
            $this->assertTrue( wldelay_custom_login_is_active() );
        }
    }

    // -------------------------------------------------------------------------
    // Hooks registration
    // -------------------------------------------------------------------------

    /**
     * Verify all expected hooks are registered.
     */
    public function test_hooks_are_registered() {
        $this->assertNotFalse( has_action( 'init', 'wldelay_custom_login_init' ) );
        $this->assertNotFalse( has_filter( 'query_vars', 'wldelay_custom_login_query_vars' ) );
        $this->assertNotFalse( has_action( 'template_redirect', 'wldelay_custom_login_template_redirect' ) );
        $this->assertNotFalse( has_action( 'login_init', 'wldelay_custom_login_block_direct_access' ) );
        $this->assertNotFalse( has_filter( 'wp_login_url', 'wldelay_filter_login_url' ) );
        $this->assertNotFalse( has_filter( 'logout_url', 'wldelay_filter_logout_url' ) );
        $this->assertNotFalse( has_filter( 'lostpassword_url', 'wldelay_filter_lostpassword_url' ) );
        $this->assertNotFalse( has_filter( 'retrieve_password_message', 'wldelay_filter_retrieve_password_message' ) );
    }
}
