<?php
/**
 * Integration tests for username-enumeration hardening (F-3-5).
 *
 * Verifies the three guards (generic login errors, ?author=N blocking,
 * REST /wp/v2/users restriction) behave correctly with the toggle OFF
 * (core behavior preserved) and ON (enumeration starved).
 */

class EnumerationHardeningTest extends WP_UnitTestCase {

    public function setUp(): void {
        parent::setUp();
        $_SERVER['REMOTE_ADDR'] = '203.0.113.55';
        unset( $_SERVER['REQUEST_URI'] );
        delete_option( 'wldelay_options' );
        wldelay_clear_options_cache();
        wp_set_current_user( 0 );
    }

    public function tearDown(): void {
        unset( $_SERVER['REMOTE_ADDR'] );
        unset( $_SERVER['REQUEST_URI'] );
        delete_option( 'wldelay_options' );
        wldelay_clear_options_cache();
        wp_set_current_user( 0 );
        parent::tearDown();
    }

    private function enable() {
        update_option( 'wldelay_options', array(
            'wldelay_enumeration_hardening_enabled' => true,
        ) );
        wldelay_clear_options_cache();
    }

    private function disable() {
        update_option( 'wldelay_options', array(
            'wldelay_enumeration_hardening_enabled' => false,
        ) );
        wldelay_clear_options_cache();
    }

    /* --------------------------------------------------------------------- */
    /* Hook registration                                                     */
    /* --------------------------------------------------------------------- */

    public function test_login_errors_filter_registered() {
        $this->assertNotFalse( has_filter( 'login_errors', 'wldelay_filter_login_errors' ) );
    }

    public function test_author_guard_registered() {
        $this->assertNotFalse( has_action( 'template_redirect', 'wldelay_block_author_enumeration' ) );
    }

    public function test_rest_endpoints_filter_registered() {
        $this->assertNotFalse( has_filter( 'rest_endpoints', 'wldelay_restrict_rest_user_endpoints' ) );
    }

    public function test_sitemap_provider_filter_registered() {
        $this->assertNotFalse( has_filter( 'wp_sitemaps_add_provider', 'wldelay_remove_users_sitemap_provider' ) );
    }

    /* --------------------------------------------------------------------- */
    /* Guard 1: generic login errors                                         */
    /* --------------------------------------------------------------------- */

    public function test_login_errors_unchanged_when_disabled() {
        $this->disable();

        $original = 'Error: The username <strong>bob</strong> is not registered.';
        $this->assertSame( $original, wldelay_filter_login_errors( $original ) );
    }

    public function test_login_errors_generic_when_enabled() {
        $this->enable();

        $generic  = wldelay_get_generic_login_error_message();
        $username = wldelay_filter_login_errors( 'Error: Unknown username. Check again or try your email address.' );
        $password = wldelay_filter_login_errors( 'Error: The password you entered for the username bob is incorrect.' );

        // Both distinct core messages collapse to the same generic string.
        $this->assertSame( $generic, $username );
        $this->assertSame( $generic, $password );
        $this->assertSame( $username, $password );
    }

    public function test_login_errors_passthrough_empty_string_when_enabled() {
        $this->enable();
        // No error to display (e.g. logout confirmation) must stay empty.
        $this->assertSame( '', wldelay_filter_login_errors( '' ) );
    }

    /* --------------------------------------------------------------------- */
    /* Guard 2: ?author=N enumeration                                        */
    /* --------------------------------------------------------------------- */

    public function test_author_query_blocked_for_guest_when_enabled() {
        $this->enable();
        $this->go_to( home_url( '/?author=1' ) );

        $blocked = wldelay_should_block_author_enumeration();
        $this->assertTrue( $blocked );
    }

    public function test_author_query_allowed_when_disabled() {
        $this->disable();
        $this->go_to( home_url( '/?author=1' ) );

        $this->assertFalse( wldelay_should_block_author_enumeration() );
    }

    public function test_author_query_allowed_for_logged_in_user_when_enabled() {
        $this->enable();
        $admin = $this->factory->user->create( array( 'role' => 'administrator' ) );
        wp_set_current_user( $admin );
        $this->go_to( home_url( '/?author=1' ) );

        // Authenticated users keep author archives (legitimate admin use).
        $this->assertFalse( wldelay_should_block_author_enumeration() );
    }

    public function test_non_author_request_not_blocked_when_enabled() {
        $this->enable();
        $this->go_to( home_url( '/' ) );

        $this->assertFalse( wldelay_should_block_author_enumeration() );
    }

    /* --------------------------------------------------------------------- */
    /* Guard 3: REST /wp/v2/users restriction                                */
    /* --------------------------------------------------------------------- */

    public function test_rest_users_listing_restricted_for_guest_when_enabled() {
        $this->enable();
        wp_set_current_user( 0 );

        $request  = new WP_REST_Request( 'GET', '/wp/v2/users' );
        $response = rest_do_request( $request );

        // Unauthenticated collection listing must not return 200 with users.
        $this->assertNotEquals( 200, $response->get_status() );
    }

    public function test_rest_users_listing_allowed_for_guest_when_disabled() {
        $this->disable();
        $this->factory->user->create( array( 'role' => 'author' ) );
        wp_set_current_user( 0 );

        $request  = new WP_REST_Request( 'GET', '/wp/v2/users' );
        $response = rest_do_request( $request );

        // Core default: the collection route exists (status is not a 404
        // produced by our guard removing the route).
        $this->assertNotEquals( 404, $response->get_status() );
    }

    public function test_rest_users_listing_allowed_for_admin_when_enabled() {
        $this->enable();
        $admin = $this->factory->user->create( array( 'role' => 'administrator' ) );
        wp_set_current_user( $admin );

        $request  = new WP_REST_Request( 'GET', '/wp/v2/users' );
        $response = rest_do_request( $request );

        $this->assertEquals( 200, $response->get_status() );
    }

    public function test_rest_single_user_restricted_for_guest_when_enabled() {
        $this->enable();

        // An author with a published post is publicly readable via the
        // single-user route by default, so this is the real enumeration vector.
        $author = $this->factory->user->create( array( 'role' => 'author' ) );
        $this->factory->post->create( array(
            'post_author' => $author,
            'post_status' => 'publish',
        ) );
        wp_set_current_user( 0 );

        $request  = new WP_REST_Request( 'GET', '/wp/v2/users/' . $author );
        $response = rest_do_request( $request );

        // Guard must drop the GET handler so the single user is not disclosed.
        $this->assertNotEquals( 200, $response->get_status() );
    }

    public function test_rest_single_user_allowed_for_guest_when_disabled() {
        $this->disable();

        $author = $this->factory->user->create( array( 'role' => 'author' ) );
        $this->factory->post->create( array(
            'post_author' => $author,
            'post_status' => 'publish',
        ) );
        wp_set_current_user( 0 );

        $request  = new WP_REST_Request( 'GET', '/wp/v2/users/' . $author );
        $response = rest_do_request( $request );

        // Core default: the single-user route exists (status is not a 404
        // produced by our guard removing the route).
        $this->assertEquals( 200, $response->get_status() );
    }

    public function test_rest_single_user_allowed_for_admin_when_enabled() {
        $this->enable();
        $admin  = $this->factory->user->create( array( 'role' => 'administrator' ) );
        $author = $this->factory->user->create( array( 'role' => 'author' ) );
        wp_set_current_user( $admin );

        $request  = new WP_REST_Request( 'GET', '/wp/v2/users/' . $author );
        $response = rest_do_request( $request );

        $this->assertEquals( 200, $response->get_status() );
    }

    /* --------------------------------------------------------------------- */
    /* Guard 4: public users XML sitemap                                     */
    /* --------------------------------------------------------------------- */

    public function test_users_sitemap_provider_removed_when_enabled() {
        $this->enable();

        // The guard only inspects the provider name, so a sentinel object
        // stands in for the real WP_Sitemaps_Users provider.
        $provider = new stdClass();
        $result   = wldelay_remove_users_sitemap_provider( $provider, 'users' );

        // A non-WP_Sitemaps_Provider return makes core skip registration.
        $this->assertFalse( $result );
    }

    public function test_users_sitemap_provider_kept_when_disabled() {
        $this->disable();

        $provider = new stdClass();
        $result   = wldelay_remove_users_sitemap_provider( $provider, 'users' );

        // Core default preserved: the provider passes through untouched.
        $this->assertSame( $provider, $result );
    }

    public function test_non_users_sitemap_provider_kept_when_enabled() {
        $this->enable();

        // Posts/pages/taxonomies sitemaps are not enumeration vectors and must
        // survive when hardening is on.
        $provider = new stdClass();
        $result   = wldelay_remove_users_sitemap_provider( $provider, 'posts' );

        $this->assertSame( $provider, $result );
    }

    /* --------------------------------------------------------------------- */
    /* Whitelist interaction                                                 */
    /* --------------------------------------------------------------------- */

    public function test_author_block_ignores_whitelist() {
        // Enumeration hardening is a global UX/recon defense, not a per-IP
        // control, so a whitelisted IP is still subject to the author block.
        update_option( 'wldelay_options', array(
            'wldelay_enumeration_hardening_enabled' => true,
            'wldelay_whitelist_enabled'             => true,
            'wldelay_whitelist_ips'                 => '203.0.113.55',
        ) );
        wldelay_clear_options_cache();
        wp_set_current_user( 0 );
        $this->go_to( home_url( '/?author=1' ) );

        $this->assertTrue( wldelay_should_block_author_enumeration() );
    }
}
