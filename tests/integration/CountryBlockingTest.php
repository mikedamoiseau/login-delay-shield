<?php
/**
 * Integration tests for Country Blocking foundation.
 */

class CountryBlockingTest extends WP_UnitTestCase {

    public function setUp(): void {
        parent::setUp();
        $_SERVER['REMOTE_ADDR'] = '203.0.113.44';
        delete_option( WLDELAY_OPTION_NAME );
        wldelay_clear_options_cache();
        remove_all_filters( 'wldelay_resolve_country_code' );
    }

    public function tearDown(): void {
        remove_all_filters( 'wldelay_resolve_country_code' );
        unset( $_SERVER['REMOTE_ADDR'], $_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW'], $_SERVER['REQUEST_URI'] );
        unset( $GLOBALS['wldelay_login_gate_rejection'] );
        delete_option( WLDELAY_OPTION_NAME );
        wldelay_clear_options_cache();
        parent::tearDown();
    }

    public function test_authenticate_filter_is_registered_before_core_auth() {
        $this->assertSame( 5, has_filter( 'authenticate', 'wldelay_country_block_authentication' ) );
    }

    public function test_wp_authenticate_user_filter_is_registered_between_delay_and_challenge() {
        // Must run after wldelay_auth_login (@1) and before challenge mode (@10),
        // so the harder block wins over presenting a challenge.
        $this->assertSame( 2, has_filter( 'wp_authenticate_user', 'wldelay_country_block_authenticate_user' ) );
    }

    /**
     * The `authenticate` @5 guard alone is not enough: core's
     * wp_authenticate_username_password (@20) re-authenticates and overwrites an
     * earlier WP_Error whenever username and password are both non-empty, so a
     * login with VALID credentials from a blocked country slipped through. Drive
     * the real auth chain rather than calling the handler directly.
     */
    public function test_valid_credentials_from_denied_country_are_rejected_through_full_auth_chain() {
        $password = 'correct-horse-battery-staple';
        $user_id  = self::factory()->user->create(
            array(
                'user_login' => 'country_blocked_user',
                'user_pass'  => $password,
            )
        );
        $this->assertIsInt( $user_id );

        update_option(
            WLDELAY_OPTION_NAME,
            array(
                'wldelay_country_blocking_enabled'   => true,
                'wldelay_country_blocking_countries' => 'RU',
            )
        );
        wldelay_clear_options_cache();
        add_filter( 'wldelay_resolve_country_code', array( $this, 'resolve_ru' ) );

        $result = wp_authenticate( 'country_blocked_user', $password );

        $this->assertWPError( $result, 'Valid credentials from a blocked country must not authenticate.' );
        $this->assertSame( 'wldelay_country_blocked', $result->get_error_code() );
    }

    public function test_late_authenticate_filter_runs_after_every_conventional_authenticator() {
        // Core authenticates at 20 and spam-checks at 99, the plugin's own
        // application-password handler sits at 25, and third-party callbacks
        // conventionally register far below 9999.
        $this->assertSame( 9999, has_filter( 'authenticate', 'wldelay_country_block_late_authentication' ) );
    }

    /**
     * @dataProvider clobber_priority_provider
     */
    public function test_late_backstop_survives_a_clobber_at_any_conventional_priority( $priority ) {
        $user = self::factory()->user->create_and_get( array( 'user_login' => 'country_prio_user_' . $priority ) );

        update_option(
            WLDELAY_OPTION_NAME,
            array(
                'wldelay_country_blocking_enabled'   => true,
                'wldelay_country_blocking_countries' => 'RU',
            )
        );
        wldelay_clear_options_cache();
        add_filter( 'wldelay_resolve_country_code', array( $this, 'resolve_ru' ) );

        $clobber = function () use ( $user ) {
            return $user;
        };
        add_filter( 'authenticate', $clobber, $priority, 3 );

        $result = wp_authenticate( $user->user_login, 'irrelevant-password' );

        remove_filter( 'authenticate', $clobber, $priority );

        $this->assertWPError( $result );
        $this->assertSame( 'wldelay_country_blocked', $result->get_error_code() );
    }

    public function clobber_priority_provider() {
        // 21 stands in for core's own authenticators, 100 for a callback after
        // core's spam check, 500 for an SSO plugin choosing a deliberately late
        // priority.
        return array( array( 21 ), array( 100 ), array( 500 ) );
    }

    public function test_late_backstop_leaves_allowed_country_login_alone() {
        $user = self::factory()->user->create_and_get( array( 'user_login' => 'country_late_ok_user' ) );

        update_option(
            WLDELAY_OPTION_NAME,
            array(
                'wldelay_country_blocking_enabled'   => true,
                'wldelay_country_blocking_countries' => 'RU',
            )
        );
        wldelay_clear_options_cache();
        add_filter(
            'wldelay_resolve_country_code',
            function () {
                return 'DE';
            }
        );

        $result = wldelay_country_block_late_authentication( $user, 'country_late_ok_user', 'pw' );

        $this->assertSame( $user, $result );
    }

    public function test_valid_credentials_from_allowed_country_still_authenticate() {
        $password = 'correct-horse-battery-staple';
        self::factory()->user->create(
            array(
                'user_login' => 'country_allowed_user',
                'user_pass'  => $password,
            )
        );

        update_option(
            WLDELAY_OPTION_NAME,
            array(
                'wldelay_country_blocking_enabled'   => true,
                'wldelay_country_blocking_countries' => 'RU',
            )
        );
        wldelay_clear_options_cache();
        add_filter(
            'wldelay_resolve_country_code',
            function () {
                return 'DE';
            }
        );

        $result = wp_authenticate( 'country_allowed_user', $password );

        $this->assertInstanceOf( 'WP_User', $result );
    }

    public function test_valid_email_login_from_denied_country_is_rejected() {
        $password = 'correct-horse-battery-staple';
        self::factory()->user->create(
            array(
                'user_login' => 'country_email_user',
                'user_email' => 'country_email_user@example.org',
                'user_pass'  => $password,
            )
        );

        update_option(
            WLDELAY_OPTION_NAME,
            array(
                'wldelay_country_blocking_enabled'   => true,
                'wldelay_country_blocking_countries' => 'RU',
            )
        );
        wldelay_clear_options_cache();
        add_filter( 'wldelay_resolve_country_code', array( $this, 'resolve_ru' ) );

        // Core resolves an email login in wp_authenticate_email_password(), a
        // different callback from the username path — but it also applies
        // wp_authenticate_user, so the @2 guard must still bite.
        $result = wp_authenticate( 'country_email_user@example.org', $password );

        $this->assertWPError( $result );
        $this->assertSame( 'wldelay_country_blocked', $result->get_error_code() );
    }

    public function test_valid_email_login_from_allowed_country_still_authenticates() {
        $password = 'correct-horse-battery-staple';
        self::factory()->user->create(
            array(
                'user_login' => 'country_email_ok_user',
                'user_email' => 'country_email_ok_user@example.org',
                'user_pass'  => $password,
            )
        );

        update_option(
            WLDELAY_OPTION_NAME,
            array(
                'wldelay_country_blocking_enabled'   => true,
                'wldelay_country_blocking_countries' => 'RU',
            )
        );
        wldelay_clear_options_cache();
        add_filter(
            'wldelay_resolve_country_code',
            function () {
                return 'DE';
            }
        );

        $result = wp_authenticate( 'country_email_ok_user@example.org', $password );

        $this->assertInstanceOf( 'WP_User', $result );
    }

    /**
     * A country block is a plugin gate rejection: it must be logged but never
     * counted, or repeated blocked requests would push a legitimate user toward
     * lockout. The REST handler tracks failures by default, so it has to
     * recognise the plugin's own gate errors and leave the counter alone.
     */
    public function test_rest_country_block_is_not_counted_toward_lockout() {
        wldelay_create_log_table();
        update_option(
            WLDELAY_OPTION_NAME,
            array(
                'wldelay_country_blocking_enabled'     => true,
                'wldelay_country_blocking_countries'   => 'RU',
                'wldelay_rest_enabled'                 => true,
                // Application-password protection OFF is the case that reaches
                // the REST handler's tracking branch.
                'wldelay_application_password_enabled'  => false,
                'wldelay_lockout_enabled'              => true,
                'wldelay_delay'                        => 0,
            )
        );
        wldelay_clear_options_cache();
        add_filter( 'wldelay_resolve_country_code', array( $this, 'resolve_ru' ) );

        // The handler only acts on a request it recognises as REST.
        $_SERVER['REQUEST_URI']   = '/wp-json/wp/v2/users/me';
        $_SERVER['PHP_AUTH_USER'] = 'admin';
        $_SERVER['PHP_AUTH_PW']   = 'app-password';

        $blocked = wldelay_country_block_rest_authentication( null );
        $this->assertWPError( $blocked );

        $before = wldelay_get_failure_count( null, 'admin' );
        $after_handler = wldelay_handle_rest_authentication( $blocked );

        $this->assertWPError( $after_handler );
        $this->assertSame( 'wldelay_country_blocked', $after_handler->get_error_code() );
        $this->assertSame( $before, wldelay_get_failure_count( null, 'admin' ) );

        // Not counted, but still visible to the site owner.
        $logged = wldelay_get_recent_failed_attempts( 10 );
        $this->assertNotEmpty( $logged, 'A REST country block must still be logged.' );
        $this->assertSame( 'rest', $logged[0]->source );
    }

    public function test_application_password_handler_does_not_count_a_country_block() {
        wldelay_create_log_table();
        update_option(
            WLDELAY_OPTION_NAME,
            array(
                'wldelay_country_blocking_enabled'     => true,
                'wldelay_country_blocking_countries'   => 'RU',
                'wldelay_application_password_enabled' => true,
                'wldelay_lockout_enabled'              => true,
                'wldelay_delay'                        => 0,
            )
        );
        wldelay_clear_options_cache();
        add_filter( 'wldelay_resolve_country_code', array( $this, 'resolve_ru' ) );

        $_SERVER['PHP_AUTH_USER'] = 'admin';
        $_SERVER['PHP_AUTH_PW']   = 'app-password';

        $blocked = new WP_Error( 'wldelay_country_blocked', 'Login is not available from your location.' );
        $before  = wldelay_get_failure_count( null, 'admin' );

        $result = wldelay_handle_application_password_auth( $blocked, 'admin', 'app-password' );

        $this->assertSame( $blocked, $result );
        $this->assertSame( $before, wldelay_get_failure_count( null, 'admin' ) );

        $logged = wldelay_get_recent_failed_attempts( 10 );
        $this->assertNotEmpty( $logged, 'An application-password country block must still be logged.' );
        $this->assertSame( 'application-password', $logged[0]->source );
    }

    public function test_gate_rejection_detection_requires_every_code_to_be_a_gate_code() {
        $pure = new WP_Error( 'wldelay_country_blocked', 'blocked' );
        $this->assertTrue( wldelay_is_gate_rejection_error( $pure ) );

        // A real credential failure riding along must keep the attempt countable,
        // otherwise an attempt could dodge the lockout threshold.
        $mixed = new WP_Error( 'wldelay_country_blocked', 'blocked' );
        $mixed->add( 'incorrect_password', 'wrong password' );
        $this->assertFalse( wldelay_is_gate_rejection_error( $mixed ) );

        $this->assertFalse( wldelay_is_gate_rejection_error( new WP_Error( 'incorrect_password', 'wrong' ) ) );
        $this->assertFalse( wldelay_is_gate_rejection_error( new WP_Error() ) );
        $this->assertFalse( wldelay_is_gate_rejection_error( null ) );

        // A wrong challenge ANSWER is a real failure, not a gate rejection.
        $this->assertFalse( wldelay_is_gate_rejection_error( new WP_Error( 'wldelay_challenge_failed', 'nope' ) ) );
    }

    public function test_authenticate_user_guard_marks_gate_rejection_so_the_block_is_not_counted() {
        update_option(
            WLDELAY_OPTION_NAME,
            array(
                'wldelay_country_blocking_enabled'   => true,
                'wldelay_country_blocking_countries' => 'RU',
                'wldelay_lockout_enabled'            => true,
            )
        );
        wldelay_clear_options_cache();
        add_filter( 'wldelay_resolve_country_code', array( $this, 'resolve_ru' ) );

        $user   = self::factory()->user->create_and_get( array( 'user_login' => 'country_marker_user' ) );
        $result = wldelay_country_block_authenticate_user( $user, 'whatever' );

        $this->assertWPError( $result );
        $this->assertSame( 'wldelay_country_blocked', $result->get_error_code() );
        $this->assertNotEmpty( $GLOBALS['wldelay_login_gate_rejection'] );
        unset( $GLOBALS['wldelay_login_gate_rejection'] );
    }

    public function test_authenticate_user_guard_passes_through_existing_error() {
        update_option(
            WLDELAY_OPTION_NAME,
            array(
                'wldelay_country_blocking_enabled'   => true,
                'wldelay_country_blocking_countries' => 'RU',
            )
        );
        wldelay_clear_options_cache();
        add_filter( 'wldelay_resolve_country_code', array( $this, 'resolve_ru' ) );

        $prior  = new WP_Error( 'incorrect_password', 'wrong' );
        $result = wldelay_country_block_authenticate_user( $prior, 'whatever' );

        $this->assertSame( $prior, $result );
    }

    public function test_country_blocking_is_off_by_default() {
        add_filter( 'wldelay_resolve_country_code', array( $this, 'resolve_ru' ) );

        $result = wldelay_country_block_authentication( null, 'admin', 'password' );

        $this->assertNull( $result );
    }

    public function test_enabled_country_blocking_blocks_denied_resolved_country() {
        update_option(
            WLDELAY_OPTION_NAME,
            array(
                'wldelay_country_blocking_enabled'   => true,
                'wldelay_country_blocking_countries' => "RU\nCN",
            )
        );
        wldelay_clear_options_cache();
        add_filter( 'wldelay_resolve_country_code', array( $this, 'resolve_ru' ) );

        $result = wldelay_country_block_authentication( null, 'admin', 'password' );

        $this->assertWPError( $result );
        $this->assertSame( 'wldelay_country_blocked', $result->get_error_code() );
    }

    public function test_enabled_country_blocking_allows_empty_resolver_result() {
        update_option(
            WLDELAY_OPTION_NAME,
            array(
                'wldelay_country_blocking_enabled'   => true,
                'wldelay_country_blocking_countries' => 'RU',
            )
        );
        wldelay_clear_options_cache();

        $result = wldelay_country_block_authentication( null, 'admin', 'password' );

        $this->assertNull( $result );
    }

    public function test_whitelisted_ip_bypasses_country_blocking() {
        update_option(
            WLDELAY_OPTION_NAME,
            array(
                'wldelay_country_blocking_enabled'   => true,
                'wldelay_country_blocking_countries' => 'RU',
                'wldelay_whitelist_enabled'          => true,
                'wldelay_whitelist_ips'              => '203.0.113.44',
            )
        );
        wldelay_clear_options_cache();
        wldelay_clear_whitelist_cache();
        add_filter( 'wldelay_resolve_country_code', array( $this, 'resolve_ru' ) );

        $result = wldelay_country_block_authentication( null, 'admin', 'password' );

        $this->assertNull( $result );
    }

    public function test_resolver_receives_client_ip_and_source() {
        update_option(
            WLDELAY_OPTION_NAME,
            array(
                'wldelay_country_blocking_enabled'   => true,
                'wldelay_country_blocking_countries' => 'DE',
            )
        );
        wldelay_clear_options_cache();

        $seen = array();
        add_filter(
            'wldelay_resolve_country_code',
            function ( $country, $ip, $source ) use ( &$seen ) {
                $seen = array( $country, $ip, $source );
                return 'DE';
            },
            10,
            3
        );

        wldelay_country_block_authentication( null, 'admin', 'password' );

        $this->assertSame( array( '', '203.0.113.44', 'wp-login' ), $seen );
    }

    public function test_rest_authentication_filter_is_registered() {
        $this->assertSame( 5, has_filter( 'rest_authentication_errors', 'wldelay_country_block_rest_authentication' ) );
    }

    public function test_rest_blocks_credentialed_attempt_from_denied_country() {
        update_option(
            WLDELAY_OPTION_NAME,
            array(
                'wldelay_country_blocking_enabled'   => true,
                'wldelay_country_blocking_countries' => 'RU',
            )
        );
        wldelay_clear_options_cache();
        add_filter( 'wldelay_resolve_country_code', array( $this, 'resolve_ru' ) );

        // Simulate a REST Application Password / Basic Auth attempt. This path
        // never runs the `authenticate` filter, so the REST guard must catch it.
        $_SERVER['PHP_AUTH_USER'] = 'admin';
        $_SERVER['PHP_AUTH_PW']   = 'app-password';

        $result = wldelay_country_block_rest_authentication( null );

        $this->assertWPError( $result );
        $this->assertSame( 'wldelay_country_blocked', $result->get_error_code() );
    }

    public function test_rest_ignores_anonymous_request() {
        update_option(
            WLDELAY_OPTION_NAME,
            array(
                'wldelay_country_blocking_enabled'   => true,
                'wldelay_country_blocking_countries' => 'RU',
            )
        );
        wldelay_clear_options_cache();
        add_filter( 'wldelay_resolve_country_code', array( $this, 'resolve_ru' ) );

        // No PHP_AUTH_* credentials -> not a login attempt -> pass through.
        $result = wldelay_country_block_rest_authentication( null );

        $this->assertNull( $result );
    }

    public function test_rest_respects_prior_error() {
        $prior = new WP_Error( 'existing', 'existing error' );

        $result = wldelay_country_block_rest_authentication( $prior );

        $this->assertSame( $prior, $result );
    }

    public function resolve_ru( $country = '', $ip = '', $source = '' ) {
        return 'ru';
    }
}
