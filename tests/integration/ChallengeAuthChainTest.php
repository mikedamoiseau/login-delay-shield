<?php
/**
 * Integration: challenge mode and failure tracking through the REAL auth chain.
 *
 * The handler-level tests in ChallengeModeTest / FailedLoginTrackingTest call the
 * callbacks directly. These drive wp_authenticate() so core's own sequencing —
 * email-as-login firing wp_authenticate_user twice, the application-password
 * authenticator returning a user without firing it at all, wp_login_failed
 * receiving the submitted username — is part of what is tested.
 */
class ChallengeAuthChainTest extends WP_UnitTestCase {

    const IP = '203.0.113.66';

    private $sent_mail = array();

    private $http_host;

    public function setUp(): void {
        parent::setUp();
        $_SERVER['REMOTE_ADDR'] = self::IP;
        $_POST                  = array();
        unset( $_SERVER['REQUEST_URI'], $_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW'], $_SERVER['HTTPS'] );
        unset( $GLOBALS['wldelay_login_gate_rejection'] );
        // Core records a successful application-password login in this global
        // for the rest of the request; one test's login must not leak into the next.
        $GLOBALS['wp_rest_application_password_uuid'] = null;
        wldelay_create_log_table();
        delete_option( WLDELAY_OPTION_NAME );
        wldelay_clear_options_cache();

        $this->http_host = isset( $_SERVER['HTTP_HOST'] ) ? $_SERVER['HTTP_HOST'] : null;
        $this->sent_mail = array();
        add_filter( 'wp_mail', array( $this, 'capture_mail' ) );
    }

    public function tearDown(): void {
        $_POST = array();
        unset( $_SERVER['REMOTE_ADDR'], $_SERVER['REQUEST_URI'], $_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW'], $_SERVER['HTTPS'] );
        unset( $GLOBALS['wldelay_login_gate_rejection'] );
        if ( null !== $this->http_host ) {
            $_SERVER['HTTP_HOST'] = $this->http_host;
        }
        delete_option( WLDELAY_OPTION_NAME );
        wldelay_clear_options_cache();
        parent::tearDown();
    }

    public function capture_mail( $args ) {
        $this->sent_mail[] = $args;
        return $args;
    }

    private function options( array $options ) {
        // Pin everything that could otherwise reject or email on its own, so each
        // test observes only the behaviour it names.
        $base = array(
            'wldelay_delay'               => 0,
            'wldelay_delay_random'        => 0,
            'wldelay_progressive_enabled' => 0,
            'wldelay_lockout_enabled'     => 0,
            'wldelay_email_enabled'       => 0,
        );
        update_option( WLDELAY_OPTION_NAME, array_merge( $base, $options ) );
        wldelay_clear_options_cache();
    }

    private function challenge_options( array $extra = array() ) {
        $this->options(
            array_merge(
                array(
                    'wldelay_challenge_mode_enabled'   => 1,
                    'wldelay_challenge_mode_threshold' => 1,
                    'wldelay_challenge_mode_provider'  => 'math',
                ),
                $extra
            )
        );
    }

    /**
     * Simulate a wp-login.php form POST for the given identity.
     */
    private function post_login_form( $log, $pwd, $response = null ) {
        $_POST = array(
            'log'       => $log,
            'pwd'       => $pwd,
            'wp-submit' => 'Log In',
        );
        if ( null !== $response ) {
            $_POST['wldelay_challenge_response'] = $response;
        }
        unset( $GLOBALS['wldelay_login_gate_rejection'] );
        return wp_authenticate( $log, $pwd );
    }

    private function math_answer() {
        $state = wldelay_get_challenge_state( self::IP );
        $this->assertSame( 'math', $state['provider'] );
        return (string) ( (int) $state['a'] + (int) $state['b'] );
    }

    private function last_emailed_code() {
        $this->assertNotEmpty( $this->sent_mail, 'a code was emailed' );
        $last = end( $this->sent_mail );
        $this->assertSame( 1, preg_match( '/\b(\d{6})\b/', $last['message'], $m ) );
        return $m[1];
    }

    /**
     * When user_login is itself an email address, core resolves the account on
     * the username path AND on the email path, firing wp_authenticate_user
     * twice. The first pass consumed the solved challenge; the second re-issued
     * one and returned challenge_required, which is a gate rejection — so a
     * wrong password behind a solved challenge was never counted or delayed.
     */
    public function test_email_as_login_wrong_password_behind_solved_challenge_is_counted() {
        self::factory()->user->create(
            array(
                'user_login' => 'owner@example.org',
                'user_email' => 'owner@example.org',
                'user_pass'  => 'right-password',
            )
        );
        $this->challenge_options();
        wldelay_track_failed_attempt( '', 'wp-login' );

        $first = $this->post_login_form( 'owner@example.org', 'wrong-password' );
        $this->assertSame( 'wldelay_challenge_required', $first->get_error_code() );

        $before = wldelay_get_failure_count( self::IP, '' );
        $result = $this->post_login_form( 'owner@example.org', 'wrong-password', $this->math_answer() );

        $this->assertWPError( $result );
        $this->assertSame( 'incorrect_password', $result->get_error_code() );
        $this->assertSame( $before + 1, wldelay_get_failure_count( self::IP, '' ), 'the wrong password must be counted' );

        // And the right password behind a solved challenge signs in.
        $this->post_login_form( 'owner@example.org', 'right-password' );
        $ok = $this->post_login_form( 'owner@example.org', 'right-password', $this->math_answer() );
        $this->assertInstanceOf( 'WP_User', $ok );
    }

    /**
     * Under the ip_username strategy the counter and every check must agree on
     * the key. wp_login_failed passes the username as typed ("Carol"); the
     * checks use the normalized form ("carol").
     */
    public function test_ip_username_counts_under_the_normalized_username() {
        self::factory()->user->create( array( 'user_login' => 'carol', 'user_pass' => 'right-password' ) );
        $this->options(
            array(
                'wldelay_lockout_enabled'          => 1,
                'wldelay_lockout_threshold'        => 3,
                'wldelay_lockout_attempt_strategy' => 'ip_username',
            )
        );

        for ( $i = 0; $i < 3; $i++ ) {
            $this->post_login_form( 'Carol', 'wrong-' . $i );
        }

        $this->assertSame( 3, wldelay_get_failure_count( self::IP, 'carol' ) );
        $this->assertTrue( wldelay_is_ip_locked( self::IP, 'carol' ) );
    }

    /**
     * With XML-RPC protection on (delay mode), XML-RPC credential failures must
     * count toward the threshold like the login form's do. They were only
     * logged, so an XML-RPC-only brute force never reached lockout.
     */
    public function test_xmlrpc_failures_are_counted_when_protection_is_on() {
        self::factory()->user->create( array( 'user_login' => 'xr', 'user_pass' => 'right-password' ) );
        $this->options(
            array(
                'wldelay_xmlrpc_enabled'    => 1,
                'wldelay_lockout_enabled'   => 1,
                'wldelay_lockout_threshold' => 3,
            )
        );
        $_SERVER['REQUEST_URI'] = '/xmlrpc.php';

        for ( $i = 0; $i < 3; $i++ ) {
            unset( $GLOBALS['wldelay_login_gate_rejection'] );
            wp_authenticate( 'xr', 'wrong-' . $i );
        }

        $this->assertSame( 3, wldelay_get_failure_count( self::IP, 'xr' ) );

        unset( $GLOBALS['wldelay_login_gate_rejection'] );
        $locked = wp_authenticate( 'xr', 'right-password' );
        $this->assertWPError( $locked, 'the correct password is refused once the IP is locked' );
        $this->assertSame( 'wldelay_ip_locked', $locked->get_error_code() );
    }

    public function test_xmlrpc_failures_are_not_counted_when_protection_is_off_or_blocking() {
        self::factory()->user->create( array( 'user_login' => 'xr', 'user_pass' => 'right-password' ) );
        $_SERVER['REQUEST_URI'] = '/xmlrpc.php';

        $this->options( array( 'wldelay_xmlrpc_enabled' => 0 ) );
        wp_authenticate( 'xr', 'wrong' );
        $this->assertSame( 0, wldelay_get_failure_count( self::IP, 'xr' ) );

        // Block mode rejects every XML-RPC login outright; nothing to count.
        $this->options( array( 'wldelay_xmlrpc_enabled' => 1, 'wldelay_xmlrpc_block' => 1 ) );
        unset( $GLOBALS['wldelay_login_gate_rejection'] );
        wp_authenticate( 'xr', 'wrong' );
        $this->assertSame( 0, wldelay_get_failure_count( self::IP, 'xr' ) );
    }

    /**
     * A URL that merely mentions xmlrpc.php is still a login-form request.
     */
    public function test_xmlrpc_detection_matches_the_script_path_not_a_substring() {
        $_SERVER['REQUEST_URI'] = '/wp-login.php?redirect_to=%2Fxmlrpc.php';
        $this->assertFalse( wldelay_is_xmlrpc_request() );

        $_SERVER['REQUEST_URI'] = '/wp/xmlrpc.php?rsd';
        $this->assertTrue( wldelay_is_xmlrpc_request() );
    }

    /**
     * The hard-block for non-interactive sources lives on wp_authenticate_user,
     * which core's application-password authenticator (@20) never fires. A
     * valid XML-RPC application password from an over-threshold IP got in.
     */
    public function test_xmlrpc_application_password_is_hard_blocked_when_a_challenge_is_required() {
        add_filter( 'application_password_is_api_request', '__return_true' );
        add_filter( 'wp_is_application_passwords_available', '__return_true' );
        $_SERVER['REQUEST_URI'] = '/xmlrpc.php';
        $user_id                = self::factory()->user->create( array( 'user_login' => 'apiuser' ) );
        list( $app_password )  = WP_Application_Passwords::create_new_application_password( $user_id, array( 'name' => 'test' ) );

        $this->challenge_options();
        $this->assertInstanceOf( 'WP_User', wp_authenticate( 'apiuser', $app_password ), 'control: no challenge required yet' );

        wldelay_track_failed_attempt( 'apiuser', 'xmlrpc' );
        unset( $GLOBALS['wldelay_login_gate_rejection'] );
        $result = wp_authenticate( 'apiuser', $app_password );

        $this->assertWPError( $result );
        $this->assertSame( 'wldelay_challenge_required', $result->get_error_code() );
    }

    /**
     * Under ip_username the XML-RPC hard-block keyed on $_POST['log'], which
     * XML-RPC never sends, so it read the IP-only counter and never fired.
     */
    public function test_xmlrpc_hard_block_uses_the_submitted_username_under_ip_username() {
        self::factory()->user->create( array( 'user_login' => 'xr2', 'user_pass' => 'right-password' ) );
        $this->challenge_options( array( 'wldelay_lockout_attempt_strategy' => 'ip_username' ) );
        $_SERVER['REQUEST_URI'] = '/xmlrpc.php';
        wldelay_track_failed_attempt( 'xr2', 'xmlrpc' );

        $result = wp_authenticate( 'xr2', 'right-password' );

        $this->assertWPError( $result );
        $this->assertSame( 'wldelay_challenge_required', $result->get_error_code() );
    }

    /**
     * Once the per-IP send limit is reached, a blank submission re-issued the
     * SAME emailed code with the wrong-answer count reset — so one code could
     * be guessed at five times, then five more, indefinitely.
     */
    public function test_blank_submission_does_not_reset_the_email_wrong_answer_cap() {
        self::factory()->user->create( array( 'user_login' => 'mailuser', 'user_email' => 'mailuser@example.org', 'user_pass' => 'right-password' ) );
        $this->challenge_options( array( 'wldelay_challenge_mode_provider' => 'email' ) );
        wldelay_track_failed_attempt( '', 'wp-login' );

        $this->post_login_form( 'mailuser', 'right-password' ); // issues + emails the code
        $code = $this->last_emailed_code();

        // Exhaust the per-IP send limit so a re-issue can only reuse this code.
        set_transient( 'wldelay_challenge_email_rl_' . substr( md5( self::IP ), 0, 20 ), 5, 600 );

        for ( $i = 0; $i < 4; $i++ ) {
            $this->post_login_form( 'mailuser', 'right-password', 'wrong-' . $i ); // non-numeric: never the code
        }
        $this->post_login_form( 'mailuser', 'right-password', '' ); // blank: re-issue
        $this->post_login_form( 'mailuser', 'right-password', 'wrong-5' ); // fifth wrong answer

        $result = $this->post_login_form( 'mailuser', 'right-password', $code );
        $this->assertWPError( $result, 'the code must be dead after five wrong answers in total' );
    }

    /**
     * The send limit was per source IP only, so many IPs could flood one
     * account owner's inbox. Cap sends per recipient too.
     */
    public function test_email_codes_are_capped_per_recipient_across_ips() {
        self::factory()->user->create( array( 'user_login' => 'victim', 'user_email' => 'victim@example.org', 'user_pass' => 'right-password' ) );
        $this->challenge_options( array( 'wldelay_challenge_mode_provider' => 'email' ) );

        for ( $i = 1; $i <= 8; $i++ ) {
            $_SERVER['REMOTE_ADDR'] = '198.51.100.' . $i;
            wldelay_track_failed_attempt( '', 'wp-login' );
            $this->post_login_form( 'victim', 'whatever' );
        }

        $this->assertCount( 5, $this->sent_mail );
    }

    /**
     * Proof of work needs crypto.subtle, which browsers expose only in a secure
     * context. On plain HTTP no browser can solve it, so fall back to math.
     */
    public function test_proof_of_work_falls_back_to_math_without_https() {
        $this->challenge_options( array( 'wldelay_challenge_mode_provider' => 'pow' ) );
        $_SERVER['HTTP_HOST'] = 'example.org';

        $this->assertSame( 'math', wldelay_get_active_challenge_provider()->id() );

        $_SERVER['HTTPS'] = 'on';
        $this->assertSame( 'pow', wldelay_get_active_challenge_provider()->id() );

        // http://localhost is a secure context for browsers.
        unset( $_SERVER['HTTPS'] );
        $_SERVER['HTTP_HOST'] = 'localhost';
        $this->assertSame( 'pow', wldelay_get_active_challenge_provider()->id() );
    }

    /**
     * A logged-in (cookie) user is not guessing credentials. On a site behind
     * ambient HTTP Basic auth every REST call carries PHP_AUTH_*, and the REST
     * guard returned 403 to the editor for as long as the IP was over the
     * challenge threshold.
     */
    public function test_rest_guard_ignores_a_cookie_authenticated_user() {
        $this->challenge_options();
        wldelay_track_failed_attempt( '', 'wp-login' );
        $_SERVER['REQUEST_URI']   = '/wp-json/wp/v2/posts';
        $_SERVER['PHP_AUTH_USER'] = 'htuser';
        $_SERVER['PHP_AUTH_PW']   = 'htpass';

        $this->assertWPError( wldelay_challenge_rest_authentication( null ), 'control: anonymous credentialed REST is blocked' );

        wp_set_current_user( self::factory()->user->create( array( 'role' => 'editor' ) ) );
        $this->assertNull( wldelay_challenge_rest_authentication( null ) );
    }

    public function test_provider_registry_drops_entries_that_are_not_providers() {
        add_filter(
            'wldelay_challenge_providers',
            function ( $providers ) {
                $providers['junk'] = 'not-a-provider';
                return $providers;
            }
        );

        $providers = wldelay_get_challenge_providers();
        $this->assertArrayNotHasKey( 'junk', $providers );
        $this->assertArrayHasKey( 'math', $providers );
    }
}
