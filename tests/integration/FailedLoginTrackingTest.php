<?php
/**
 * Integration: a real failed wp-login must count + drive the threshold features.
 *
 * Regression guard for the pre-existing bug where wp-login failures never
 * incremented the failure counter: wldelay_auth_login runs on
 * wp_authenticate_user (before core verifies the password) so it only sees a
 * WP_User and its failure branch never fires, and the wp_login_failed handler
 * was log-only. Result: delay/lockout/email/progressive/challenge never
 * triggered via the login form. The fix makes the wp_login_failed handler own
 * tracking + delay for the wp-login source.
 */
class FailedLoginTrackingTest extends WP_UnitTestCase {

    public function setUp(): void {
        parent::setUp();
        $_SERVER['REMOTE_ADDR'] = '203.0.113.88';
        $_POST['log']           = 'trackme';
        $_POST['pwd']           = 'nope';   // login-form fields mark this as an
        $_POST['wp-submit']     = 'Log In'; // interactive wp-login submission
        unset( $GLOBALS['wldelay_login_gate_rejection'] );
        delete_option( 'wldelay_options' );
        wldelay_clear_options_cache();
        update_option( 'wldelay_options', array(
            'wldelay_lockout_enabled'   => 1,
            'wldelay_lockout_threshold' => 5,
            'wldelay_delay'             => 1,
            'wldelay_delay_random'      => 0,
            'wldelay_progressive_enabled' => 0,
        ) );
        wldelay_clear_options_cache();
    }

    public function tearDown(): void {
        unset( $_POST['log'], $_POST['pwd'], $_POST['wp-submit'], $_SERVER['REMOTE_ADDR'] );
        unset( $_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW'], $GLOBALS['wldelay_login_gate_rejection'] );
        delete_option( 'wldelay_options' );
        wldelay_clear_options_cache();
        parent::tearDown();
    }

    public function test_wp_login_failed_hook_is_registered() {
        $this->assertNotFalse( has_action( 'wp_login_failed', 'wldelay_on_login_failed' ) );
    }

    public function test_failed_wp_login_increments_counter_once() {
        $before = wldelay_get_failure_count( '203.0.113.88', 'trackme' );
        do_action( 'wp_login_failed', 'trackme' );
        $after = wldelay_get_failure_count( '203.0.113.88', 'trackme' );
        $this->assertSame( $before + 1, $after, 'a failed wp-login must increment the counter exactly once' );
    }

    public function test_repeated_failures_reach_lockout() {
        $opts = get_option( 'wldelay_options' );
        $opts['wldelay_lockout_threshold'] = 3;
        update_option( 'wldelay_options', $opts );
        wldelay_clear_options_cache();

        for ( $i = 0; $i < 3; $i++ ) {
            do_action( 'wp_login_failed', 'trackme' );
        }
        $this->assertTrue(
            wldelay_is_ip_locked( '203.0.113.88', 'trackme' ),
            'reaching the threshold via real failed logins must lock the IP'
        );
    }

    /**
     * Finding 4: the plugin's own gate rejections must NOT be counted, or a
     * merely-shown challenge / active lockout / country block would push toward
     * (or refresh) lockout. A wrong challenge ANSWER still counts.
     */
    public function test_gate_rejections_are_not_counted() {
        foreach ( array( 'wldelay_challenge_required', 'wldelay_challenge_unavailable', 'wldelay_ip_locked', 'wldelay_country_blocked' ) as $code ) {
            $before = wldelay_get_failure_count( '203.0.113.88', 'trackme' );
            do_action( 'wp_login_failed', 'trackme', new WP_Error( $code, 'x' ) );
            $after = wldelay_get_failure_count( '203.0.113.88', 'trackme' );
            $this->assertSame( $before, $after, "gate rejection {$code} must not increment the counter" );
        }
    }

    public function test_wrong_challenge_answer_is_counted() {
        $before = wldelay_get_failure_count( '203.0.113.88', 'trackme' );
        do_action( 'wp_login_failed', 'trackme', new WP_Error( 'wldelay_challenge_failed', 'x' ) );
        $after = wldelay_get_failure_count( '203.0.113.88', 'trackme' );
        $this->assertSame( $before + 1, $after, 'a wrong challenge answer is a real failed attempt' );
    }

    /**
     * Finding 2: a non-form auth failure (no login-form fields — e.g. a REST /
     * application-password attempt) must NOT be counted by the wp-login handler;
     * its own handler owns it.
     */
    public function test_non_form_request_not_counted_by_wp_login_handler() {
        unset( $_POST['wp-submit'], $_POST['pwd'] ); // not a login-form submission
        $_SERVER['PHP_AUTH_USER'] = 'trackme';
        $_SERVER['PHP_AUTH_PW']   = 'app-pw';
        $before = wldelay_get_failure_count( '203.0.113.88', 'trackme' );
        do_action( 'wp_login_failed', 'trackme', new WP_Error( 'incorrect_password', 'x' ) );
        $after = wldelay_get_failure_count( '203.0.113.88', 'trackme' );
        $this->assertSame( $before, $after, 'a non-form (app-password/REST) failure must not be counted here' );
    }

    /**
     * Finding B (false negative): a genuine login-FORM submission that arrives
     * with ambient HTTP Basic-auth headers (site behind Basic auth) must still
     * be counted — detection is by the form fields, not header presence.
     */
    public function test_form_login_behind_basic_auth_is_counted() {
        $_SERVER['PHP_AUTH_USER'] = 'someproxyuser';
        $_SERVER['PHP_AUTH_PW']   = 'proxypw';
        // $_POST['wp-submit']/'pwd' set in setUp -> genuine form submission.
        $before = wldelay_get_failure_count( '203.0.113.88', 'trackme' );
        do_action( 'wp_login_failed', 'trackme', new WP_Error( 'incorrect_password', 'x' ) );
        $after = wldelay_get_failure_count( '203.0.113.88', 'trackme' );
        $this->assertSame( $before + 1, $after, 'a form login behind Basic auth must still be counted' );
    }

    /**
     * Finding A (one-arg blind spot): the plugin's request marker suppresses
     * counting even when wp_login_failed is fired WITHOUT the WP 5.4+ $error
     * argument (this plugin supports WP back to 3.5.1).
     */
    public function test_marker_suppresses_count_without_error_arg() {
        wldelay_mark_login_gate_rejection();
        $before = wldelay_get_failure_count( '203.0.113.88', 'trackme' );
        do_action( 'wp_login_failed', 'trackme' ); // one arg, no $error
        $after = wldelay_get_failure_count( '203.0.113.88', 'trackme' );
        $this->assertSame( $before, $after, 'a marked gate rejection must not count even without the $error arg' );
    }

    /**
     * Finding 1: a genuine wp-login whose URL merely contains "xmlrpc.php" in a
     * query parameter must still be counted (source is decided by request
     * constants, not a URI substring).
     */
    public function test_wp_login_with_xmlrpc_in_query_is_still_counted() {
        $_SERVER['REQUEST_URI'] = '/wp-login.php?redirect_to=%2Fxmlrpc.php';
        $before = wldelay_get_failure_count( '203.0.113.88', 'trackme' );
        do_action( 'wp_login_failed', 'trackme', new WP_Error( 'incorrect_password', 'x' ) );
        $after = wldelay_get_failure_count( '203.0.113.88', 'trackme' );
        unset( $_SERVER['REQUEST_URI'] );
        $this->assertSame( $before + 1, $after, 'a real wp-login must not be misclassified as XML-RPC by a query param' );
    }
}
