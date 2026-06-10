<?php
/**
 * Integration tests for the Custom Login URL safety net:
 * loopback self-check with auto-disable, and the new-URL admin email.
 */

class CustomLoginSafetyTest extends WP_UnitTestCase {

    /**
     * Captured wp_mail calls.
     *
     * @var array
     */
    private $sent_emails = [];

    /**
     * HTTP responses the mocked loopback should return, and request log.
     */
    private $mock_http_response = null;
    private $http_requests = [];

    public function setUp(): void {
        parent::setUp();
        $this->sent_emails = [];
        $this->http_requests = [];
        $this->mock_http_response = $this->http_response( 200 );

        add_filter( 'wp_mail', [ $this, 'capture_email' ] );
        add_filter( 'pre_http_request', [ $this, 'mock_http' ], 10, 3 );
        add_filter( 'wldelay_test_enable_custom_login_self_check', '__return_true' );

        delete_option( 'wldelay_options' );
        wldelay_clear_options_cache();
        global $wp_settings_errors;
        $wp_settings_errors = [];
    }

    public function tearDown(): void {
        remove_filter( 'wp_mail', [ $this, 'capture_email' ] );
        remove_filter( 'pre_http_request', [ $this, 'mock_http' ] );
        remove_filter( 'wldelay_test_enable_custom_login_self_check', '__return_true' );
        delete_option( 'wldelay_options' );
        wldelay_clear_options_cache();
        global $wp_settings_errors;
        $wp_settings_errors = [];
        parent::tearDown();
    }

    public function capture_email( $args ) {
        $this->sent_emails[] = $args;
        return $args;
    }

    public function mock_http( $preempt, $args, $url ) {
        $this->http_requests[] = $url;
        return $this->mock_http_response;
    }

    private function http_response( $code ) {
        return [
            'headers'  => [],
            'body'     => '',
            'response' => [ 'code' => $code, 'message' => '' ],
            'cookies'  => [],
            'filename' => null,
        ];
    }

    private function settings_error_codes() {
        return wp_list_pluck( get_settings_errors( 'wldelay_options' ), 'code' );
    }

    /**
     * The settings-change handler is hooked.
     */
    public function test_settings_change_handler_is_hooked() {
        $this->assertNotFalse(
            has_action( 'update_option_wldelay_options', 'wldelay_custom_login_handle_settings_change' )
        );
    }

    /**
     * Self-check returns ok / unreachable / unverified per response.
     */
    public function test_self_check_classifies_responses() {
        $this->mock_http_response = $this->http_response( 200 );
        $this->assertSame( 'ok', wldelay_custom_login_self_check( 'secret-door' ) );

        $this->mock_http_response = $this->http_response( 404 );
        $this->assertSame( 'unreachable', wldelay_custom_login_self_check( 'secret-door' ) );

        $this->mock_http_response = new WP_Error( 'http_request_failed', 'blocked' );
        $this->assertSame( 'unverified', wldelay_custom_login_self_check( 'secret-door' ) );
    }

    /**
     * Enabling with a working URL keeps the feature on, reports success, and
     * emails the new URL to the admin.
     */
    public function test_enable_with_working_url_stays_enabled_and_emails_admin() {
        update_option( 'wldelay_options', [
            'wldelay_custom_login_enabled' => true,
            'wldelay_custom_login_slug'    => 'secret-door',
        ] );
        wldelay_clear_options_cache();

        $options = get_option( 'wldelay_options' );
        $this->assertNotEmpty( $options['wldelay_custom_login_enabled'], 'Feature should stay enabled' );
        $this->assertContains( 'wldelay_custom_login_active', $this->settings_error_codes() );

        $this->assertCount( 1, $this->sent_emails, 'New-URL email should be sent' );
        $this->assertSame( get_option( 'admin_email' ), $this->sent_emails[0]['to'] );
        $this->assertStringContainsString( 'secret-door', $this->sent_emails[0]['message'] );
        $this->assertStringContainsString( 'WLDELAY_DISABLE_CUSTOM_LOGIN', $this->sent_emails[0]['message'] );
    }

    /**
     * A definitive 404 self-check auto-disables the feature instead of
     * stranding everyone behind a dead login URL.
     */
    public function test_enable_with_404_url_auto_disables() {
        $this->mock_http_response = $this->http_response( 404 );

        update_option( 'wldelay_options', [
            'wldelay_custom_login_enabled' => true,
            'wldelay_custom_login_slug'    => 'secret-door',
        ] );
        wldelay_clear_options_cache();

        $options = get_option( 'wldelay_options' );
        $this->assertEmpty( $options['wldelay_custom_login_enabled'], 'Feature should be auto-disabled on 404' );
        $this->assertFalse( wldelay_custom_login_is_active() );
        $this->assertContains( 'wldelay_custom_login_unreachable', $this->settings_error_codes() );
        $this->assertCount( 0, $this->sent_emails, 'No new-URL email after auto-disable' );
    }

    /**
     * A blocked loopback (WP_Error) leaves the feature enabled but warns.
     */
    public function test_enable_with_blocked_loopback_stays_enabled_with_warning() {
        $this->mock_http_response = new WP_Error( 'http_request_failed', 'cURL error 7' );

        update_option( 'wldelay_options', [
            'wldelay_custom_login_enabled' => true,
            'wldelay_custom_login_slug'    => 'secret-door',
        ] );
        wldelay_clear_options_cache();

        $options = get_option( 'wldelay_options' );
        $this->assertNotEmpty( $options['wldelay_custom_login_enabled'], 'Inconclusive check must not auto-disable' );
        $this->assertContains( 'wldelay_custom_login_unverified', $this->settings_error_codes() );
        $this->assertCount( 1, $this->sent_emails, 'New-URL email still sent on inconclusive check' );
    }

    /**
     * Slug change while enabled re-runs the check; unrelated changes do not.
     */
    public function test_check_runs_on_slug_change_but_not_unrelated_change() {
        update_option( 'wldelay_options', [
            'wldelay_custom_login_enabled' => true,
            'wldelay_custom_login_slug'    => 'secret-door',
        ] );
        $this->assertCount( 1, $this->http_requests );

        // Unrelated change: no new loopback request.
        update_option( 'wldelay_options', [
            'wldelay_custom_login_enabled' => true,
            'wldelay_custom_login_slug'    => 'secret-door',
            'wldelay_delay'                => 3,
        ] );
        $this->assertCount( 1, $this->http_requests, 'Unrelated change must not re-run the check' );

        // Slug change: check re-runs.
        update_option( 'wldelay_options', [
            'wldelay_custom_login_enabled' => true,
            'wldelay_custom_login_slug'    => 'other-door',
        ] );
        $this->assertCount( 2, $this->http_requests, 'Slug change should re-run the check' );
        $this->assertStringContainsString( 'other-door', end( $this->http_requests ) );
    }

    /**
     * Disabling the feature never triggers a check or email.
     */
    public function test_disable_triggers_nothing() {
        update_option( 'wldelay_options', [
            'wldelay_custom_login_enabled' => true,
            'wldelay_custom_login_slug'    => 'secret-door',
        ] );
        $this->sent_emails = [];
        $this->http_requests = [];

        update_option( 'wldelay_options', [
            'wldelay_custom_login_enabled' => false,
            'wldelay_custom_login_slug'    => 'secret-door',
        ] );

        $this->assertCount( 0, $this->http_requests );
        $this->assertCount( 0, $this->sent_emails );
    }

    /**
     * The wldelay_send_custom_login_email filter suppresses the email.
     */
    public function test_email_filter_suppresses_email() {
        add_filter( 'wldelay_send_custom_login_email', '__return_false' );

        update_option( 'wldelay_options', [
            'wldelay_custom_login_enabled' => true,
            'wldelay_custom_login_slug'    => 'secret-door',
        ] );

        remove_filter( 'wldelay_send_custom_login_email', '__return_false' );

        $this->assertCount( 0, $this->sent_emails );
    }
}
