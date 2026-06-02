<?php
/**
 * Integration tests for the login-page lockout feedback block (F-1-4).
 *
 * Exercises the pure-frontend presentation layer over the existing lockout
 * data: the login_message block, the countdown seed, the filterable help link,
 * output escaping, and the wp_login_errors warning wrapping. No backend/auth
 * behaviour is asserted here beyond reusing the real lockout helpers via the
 * fixture.
 */

class LoginLockoutFeedbackTest extends WP_UnitTestCase {

    /**
     * Shared test IP all assertions key off.
     *
     * @var string
     */
    private $ip = '192.168.1.100';

    public function setUp(): void {
        parent::setUp();
        wldelay_create_lockout_table();
        WLDelay_Test_Fixture::reset();
        $_SERVER['REMOTE_ADDR'] = $this->ip;
    }

    public function tearDown(): void {
        WLDelay_Test_Fixture::reset();
        remove_all_filters( 'wldelay_login_help_url' );
        parent::tearDown();
    }

    /**
     * Lock the current IP via the real production path.
     */
    private function lock_current_ip( $duration = 900 ) {
        WLDelay_Test_Fixture::make()
            ->with_current_ip( $this->ip )
            ->with_option( 'wldelay_lockout_enabled', true )
            ->with_lockout( $this->ip, '', $duration )
            ->apply();
    }

    public function test_locked_block_contains_distinct_block_and_a11y_attrs() {
        $this->lock_current_ip();

        $out = wldelay_login_message_lockout( '' );

        $this->assertStringContainsString( 'wldelay-login-status', $out );
        $this->assertStringContainsString( 'role="alert"', $out );
        $this->assertStringContainsString( 'aria-live="assertive"', $out );
    }

    public function test_locked_block_shows_human_readable_remaining_time() {
        $this->lock_current_ip();

        $out = wldelay_login_message_lockout( '' );

        // human_time_diff phrasing for a ~15 minute lockout.
        $this->assertMatchesRegularExpression( '/\d+\s+(min|minute|hour|second)/i', $out );
    }

    public function test_locked_block_includes_countdown_seed() {
        $this->lock_current_ip( 120 );

        $out = wldelay_login_message_lockout( '' );

        $this->assertStringContainsString( 'data-wldelay-remaining="', $out );

        // The seed must be the real remaining seconds (> 0 for an active lock).
        $this->assertMatchesRegularExpression( '/data-wldelay-remaining="\d+"/', $out );
        $remaining = wldelay_get_lockout_remaining_seconds();
        $this->assertGreaterThan( 0, $remaining );
        $this->assertStringContainsString( 'data-wldelay-remaining="' . (int) $remaining . '"', $out );
    }

    public function test_locked_block_includes_help_link() {
        $this->lock_current_ip();

        $out = wldelay_login_message_lockout( '' );

        $this->assertStringContainsString( 'Need help getting in?', $out );
        $this->assertStringContainsString( '<a href="', $out );
    }

    public function test_not_locked_returns_input_unchanged() {
        WLDelay_Test_Fixture::make()
            ->with_current_ip( $this->ip )
            ->with_option( 'wldelay_lockout_enabled', true )
            ->apply();

        $input = '<p>original message</p>';
        $this->assertSame( $input, wldelay_login_message_lockout( $input ) );
        $this->assertSame( '', wldelay_render_login_lockout_block() );
    }

    public function test_feature_disabled_returns_input_unchanged() {
        // Lock the IP first, then disable the feature: block must not render.
        $this->lock_current_ip();

        $options = wldelay_get_options();
        $options['wldelay_lockout_enabled'] = false;
        update_option( WLDELAY_OPTION_NAME, $options );
        wldelay_clear_options_cache();

        $input = '<p>original</p>';
        $this->assertSame( $input, wldelay_login_message_lockout( $input ) );
        $this->assertSame( '', wldelay_render_login_lockout_block() );
    }

    public function test_help_url_is_filterable() {
        $this->lock_current_ip();

        add_filter( 'wldelay_login_help_url', function () {
            return 'https://example.com/support';
        } );

        $out = wldelay_login_message_lockout( '' );

        $this->assertStringContainsString( 'https://example.com/support', $out );
        $this->assertSame( 'https://example.com/support', wldelay_login_help_url() );
    }

    public function test_help_url_default_is_lostpassword_url() {
        $this->assertSame( wp_lostpassword_url(), wldelay_login_help_url() );
    }

    public function test_output_is_escaped() {
        $this->lock_current_ip();

        // A help URL with characters that must be escaped by esc_url.
        add_filter( 'wldelay_login_help_url', function () {
            return 'https://example.com/?a=1&b="x"<script>';
        } );

        $out = wldelay_login_message_lockout( '' );

        // esc_url must strip the raw quote/angle-bracket injection.
        $this->assertStringNotContainsString( '"x"<script>', $out );
        $this->assertStringNotContainsString( '<script>', $out );
        // The ampersand is encoded by esc_url.
        $this->assertStringContainsString( 'a=1', $out );
    }

    public function test_login_errors_warning_wraps_attempts_remaining() {
        WLDelay_Test_Fixture::make()
            ->with_current_ip( $this->ip )
            ->with_option( 'wldelay_lockout_enabled', true )
            ->apply();

        $errors = new WP_Error();
        $errors->add( 'wldelay_attempts_remaining', 'Login failed. 2 attempts remaining before temporary lockout.' );

        $result = wldelay_login_errors_warning( $errors );

        $messages = $result->get_error_messages( 'wldelay_attempts_remaining' );
        $this->assertNotEmpty( $messages );
        $this->assertStringContainsString( 'wldelay-login-warning', $messages[0] );
        // Original message text preserved (escaped form).
        $this->assertStringContainsString( 'attempts remaining before temporary lockout', $messages[0] );
    }

    public function test_login_errors_warning_passthrough_when_no_attempts_code() {
        $errors = new WP_Error( 'invalid_username', 'Unknown username.' );

        $result = wldelay_login_errors_warning( $errors );

        $messages = $result->get_error_messages( 'invalid_username' );
        $this->assertSame( array( 'Unknown username.' ), $messages );
        $this->assertEmpty( $result->get_error_messages( 'wldelay_attempts_remaining' ) );
    }

    public function test_countdown_formatter() {
        $this->assertSame( '1:59', wldelay_format_countdown( 119 ) );
        $this->assertSame( '0:08', wldelay_format_countdown( 8 ) );
        $this->assertSame( '0:00', wldelay_format_countdown( 0 ) );
        $this->assertSame( '0:00', wldelay_format_countdown( -5 ) );
    }
}
