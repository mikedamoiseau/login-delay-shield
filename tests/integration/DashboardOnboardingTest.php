<?php
/**
 * Integration tests for the dashboard onboarding CTA (F-1-7).
 */

class DashboardOnboardingTest extends WP_UnitTestCase {

    public function setUp(): void {
        parent::setUp();

        $admin_id = $this->factory->user->create( array( 'role' => 'administrator' ) );
        wp_set_current_user( $admin_id );
    }

    /**
     * Reset options and dashboard sub-caches after each test.
     */
    public function tearDown(): void {
        global $wpdb;

        delete_option( WLDELAY_OPTION_NAME );
        wldelay_clear_options_cache();

        $table_name = wldelay_get_log_table_name();
        $wpdb->query( "TRUNCATE TABLE $table_name" );

        delete_transient( WLDELAY_DASH_RECENT_CACHE );
        delete_transient( WLDELAY_DASH_TRENDS_CACHE );

        parent::tearDown();
    }

    /**
     * Capture the CTA output.
     *
     * @return string
     */
    private function render_cta() {
        ob_start();
        wldelay_render_dashboard_onboarding_cta();
        return ob_get_clean();
    }

    /**
     * On a fresh install (score 0% < 50%) the CTA shows heading, score,
     * a disabled-feature label, and the escaped wizard link.
     */
    public function test_cta_renders_on_weak_install() {
        delete_option( WLDELAY_OPTION_NAME );
        wldelay_clear_options_cache();

        $output = $this->render_cta();

        // Heading.
        $this->assertStringContainsString( 'Finish setting up your login protection', $output );

        // Current score percentage (0% on a fresh, all-off install).
        $this->assertStringContainsString( '0%', $output );

        // At least one disabled feature label appears in the checklist.
        $this->assertStringContainsString( 'IP Lockout', $output );
        $this->assertStringContainsString( '<ul', $output );

        // Wizard link: settings page slug + setup wizard anchor.
        $this->assertStringContainsString( 'page=login-delay-shield-admin', $output );
        $this->assertStringContainsString( 'wldelay-setup-wizard-title', $output );

        // Accessible structure.
        $this->assertStringContainsString( '<section', $output );
        $this->assertStringContainsString( 'aria-labelledby="wldelay-onboarding-cta-title"', $output );
    }

    /**
     * Once enough features are enabled to reach >= 50%, the CTA renders nothing.
     */
    public function test_cta_hidden_when_score_at_least_fifty() {
        // Lockout (20) + Progressive (15) + Custom Login (15) = 50 of max 100 = 50%.
        update_option(
            WLDELAY_OPTION_NAME,
            array(
                'wldelay_lockout_enabled'      => 1,
                'wldelay_progressive_enabled'  => 1,
                'wldelay_custom_login_enabled' => 1,
            )
        );
        wldelay_clear_options_cache();

        // Sanity-check the score actually reaches the gate.
        $score = wldelay_get_security_score();
        $pct   = (int) round( $score['score'] / max( 1, $score['max'] ) * 100 );
        $this->assertGreaterThanOrEqual( 50, $pct );

        $output = $this->render_cta();

        $this->assertSame( '', trim( $output ) );
    }

    /**
     * The full widget includes the CTA on a fresh install even with zero
     * failed attempts (the CTA is not gated behind the empty-attempts return).
     */
    public function test_full_widget_shows_cta_with_zero_attempts() {
        global $wpdb;

        delete_option( WLDELAY_OPTION_NAME );
        wldelay_clear_options_cache();

        $table_name = wldelay_get_log_table_name();
        $wpdb->query( "TRUNCATE TABLE $table_name" );
        delete_transient( WLDELAY_DASH_RECENT_CACHE );
        delete_transient( WLDELAY_DASH_TRENDS_CACHE );

        ob_start();
        wldelay_dashboard_widget_content();
        $output = ob_get_clean();

        // Empty-attempts message still present...
        $this->assertStringContainsString( 'No failed login attempts recorded', $output );
        // ...but the CTA appears before that early return.
        $this->assertStringContainsString( 'Finish setting up your login protection', $output );
        $this->assertStringContainsString( 'wldelay-setup-wizard-title', $output );
    }

    /**
     * The wizard URL is run through esc_url and feature labels through esc_html.
     */
    public function test_cta_escapes_output() {
        delete_option( WLDELAY_OPTION_NAME );
        wldelay_clear_options_cache();

        $output = $this->render_cta();

        // esc_url turns the query separator into &#038; (or &amp;) — the raw
        // href therefore contains the encoded, escaped wizard URL.
        $expected = esc_url(
            add_query_arg(
                'page',
                'login-delay-shield-admin',
                admin_url( 'options-general.php' )
            ) . '#wldelay-setup-wizard-title'
        );
        $this->assertStringContainsString( 'href="' . $expected . '"', $output );

        // Feature label is esc_html'd (plain ASCII label round-trips unchanged).
        $this->assertStringContainsString( esc_html__( 'IP Lockout', 'login-delay-shield' ), $output );
    }

    /**
     * The CTA frames the gap as an achievable goal — "reach a strong setup" with
     * a bounded "recommended next steps" list — instead of a raw deficit dump of
     * every disabled protection (R4-4).
     */
    public function test_cta_frames_achievable_next_steps() {
        delete_option( WLDELAY_OPTION_NAME );
        wldelay_clear_options_cache();

        $output = $this->render_cta();

        // Goal-oriented framing, not a bare "your security score is X%".
        $this->assertStringContainsString( 'reach a strong setup', $output );
        $this->assertStringContainsString( 'Recommended next steps:', $output );
        $this->assertStringNotContainsString( "What's missing:", $output );

        // The recommended list is the minimal set that crosses 50% (IP Lockout
        // 20 + Progressive 15 + Custom Login 15 = 50), so exactly 3 items show
        // on an all-off install — not the full disabled-feature dump.
        $this->assertSame( 3, substr_count( $output, '<li>' ) );
    }
}
