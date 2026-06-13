<?php
/**
 * Integration tests for plugin settings.
 */

class SettingsTest extends WP_UnitTestCase {

    /**
     * @var LDS_Settings
     */
    private $settings;

    /**
     * Set up before each test.
     */
    public function setUp(): void {
        parent::setUp();
        $this->settings = new LDS_Settings();
        // Clear options cache
        wldelay_clear_options_cache();
    }

    /**
     * Render the settings page with the admin request URI WordPress expects.
     *
     * @return string Rendered settings page HTML.
     */
    private function render_settings_page() {
        $previous_request_uri = isset( $_SERVER['REQUEST_URI'] ) ? $_SERVER['REQUEST_URI'] : null;
        $_SERVER['REQUEST_URI'] = '/wp-admin/options-general.php?page=login-delay-shield-admin';

        ob_start();
        $this->settings->create_admin_page();
        $output = ob_get_clean();

        if ( $previous_request_uri === null ) {
            unset( $_SERVER['REQUEST_URI'] );
        } else {
            $_SERVER['REQUEST_URI'] = $previous_request_uri;
        }

        return $output;
    }

    /**
     * Test that settings page is registered.
     */
    public function test_settings_page_registered() {
        // Set up admin user with manage_options capability
        $admin_id = $this->factory->user->create( [ 'role' => 'administrator' ] );
        wp_set_current_user( $admin_id );

        // Simulate admin_menu action
        do_action( 'admin_menu' );

        global $submenu;

        // Check if our page is in the options-general.php submenu
        $found = false;
        if ( isset( $submenu['options-general.php'] ) ) {
            foreach ( $submenu['options-general.php'] as $item ) {
                if ( in_array( 'login-delay-shield-admin', $item, true ) ) {
                    $found = true;
                    break;
                }
            }
        }

        $this->assertTrue( $found, 'Settings page should be registered under Settings menu' );
    }

    /**
     * Test that settings are registered.
     */
    public function test_settings_registered() {
        global $wp_registered_settings;

        // Call page_init directly to avoid WordPress redirect issues during admin_init
        $this->settings->page_init();

        $this->assertArrayHasKey( 'wldelay_options', $wp_registered_settings );
    }

    /**
     * Test that options are saved correctly.
     */
    public function test_options_saved_correctly() {
        $input = [
            'wldelay_delay' => 3,
            'wldelay_delay_random' => false,
            'wldelay_delay_random_min' => 2,
            'wldelay_delay_random_max' => 6,
            'wldelay_email_enabled' => true,
            'wldelay_email_threshold' => 10,
            'wldelay_email_address' => 'test@example.com',
            'wldelay_rest_enabled' => true,
            'wldelay_application_password_enabled' => true,
            'wldelay_password_reset_enabled' => true,
            'wldelay_fail2ban_enabled' => true,
            'wldelay_fail2ban_log_path' => 'security/fail2ban.log',
            'wldelay_fail2ban_include_lockouts' => true,
        ];

        $result = $this->settings->sanitize( $input );

        $this->assertEquals( 3, $result['wldelay_delay'] );
        $this->assertFalse( $result['wldelay_delay_random'] );
        $this->assertEquals( 2, $result['wldelay_delay_random_min'] );
        $this->assertEquals( 6, $result['wldelay_delay_random_max'] );
        $this->assertTrue( $result['wldelay_email_enabled'] );
        $this->assertEquals( 10, $result['wldelay_email_threshold'] );
        $this->assertEquals( 'test@example.com', $result['wldelay_email_address'] );
        $this->assertTrue( $result['wldelay_rest_enabled'] );
        $this->assertTrue( $result['wldelay_application_password_enabled'] );
        $this->assertTrue( $result['wldelay_password_reset_enabled'] );
        $this->assertTrue( $result['wldelay_fail2ban_enabled'] );
        $this->assertMatchesRegularExpression(
            '#/login-delay-shield-fail2ban-[A-Za-z0-9]{16}/security/fail2ban\.log$#',
            $result['wldelay_fail2ban_log_path']
        );
        $this->assertTrue( $result['wldelay_fail2ban_include_lockouts'] );
    }

    /**
     * Test default values are used when option is not set.
     */
    public function test_default_values_loaded() {
        delete_option( 'wldelay_options' );

        $options = get_option( 'wldelay_options' );

        // When option doesn't exist, get_option returns false
        $this->assertFalse( $options );

        // The plugin code should use defaults from LDS_Settings constants
        $this->assertEquals( 1, LDS_Settings::_DEFAULT_DELAY_IN_SECONDS );
        $this->assertEquals( 1, LDS_Settings::_DEFAULT_RANDOM_MIN );
        $this->assertEquals( 5, LDS_Settings::_DEFAULT_RANDOM_MAX );
        $this->assertEquals( 5, LDS_Settings::_DEFAULT_EMAIL_THRESHOLD );
    }

    /**
     * Test security health score remains a 0-100 scale.
     */
    public function test_security_health_score_max_is_100() {
        $health = wldelay_get_security_score( array() );

        $this->assertSame( 100, $health['max'] );
    }

    /**
     * Test protection profiles expose the guided setup choices.
     */
    public function test_protection_profiles_are_available() {
        $profiles = wldelay_get_protection_profiles();

        $this->assertArrayHasKey( 'conservative', $profiles );
        $this->assertArrayHasKey( 'balanced', $profiles );
        $this->assertArrayHasKey( 'aggressive', $profiles );
        $this->assertSame( 'Balanced', $profiles['balanced']['label'] );
        $this->assertTrue( $profiles['balanced']['settings']['wldelay_lockout_enabled'] );
        $this->assertTrue( $profiles['balanced']['settings']['wldelay_progressive_enabled'] );
        $this->assertTrue( $profiles['balanced']['settings']['wldelay_rest_enabled'] );
        $this->assertTrue( $profiles['balanced']['settings']['wldelay_password_reset_enabled'] );
    }

    /**
     * Test applying a protection profile rewrites the matching settings.
     */
    public function test_balanced_protection_profile_applies_recommended_settings() {
        $result = $this->settings->sanitize(
            array(
                'wldelay_profile_action'     => 'apply',
                'wldelay_protection_profile' => 'balanced',
            )
        );

        $this->assertSame( 'balanced', $result['wldelay_protection_profile'] );
        $this->assertSame( 2, $result['wldelay_delay'] );
        $this->assertTrue( $result['wldelay_delay_random'] );
        $this->assertTrue( $result['wldelay_progressive_enabled'] );
        $this->assertTrue( $result['wldelay_lockout_enabled'] );
        $this->assertSame( 7, $result['wldelay_lockout_threshold'] );
        $this->assertSame( 60, $result['wldelay_lockout_duration'] );
        $this->assertTrue( $result['wldelay_email_enabled'] );
        $this->assertTrue( $result['wldelay_xmlrpc_enabled'] );
        $this->assertFalse( $result['wldelay_xmlrpc_block'] );
        $this->assertTrue( $result['wldelay_rest_enabled'] );
        $this->assertTrue( $result['wldelay_application_password_enabled'] );
        $this->assertTrue( $result['wldelay_password_reset_enabled'] );
    }

    /**
     * Test aggressive profile makes the high-friction XML-RPC choice explicit.
     */
    public function test_aggressive_protection_profile_blocks_xmlrpc_authentication() {
        $result = $this->settings->sanitize(
            array(
                'wldelay_profile_action'     => 'apply',
                'wldelay_protection_profile' => 'aggressive',
            )
        );

        $this->assertSame( 'aggressive', $result['wldelay_protection_profile'] );
        $this->assertTrue( $result['wldelay_xmlrpc_enabled'] );
        $this->assertTrue( $result['wldelay_xmlrpc_block'] );
        $this->assertSame( 5, $result['wldelay_lockout_threshold'] );
        // IP-wide counting must stay; ip_username would let password spraying
        // evade the threshold by spreading attempts across usernames.
        $this->assertSame( 'ip', $result['wldelay_lockout_attempt_strategy'] );
    }

    /**
     * Test invalid profile input cannot apply unexpected settings.
     */
    public function test_invalid_protection_profile_does_not_apply_profile_settings() {
        $result = $this->settings->sanitize(
            array(
                'wldelay_profile_action'     => 'apply',
                'wldelay_protection_profile' => 'unknown',
                'wldelay_delay'              => 4,
            )
        );

        $this->assertSame( '', $result['wldelay_protection_profile'] );
        $this->assertSame( 4, $result['wldelay_delay'] );
        $this->assertFalse( $result['wldelay_lockout_enabled'] );
        $this->assertFalse( $result['wldelay_progressive_enabled'] );
    }

    /**
     * Test a normal save (no apply action) never applies the selected profile.
     *
     * Mirrors an implicit Enter-key submit: the profile radio carries a value
     * but the apply-action field is empty, so manual settings must survive.
     */
    public function test_normal_save_does_not_apply_selected_profile() {
        $result = $this->settings->sanitize(
            array(
                'wldelay_profile_action'     => '',
                'wldelay_protection_profile' => 'balanced',
                'wldelay_delay'              => 4,
            )
        );

        $this->assertSame( '', $result['wldelay_protection_profile'] );
        $this->assertSame( 4, $result['wldelay_delay'] );
        $this->assertFalse( $result['wldelay_lockout_enabled'] );
        $this->assertFalse( $result['wldelay_progressive_enabled'] );
    }

    /**
     * Test setup wizard renders visible protection profile controls.
     */
    public function test_setup_wizard_renders_protection_profiles() {
        update_option(
            'wldelay_options',
            array(
                'wldelay_protection_profile' => 'balanced',
            )
        );

        $output = $this->render_settings_page();

        $this->assertStringContainsString( 'Security Setup Wizard', $output );
        $this->assertStringContainsString( 'Protection Profiles', $output );
        $this->assertStringContainsString( 'name="wldelay_options[wldelay_protection_profile]"', $output );
        $this->assertStringContainsString( 'value="conservative"', $output );
        $this->assertStringContainsString( 'value="balanced"', $output );
        $this->assertStringContainsString( 'value="aggressive"', $output );
        $this->assertMatchesRegularExpression( '/value="balanced"[^>]+checked=[\'"]checked[\'"]/s', $output );
        $this->assertStringContainsString( 'name="wldelay_options[wldelay_profile_action]"', $output );
        $this->assertStringContainsString( 'Apply selected profile', $output );
    }

    /**
     * Test setup wizard summarizes profile effects for users.
     */
    public function test_setup_wizard_displays_profile_effects() {
        $output = $this->render_settings_page();

        $this->assertStringContainsString( 'Lockout after 7 failed attempts', $output );
        $this->assertStringContainsString( 'Blocks XML-RPC authentication', $output );
        $this->assertStringContainsString( 'Password reset protection', $output );
    }

    /**
     * Test setup wizard displays the current selected profile.
     */
    public function test_setup_wizard_displays_current_profile_badge() {
        update_option(
            'wldelay_options',
            array(
                'wldelay_protection_profile' => 'aggressive',
            )
        );

        $output = $this->render_settings_page();

        $this->assertStringContainsString( 'Current profile: Aggressive', $output );
    }

    /**
     * Test that delay value is bounded.
     */
    public function test_delay_value_bounded() {
        // Test max bound
        $input = [ 'wldelay_delay' => 100 ];
        $result = $this->settings->sanitize( $input );
        $this->assertEquals( 10, $result['wldelay_delay'] );

        // Test min bound (0 is allowed)
        $input = [ 'wldelay_delay' => 0 ];
        $result = $this->settings->sanitize( $input );
        $this->assertEquals( 0, $result['wldelay_delay'] );
    }

    /**
     * Test that random delay bounds are enforced.
     */
    public function test_random_delay_bounds_enforced() {
        $input = [
            'wldelay_delay_random_min' => 0,
            'wldelay_delay_random_max' => 100,
        ];

        $result = $this->settings->sanitize( $input );

        $this->assertEquals( 1, $result['wldelay_delay_random_min'] );
        $this->assertEquals( 10, $result['wldelay_delay_random_max'] );
    }

    /**
     * Test that min cannot exceed max after sanitization.
     */
    public function test_min_max_relationship_enforced() {
        $input = [
            'wldelay_delay_random_min' => 8,
            'wldelay_delay_random_max' => 5,
        ];

        $result = $this->settings->sanitize( $input );

        // min should be adjusted to equal max
        $this->assertLessThanOrEqual(
            $result['wldelay_delay_random_max'],
            $result['wldelay_delay_random_min']
        );
    }

    /**
     * Test email threshold bounds.
     */
    public function test_email_threshold_bounds() {
        // Test lower bound
        $input = [ 'wldelay_email_threshold' => 0 ];
        $result = $this->settings->sanitize( $input );
        $this->assertEquals( 1, $result['wldelay_email_threshold'] );

        // Test upper bound
        $input = [ 'wldelay_email_threshold' => 1000 ];
        $result = $this->settings->sanitize( $input );
        $this->assertEquals( 100, $result['wldelay_email_threshold'] );
    }

    /**
     * Test option group is correct.
     */
    public function test_option_group() {
        // Call page_init directly to avoid WordPress redirect issues during admin_init
        $this->settings->page_init();

        global $wp_registered_settings;

        $this->assertArrayHasKey( 'wldelay_options', $wp_registered_settings );
        $this->assertEquals(
            'wldelay_option_group',
            $wp_registered_settings['wldelay_options']['group']
        );
    }

    /**
     * Test settings sections are registered.
     */
    public function test_settings_sections_registered() {
        // Call page_init directly to avoid WordPress redirect issues during admin_init
        $this->settings->page_init();

        global $wp_settings_sections;

        $this->assertArrayHasKey( 'login-delay-shield-admin', $wp_settings_sections );
        $this->assertArrayHasKey( 'wldelay_setting_section_id', $wp_settings_sections['login-delay-shield-admin'] );
        $this->assertArrayHasKey( 'wldelay_email_section_id', $wp_settings_sections['login-delay-shield-admin'] );
    }

    /**
     * Test settings fields are registered.
     */
    public function test_settings_fields_registered() {
        // Call page_init directly to avoid WordPress redirect issues during admin_init
        $this->settings->page_init();

        global $wp_settings_fields;

        $page = 'login-delay-shield-admin';

        // Check general section fields
        $this->assertArrayHasKey( 'wldelay_delay', $wp_settings_fields[ $page ]['wldelay_setting_section_id'] );
        $this->assertArrayHasKey( 'wldelay_delay_random', $wp_settings_fields[ $page ]['wldelay_setting_section_id'] );
        $this->assertArrayHasKey( 'wldelay_delay_random_min', $wp_settings_fields[ $page ]['wldelay_setting_section_id'] );
        $this->assertArrayHasKey( 'wldelay_delay_random_max', $wp_settings_fields[ $page ]['wldelay_setting_section_id'] );

        // Check email section fields
        $this->assertArrayHasKey( 'wldelay_email_enabled', $wp_settings_fields[ $page ]['wldelay_email_section_id'] );
        $this->assertArrayHasKey( 'wldelay_email_threshold', $wp_settings_fields[ $page ]['wldelay_email_section_id'] );
        $this->assertArrayHasKey( 'wldelay_email_address', $wp_settings_fields[ $page ]['wldelay_email_section_id'] );

        // Check auth protection section fields
        $this->assertArrayHasKey( 'wldelay_rest_enabled', $wp_settings_fields[ $page ]['wldelay_xmlrpc_section_id'] );
        $this->assertArrayHasKey( 'wldelay_application_password_enabled', $wp_settings_fields[ $page ]['wldelay_xmlrpc_section_id'] );
        $this->assertArrayHasKey( 'wldelay_password_reset_enabled', $wp_settings_fields[ $page ]['wldelay_xmlrpc_section_id'] );

        // Check fail2ban logging fields
        $this->assertArrayHasKey( 'wldelay_fail2ban_enabled', $wp_settings_fields[ $page ]['wldelay_log_section_id'] );
        $this->assertArrayHasKey( 'wldelay_fail2ban_log_path', $wp_settings_fields[ $page ]['wldelay_log_section_id'] );
        $this->assertArrayHasKey( 'wldelay_fail2ban_include_lockouts', $wp_settings_fields[ $page ]['wldelay_log_section_id'] );
    }
    /**
     * Test telemetry UI renders filtered rows and export URL.
     */
    public function test_login_log_telemetry_renders_filtered_results() {
        global $wpdb;
        wldelay_create_log_table();
        $table_name = wldelay_get_log_table_name();
        $wpdb->query( 'TRUNCATE TABLE ' . $table_name );
        $wpdb->insert( $table_name, array( 'ip_address' => '203.0.113.10', 'username' => 'alice', 'attempted_at' => '2026-04-01 10:00:00', 'source' => 'wp-login' ) );
        $wpdb->insert( $table_name, array( 'ip_address' => '203.0.113.11', 'username' => 'bob', 'attempted_at' => '2026-04-01 11:00:00', 'source' => 'xmlrpc' ) );

        $admin_id = $this->factory->user->create( array( 'role' => 'administrator' ) );
        wp_set_current_user( $admin_id );

        $_GET['wldelay_log_username'] = 'alice';
        $_SERVER['REQUEST_URI'] = '/wp-admin/options-general.php?page=login-delay-shield-admin&wldelay_log_username=alice';

        ob_start();
        $this->settings->create_admin_page();
        $output = ob_get_clean();

        unset( $_GET['wldelay_log_username'], $_SERVER['REQUEST_URI'] );

        $this->assertStringContainsString( 'Failed Login Telemetry', $output );
        $this->assertStringContainsString( 'alice', $output );
        $this->assertStringNotContainsString( 'bob', $output );
        $this->assertStringContainsString( 'wldelay_log_username=alice', html_entity_decode( $output, ENT_QUOTES, 'UTF-8' ) );
        $this->assertStringContainsString( 'Export filtered CSV', $output );
    }

    /**
     * Test telemetry table renders stored local-time MySQL values without GMT conversion.
     */
    public function test_login_log_telemetry_does_not_double_convert_local_time() {
        global $wpdb;
        wldelay_create_log_table();
        $table_name = wldelay_get_log_table_name();
        $wpdb->query( 'TRUNCATE TABLE ' . $table_name );
        $wpdb->insert( $table_name, array( 'ip_address' => '203.0.113.20', 'username' => 'time-user', 'attempted_at' => '2026-04-01 12:00:00', 'source' => 'wp-login' ) );

        update_option( 'timezone_string', '' );
        update_option( 'gmt_offset', 2 );
        update_option( 'date_format', 'Y-m-d' );
        update_option( 'time_format', 'H:i' );

        $_SERVER['REQUEST_URI'] = '/wp-admin/options-general.php?page=login-delay-shield-admin';

        ob_start();
        $this->settings->create_admin_page();
        $output = ob_get_clean();

        unset( $_SERVER['REQUEST_URI'] );

        $this->assertStringContainsString( '2026-04-01 12:00', $output );
        $this->assertStringNotContainsString( '2026-04-01 14:00', $output );
    }

    // -------------------------------------------------------------------------
    // Botnet sanitization tests (F-1-9, Task 7 durability fix)
    // -------------------------------------------------------------------------

    /**
     * Test botnet IP threshold is clamped (max 100).
     */
    public function test_botnet_ip_threshold_clamped_to_max() {
        $result = $this->settings->sanitize( array( 'wldelay_botnet_ip_threshold' => 999 ) );
        $this->assertSame( 100, $result['wldelay_botnet_ip_threshold'] );
    }

    /**
     * Test botnet IP threshold is clamped (min 2).
     */
    public function test_botnet_ip_threshold_clamped_to_min() {
        $result = $this->settings->sanitize( array( 'wldelay_botnet_ip_threshold' => 0 ) );
        $this->assertSame( 2, $result['wldelay_botnet_ip_threshold'] );
    }

    /**
     * Test botnet window minutes is clamped (max 60).
     */
    public function test_botnet_window_minutes_clamped_to_max() {
        $result = $this->settings->sanitize( array( 'wldelay_botnet_window_minutes' => 999 ) );
        $this->assertSame( 60, $result['wldelay_botnet_window_minutes'] );
    }

    /**
     * Test botnet window minutes is clamped (min 5).
     */
    public function test_botnet_window_minutes_clamped_to_min() {
        $result = $this->settings->sanitize( array( 'wldelay_botnet_window_minutes' => 1 ) );
        $this->assertSame( 5, $result['wldelay_botnet_window_minutes'] );
    }

    /**
     * Test botnet enabled checkbox: unchecked (absent) stores false.
     */
    public function test_botnet_enabled_absent_stores_false() {
        $result = $this->settings->sanitize( array() );
        $this->assertFalse( $result['wldelay_botnet_enabled'] );
    }

    /**
     * Test botnet enabled checkbox: present stores true.
     */
    public function test_botnet_enabled_present_stores_true() {
        $result = $this->settings->sanitize( array( 'wldelay_botnet_enabled' => '1' ) );
        $this->assertTrue( $result['wldelay_botnet_enabled'] );
    }

    /**
     * Test that a save round-trip now persists all 3 botnet keys (durability fix).
     *
     * Before this task, sanitize() built a fresh array without the botnet keys,
     * so they were dropped from storage on every save. This test confirms the fix.
     */
    public function test_botnet_keys_persist_through_save_round_trip() {
        $input = array(
            'wldelay_botnet_enabled'       => '1',
            'wldelay_botnet_ip_threshold'  => 8,
            'wldelay_botnet_window_minutes' => 20,
        );
        $sanitized = $this->settings->sanitize( $input );

        $this->assertArrayHasKey( 'wldelay_botnet_enabled', $sanitized );
        $this->assertArrayHasKey( 'wldelay_botnet_ip_threshold', $sanitized );
        $this->assertArrayHasKey( 'wldelay_botnet_window_minutes', $sanitized );

        $this->assertTrue( $sanitized['wldelay_botnet_enabled'] );
        $this->assertSame( 8, $sanitized['wldelay_botnet_ip_threshold'] );
        $this->assertSame( 20, $sanitized['wldelay_botnet_window_minutes'] );
    }

    /**
     * Test settings card for botnet detection is rendered on the admin page.
     */
    public function test_botnet_settings_card_is_rendered() {
        $admin_id = $this->factory->user->create( array( 'role' => 'administrator' ) );
        wp_set_current_user( $admin_id );
        $_SERVER['REQUEST_URI'] = '/wp-admin/options-general.php?page=login-delay-shield-admin';

        ob_start();
        $this->settings->create_admin_page();
        $output = ob_get_clean();

        unset( $_SERVER['REQUEST_URI'] );

        $this->assertStringContainsString( 'Distributed Attack Detection', $output );
        $this->assertStringContainsString( 'wldelay_botnet_enabled', $output );
        $this->assertStringContainsString( 'wldelay_botnet_ip_threshold', $output );
        $this->assertStringContainsString( 'wldelay_botnet_window_minutes', $output );
    }

    // -------------------------------------------------------------------------
    // Dashboard widget banner tests (F-1-9)
    // -------------------------------------------------------------------------

    /**
     * Test dashboard widget shows botnet banner when detections transient is set.
     */
    public function test_dashboard_widget_shows_botnet_banner_when_detections_exist() {
        $admin_id = $this->factory->user->create( array( 'role' => 'administrator' ) );
        wp_set_current_user( $admin_id );

        set_transient(
            'wldelay_botnet_detections',
            array(
                array(
                    'username'       => 'targetuser',
                    'distinct_ips'   => 12,
                    'window_minutes' => 15,
                    'detected_at'    => time() - 300,
                ),
            ),
            DAY_IN_SECONDS
        );

        ob_start();
        wldelay_dashboard_widget_content();
        $output = ob_get_clean();

        delete_transient( 'wldelay_botnet_detections' );

        $this->assertStringContainsString( 'Distributed attack detected', $output );
        $this->assertStringContainsString( 'targetuser', $output );
    }

    /**
     * Test dashboard widget shows no botnet banner when no detections exist.
     */
    public function test_dashboard_widget_hides_botnet_banner_when_no_detections() {
        $admin_id = $this->factory->user->create( array( 'role' => 'administrator' ) );
        wp_set_current_user( $admin_id );

        delete_transient( 'wldelay_botnet_detections' );

        ob_start();
        wldelay_dashboard_widget_content();
        $output = ob_get_clean();

        $this->assertStringNotContainsString( 'Distributed attack detected', $output );
        $this->assertStringNotContainsString( 'wldelay-botnet-alert', $output );
    }

    /**
     * Test telemetry source dropdown preserves active legacy/future source filters.
     */
    public function test_login_log_telemetry_preserves_legacy_source_filter_selection() {
        global $wpdb;
        wldelay_create_log_table();
        $table_name = wldelay_get_log_table_name();
        $wpdb->query( 'TRUNCATE TABLE ' . $table_name );
        $wpdb->insert( $table_name, array( 'ip_address' => '203.0.113.30', 'username' => 'legacy-user', 'attempted_at' => '2026-04-01 10:00:00', 'source' => 'legacy-source' ) );

        $_GET['wldelay_log_source'] = 'legacy-source';
        $_SERVER['REQUEST_URI'] = '/wp-admin/options-general.php?page=login-delay-shield-admin&wldelay_log_source=legacy-source';

        ob_start();
        $this->settings->create_admin_page();
        $output = ob_get_clean();

        unset( $_GET['wldelay_log_source'], $_SERVER['REQUEST_URI'] );

        $this->assertMatchesRegularExpression( '/value=["\']legacy-source["\'][^>]+selected/', $output );
        $this->assertStringContainsString( 'legacy-user', $output );
    }

}
