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
        ];

        $result = $this->settings->sanitize( $input );

        $this->assertEquals( 3, $result['wldelay_delay'] );
        $this->assertFalse( $result['wldelay_delay_random'] );
        $this->assertEquals( 2, $result['wldelay_delay_random_min'] );
        $this->assertEquals( 6, $result['wldelay_delay_random_max'] );
        $this->assertTrue( $result['wldelay_email_enabled'] );
        $this->assertEquals( 10, $result['wldelay_email_threshold'] );
        $this->assertEquals( 'test@example.com', $result['wldelay_email_address'] );
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
    }
}
