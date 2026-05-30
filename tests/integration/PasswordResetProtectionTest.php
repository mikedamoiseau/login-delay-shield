<?php
/**
 * Integration tests for password reset protection.
 */

class PasswordResetProtectionTest extends WP_UnitTestCase {
    public function setUp(): void {
        parent::setUp();

        $_SERVER['REMOTE_ADDR'] = '192.0.2.44';
        $_POST['user_login']    = 'AdminUser';

        delete_option( WLDELAY_OPTION_NAME );
        wldelay_clear_options_cache();
        wldelay_create_log_table();

        global $wpdb;
        $wpdb->query( 'TRUNCATE TABLE ' . wldelay_get_log_table_name() );
    }

    public function tearDown(): void {
        unset( $_SERVER['REMOTE_ADDR'], $_POST['user_login'] );

        delete_option( WLDELAY_OPTION_NAME );
        wldelay_clear_options_cache();

        parent::tearDown();
    }

    public function test_password_reset_handler_is_registered() {
        $this->assertNotFalse(
            has_action( 'lostpassword_post', 'wldelay_handle_password_reset_request' ),
            'Password reset submissions should be protected before reset emails are sent.'
        );
    }

    public function test_password_reset_submission_is_delayed_and_logged_with_source() {
        update_option(
            WLDELAY_OPTION_NAME,
            array(
                'wldelay_delay'                  => 1,
                'wldelay_delay_random'           => false,
                'wldelay_password_reset_enabled' => true,
            )
        );
        wldelay_clear_options_cache();

        $errors = new WP_Error();

        $start = microtime( true );
        wldelay_handle_password_reset_request( $errors );
        $elapsed = microtime( true ) - $start;

        $this->assertGreaterThanOrEqual( 0.9, $elapsed, 'Password reset attempts should receive the configured delay.' );
        $this->assertFalse( $errors->has_errors(), 'Delay-only password reset protection should not block before lockout.' );

        global $wpdb;
        $row = $wpdb->get_row( 'SELECT ip_address, username, source FROM ' . wldelay_get_log_table_name() . ' ORDER BY id DESC LIMIT 1', ARRAY_A );

        $this->assertSame( '192.0.2.44', $row['ip_address'] );
        $this->assertSame( 'adminuser', $row['username'] );
        $this->assertSame( 'password-reset', $row['source'] );
    }

    public function test_password_reset_source_has_display_label() {
        $this->assertSame( 'Password Reset', wldelay_get_login_source_label( 'password-reset' ) );
    }

    public function test_password_reset_attempts_trigger_lockout_at_threshold() {
        update_option(
            WLDELAY_OPTION_NAME,
            array(
                'wldelay_delay'                  => 0,
                'wldelay_delay_random'           => false,
                'wldelay_password_reset_enabled' => true,
                'wldelay_lockout_enabled'        => true,
                'wldelay_lockout_threshold'      => 2,
                'wldelay_lockout_duration'       => 60,
            )
        );
        wldelay_clear_options_cache();

        $first_errors = new WP_Error();
        wldelay_handle_password_reset_request( $first_errors );

        $second_errors = new WP_Error();
        wldelay_handle_password_reset_request( $second_errors );

        $this->assertFalse( $first_errors->has_errors(), 'First reset attempt should not be blocked before threshold.' );
        $this->assertTrue( $second_errors->has_errors(), 'Threshold reset attempt should be blocked.' );
        $this->assertContains( 'wldelay_password_reset_locked', $second_errors->get_error_codes() );
        $this->assertTrue( wldelay_is_ip_locked( '192.0.2.44', 'adminuser' ) );

        $message = implode( ' ', $second_errors->get_error_messages() );
        $this->assertStringContainsString( 'try again', strtolower( $message ) );
        $this->assertStringNotContainsString( 'AdminUser', $message );
        $this->assertStringNotContainsString( 'adminuser', $message );
    }

    public function test_existing_lockout_blocks_password_reset_without_new_log_entry() {
        update_option(
            WLDELAY_OPTION_NAME,
            array(
                'wldelay_delay'                  => 0,
                'wldelay_delay_random'           => false,
                'wldelay_password_reset_enabled' => true,
                'wldelay_lockout_enabled'        => true,
                'wldelay_lockout_threshold'      => 2,
                'wldelay_lockout_duration'       => 60,
            )
        );
        wldelay_clear_options_cache();
        wldelay_lock_ip( '192.0.2.44', 'adminuser', 'password-reset' );

        $errors = new WP_Error();
        wldelay_handle_password_reset_request( $errors );

        global $wpdb;
        $count = (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . wldelay_get_log_table_name() );

        $this->assertContains( 'wldelay_password_reset_locked', $errors->get_error_codes() );
        $this->assertSame( 0, $count );
    }

    public function test_whitelisted_ip_bypasses_password_reset_protection() {
        update_option(
            WLDELAY_OPTION_NAME,
            array(
                'wldelay_delay'                  => 1,
                'wldelay_delay_random'           => false,
                'wldelay_password_reset_enabled' => true,
                'wldelay_whitelist_enabled'      => true,
                'wldelay_whitelist_ips'          => '192.0.2.44',
            )
        );
        wldelay_clear_options_cache();

        $errors = new WP_Error();

        $start = microtime( true );
        wldelay_handle_password_reset_request( $errors );
        $elapsed = microtime( true ) - $start;

        global $wpdb;
        $count = (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . wldelay_get_log_table_name() );

        $this->assertFalse( $errors->has_errors() );
        $this->assertLessThan( 0.5, $elapsed, 'Whitelisted reset submissions should not be delayed.' );
        $this->assertSame( 0, $count );
    }
}
