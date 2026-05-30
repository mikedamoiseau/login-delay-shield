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
}
