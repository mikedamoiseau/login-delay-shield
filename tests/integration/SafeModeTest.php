<?php
/**
 * Integration tests for the WLDELAY_SAFE_MODE emergency kill switch.
 *
 * Safe mode cannot be exercised through the real constant inside the test
 * suite (constants cannot be undefined), so these tests toggle it through the
 * WP_TESTS_DOMAIN-gated `wldelay_test_safe_mode` filter that
 * wldelay_is_safe_mode() exposes for exactly this purpose.
 */

class SafeModeTest extends WP_UnitTestCase {

    public function setUp(): void {
        parent::setUp();
        wldelay_create_tables();
        WLDelay_Test_Fixture::reset();
        unset( $_POST['log'] );
        $_SERVER['REMOTE_ADDR'] = '192.168.7.77';
    }

    public function tearDown(): void {
        remove_filter( 'wldelay_test_safe_mode', '__return_true' );
        WLDelay_Test_Fixture::reset();
        unset( $_POST['log'] );
        unset( $_SERVER['REMOTE_ADDR'] );
        parent::tearDown();
    }

    private function enable_safe_mode() {
        add_filter( 'wldelay_test_safe_mode', '__return_true' );
    }

    /**
     * Safe mode is off unless the constant (or test filter) enables it.
     */
    public function test_safe_mode_off_by_default() {
        $this->assertFalse( wldelay_is_safe_mode() );
    }

    public function test_safe_mode_on_via_test_filter() {
        $this->enable_safe_mode();

        $this->assertTrue( wldelay_is_safe_mode() );
    }

    /**
     * The admin notice hook is registered.
     */
    public function test_admin_notice_is_hooked() {
        $this->assertNotFalse(
            has_action( 'admin_notices', 'wldelay_safe_mode_admin_notice' ),
            'Safe mode admin notice should be hooked to admin_notices'
        );
    }

    /**
     * Failed logins are not delayed while safe mode is active.
     */
    public function test_no_delay_on_failed_login_in_safe_mode() {
        $this->enable_safe_mode();

        WLDelay_Test_Fixture::make()
            ->with_options( [ 'wldelay_delay' => 3 ] )
            ->apply();

        $error = new WP_Error( 'invalid_username', 'Invalid username' );

        $start = microtime( true );
        $result = wldelay_auth_login( $error, 'wrongpassword' );
        $elapsed = microtime( true ) - $start;

        $this->assertSame( $error, $result, 'Error should pass through untouched in safe mode' );
        $this->assertLessThan( 0.5, $elapsed, 'No delay should be applied in safe mode' );
    }

    /**
     * A locked-out IP can authenticate while safe mode is active — the core
     * recovery scenario the constant exists for.
     */
    public function test_locked_ip_can_authenticate_in_safe_mode() {
        $user = $this->factory->user->create_and_get( [
            'user_login' => 'lockedadmin',
            'user_pass'  => 'correct-password',
        ] );

        WLDelay_Test_Fixture::make()
            ->with_current_ip( '192.168.7.77' )
            ->with_options( [ 'wldelay_lockout_enabled' => true ] )
            ->with_lockout( '192.168.7.77' )
            ->apply();

        // Sanity: without safe mode the lockout blocks authentication.
        $blocked = wldelay_auth_login( $user, 'correct-password' );
        $this->assertInstanceOf( WP_Error::class, $blocked );
        $this->assertSame( 'wldelay_ip_locked', $blocked->get_error_code() );

        // With safe mode the same locked IP authenticates normally.
        $this->enable_safe_mode();
        $result = wldelay_auth_login( $user, 'correct-password' );

        $this->assertInstanceOf( WP_User::class, $result );
        $this->assertEquals( $user->ID, $result->ID );
    }

    /**
     * Failed attempts are not logged while safe mode is active.
     */
    public function test_failed_attempts_not_logged_in_safe_mode() {
        global $wpdb;
        $this->enable_safe_mode();

        wldelay_on_login_failed( 'someuser' );

        $table = wldelay_get_log_table_name();
        $count = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table}" );
        $this->assertSame( 0, $count, 'Safe mode should suppress failed-attempt logging' );
    }

    /**
     * Lockout feedback UI is inactive while safe mode is active, even when a
     * lockout exists for the current IP.
     */
    public function test_login_feedback_inactive_in_safe_mode() {
        WLDelay_Test_Fixture::make()
            ->with_current_ip( '192.168.7.77' )
            ->with_options( [ 'wldelay_lockout_enabled' => true ] )
            ->with_lockout( '192.168.7.77' )
            ->apply();

        $this->assertTrue( wldelay_login_feedback_active(), 'Sanity: feedback active when locked' );

        $this->enable_safe_mode();
        $this->assertFalse( wldelay_login_feedback_active(), 'Feedback should be inactive in safe mode' );
    }

    /**
     * The admin notice renders for administrators while safe mode is active.
     */
    public function test_admin_notice_rendered_for_admin_in_safe_mode() {
        $this->enable_safe_mode();
        wp_set_current_user( $this->factory->user->create( [ 'role' => 'administrator' ] ) );

        ob_start();
        wldelay_safe_mode_admin_notice();
        $output = ob_get_clean();

        $this->assertStringContainsString( 'WLDELAY_SAFE_MODE', $output );
        $this->assertStringContainsString( 'notice-warning', $output );
    }

    /**
     * No notice without safe mode, and none for non-admins.
     */
    public function test_admin_notice_not_rendered_when_inactive_or_unprivileged() {
        wp_set_current_user( $this->factory->user->create( [ 'role' => 'administrator' ] ) );

        ob_start();
        wldelay_safe_mode_admin_notice();
        $this->assertSame( '', ob_get_clean(), 'No notice while safe mode is off' );

        $this->enable_safe_mode();
        wp_set_current_user( $this->factory->user->create( [ 'role' => 'subscriber' ] ) );

        ob_start();
        wldelay_safe_mode_admin_notice();
        $this->assertSame( '', ob_get_clean(), 'No notice for non-admins' );
    }
}
