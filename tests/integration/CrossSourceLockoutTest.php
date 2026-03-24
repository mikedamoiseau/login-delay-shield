<?php
/**
 * Integration tests for cascading authentication failures across multiple auth sources.
 *
 * Covers the scenario where the same IP fails via wp-login, then REST, then application-password
 * in sequence. Verifies that all three paths share the same IP-based failure counter and that
 * lockout triggers at the expected threshold regardless of which source crosses it.
 */

class CrossSourceLockoutTest extends WP_UnitTestCase {

    /**
     * IP address used throughout all tests.
     */
    const TEST_IP = '10.20.30.40';

    /**
     * Set up before each test.
     */
    public function setUp(): void {
        parent::setUp();

        wldelay_create_log_table();
        $this->truncate_log_table();

        $_SERVER['REMOTE_ADDR'] = self::TEST_IP;
        unset( $_SERVER['REQUEST_URI'], $_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW'] );
        unset( $_POST['log'] );

        delete_option( 'wldelay_options' );
        wldelay_clear_options_cache();

        // Clear failure/lockout transients for the test IP
        delete_transient( 'wldelay_fails_' . md5( self::TEST_IP ) );
        delete_transient( 'wldelay_lockout_' . md5( self::TEST_IP ) );
        delete_transient( 'wldelay_email_cooldown' );

        // Ensure application passwords are available for deterministic behaviour
        add_filter( 'wp_is_application_passwords_available', '__return_true' );
    }

    /**
     * Tear down after each test.
     */
    public function tearDown(): void {
        unset( $_SERVER['REMOTE_ADDR'], $_SERVER['REQUEST_URI'], $_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW'] );
        unset( $_POST['log'] );

        remove_all_filters( 'wp_is_application_passwords_available' );

        delete_transient( 'wldelay_fails_' . md5( self::TEST_IP ) );
        delete_transient( 'wldelay_lockout_' . md5( self::TEST_IP ) );

        delete_option( 'wldelay_options' );
        wldelay_clear_options_cache();
        $this->truncate_log_table();

        parent::tearDown();
    }

    /**
     * Test that failures across wp-login, REST, and application-password increment a shared
     * IP-based counter and trigger lockout once the threshold is reached.
     *
     * Scenario:
     *   - Attempt 1 via wp-login   → counter = 1, no lockout
     *   - Attempt 2 via REST       → counter = 2, no lockout
     *   - Attempt 3 via app-pass   → counter = 3, lockout triggered (threshold = 3)
     */
    public function test_cascading_failures_across_sources_trigger_lockout() {
        update_option( 'wldelay_options', [
            'wldelay_delay'                        => 1,
            'wldelay_delay_random'                 => false,
            'wldelay_lockout_enabled'              => true,
            'wldelay_lockout_threshold'            => 3,
            'wldelay_lockout_duration'             => 60,
            'wldelay_rest_enabled'                 => true,
            'wldelay_application_password_enabled' => true,
        ] );
        wldelay_clear_options_cache();

        // --- Step 1: wp-login failure (counter → 1) ---
        $_SERVER['REQUEST_URI'] = '/wp-login.php';
        $_POST['log']           = 'testuser';
        $result1 = wldelay_auth_login( new WP_Error( 'invalid_password', 'Wrong password' ), 'wrongpass' );

        $this->assertInstanceOf( WP_Error::class, $result1 );
        $this->assertNotEquals(
            'wldelay_ip_locked',
            $result1->get_error_code(),
            'Should not lock after first failure'
        );
        $this->assertEquals( 1, wldelay_get_failure_count( self::TEST_IP ), 'Counter should be 1 after wp-login failure' );

        // --- Step 2: REST failure (counter → 2) ---
        // PHP_AUTH_USER set (for username capture) but PHP_AUTH_PW NOT set so
        // wldelay_is_application_password_attempt() returns false and the REST
        // handler processes this attempt rather than deferring to the app-password handler.
        $_SERVER['REQUEST_URI']  = '/wp-json/wp/v2/posts';
        $_SERVER['PHP_AUTH_USER'] = 'testuser';
        unset( $_SERVER['PHP_AUTH_PW'] );

        $result2 = wldelay_handle_rest_authentication( new WP_Error( 'rest_invalid', 'Invalid credentials' ) );

        $this->assertInstanceOf( WP_Error::class, $result2 );
        $this->assertNotEquals(
            'wldelay_ip_locked',
            $result2->get_error_code(),
            'Should not lock after second failure'
        );
        $this->assertEquals( 2, wldelay_get_failure_count( self::TEST_IP ), 'Counter should be 2 after REST failure' );

        // --- Step 3: application-password failure (counter → 3 → lockout) ---
        $_SERVER['PHP_AUTH_USER'] = 'testuser';
        $_SERVER['PHP_AUTH_PW']   = 'bad-app-pass';

        $result3 = wldelay_handle_application_password_auth(
            new WP_Error( 'invalid_application_password', 'Bad application password' ),
            'testuser',
            'bad-app-pass'
        );

        $this->assertInstanceOf( WP_Error::class, $result3 );
        $this->assertEquals(
            'wldelay_ip_locked',
            $result3->get_error_code(),
            'Should be locked after third failure reaches threshold'
        );
        $this->assertEquals( 3, wldelay_get_failure_count( self::TEST_IP ), 'Counter should be 3 after app-password failure' );
    }

    /**
     * Test that after cross-source failures trigger a lockout, subsequent wp-login attempts
     * from the same IP are immediately blocked without applying a delay.
     */
    public function test_lockout_triggered_by_cross_source_failures_blocks_subsequent_wp_login() {
        update_option( 'wldelay_options', [
            'wldelay_delay'                        => 1,
            'wldelay_delay_random'                 => false,
            'wldelay_lockout_enabled'              => true,
            'wldelay_lockout_threshold'            => 2,
            'wldelay_lockout_duration'             => 60,
            'wldelay_rest_enabled'                 => true,
            'wldelay_application_password_enabled' => true,
        ] );
        wldelay_clear_options_cache();

        // Failure 1: wp-login
        $_SERVER['REQUEST_URI'] = '/wp-login.php';
        $_POST['log']           = 'testuser';
        wldelay_auth_login( new WP_Error( 'invalid_password', 'Wrong' ), 'wrong' );

        // Failure 2: REST — triggers lockout (threshold = 2)
        $_SERVER['REQUEST_URI']   = '/wp-json/wp/v2/posts';
        $_SERVER['PHP_AUTH_USER'] = 'testuser';
        unset( $_SERVER['PHP_AUTH_PW'] );
        wldelay_handle_rest_authentication( new WP_Error( 'rest_invalid', 'Bad creds' ) );

        $this->assertTrue( wldelay_is_ip_locked( self::TEST_IP ), 'IP should be locked after cross-source failures' );

        // Now a subsequent wp-login attempt should be blocked immediately (no delay)
        $_SERVER['REQUEST_URI'] = '/wp-login.php';
        $_POST['log']           = 'testuser';
        $user = $this->factory->user->create_and_get( [ 'user_login' => 'testuser', 'user_pass' => 'correct' ] );

        $start  = microtime( true );
        $result = wldelay_auth_login( $user, 'correct' );
        $elapsed = microtime( true ) - $start;

        $this->assertInstanceOf( WP_Error::class, $result );
        $this->assertEquals( 'wldelay_ip_locked', $result->get_error_code() );
        $this->assertLessThan( 1.0, $elapsed, 'Locked IP should be rejected immediately without delay' );
    }

    /**
     * Test that REST and application-password failures each log an entry with the correct source.
     */
    public function test_cross_source_failures_log_distinct_sources() {
        update_option( 'wldelay_options', [
            'wldelay_delay'                        => 1,
            'wldelay_delay_random'                 => false,
            'wldelay_lockout_enabled'              => true,
            'wldelay_lockout_threshold'            => 10,
            'wldelay_rest_enabled'                 => true,
            'wldelay_application_password_enabled' => true,
        ] );
        wldelay_clear_options_cache();

        // REST failure
        $_SERVER['REQUEST_URI']   = '/wp-json/wp/v2/posts';
        $_SERVER['PHP_AUTH_USER'] = 'testuser';
        unset( $_SERVER['PHP_AUTH_PW'] );
        wldelay_handle_rest_authentication( new WP_Error( 'rest_invalid', 'Bad creds' ) );

        // application-password failure
        $_SERVER['PHP_AUTH_USER'] = 'testuser';
        $_SERVER['PHP_AUTH_PW']   = 'bad-app-pass';
        wldelay_handle_application_password_auth(
            new WP_Error( 'invalid_application_password', 'Bad' ),
            'testuser',
            'bad-app-pass'
        );

        $logs    = wldelay_get_recent_failed_attempts( 10 );
        $sources = array_column( (array) $logs, 'source' );

        $this->assertContains( 'rest', $sources, 'REST failure should be logged with source=rest' );
        $this->assertContains( 'application-password', $sources, 'App-password failure should be logged with source=application-password' );
        $this->assertEquals( 2, wldelay_get_failure_count( self::TEST_IP ), 'Shared counter should reflect both failures' );
    }

    /**
     * Truncate the login log table between tests.
     */
    private function truncate_log_table() {
        global $wpdb;
        $table_name = wldelay_get_log_table_name();
        $wpdb->query( "TRUNCATE TABLE $table_name" ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
    }
}
