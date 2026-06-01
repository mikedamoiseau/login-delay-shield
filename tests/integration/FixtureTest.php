<?php
/**
 * Integration tests for the declarative test-fixture builder (F-2-5).
 *
 * Proves the builder materialises real plugin state: applied lockouts are seen
 * by the public lockout API, option overrides reach wldelay_get_options(),
 * failed-attempt registration increments the tracked counter, and reset()
 * returns the plugin to a clean slate.
 */

class FixtureTest extends WP_UnitTestCase {

    const TEST_IP = '198.51.100.77';

    /**
     * Ensure the lockout table exists and the slate is clean before each test.
     */
    public function setUp(): void {
        parent::setUp();
        wldelay_create_lockout_table();
        WLDelay_Test_Fixture::reset();
    }

    /**
     * Tear down via the single fixture reset call.
     */
    public function tearDown(): void {
        WLDelay_Test_Fixture::reset();
        parent::tearDown();
    }

    /**
     * make() returns a fresh builder instance each time.
     */
    public function test_make_returns_builder_instance() {
        $a = WLDelay_Test_Fixture::make();
        $b = WLDelay_Test_Fixture::make();

        $this->assertInstanceOf( WLDelay_Test_Fixture::class, $a );
        $this->assertNotSame( $a, $b );
    }

    /**
     * with_option / with_options are reflected in wldelay_get_options().
     */
    public function test_with_option_reflected_in_get_options() {
        WLDelay_Test_Fixture::make()
            ->with_option( 'wldelay_delay', 4 )
            ->with_options( array(
                'wldelay_lockout_enabled'  => true,
                'wldelay_lockout_threshold' => 6,
            ) )
            ->apply();

        $options = wldelay_get_options();

        $this->assertEquals( 4, $options['wldelay_delay'] );
        $this->assertTrue( ! empty( $options['wldelay_lockout_enabled'] ) );
        $this->assertEquals( 6, $options['wldelay_lockout_threshold'] );
    }

    /**
     * An applied lockout makes wldelay_is_ip_locked() return true.
     */
    public function test_with_lockout_makes_ip_locked() {
        WLDelay_Test_Fixture::make()
            ->with_current_ip( self::TEST_IP )
            ->with_option( 'wldelay_lockout_enabled', true )
            ->with_lockout( self::TEST_IP )
            ->apply();

        $this->assertTrue( wldelay_is_ip_locked( self::TEST_IP ) );
    }

    /**
     * The applied lockout is durable: it survives transient eviction because the
     * builder wrote it through the real persistent store.
     */
    public function test_with_lockout_persists_to_durable_store() {
        WLDelay_Test_Fixture::make()
            ->with_current_ip( self::TEST_IP )
            ->with_option( 'wldelay_lockout_enabled', true )
            ->with_lockout( self::TEST_IP )
            ->apply();

        delete_transient( wldelay_get_lockout_transient_key( self::TEST_IP ) );
        wldelay_reset_persistence_runtime_cache();

        $this->assertTrue(
            wldelay_is_ip_locked( self::TEST_IP ),
            'Fixture lockout must be backed by the durable store'
        );
    }

    /**
     * with_failed_attempt increments the tracked failure counter, even when the
     * test left every counter-consuming feature off.
     */
    public function test_with_failed_attempt_increments_count() {
        WLDelay_Test_Fixture::make()
            ->with_current_ip( self::TEST_IP )
            ->with_failed_attempt( self::TEST_IP, 'someuser', 3 )
            ->apply();

        $this->assertEquals( 3, wldelay_get_failure_count( self::TEST_IP ) );
    }

    /**
     * with_failed_attempt does not itself trip a lockout (the count is recorded
     * without changing observable lockout state when the test left lockout off).
     */
    public function test_with_failed_attempt_does_not_lock() {
        WLDelay_Test_Fixture::make()
            ->with_current_ip( self::TEST_IP )
            ->with_failed_attempt( self::TEST_IP, '', 3 )
            ->apply();

        $this->assertFalse( wldelay_is_ip_locked( self::TEST_IP ) );
    }

    /**
     * with_whitelist enables the whitelist and matches the listed IP.
     */
    public function test_with_whitelist_matches_listed_ip() {
        WLDelay_Test_Fixture::make()
            ->with_current_ip( self::TEST_IP )
            ->with_whitelist( array( self::TEST_IP, '10.0.0.0/8' ) )
            ->apply();

        $this->assertTrue( wldelay_is_ip_whitelisted() );

        $_SERVER['REMOTE_ADDR'] = '10.5.5.5';
        $this->assertTrue( wldelay_is_ip_whitelisted() );

        $_SERVER['REMOTE_ADDR'] = '192.0.2.1';
        $this->assertFalse( wldelay_is_ip_whitelisted() );
    }

    /**
     * with_current_ip sets $_SERVER['REMOTE_ADDR'] for the client-IP helper.
     */
    public function test_with_current_ip_sets_remote_addr() {
        WLDelay_Test_Fixture::make()
            ->with_current_ip( self::TEST_IP )
            ->apply();

        $this->assertEquals( self::TEST_IP, $_SERVER['REMOTE_ADDR'] );
        $this->assertEquals( self::TEST_IP, wldelay_get_client_ip() );
    }

    /**
     * build() is an alias for apply().
     */
    public function test_build_is_alias_for_apply() {
        WLDelay_Test_Fixture::make()
            ->with_option( 'wldelay_delay', 7 )
            ->build();

        $this->assertEquals( 7, wldelay_get_options()['wldelay_delay'] );
    }

    /**
     * reset() returns the plugin to a clean slate: no options, no lockout, no
     * failure counter, and the auth-related $_SERVER keys cleared.
     */
    public function test_reset_returns_clean_slate() {
        WLDelay_Test_Fixture::make()
            ->with_current_ip( self::TEST_IP )
            ->with_option( 'wldelay_lockout_enabled', true )
            ->with_lockout( self::TEST_IP )
            ->with_failed_attempt( self::TEST_IP, '', 2 )
            ->apply();

        // Sanity: state is present before reset.
        $this->assertTrue( wldelay_is_ip_locked( self::TEST_IP ) );
        $this->assertNotFalse( get_option( WLDELAY_OPTION_NAME ) );

        WLDelay_Test_Fixture::reset();

        $this->assertFalse( get_option( WLDELAY_OPTION_NAME ) );
        $this->assertArrayNotHasKey( 'REMOTE_ADDR', $_SERVER );
        $this->assertFalse( wldelay_is_ip_locked( self::TEST_IP ) );
        $this->assertEquals( 0, wldelay_get_failure_count( self::TEST_IP ) );

        // Durable store is empty too.
        $this->assertEmpty( wldelay_get_persistence_store()->get_active_lockouts() );
    }

    /**
     * A password-reset lockout locks ONLY the password-reset path: it must not
     * leak onto the normal login path. Guards the fixture's type-aware
     * transient-key selection — a login transient here would falsely report
     * wldelay_is_ip_locked() == true for an impossible production state.
     */
    public function test_password_reset_lockout_does_not_lock_login_path() {
        WLDelay_Test_Fixture::make()
            ->with_current_ip( self::TEST_IP )
            ->with_lockout( self::TEST_IP, '', 900, 'password-reset' )
            ->apply();

        $this->assertTrue(
            wldelay_is_password_reset_locked( self::TEST_IP ),
            'password-reset fixture must lock the password-reset path'
        );
        $this->assertFalse(
            wldelay_is_ip_locked( self::TEST_IP ),
            'password-reset fixture must NOT lock the normal login path'
        );
    }

    /**
     * Seeding failed attempts from a different IP must not change the fixture's
     * declared current IP. with_current_ip(A)->with_failed_attempt(B) must leave
     * the simulated request originating from A, not B.
     */
    public function test_failed_attempt_does_not_override_current_ip() {
        $current = '198.51.100.10';
        $attempt = '198.51.100.20';

        WLDelay_Test_Fixture::make()
            ->with_current_ip( $current )
            ->with_failed_attempt( $attempt, 'someuser', 2 )
            ->apply();

        // The declared current IP wins for the final request.
        $this->assertSame( $current, $_SERVER['REMOTE_ADDR'] );
        $this->assertSame( $current, wldelay_get_client_ip() );

        // The attempts were still recorded against the attempt IP.
        $this->assertEquals( 2, wldelay_get_failure_count( $attempt ) );
    }
}
