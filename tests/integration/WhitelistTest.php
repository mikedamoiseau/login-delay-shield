<?php
/**
 * Integration tests for IP whitelist functionality.
 */

class WhitelistTest extends WP_UnitTestCase {

    /**
     * Set up before each test.
     */
    public function setUp(): void {
        parent::setUp();
        wldelay_create_lockout_table();
        WLDelay_Test_Fixture::reset();
    }

    /**
     * Tear down after each test.
     */
    public function tearDown(): void {
        WLDelay_Test_Fixture::reset();
        parent::tearDown();
    }

    /**
     * Test that whitelist is disabled by default.
     */
    public function test_whitelist_disabled_by_default() {
        $_SERVER['REMOTE_ADDR'] = '192.168.1.1';

        $this->assertFalse( wldelay_is_ip_whitelisted() );
    }

    /**
     * Test that whitelist check returns false when disabled.
     */
    public function test_whitelist_returns_false_when_disabled() {
        WLDelay_Test_Fixture::make()
            ->with_current_ip( '192.168.1.1' )
            ->with_options( [
                'wldelay_whitelist_enabled' => false,
                'wldelay_whitelist_ips'     => "192.168.1.1\n10.0.0.1",
            ] )
            ->apply();

        $this->assertFalse( wldelay_is_ip_whitelisted() );
    }

    /**
     * Test that whitelisted IP is detected (exact match).
     */
    public function test_exact_ip_match_is_whitelisted() {
        WLDelay_Test_Fixture::make()
            ->with_current_ip( '192.168.1.100' )
            ->with_whitelist( [ '192.168.1.100', '10.0.0.1' ] )
            ->apply();

        $this->assertTrue( wldelay_is_ip_whitelisted() );
    }

    /**
     * Test that non-whitelisted IP is not matched.
     */
    public function test_non_whitelisted_ip_not_matched() {
        WLDelay_Test_Fixture::make()
            ->with_current_ip( '192.168.1.200' )
            ->with_whitelist( [ '192.168.1.100', '10.0.0.1' ] )
            ->apply();

        $this->assertFalse( wldelay_is_ip_whitelisted() );
    }

    /**
     * Test that CIDR range matching works.
     */
    public function test_cidr_range_matching() {
        WLDelay_Test_Fixture::make()
            ->with_current_ip( '192.168.1.50' )
            ->with_whitelist( [ '192.168.1.0/24' ] )
            ->apply();

        $this->assertTrue( wldelay_is_ip_whitelisted() );
    }

    /**
     * Test that IP outside CIDR range is not matched.
     */
    public function test_ip_outside_cidr_not_matched() {
        WLDelay_Test_Fixture::make()
            ->with_current_ip( '192.168.2.50' )
            ->with_whitelist( [ '192.168.1.0/24' ] )
            ->apply();

        $this->assertFalse( wldelay_is_ip_whitelisted() );
    }

    /**
     * Test wldelay_ip_in_range with exact IPv4 match.
     */
    public function test_ip_in_range_exact_ipv4() {
        $this->assertTrue( wldelay_ip_in_range( '192.168.1.1', '192.168.1.1' ) );
        $this->assertFalse( wldelay_ip_in_range( '192.168.1.1', '192.168.1.2' ) );
    }

    /**
     * Test wldelay_ip_in_range with IPv4 CIDR /24.
     */
    public function test_ip_in_range_cidr_24() {
        $this->assertTrue( wldelay_ip_in_range( '192.168.1.1', '192.168.1.0/24' ) );
        $this->assertTrue( wldelay_ip_in_range( '192.168.1.255', '192.168.1.0/24' ) );
        $this->assertFalse( wldelay_ip_in_range( '192.168.2.1', '192.168.1.0/24' ) );
    }

    /**
     * Test wldelay_ip_in_range with IPv4 CIDR /8.
     */
    public function test_ip_in_range_cidr_8() {
        $this->assertTrue( wldelay_ip_in_range( '10.0.0.1', '10.0.0.0/8' ) );
        $this->assertTrue( wldelay_ip_in_range( '10.255.255.255', '10.0.0.0/8' ) );
        $this->assertFalse( wldelay_ip_in_range( '11.0.0.1', '10.0.0.0/8' ) );
    }

    /**
     * Test wldelay_ip_in_range with IPv4 CIDR /32 (single IP).
     */
    public function test_ip_in_range_cidr_32() {
        $this->assertTrue( wldelay_ip_in_range( '192.168.1.100', '192.168.1.100/32' ) );
        $this->assertFalse( wldelay_ip_in_range( '192.168.1.101', '192.168.1.100/32' ) );
    }

    /**
     * Test whitelisted IP bypasses delay on failed login.
     */
    public function test_whitelisted_ip_bypasses_delay() {
        WLDelay_Test_Fixture::make()
            ->with_current_ip( '192.168.1.100' )
            ->with_options( [
                'wldelay_delay'        => 3, // 3 second delay normally
                'wldelay_delay_random' => false,
            ] )
            ->with_whitelist( [ '192.168.1.100' ] )
            ->apply();

        $error = new WP_Error( 'invalid_password', 'Invalid password' );

        $start = microtime( true );
        $result = wldelay_auth_login( $error, 'wrongpassword' );
        $elapsed = microtime( true ) - $start;

        // Should return immediately without delay
        $this->assertInstanceOf( WP_Error::class, $result );
        $this->assertLessThan( 1.0, $elapsed, 'Whitelisted IP should bypass delay' );
    }

    /**
     * Test non-whitelisted IP still gets delay.
     */
    public function test_non_whitelisted_ip_gets_delay() {
        WLDelay_Test_Fixture::make()
            ->with_current_ip( '192.168.1.200' )
            ->with_options( [
                'wldelay_delay'        => 1,
                'wldelay_delay_random' => false,
            ] )
            ->with_whitelist( [ '192.168.1.100' ] )
            ->apply();

        $error = new WP_Error( 'invalid_password', 'Invalid password' );

        $start = microtime( true );
        wldelay_auth_login( $error, 'wrongpassword' );
        $elapsed = microtime( true ) - $start;

        // Should have delay applied
        $this->assertGreaterThanOrEqual( 0.9, $elapsed, 'Non-whitelisted IP should get delay' );
    }

    /**
     * Test whitelisted IP bypasses lockout.
     */
    public function test_whitelisted_ip_bypasses_lockout() {
        WLDelay_Test_Fixture::make()
            ->with_current_ip( '192.168.1.100' )
            ->with_options( [
                'wldelay_lockout_enabled'   => true,
                'wldelay_lockout_threshold' => 3,
                'wldelay_lockout_duration'  => 60,
            ] )
            ->with_whitelist( [ '192.168.1.100' ] )
            ->with_lockout( '192.168.1.100' ) // Simulate being locked out.
            ->apply();

        $error = new WP_Error( 'invalid_password', 'Invalid password' );
        $result = wldelay_auth_login( $error, 'wrongpassword' );

        // Whitelisted IP should bypass lockout and return original error
        $this->assertInstanceOf( WP_Error::class, $result );
        $this->assertEquals( 'invalid_password', $result->get_error_code() );
    }

    /**
     * Test whitelisted IP on successful login returns user immediately.
     */
    public function test_whitelisted_ip_successful_login() {
        WLDelay_Test_Fixture::make()
            ->with_current_ip( '192.168.1.100' )
            ->with_whitelist( [ '192.168.1.100' ] )
            ->apply();

        $user = $this->factory->user->create_and_get( [
            'user_login' => 'testuser',
            'user_pass' => 'testpassword',
        ] );

        $result = wldelay_auth_login( $user, 'testpassword' );

        $this->assertInstanceOf( WP_User::class, $result );
        $this->assertEquals( $user->ID, $result->ID );
    }

    /**
     * Test empty whitelist doesn't match any IP.
     */
    public function test_empty_whitelist_matches_nothing() {
        WLDelay_Test_Fixture::make()
            ->with_current_ip( '192.168.1.1' )
            ->with_options( [
                'wldelay_whitelist_enabled' => true,
                'wldelay_whitelist_ips'     => '',
            ] )
            ->apply();

        $this->assertFalse( wldelay_is_ip_whitelisted() );
    }

    /**
     * Test whitelist with multiple entries.
     */
    public function test_whitelist_multiple_entries() {
        WLDelay_Test_Fixture::make()
            ->with_whitelist( [ '192.168.1.1', '10.0.0.0/8', '172.16.0.100' ] )
            ->apply();

        // Test exact match
        $_SERVER['REMOTE_ADDR'] = '192.168.1.1';
        $this->assertTrue( wldelay_is_ip_whitelisted() );

        // Test CIDR match
        $_SERVER['REMOTE_ADDR'] = '10.50.100.200';
        $this->assertTrue( wldelay_is_ip_whitelisted() );

        // Test another exact match
        $_SERVER['REMOTE_ADDR'] = '172.16.0.100';
        $this->assertTrue( wldelay_is_ip_whitelisted() );

        // Test non-match
        $_SERVER['REMOTE_ADDR'] = '192.168.2.1';
        $this->assertFalse( wldelay_is_ip_whitelisted() );
    }
}
