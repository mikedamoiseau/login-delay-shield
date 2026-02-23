<?php
/**
 * Integration tests for recovery tools (unlock current IP + CLI helpers).
 */

class RecoveryToolsTest extends WP_UnitTestCase {

    public function setUp(): void {
        parent::setUp();

        delete_option( 'wldelay_options' );
        wldelay_clear_options_cache();

        $_SERVER['REMOTE_ADDR'] = '192.168.50.10';
    }

    public function tearDown(): void {
        unset( $_SERVER['REMOTE_ADDR'] );

        delete_option( 'wldelay_options' );
        wldelay_clear_options_cache();

        parent::tearDown();
    }

    public function test_delete_lockout_for_ip_removes_ip_only_key() {
        $ip = '192.168.50.10';

        wldelay_lock_ip( $ip );
        $this->assertTrue( wldelay_is_ip_locked( $ip ) );

        $deleted = wldelay_delete_lockout_for_ip( $ip );

        $this->assertSame( 1, $deleted );
        $this->assertFalse( wldelay_is_ip_locked( $ip ) );
    }

    public function test_delete_lockout_for_ip_removes_ip_username_key_when_username_provided() {
        $ip = '192.168.50.20';
        $username = 'admin';
        $pair_options = [ 'wldelay_lockout_attempt_strategy' => 'ip_username' ];
        $key = wldelay_get_lockout_transient_key( $ip, $username, $pair_options );

        set_transient( $key, time(), 10 * MINUTE_IN_SECONDS );
        $this->assertNotFalse( get_transient( $key ) );

        $deleted = wldelay_delete_lockout_for_ip( $ip, $username );

        $this->assertSame( 1, $deleted );
        $this->assertFalse( get_transient( $key ) );
    }

    public function test_flush_lockout_transients_removes_all_lockouts() {
        $ip_one = '192.168.50.30';
        $ip_two = '192.168.50.31';

        wldelay_lock_ip( $ip_one );
        wldelay_lock_ip( $ip_two );

        $this->assertTrue( wldelay_is_ip_locked( $ip_one ) );
        $this->assertTrue( wldelay_is_ip_locked( $ip_two ) );

        $deleted = wldelay_flush_lockout_transients();

        $this->assertGreaterThanOrEqual( 2, $deleted );
        $this->assertFalse( wldelay_is_ip_locked( $ip_one ) );
        $this->assertFalse( wldelay_is_ip_locked( $ip_two ) );
    }

    public function test_unlock_current_ip_url_contains_expected_action_and_nonce() {
        $url = wldelay_get_unlock_current_ip_url();

        $this->assertStringContainsString( 'action=wldelay_unlock_current_ip', $url );
        $this->assertStringContainsString( '_wpnonce=', $url );
    }
}
