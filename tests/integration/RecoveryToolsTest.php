<?php
/**
 * Integration tests for recovery tools (unlock current IP + CLI helpers).
 */

class RecoveryToolsTest extends WP_UnitTestCase {

    public function setUp(): void {
        parent::setUp();

        delete_option( 'wldelay_options' );
        delete_option( wldelay_get_transient_registry_option_name() );
        wldelay_clear_options_cache();

        $_SERVER['REMOTE_ADDR'] = '192.168.50.10';
    }

    public function tearDown(): void {
        unset( $_SERVER['REMOTE_ADDR'] );

        delete_option( 'wldelay_options' );
        delete_option( wldelay_get_transient_registry_option_name() );
        wldelay_clear_options_cache();

        parent::tearDown();
    }

    public function test_delete_lockout_for_ip_removes_lockout_and_failure_keys() {
        $ip = '192.168.50.10';

        $lockout_key = wldelay_get_lockout_transient_key( $ip );
        $fails_key = wldelay_get_failure_transient_key( $ip );

        set_transient( $lockout_key, time(), 10 * MINUTE_IN_SECONDS );
        set_transient( $fails_key, 5, HOUR_IN_SECONDS );

        wldelay_register_transient_key( $lockout_key );
        wldelay_register_transient_key( $fails_key );

        $deleted = wldelay_delete_lockout_for_ip( $ip );

        $this->assertSame( 2, $deleted );
        $this->assertFalse( get_transient( $lockout_key ) );
        $this->assertFalse( get_transient( $fails_key ) );
    }

    public function test_delete_lockout_for_ip_removes_ip_username_keys_when_username_provided() {
        $ip = '192.168.50.20';
        $username = 'admin';
        $pair_options = [ 'wldelay_lockout_attempt_strategy' => 'ip_username' ];

        $lockout_key = wldelay_get_lockout_transient_key( $ip, $username, $pair_options );
        $fails_key = wldelay_get_failure_transient_key( $ip, $username, $pair_options );

        set_transient( $lockout_key, time(), 10 * MINUTE_IN_SECONDS );
        set_transient( $fails_key, 3, HOUR_IN_SECONDS );

        wldelay_register_transient_key( $lockout_key );
        wldelay_register_transient_key( $fails_key );

        $deleted = wldelay_delete_lockout_for_ip( $ip, $username );

        $this->assertSame( 2, $deleted );
        $this->assertFalse( get_transient( $lockout_key ) );
        $this->assertFalse( get_transient( $fails_key ) );
    }

    public function test_flush_lockout_transients_removes_lockouts_and_failure_counters() {
        $ip_one = '192.168.50.30';
        $ip_two = '192.168.50.31';

        $lockout_one = wldelay_get_lockout_transient_key( $ip_one );
        $lockout_two = wldelay_get_lockout_transient_key( $ip_two );
        $fails_one = wldelay_get_failure_transient_key( $ip_one );
        $fails_two = wldelay_get_failure_transient_key( $ip_two );

        set_transient( $lockout_one, time(), 10 * MINUTE_IN_SECONDS );
        set_transient( $lockout_two, time(), 10 * MINUTE_IN_SECONDS );
        set_transient( $fails_one, 2, HOUR_IN_SECONDS );
        set_transient( $fails_two, 4, HOUR_IN_SECONDS );

        wldelay_register_transient_key( $lockout_one );
        wldelay_register_transient_key( $lockout_two );
        wldelay_register_transient_key( $fails_one );
        wldelay_register_transient_key( $fails_two );

        $deleted = wldelay_flush_lockout_transients();

        $this->assertGreaterThanOrEqual( 4, $deleted );
        $this->assertFalse( get_transient( $lockout_one ) );
        $this->assertFalse( get_transient( $lockout_two ) );
        $this->assertFalse( get_transient( $fails_one ) );
        $this->assertFalse( get_transient( $fails_two ) );
    }

    public function test_unlock_current_ip_url_contains_expected_action_and_nonce() {
        $url = wldelay_get_unlock_current_ip_url();

        $this->assertStringContainsString( 'action=wldelay_unlock_current_ip', $url );
        $this->assertStringContainsString( '_wpnonce=', $url );
    }
}
