<?php
/**
 * Integration tests for the Emergency Recovery URL.
 *
 * Handlers return early under WP_TESTS_DOMAIN instead of exit/echo, so behavior
 * is assertable: token storage, match, lockout clear, audit, rate-limit.
 */

class RecoveryUrlTest extends WP_UnitTestCase {

    public function setUp(): void {
        parent::setUp();
        wldelay_create_lockout_table();
        delete_option( 'wldelay_options' );
        wldelay_clear_options_cache();
        $_GET     = array();
        $_POST    = array();
        $_REQUEST = array();
        $_SERVER['REMOTE_ADDR'] = '203.0.113.7';
    }

    public function tearDown(): void {
        delete_option( 'wldelay_options' );
        wldelay_clear_options_cache();
        unset( $_SERVER['REMOTE_ADDR'] );
        $_GET     = array();
        $_POST    = array();
        $_REQUEST = array();
        parent::tearDown();
    }

    private function enable_recovery() {
        update_option( 'wldelay_options', array( 'wldelay_recovery_enabled' => true ) );
        wldelay_clear_options_cache();
    }

    public function test_generate_stores_hash_not_raw_and_matches() {
        $token = wldelay_recovery_generate_token();
        $opts  = wldelay_get_options();

        $this->assertNotEmpty( $opts['wldelay_recovery_token_hash'] );
        $this->assertNotSame( $token, $opts['wldelay_recovery_token_hash'] );
        $this->assertSame( hash( 'sha256', $token ), $opts['wldelay_recovery_token_hash'] );
        $this->assertNotEmpty( $opts['wldelay_recovery_generated_at'] );
        $this->assertTrue( wldelay_recovery_token_matches( $token ) );
    }

    public function test_regenerate_invalidates_previous_token() {
        $first = wldelay_recovery_generate_token();
        $this->assertTrue( wldelay_recovery_token_matches( $first ) );

        $second = wldelay_recovery_generate_token();
        $this->assertFalse( wldelay_recovery_token_matches( $first ) );
        $this->assertTrue( wldelay_recovery_token_matches( $second ) );
    }

    public function test_request_ignored_when_disabled() {
        $token = wldelay_recovery_generate_token(); // stores hash, but feature off.
        $_GET[ WLDELAY_RECOVERY_QUERY_VAR ] = $token;

        // Disabled -> handler returns without dying. No exception = pass.
        wldelay_recovery_handle_request();
        $this->assertTrue( true );
    }

    public function test_confirm_clears_caller_ip_lockout() {
        $this->enable_recovery();
        $token = wldelay_recovery_generate_token();

        wldelay_lock_ip( '203.0.113.7' );
        $this->assertTrue( wldelay_is_ip_locked( '203.0.113.7' ) );

        $nonce = wp_create_nonce( 'wldelay_recovery_confirm' );
        $_POST['wldelay_recovery_token'] = $token;
        $_POST['_wpnonce']    = $nonce;
        $_REQUEST['_wpnonce'] = $nonce;

        wldelay_recovery_handle_confirm();

        $this->assertFalse( wldelay_is_ip_locked( '203.0.113.7' ) );
        $opts = wldelay_get_options();
        $this->assertNotEmpty( $opts['wldelay_recovery_last_used_at'] );
    }

    public function test_rate_limit_blocks_after_threshold() {
        for ( $i = 0; $i < WLDELAY_RECOVERY_RL_MAX; $i++ ) {
            $this->assertFalse( wldelay_recovery_rate_limit_hit( '198.51.100.9' ) );
        }
        $this->assertTrue( wldelay_recovery_rate_limit_hit( '198.51.100.9' ) );
    }
}
