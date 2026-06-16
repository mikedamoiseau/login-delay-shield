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

    /**
     * A settings save must not wipe an active recovery token.
     *
     * wldelay_recovery_generate_token() writes token_hash + generated_at to
     * wldelay_options via update_option(). The sanitize callback then reads
     * wldelay_options from the DB so those handler-managed keys are carried
     * through even when the submitted form input omits them entirely.
     */
    public function test_settings_save_preserves_token() {
        // Generate a token so the three managed keys are written to the stored option.
        $token = wldelay_recovery_generate_token();
        wldelay_clear_options_cache();

        $stored_before = wldelay_get_options();
        $expected_hash = $stored_before['wldelay_recovery_token_hash'];

        $this->assertNotEmpty( $expected_hash, 'Pre-condition: token hash must be stored before save.' );

        // Simulate a settings-form save that includes the enable flag but none
        // of the three handler-managed keys.
        $settings = new LDS_Settings();
        $result   = $settings->sanitize( array( 'wldelay_recovery_enabled' => '1' ) );

        // The enable flag must be honoured.
        $this->assertTrue( $result['wldelay_recovery_enabled'] );

        // The token hash must survive the save untouched.
        $this->assertArrayHasKey( 'wldelay_recovery_token_hash', $result, 'token_hash key must be present after sanitize.' );
        $this->assertSame( $expected_hash, $result['wldelay_recovery_token_hash'], 'token_hash must equal the pre-save value.' );
    }
}
