<?php
/**
 * Unit tests for recovery token core (hash + match + URL).
 */

use Brain\Monkey;
use Brain\Monkey\Functions;

class RecoveryTokenTest extends \PHPUnit\Framework\TestCase {

    protected function setUp(): void {
        parent::setUp();
        Monkey\setUp();
        Functions\when( 'home_url' )->alias( function ( $path = '' ) {
            return 'https://example.test' . $path;
        } );
    }

    protected function tearDown(): void {
        Monkey\tearDown();
        parent::tearDown();
    }

    public function test_hash_is_sha256_hex_of_token() {
        $this->assertSame( hash( 'sha256', 'abc' ), wldelay_recovery_hash( 'abc' ) );
    }

    public function test_token_matches_uses_stored_hash() {
        $token = 'deadbeef';
        Functions\when( 'wldelay_get_options' )->justReturn(
            array( 'wldelay_recovery_token_hash' => hash( 'sha256', $token ) )
        );
        $this->assertTrue( wldelay_recovery_token_matches( $token ) );
        $this->assertFalse( wldelay_recovery_token_matches( 'wrong' ) );
    }

    public function test_token_matches_false_when_no_hash_stored() {
        Functions\when( 'wldelay_get_options' )->justReturn( array() );
        $this->assertFalse( wldelay_recovery_token_matches( 'anything' ) );
    }

    public function test_build_url_uses_query_var() {
        $url = wldelay_recovery_build_url( 'tok123' );
        $this->assertSame( 'https://example.test/?wldelay_recovery=tok123', $url );
    }
}
