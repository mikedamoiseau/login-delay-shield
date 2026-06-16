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

    public function test_age_days_null_when_never_generated() {
        Functions\when( 'wldelay_get_options' )->justReturn( array( 'wldelay_recovery_generated_at' => '' ) );
        $this->assertNull( wldelay_recovery_generated_age_days() );
    }

    public function test_age_days_and_needs_rotation() {
        Functions\when( 'current_time' )->justReturn( '2026-01-01 00:00:00' );
        $past = gmdate( 'Y-m-d H:i:s', strtotime( '2026-01-01 00:00:00' ) - ( 100 * DAY_IN_SECONDS ) );
        Functions\when( 'wldelay_get_options' )->justReturn( array( 'wldelay_recovery_generated_at' => $past ) );

        $this->assertSame( 100, wldelay_recovery_generated_age_days() );
        $this->assertTrue( wldelay_recovery_needs_rotation() );
    }

    public function test_needs_rotation_false_when_fresh() {
        Functions\when( 'current_time' )->justReturn( '2026-01-01 00:00:00' );
        $recent = gmdate( 'Y-m-d H:i:s', strtotime( '2026-01-01 00:00:00' ) - ( 10 * DAY_IN_SECONDS ) );
        Functions\when( 'wldelay_get_options' )->justReturn( array( 'wldelay_recovery_generated_at' => $recent ) );
        $this->assertFalse( wldelay_recovery_needs_rotation() );
    }
}
