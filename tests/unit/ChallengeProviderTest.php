<?php
/**
 * Unit tests for the challenge provider registry + math provider.
 */

use Brain\Monkey\Functions;

class ChallengeProviderTest extends LDS_Unit_Test_Case {

    protected function setUp(): void {
        parent::setUp();
        Functions\when( 'wp_hash' )->alias( function ( $s ) { return 'h:' . $s; } );
        Functions\when( 'wp_rand' )->justReturn( 4 );
        Functions\when( '__' )->returnArg( 1 );
        Functions\when( 'esc_html' )->returnArg( 1 );
        Functions\when( 'esc_html__' )->returnArg( 1 );
    }

    public function test_registry_contains_three_builtin_providers() {
        Functions\when( 'apply_filters' )->alias( function ( $tag, $value ) { return $value; } );
        $providers = wldelay_get_challenge_providers();
        $this->assertArrayHasKey( 'math', $providers );
        $this->assertArrayHasKey( 'email', $providers );
        $this->assertArrayHasKey( 'pow', $providers );
    }

    public function test_active_provider_falls_back_to_math_for_unknown_id() {
        Functions\when( 'apply_filters' )->alias( function ( $tag, $value ) { return $value; } );
        $provider = wldelay_get_active_challenge_provider( array( 'wldelay_challenge_mode_provider' => 'nope' ) );
        $this->assertSame( 'math', $provider->id() );
    }

    public function test_math_issue_then_verify_roundtrip() {
        $provider = new LDS_Math_Challenge_Provider();
        $state    = $provider->issue( 'bob', '203.0.113.9' );
        // wp_rand stubbed to 4 => 4 + 4 = 8.
        $this->assertTrue( $provider->verify( '8', $state, 'bob', '203.0.113.9' ) );
        $this->assertFalse( $provider->verify( '9', $state, 'bob', '203.0.113.9' ) );
    }

    public function test_active_provider_hard_fallback_when_math_removed() {
        // A filter that empties the registry must not yield a null provider.
        Functions\when( 'apply_filters' )->alias( function ( $tag, $value ) { return array(); } );
        $provider = wldelay_get_active_challenge_provider( array( 'wldelay_challenge_mode_provider' => 'math' ) );
        $this->assertInstanceOf( 'LDS_Math_Challenge_Provider', $provider );
    }

    public function test_custom_provider_can_register_via_filter() {
        Functions\when( 'apply_filters' )->alias( function ( $tag, $value ) {
            $value['stub'] = new LDS_Math_Challenge_Provider();
            return $value;
        } );
        $this->assertNotNull( wldelay_get_challenge_provider( 'stub' ) );
    }
}
