<?php
/**
 * Unit tests for the proof-of-work challenge provider.
 */

use Brain\Monkey\Functions;

class PowChallengeProviderTest extends LDS_Unit_Test_Case {

    protected function setUp(): void {
        parent::setUp();
        Functions\when( '__' )->returnArg( 1 );
        Functions\when( 'esc_html__' )->returnArg( 1 );
        Functions\when( 'wp_json_encode' )->alias( 'json_encode' );
        Functions\when( 'wp_generate_password' )->justReturn( 'FIXEDCHALLENGE01' );
    }

    public function test_verify_accepts_nonce_meeting_difficulty() {
        $provider = new LDS_Pow_Challenge_Provider();
        $state    = array( 'challenge' => 'abc', 'difficulty' => 2 );
        // Brute a nonce that yields sha256 with 2 leading zeros for 'abc'.
        $nonce = '';
        for ( $i = 0; $i < 100000; $i++ ) {
            if ( 0 === strncmp( hash( 'sha256', 'abc' . $i ), '00', 2 ) ) {
                $nonce = (string) $i;
                break;
            }
        }
        $this->assertNotSame( '', $nonce, 'precondition: found a nonce' );
        $this->assertTrue( $provider->verify( $nonce, $state, 'bob', '203.0.113.9' ) );
    }

    public function test_verify_rejects_bad_nonce_and_empty() {
        $provider = new LDS_Pow_Challenge_Provider();
        $state    = array( 'challenge' => 'abc', 'difficulty' => 6 );
        $this->assertFalse( $provider->verify( '1', $state, 'bob', '203.0.113.9' ) );
        $this->assertFalse( $provider->verify( '', $state, 'bob', '203.0.113.9' ) );
    }

    public function test_issue_returns_challenge_and_difficulty() {
        $provider = new LDS_Pow_Challenge_Provider();
        $state    = $provider->issue( 'bob', '203.0.113.9' );
        $this->assertSame( 'FIXEDCHALLENGE01', $state['challenge'] );
        $this->assertArrayHasKey( 'difficulty', $state );
    }
}
