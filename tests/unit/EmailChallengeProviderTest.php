<?php
/**
 * Unit tests for the email one-time-code challenge provider.
 */

use Brain\Monkey\Functions;

class EmailChallengeProviderTest extends LDS_Unit_Test_Case {

    protected function setUp(): void {
        parent::setUp();
        Functions\when( 'wp_hash' )->alias( function ( $s ) { return 'h:' . $s; } );
        Functions\when( 'wp_rand' )->justReturn( 123456 );
        Functions\when( '__' )->returnArg( 1 );
        Functions\when( 'esc_html__' )->returnArg( 1 );
        Functions\when( 'get_transient' )->justReturn( false );
        Functions\when( 'set_transient' )->justReturn( true );
    }

    public function test_is_available_false_without_resolvable_user() {
        Functions\when( 'get_user_by' )->justReturn( false );
        $provider = new LDS_Email_Challenge_Provider();
        $this->assertFalse( $provider->is_available( 'ghost', '203.0.113.9' ) );
    }

    public function test_issue_sends_mail_and_stores_hashed_code() {
        Functions\when( 'get_user_by' )->justReturn( $this->makeUser( 'bob@example.com' ) );
        Functions\expect( 'wp_mail' )->once()->andReturn( true );

        $provider = new LDS_Email_Challenge_Provider();
        $state    = $provider->issue( 'bob', '203.0.113.9' );
        $this->assertSame( wp_hash( '123456' ), $state['answer'] );
        $this->assertTrue( $provider->verify( '123456', $state, 'bob', '203.0.113.9' ) );
    }

    public function test_issue_preserves_prior_code_when_rate_limited() {
        Functions\when( 'get_user_by' )->justReturn( $this->makeUser( 'bob@example.com' ) );
        // rate-limit counter at cap (5); challenge state holds a prior email code.
        Functions\when( 'get_transient' )->alias( function ( $key ) {
            if ( 0 === strpos( (string) $key, 'wldelay_challenge_email_rl_' ) ) {
                return 5;
            }
            return array( 'provider' => 'email', 'answer' => 'h:PRIOR' );
        } );
        Functions\expect( 'wp_mail' )->never();

        $provider = new LDS_Email_Challenge_Provider();
        $state    = $provider->issue( 'bob', '203.0.113.9' );
        $this->assertSame( 'h:PRIOR', $state['answer'], 'rate-limited issue must not clobber the delivered code' );
    }

    public function test_issue_fails_closed_when_send_fails_and_no_prior() {
        Functions\when( 'get_user_by' )->justReturn( $this->makeUser( 'bob@example.com' ) );
        Functions\when( 'get_transient' )->justReturn( false ); // no rl count, no prior state
        Functions\when( 'wp_generate_password' )->justReturn( 'RANDOMFALLBACK' );
        Functions\when( 'wp_mail' )->justReturn( false ); // delivery failed

        $provider = new LDS_Email_Challenge_Provider();
        $state    = $provider->issue( 'bob', '203.0.113.9' );
        // Unmatchable: answer is the hash of a random string, never '123456'.
        $this->assertSame( wp_hash( 'RANDOMFALLBACK' ), $state['answer'] );
        $this->assertFalse( $provider->verify( '123456', $state, 'bob', '203.0.113.9' ) );
    }

    /** Helper: minimal WP_User double with user_email. */
    private function makeUser( $email ) {
        if ( ! class_exists( 'WP_User' ) ) {
            eval( 'class WP_User { public $user_email; }' );
        }
        $u             = new WP_User();
        $u->user_email = $email;
        return $u;
    }
}
