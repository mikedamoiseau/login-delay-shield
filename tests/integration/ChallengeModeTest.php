<?php
/**
 * Integration: challenge-mode enforcement.
 *
 * The interactive gate hooks wp_authenticate_user, which core fires after the
 * username is resolved but BEFORE wp_check_password() — returning a WP_Error
 * there stops authentication without the password ever being checked, and is
 * not clobberable by core's later re-authentication (unlike the `authenticate`
 * filter).
 */
class ChallengeModeTest extends WP_UnitTestCase {

    private $user;

    public function setUp(): void {
        parent::setUp();
        $_SERVER['REMOTE_ADDR'] = '203.0.113.55';
        $_POST['log']           = 'chaluser'; // real wp-login always posts an identity
        unset( $_POST['wldelay_challenge_response'] );
        delete_option( 'wldelay_options' );
        wldelay_clear_options_cache();

        $this->user = $this->factory->user->create_and_get( array(
            'user_login' => 'chaluser',
            'user_pass'  => 'correct-horse',
            'user_email' => 'chal@example.com',
        ) );

        update_option( 'wldelay_options', array(
            'wldelay_challenge_mode_enabled'   => 1,
            'wldelay_challenge_mode_threshold' => 1,
            'wldelay_challenge_mode_provider'  => 'math',
        ) );
        wldelay_clear_options_cache();

        // Push the IP's failure counter over the threshold.
        wldelay_track_failed_attempt( 'chaluser', 'wp-login' );
    }

    public function tearDown(): void {
        unset( $_POST['log'] );
        unset( $_POST['wldelay_challenge_response'] );
        unset( $_SERVER['REMOTE_ADDR'] );
        unset( $_SERVER['REQUEST_URI'] );
        unset( $_SERVER['PHP_AUTH_USER'] );
        unset( $_SERVER['PHP_AUTH_PW'] );
        delete_option( 'wldelay_options' );
        wldelay_clear_options_cache();
        parent::tearDown();
    }

    public function test_gate_hooked_on_wp_authenticate_user() {
        $this->assertSame(
            10,
            has_filter( 'wp_authenticate_user', 'wldelay_challenge_authenticate_user' ),
            'challenge gate must hook wp_authenticate_user (before wp_check_password)'
        );
    }

    public function test_missing_response_issues_challenge_and_blocks() {
        $result = wldelay_challenge_authenticate_user( $this->user, 'correct-horse' );
        $this->assertWPError( $result );
        $this->assertSame( 'wldelay_challenge_required', $result->get_error_code() );

        $state = wldelay_get_challenge_state( '203.0.113.55' );
        $this->assertNotEmpty( $state, 'a challenge was issued' );
        $this->assertSame( 'math', $state['provider'] );
    }

    public function test_correct_response_passes_through_to_user() {
        wldelay_challenge_authenticate_user( $this->user, 'correct-horse' ); // issue
        $state = wldelay_get_challenge_state( '203.0.113.55' );

        $_POST['wldelay_challenge_response'] = (string) ( (int) $state['a'] + (int) $state['b'] );
        $result = wldelay_challenge_authenticate_user( $this->user, 'correct-horse' );

        $this->assertInstanceOf( 'WP_User', $result );
        $this->assertSame( $this->user->ID, $result->ID );
        $this->assertEmpty( wldelay_get_challenge_state( '203.0.113.55' ), 'state cleared on pass' );
    }

    public function test_wrong_response_reissues_and_blocks() {
        wldelay_challenge_authenticate_user( $this->user, 'correct-horse' ); // issue
        $_POST['wldelay_challenge_response'] = '99999';
        $result = wldelay_challenge_authenticate_user( $this->user, 'correct-horse' );

        $this->assertWPError( $result );
        $this->assertSame( 'wldelay_challenge_failed', $result->get_error_code() );
    }

    public function test_disabled_challenge_is_noop() {
        update_option( 'wldelay_options', array( 'wldelay_challenge_mode_enabled' => 0 ) );
        wldelay_clear_options_cache();

        $result = wldelay_challenge_authenticate_user( $this->user, 'correct-horse' );
        $this->assertInstanceOf( 'WP_User', $result );
    }

    public function test_non_interactive_source_hard_blocks() {
        // Force the login source to xmlrpc; no challenge can be rendered there.
        $_SERVER['REQUEST_URI'] = '/xmlrpc.php';
        $result = wldelay_challenge_authenticate_user( $this->user, 'correct-horse' );

        $this->assertWPError( $result );
        $this->assertSame( 'wldelay_challenge_required', $result->get_error_code() );
        // No interactive challenge state is issued for a hard-blocked source.
        $this->assertEmpty( wldelay_get_challenge_state( '203.0.113.55' ) );
    }

    public function test_rest_application_password_hard_blocks() {
        $this->assertSame(
            6,
            has_filter( 'rest_authentication_errors', 'wldelay_challenge_rest_authentication' )
        );

        $_SERVER['PHP_AUTH_USER'] = 'chaluser';
        $_SERVER['PHP_AUTH_PW']   = 'app-pw';
        $result = wldelay_challenge_rest_authentication( null );

        $this->assertWPError( $result );
        $this->assertSame( 'wldelay_challenge_required', $result->get_error_code() );
        $this->assertSame( 403, $result->get_error_data()['status'] );
    }

    public function test_rest_guard_respects_prior_error() {
        $_SERVER['PHP_AUTH_USER'] = 'chaluser';
        $_SERVER['PHP_AUTH_PW']   = 'app-pw';
        $prior  = new WP_Error( 'existing', 'existing' );
        $result = wldelay_challenge_rest_authentication( $prior );
        $this->assertSame( $prior, $result );
    }

    public function test_render_outputs_active_provider_fields() {
        wldelay_challenge_authenticate_user( $this->user, 'correct-horse' ); // issue math
        ob_start();
        wldelay_render_challenge_field();
        $html = ob_get_clean();

        $this->assertStringContainsString( 'wldelay_challenge_response', $html );
        $this->assertStringContainsString( 'what is', $html ); // math question text
    }

    /**
     * Finding 1: under ip_username the counter is keyed by the SUBMITTED
     * identity. Authenticating by email must still be challenged even though
     * WP resolves it to a different user_login.
     */
    public function test_gate_keys_by_submitted_username_under_ip_username() {
        $_SERVER['REMOTE_ADDR'] = '198.51.100.7'; // fresh IP: no setUp failures here
        update_option( 'wldelay_options', array(
            'wldelay_challenge_mode_enabled'    => 1,
            'wldelay_challenge_mode_threshold'  => 1,
            'wldelay_challenge_mode_provider'   => 'math',
            'wldelay_lockout_attempt_strategy'  => 'ip_username',
        ) );
        wldelay_clear_options_cache();

        $_POST['log'] = 'chal@example.com'; // submitted as email
        wldelay_track_failed_attempt( wldelay_normalize_username( 'chal@example.com' ), 'wp-login' );

        $result = wldelay_challenge_authenticate_user( $this->user, 'correct-horse' );
        $this->assertWPError( $result );
        $this->assertSame( 'wldelay_challenge_required', $result->get_error_code() );
    }

    /**
     * Finding 2: the REST guard must key the counter by the PHP-auth username
     * under ip_username, not an IP-only lookup.
     */
    public function test_rest_guard_keys_by_php_auth_username_under_ip_username() {
        $_SERVER['REMOTE_ADDR'] = '198.51.100.8';
        update_option( 'wldelay_options', array(
            'wldelay_challenge_mode_enabled'   => 1,
            'wldelay_challenge_mode_threshold' => 1,
            'wldelay_challenge_mode_provider'  => 'math',
            'wldelay_lockout_attempt_strategy' => 'ip_username',
        ) );
        wldelay_clear_options_cache();

        $_SERVER['PHP_AUTH_USER'] = 'chaluser';
        $_SERVER['PHP_AUTH_PW']   = 'app-pw';
        wldelay_track_failed_attempt( 'chaluser', 'application-password' );

        $result = wldelay_challenge_rest_authentication( null );
        $this->assertWPError( $result );
        $this->assertSame( 403, $result->get_error_data()['status'] );
    }

    /**
     * Finding 3: challenge state is bound to the account it was issued for. A
     * response solved for one account cannot clear another account's challenge
     * on the same IP.
     */
    public function test_challenge_state_bound_to_account() {
        wldelay_challenge_authenticate_user( $this->user, 'correct-horse' ); // issue for chaluser
        $state  = wldelay_get_challenge_state( '203.0.113.55' );
        $answer = (string) ( (int) $state['a'] + (int) $state['b'] );

        $victim = $this->factory->user->create_and_get( array(
            'user_login' => 'victim',
            'user_pass'  => 'victim-pass',
            'user_email' => 'victim@example.com',
        ) );
        wldelay_track_failed_attempt( 'victim', 'wp-login' );

        // Attacker replays chaluser's solved answer while authenticating as victim.
        $_POST['log']                        = 'victim';
        $_POST['wldelay_challenge_response'] = $answer;
        $result = wldelay_challenge_authenticate_user( $victim, 'victim-pass' );

        $this->assertWPError( $result, 'answer bound to chaluser must not clear victim challenge' );
    }

    /**
     * Finding 5: changing the active provider invalidates an outstanding
     * challenge instead of cross-accepting a matching answer hash.
     */
    public function test_provider_change_invalidates_outstanding_challenge() {
        wldelay_challenge_authenticate_user( $this->user, 'correct-horse' ); // issue math
        $state  = wldelay_get_challenge_state( '203.0.113.55' );
        $answer = (string) ( (int) $state['a'] + (int) $state['b'] );

        $opts = get_option( 'wldelay_options' );
        $opts['wldelay_challenge_mode_provider'] = 'email';
        update_option( 'wldelay_options', $opts );
        wldelay_clear_options_cache();

        $_POST['wldelay_challenge_response'] = $answer; // stale math answer
        $result = wldelay_challenge_authenticate_user( $this->user, 'correct-horse' );

        $this->assertWPError( $result );
        $this->assertSame( 'wldelay_challenge_required', $result->get_error_code() );
    }

    /**
     * Finding 1 (residual): when no username is submitted, the failure counter
     * is recorded under the IP-only key even with ip_username; the gate must
     * key by that same empty identity, not fall back to $user->user_login.
     */
    public function test_gate_keys_by_ip_only_when_no_username_submitted() {
        $_SERVER['REMOTE_ADDR'] = '198.51.100.9';
        unset( $_POST['log'] ); // programmatic sign-in: no posted identity
        update_option( 'wldelay_options', array(
            'wldelay_challenge_mode_enabled'   => 1,
            'wldelay_challenge_mode_threshold' => 1,
            'wldelay_challenge_mode_provider'  => 'math',
            'wldelay_lockout_attempt_strategy' => 'ip_username',
        ) );
        wldelay_clear_options_cache();

        wldelay_track_failed_attempt( '', 'wp-login' ); // recorded under IP-only key

        $result = wldelay_challenge_authenticate_user( $this->user, 'correct-horse' );
        $this->assertWPError( $result );
        $this->assertSame( 'wldelay_challenge_required', $result->get_error_code() );

        // And the empty-identity challenge must be SOLVABLE (not permanently
        // stale): solving the issued math question passes.
        $state = wldelay_get_challenge_state( '198.51.100.9' );
        $_POST['wldelay_challenge_response'] = (string) ( (int) $state['a'] + (int) $state['b'] );
        $solved = wldelay_challenge_authenticate_user( $this->user, 'correct-horse' );
        $this->assertInstanceOf( 'WP_User', $solved );
    }

    /**
     * The email code is abandoned after a bounded number of wrong answers, so a
     * single 6-digit code cannot be ground indefinitely.
     */
    public function test_email_challenge_abandoned_after_max_wrong_answers() {
        update_option( 'wldelay_options', array(
            'wldelay_challenge_mode_enabled'   => 1,
            'wldelay_challenge_mode_threshold' => 1,
            'wldelay_challenge_mode_provider'  => 'email',
        ) );
        wldelay_clear_options_cache();

        wldelay_challenge_authenticate_user( $this->user, 'correct-horse' ); // issue
        $orig = wldelay_get_challenge_state( '203.0.113.55' );

        for ( $i = 0; $i < 5; $i++ ) {
            $_POST['wldelay_challenge_response'] = 'nope-' . $i; // non-numeric: always wrong
            wldelay_challenge_authenticate_user( $this->user, 'correct-horse' );
        }

        // After the cap the challenge is abandoned (state consumed, not restored).
        $after = wldelay_get_challenge_state( '203.0.113.55' );
        $this->assertTrue(
            empty( $after ) || $after['answer'] !== $orig['answer'],
            'the same code must not survive past the wrong-answer cap'
        );
    }

    /**
     * Finding 4 (regression guard): a wrong email answer must NOT destroy the
     * already-delivered code. Consume-before-verify deletes state; the wrong
     * path restores the same challenge instead of minting/sending a new one.
     */
    public function test_email_wrong_answer_preserves_delivered_code() {
        update_option( 'wldelay_options', array(
            'wldelay_challenge_mode_enabled'   => 1,
            'wldelay_challenge_mode_threshold' => 1,
            'wldelay_challenge_mode_provider'  => 'email',
        ) );
        wldelay_clear_options_cache();

        wldelay_challenge_authenticate_user( $this->user, 'correct-horse' ); // issue email
        $before = wldelay_get_challenge_state( '203.0.113.55' );
        $this->assertSame( 'email', $before['provider'] );

        $_POST['wldelay_challenge_response'] = 'nope-not-the-code'; // non-numeric: always wrong
        $result = wldelay_challenge_authenticate_user( $this->user, 'correct-horse' );
        $this->assertWPError( $result );
        $this->assertSame( 'wldelay_challenge_failed', $result->get_error_code() );

        $after = wldelay_get_challenge_state( '203.0.113.55' );
        $this->assertSame(
            $before['answer'],
            $after['answer'],
            'delivered email code must survive a wrong answer'
        );
    }

    /**
     * Finding 4 (mitigation): a solved challenge is consumed, so replaying the
     * same response is rejected and a fresh challenge is required.
     */
    public function test_solved_challenge_is_single_use() {
        wldelay_challenge_authenticate_user( $this->user, 'correct-horse' ); // issue
        $state  = wldelay_get_challenge_state( '203.0.113.55' );
        $answer = (string) ( (int) $state['a'] + (int) $state['b'] );

        $_POST['wldelay_challenge_response'] = $answer;
        $first  = wldelay_challenge_authenticate_user( $this->user, 'correct-horse' );
        $this->assertInstanceOf( 'WP_User', $first );

        $second = wldelay_challenge_authenticate_user( $this->user, 'correct-horse' );
        $this->assertWPError( $second, 'consumed challenge cannot be replayed' );
    }
}
