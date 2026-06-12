<?php
/**
 * Unit tests for the shared failed-authentication pipeline (F-2-4).
 */

use Brain\Monkey\Functions;

class PipelineTest extends LDS_Unit_Test_Case {

    /**
     * Default happy-path return values for the pipeline's action
     * collaborators (the functions with side effects / computed values).
     *
     * @var array
     */
    private const ACTION_DEFAULTS = array(
        'wldelay_get_failure_count'    => 2,
        'wldelay_get_delay_value'      => 4,
        'wldelay_track_failed_attempt' => 3,
        'wldelay_log_failed_attempt'   => null,
        'wldelay_emit_event'           => null,
        'wldelay_is_ip_locked'         => false,
    );

    /**
     * Stub the gate collaborators with happy-path defaults; individual
     * tests override these with Functions\when().
     *
     * The action collaborators are NOT stubbed here: Brain Monkey does not
     * allow Functions\expect() on a function already registered through
     * Functions\when() (the when() stub silently swallows the calls), so
     * tests stub them via stub_actions() excluding the ones they expect().
     */
    protected function setUp(): void {
        parent::setUp();
        Functions\when( 'wldelay_is_safe_mode' )->justReturn( false );
        Functions\when( 'wldelay_is_ip_whitelisted' )->justReturn( false );
        Functions\when( 'wldelay_get_client_ip' )->justReturn( '203.0.113.9' );
        Functions\when( 'wldelay_get_options' )->justReturn( array( 'wldelay_lockout_enabled' => 1 ) );
    }

    /**
     * Stub the action collaborators with their happy-path defaults, except
     * the ones the calling test sets Functions\expect() on.
     *
     * @param array $except Function names the test handles via Functions\expect().
     */
    private function stub_actions( array $except = array() ) {
        foreach ( self::ACTION_DEFAULTS as $function => $return ) {
            if ( ! in_array( $function, $except, true ) ) {
                Functions\when( $function )->justReturn( $return );
            }
        }
    }

    /**
     * Safe mode gates the pipeline with no side effects.
     */
    public function test_safe_mode_returns_unprocessed() {
        $this->stub_actions();
        Functions\when( 'wldelay_is_safe_mode' )->justReturn( true );
        $r = wldelay_process_failed_attempt( 'admin', 'wp-login' );
        $this->assertFalse( $r['processed'] );
        $this->assertSame( 0, $r['failed_attempts'] );
    }

    /**
     * Whitelisted IPs bypass the pipeline.
     */
    public function test_whitelisted_ip_returns_unprocessed() {
        $this->stub_actions();
        Functions\when( 'wldelay_is_ip_whitelisted' )->justReturn( true );
        $r = wldelay_process_failed_attempt( 'admin', 'wp-login' );
        $this->assertFalse( $r['processed'] );
    }

    /**
     * Missing client IP gates the pipeline.
     */
    public function test_empty_ip_returns_unprocessed() {
        $this->stub_actions();
        Functions\when( 'wldelay_get_client_ip' )->justReturn( '' );
        $r = wldelay_process_failed_attempt( 'admin', 'wp-login' );
        $this->assertFalse( $r['processed'] );
    }

    /**
     * Default run tracks, logs, emits, and returns the computed delay.
     */
    public function test_full_run_tracks_logs_and_returns_delay() {
        $this->stub_actions(
            array( 'wldelay_track_failed_attempt', 'wldelay_log_failed_attempt', 'wldelay_emit_event' )
        );
        Functions\expect( 'wldelay_track_failed_attempt' )->once()->with( 'admin', 'rest' )->andReturn( 3 );
        Functions\expect( 'wldelay_log_failed_attempt' )->once()->with( '203.0.113.9', 'admin', 'rest' );
        Functions\expect( 'wldelay_emit_event' )->once()->with(
            'failed_attempt',
            array(
                'ip'              => '203.0.113.9',
                'username'        => 'admin',
                'source'          => 'rest',
                'failed_attempts' => 3,
            )
        );
        $r = wldelay_process_failed_attempt( 'admin', 'rest' );
        $this->assertTrue( $r['processed'] );
        $this->assertSame( 3, $r['failed_attempts'] );
        $this->assertSame( 4, $r['delay'] );
    }

    /**
     * The progressive delay is computed from the PRE-increment failure count:
     * wldelay_get_delay_value must run before wldelay_track_failed_attempt.
     */
    public function test_delay_computed_before_tracking() {
        $this->stub_actions(
            array( 'wldelay_get_delay_value', 'wldelay_track_failed_attempt' )
        );
        $calls = array();
        Functions\when( 'wldelay_get_delay_value' )->alias(
            function () use ( &$calls ) {
                $calls[] = 'delay';
                return 4;
            }
        );
        Functions\when( 'wldelay_track_failed_attempt' )->alias(
            function () use ( &$calls ) {
                $calls[] = 'track';
                return 3;
            }
        );
        wldelay_process_failed_attempt( 'admin', 'rest' );
        $this->assertSame( array( 'delay', 'track' ), $calls );
    }

    /**
     * track=false skips the counter but still logs and emits.
     */
    public function test_track_false_skips_counter_but_still_logs_and_emits() {
        $this->stub_actions(
            array( 'wldelay_track_failed_attempt', 'wldelay_log_failed_attempt', 'wldelay_emit_event' )
        );
        Functions\expect( 'wldelay_track_failed_attempt' )->never();
        Functions\expect( 'wldelay_log_failed_attempt' )->once();
        Functions\expect( 'wldelay_emit_event' )->once();
        $r = wldelay_process_failed_attempt( 'admin', 'wp-login', array( 'track' => false ) );
        $this->assertSame( 0, $r['failed_attempts'] );
    }

    /**
     * log=false skips both the DB log and the event emission.
     */
    public function test_log_false_skips_log_and_event() {
        $this->stub_actions(
            array( 'wldelay_log_failed_attempt', 'wldelay_emit_event' )
        );
        Functions\expect( 'wldelay_log_failed_attempt' )->never();
        Functions\expect( 'wldelay_emit_event' )->never();
        $r = wldelay_process_failed_attempt( 'admin', 'wp-login', array( 'log' => false ) );
        // Mockery verifies the never() expectations in tearDown.
        $this->assertTrue( $r['processed'] );
    }

    /**
     * delay=false skips the progressive delay computation entirely.
     */
    public function test_delay_false_skips_delay_computation() {
        $this->stub_actions(
            array( 'wldelay_get_failure_count', 'wldelay_get_delay_value' )
        );
        Functions\expect( 'wldelay_get_failure_count' )->never();
        Functions\expect( 'wldelay_get_delay_value' )->never();
        $r = wldelay_process_failed_attempt( 'admin', 'wp-login', array( 'delay' => false ) );
        $this->assertSame( 0, $r['delay'] );
    }

    /**
     * Locked flag reflects the lockout state after the attempt.
     */
    public function test_locked_flag_reflects_lockout_state() {
        $this->stub_actions();
        Functions\when( 'wldelay_is_ip_locked' )->justReturn( true );
        $r = wldelay_process_failed_attempt( 'admin', 'wp-login' );
        $this->assertTrue( $r['locked'] );
    }

    /**
     * Untracked log paths still emit the current failure counter in the
     * event payload; the return-value contract stays at 0.
     */
    public function test_untracked_log_emits_current_counter_in_payload() {
        $this->stub_actions(
            array( 'wldelay_emit_event', 'wldelay_get_failure_count' )
        );
        Functions\when( 'wldelay_get_failure_count' )->justReturn( 7 );
        Functions\expect( 'wldelay_emit_event' )->once()->with(
            'failed_attempt',
            array(
                'ip'              => '203.0.113.9',
                'username'        => 'admin',
                'source'          => 'wp-login',
                'failed_attempts' => 7,
            )
        );
        $r = wldelay_process_failed_attempt( 'admin', 'wp-login', array( 'track' => false, 'delay' => false ) );
        $this->assertSame( 0, $r['failed_attempts'] ); // return contract unchanged
    }

    /**
     * lockout=false skips the lockout lookup entirely.
     */
    public function test_lockout_false_skips_lockout_lookup() {
        $this->stub_actions(
            array( 'wldelay_is_ip_locked' )
        );
        Functions\expect( 'wldelay_is_ip_locked' )->never();
        $r = wldelay_process_failed_attempt( 'admin', 'wp-login', array( 'lockout' => false ) );
        $this->assertFalse( $r['locked'] );
    }
}
