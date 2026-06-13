<?php
/**
 * Unit tests for the botnet / credential-stuffing detection module (F-1-9).
 *
 * Mirrors PipelineTest.php conventions:
 *  - setUp() stubs gate collaborators with happy-path defaults.
 *  - stub_actions() stubs side-effect collaborators EXCEPT those the test
 *    expects via Functions\expect() (Brain Monkey silently swallows expect()
 *    when the same function was already registered through when()).
 *  - All WordPress runtime functions are provided by Brain Monkey — no WP.
 */

use Brain\Monkey\Functions;
use Brain\Monkey\Filters;

class BotnetDetectionTest extends LDS_Unit_Test_Case {

    /**
     * Default happy-path returns for the collaborators that have side effects
     * or computed values.
     */
    private const ACTION_DEFAULTS = array(
        'get_transient'      => false,
        'wldelay_defer_task' => null,
        'apply_filters'      => null, // overridden per test; listed here for documentation
    );

    /**
     * Stub gate and value collaborators with sensible defaults so each test
     * only needs to override the one thing it is testing.
     *
     * The Brain Monkey gotcha: never call Functions\when() on a function you
     * also use Functions\expect() on in the same test — the when() stub
     * silently swallows the expect() invocations. Use stub_actions($except)
     * to keep them separate.
     *
     * @param array $except Function names the calling test handles via expect().
     */
    private function stub_actions( array $except = array() ) {
        if ( ! in_array( 'get_transient', $except, true ) ) {
            Functions\when( 'get_transient' )->justReturn( false );
        }
        if ( ! in_array( 'wldelay_defer_task', $except, true ) ) {
            Functions\when( 'wldelay_defer_task' )->justReturn( null );
        }
    }

    // =========================================================================
    // wldelay_botnet_get_ip_threshold() — clamp + filter
    // =========================================================================

    /**
     * Threshold below 2 is clamped up to 2 (cannot be 0 or 1).
     */
    public function test_threshold_clamped_to_minimum_2() {
        Functions\when( 'wldelay_get_options' )->justReturn(
            array( 'wldelay_botnet_ip_threshold' => 0 )
        );
        Functions\when( 'apply_filters' )->alias( function ( $tag, $value ) {
            return $value; // pass-through
        } );

        $this->assertSame( 2, wldelay_botnet_get_ip_threshold() );
    }

    /**
     * Threshold above 100 is clamped down to 100.
     */
    public function test_threshold_clamped_to_maximum_100() {
        Functions\when( 'wldelay_get_options' )->justReturn(
            array( 'wldelay_botnet_ip_threshold' => 999 )
        );
        Functions\when( 'apply_filters' )->alias( function ( $tag, $value ) {
            return $value;
        } );

        $this->assertSame( 100, wldelay_botnet_get_ip_threshold() );
    }

    /**
     * Threshold filter is applied, but the post-filter value is still floored
     * to 2 so a filter returning 1 (or 0) cannot bypass the minimum.
     */
    public function test_threshold_filter_applies_with_floor() {
        Functions\when( 'wldelay_get_options' )->justReturn(
            array( 'wldelay_botnet_ip_threshold' => 5 ) // within [2,100]
        );
        // Filter returns 1 — below the minimum.
        Functions\when( 'apply_filters' )->alias( function ( $tag, $value ) {
            if ( 'wldelay_botnet_ip_threshold' === $tag ) {
                return 1;
            }
            return $value;
        } );

        $this->assertSame( 2, wldelay_botnet_get_ip_threshold() );
    }

    // =========================================================================
    // wldelay_botnet_get_window_seconds() — clamp
    // =========================================================================

    /**
     * Window above 60 minutes is clamped to 60 * MINUTE_IN_SECONDS.
     */
    public function test_window_clamped_to_maximum_60_minutes() {
        Functions\when( 'wldelay_get_options' )->justReturn(
            array( 'wldelay_botnet_window_minutes' => 999 )
        );
        Functions\when( 'apply_filters' )->alias( function ( $tag, $value ) {
            return $value;
        } );

        $this->assertSame( 60 * MINUTE_IN_SECONDS, wldelay_botnet_get_window_seconds() );
    }

    /**
     * Window below 5 minutes is clamped to 5 * MINUTE_IN_SECONDS.
     */
    public function test_window_clamped_to_minimum_5_minutes() {
        Functions\when( 'wldelay_get_options' )->justReturn(
            array( 'wldelay_botnet_window_minutes' => 1 )
        );
        Functions\when( 'apply_filters' )->alias( function ( $tag, $value ) {
            return $value;
        } );

        $this->assertSame( 5 * MINUTE_IN_SECONDS, wldelay_botnet_get_window_seconds() );
    }

    // =========================================================================
    // wldelay_botnet_on_failed_attempt() — the hot-path listener
    // =========================================================================

    /**
     * When botnet detection is disabled, wldelay_defer_task is never called.
     */
    public function test_listener_skips_when_disabled() {
        Functions\when( 'wldelay_get_options' )->justReturn(
            array( 'wldelay_botnet_enabled' => false )
        );
        $this->stub_actions( array( 'wldelay_defer_task' ) );

        Functions\expect( 'wldelay_defer_task' )->never();

        wldelay_botnet_on_failed_attempt( array( 'username' => 'admin' ) );

        // Mockery verifies the never() expectation in tearDown; this assertion
        // tells PHPUnit the test is not risky (it has at least one check).
        $this->addToAssertionCount( 1 );
    }

    /**
     * A blank / whitespace-only username short-circuits before any deferral.
     */
    public function test_listener_skips_empty_username() {
        Functions\when( 'wldelay_get_options' )->justReturn(
            array( 'wldelay_botnet_enabled' => true )
        );
        $this->stub_actions( array( 'wldelay_defer_task' ) );

        Functions\expect( 'wldelay_defer_task' )->never();

        wldelay_botnet_on_failed_attempt( array( 'username' => '  ' ) );

        $this->addToAssertionCount( 1 );
    }

    /**
     * When the per-username cooldown transient exists, the check is skipped
     * (already alerted; don't spam the queue).
     */
    public function test_listener_skips_during_cooldown() {
        Functions\when( 'wldelay_get_options' )->justReturn(
            array( 'wldelay_botnet_enabled' => true )
        );
        // Cooldown transient is present (truthy, non-false).
        Functions\when( 'get_transient' )->justReturn( time() );
        $this->stub_actions( array( 'wldelay_defer_task', 'get_transient' ) );

        Functions\expect( 'wldelay_defer_task' )->never();

        wldelay_botnet_on_failed_attempt( array( 'username' => 'admin' ) );

        $this->addToAssertionCount( 1 );
    }

    /**
     * Happy path: enabled, non-empty username, no cooldown → one deferred task.
     */
    public function test_listener_defers_check_when_eligible() {
        Functions\when( 'wldelay_get_options' )->justReturn(
            array( 'wldelay_botnet_enabled' => true )
        );
        Functions\when( 'get_transient' )->justReturn( false ); // no cooldown

        Functions\expect( 'wldelay_defer_task' )
            ->once()
            ->with( 'botnet_check', array( 'username' => 'admin' ) );

        wldelay_botnet_on_failed_attempt( array( 'username' => 'admin' ) );

        // once() is verified by Mockery in tearDown.
        $this->addToAssertionCount( 1 );
    }
}
