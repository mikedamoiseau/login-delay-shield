<?php
/**
 * Integration tests for the unified async task + event dispatch layer (F-4-9).
 *
 * Verifies the layer against a real WordPress runtime: events reach real
 * subscribers, deferred tasks run on the shutdown flush hook and are cleared
 * afterwards, and the cron backstop is scheduled on activation / removed on
 * deactivation.
 */

class AsyncTaskTest extends WP_UnitTestCase {

    public function tearDown(): void {
        wldelay_reset_deferred_tasks();

        $timestamp = wp_next_scheduled( 'wldelay_async_cron' );
        if ( $timestamp ) {
            wp_unschedule_event( $timestamp, 'wldelay_async_cron' );
        }

        parent::tearDown();
    }

    /**
     * wldelay_emit_event triggers a listener subscribed via wldelay_on_event,
     * passing the payload through.
     */
    public function test_emit_event_triggers_subscribed_listener() {
        $received = null;

        wldelay_on_event( 'phpunit_probe', function ( $payload ) use ( &$received ) {
            $received = $payload;
        } );

        wldelay_emit_event( 'phpunit_probe', array( 'answer' => 42 ) );

        $this->assertSame( array( 'answer' => 42 ), $received );
    }

    /**
     * The generic 'wldelay_event' hook fires alongside the namespaced one, so a
     * single subscriber can observe every event (the SIEM/audit seam).
     */
    public function test_generic_event_hook_receives_name_and_payload() {
        $seen = array();

        add_action( 'wldelay_event', function ( $name, $payload ) use ( &$seen ) {
            $seen[] = array( $name, $payload );
        }, 10, 2 );

        wldelay_emit_event( 'lockout', array( 'ip' => '203.0.113.7' ) );

        $this->assertCount( 1, $seen );
        $this->assertSame( 'lockout', $seen[0][0] );
        $this->assertSame( array( 'ip' => '203.0.113.7' ), $seen[0][1] );
    }

    /**
     * A task deferred during a request runs when the shutdown flush hook fires,
     * and the queue is cleared afterwards (idempotent — re-firing does nothing).
     */
    public function test_deferred_task_runs_on_shutdown_flush() {
        $runs = 0;

        wldelay_register_task_handler( 'phpunit_counter', function () use ( &$runs ) {
            $runs++;
        } );

        wldelay_defer_task( 'phpunit_counter' );
        $this->assertSame( 1, wldelay_count_deferred_tasks() );

        // The flush is bound to the 'shutdown' action; invoke that exact
        // callback to simulate the response having been sent (without firing
        // WordPress' full shutdown chain, which manages its own output buffers).
        $this->assertNotFalse(
            has_action( 'shutdown', 'wldelay_flush_deferred_tasks' ),
            'flush should be hooked to shutdown'
        );
        wldelay_flush_deferred_tasks();

        $this->assertSame( 1, $runs );
        $this->assertSame( 0, wldelay_count_deferred_tasks() );

        // Flushing again must not re-run the drained task (idempotent).
        wldelay_flush_deferred_tasks();
        $this->assertSame( 1, $runs );
    }

    /**
     * The persistence purge task is registered and routes purge_expired through
     * the task layer (proof-of-use wiring).
     */
    public function test_purge_expired_task_is_registered_and_runs() {
        wldelay_create_lockout_table();
        $store = wldelay_get_persistence_store();
        $table = wldelay_get_lockout_table_name();

        global $wpdb;
        // Isolate this assertion from rows left by other integration tests.
        $wpdb->query( "TRUNCATE TABLE $table" );

        // Insert an already-expired lockout row.
        $wpdb->insert( $table, array(
            'transient_key' => 'wldelay_lockout_test',
            'ip_address'    => '198.51.100.4',
            'username'      => 'someone',
            'expires_at'    => gmdate( 'Y-m-d H:i:s', time() - HOUR_IN_SECONDS ),
            'created_at'    => gmdate( 'Y-m-d H:i:s', time() - DAY_IN_SECONDS ),
        ) );

        $this->assertSame( 1, (int) $wpdb->get_var( "SELECT COUNT(*) FROM $table" ) );

        wldelay_defer_task( 'purge_expired_lockouts' );
        wldelay_flush_deferred_tasks();

        $this->assertSame( 0, (int) $wpdb->get_var( "SELECT COUNT(*) FROM $table" ) );
    }

    /**
     * A throwing task_failed observer must not abort the flush: the original
     * failure is still logged, the observer fault is isolated, and unrelated
     * tasks queued after the failing one still run. F-4-9 round-3 review fix.
     */
    public function test_throwing_failure_observer_does_not_abort_drain() {
        $second_ran = false;

        wldelay_register_task_handler( 'boom', function () {
            throw new \RuntimeException( 'task boom' );
        } );
        wldelay_register_task_handler( 'after_boom', function () use ( &$second_ran ) {
            $second_ran = true;
        } );

        // A monitoring subscriber to the failure event that itself throws.
        wldelay_on_event( 'task_failed', function () {
            throw new \RuntimeException( 'observer boom' );
        } );

        wldelay_defer_task( 'boom' );
        wldelay_defer_task( 'after_boom' );

        // Must not throw out of the flush despite both the task and the
        // failure observer throwing.
        wldelay_flush_deferred_tasks();

        $this->assertTrue( $second_ran, 'task queued after the failing one must still run' );
        $this->assertSame( 0, wldelay_count_deferred_tasks() );
    }

    /**
     * Hitting the flush pass cap emits a flush_pass_cap event carrying the
     * dropped count and ids, so monitoring can observe stranded work that
     * error_log() alone (often disabled in production) would hide — e.g. a
     * stranded purge_expired_lockouts run. R3-5 review fix.
     */
    public function test_flush_pass_cap_emits_event_with_dropped_work() {
        $observed = null;
        wldelay_on_event( 'flush_pass_cap', function ( $payload ) use ( &$observed ) {
            $observed = $payload;
        } );

        // A handler that re-enqueues itself every pass: drained to the cap, then
        // the leftover is dropped — which is exactly when the event must fire.
        wldelay_register_task_handler( 'greedy', function () {
            wldelay_defer_task( 'greedy' );
        } );
        wldelay_defer_task( 'greedy' );

        wldelay_flush_deferred_tasks();

        $this->assertIsArray( $observed, 'flush_pass_cap event should fire when the cap is hit' );
        $this->assertSame( WLDELAY_MAX_FLUSH_PASSES, $observed['passes'] );
        $this->assertSame( 1, $observed['dropped'] );
        $this->assertSame( array( 'greedy' ), $observed['dropped_ids'] );
    }

    /**
     * A clean flush (no leftover work) must NOT emit flush_pass_cap — the event
     * is a stranded-work signal, not a per-flush heartbeat.
     */
    public function test_flush_pass_cap_event_not_emitted_on_clean_drain() {
        $fired = false;
        wldelay_on_event( 'flush_pass_cap', function () use ( &$fired ) {
            $fired = true;
        } );

        wldelay_register_task_handler( 'tidy', function () {} );
        wldelay_defer_task( 'tidy' );

        wldelay_flush_deferred_tasks();

        $this->assertFalse( $fired, 'flush_pass_cap must not fire when the queue drains cleanly' );
    }

    /**
     * The cron backstop hook is bound to the flush callback.
     */
    public function test_cron_backstop_action_is_registered() {
        $this->assertNotFalse(
            has_action( 'wldelay_async_cron', 'wldelay_run_async_cron' ),
            'wldelay_run_async_cron should be hooked to the wldelay_async_cron event'
        );
    }

    /**
     * Activation schedules the cron backstop; deactivation removes it.
     */
    public function test_cron_backstop_scheduled_and_unscheduled() {
        $timestamp = wp_next_scheduled( 'wldelay_async_cron' );
        if ( $timestamp ) {
            wp_unschedule_event( $timestamp, 'wldelay_async_cron' );
        }
        $this->assertFalse( wp_next_scheduled( 'wldelay_async_cron' ) );

        wldelay_schedule_async_cron();
        $this->assertNotFalse( wp_next_scheduled( 'wldelay_async_cron' ) );

        // Idempotent: scheduling again keeps the same timestamp.
        $first = wp_next_scheduled( 'wldelay_async_cron' );
        wldelay_schedule_async_cron();
        $this->assertSame( $first, wp_next_scheduled( 'wldelay_async_cron' ) );

        wldelay_unschedule_async_cron();
        $this->assertFalse( wp_next_scheduled( 'wldelay_async_cron' ) );
    }

    /**
     * Deactivation removes ALL scheduled occurrences, not just the next one.
     * Duplicate schedules can exist (concurrent scheduling, migration, old
     * versions); wldelay_unschedule_async_cron() must clear every instance.
     * F-4-9 round-4 review fix.
     */
    public function test_unschedule_clears_duplicate_cron_events() {
        // Force two distinct occurrences of the hook into cron storage.
        $timestamp = wp_next_scheduled( 'wldelay_async_cron' );
        if ( $timestamp ) {
            wp_unschedule_event( $timestamp, 'wldelay_async_cron' );
        }
        wp_schedule_event( time() + 100, 'daily', 'wldelay_async_cron' );
        wp_schedule_event( time() + 200, 'daily', 'wldelay_async_cron' );

        // Two occurrences are now scheduled under the same hook.
        $crons   = _get_cron_array();
        $matches = 0;
        foreach ( $crons as $events ) {
            if ( isset( $events['wldelay_async_cron'] ) ) {
                $matches++;
            }
        }
        $this->assertSame( 2, $matches, 'two occurrences should be scheduled' );

        // Deactivation must remove BOTH, not just the next one.
        wldelay_unschedule_async_cron();

        $this->assertFalse( wp_next_scheduled( 'wldelay_async_cron' ) );
        $crons = _get_cron_array();
        foreach ( $crons as $events ) {
            $this->assertArrayNotHasKey(
                'wldelay_async_cron',
                $events,
                'no wldelay_async_cron occurrences should remain after unschedule'
            );
        }
    }

    /**
     * The cron tick emits a recurring event so subscribers (e.g. GC) get a
     * durable backstop independent of per-request shutdown.
     */
    public function test_cron_tick_emits_event() {
        $ticked = false;
        wldelay_on_event( 'cron_tick', function () use ( &$ticked ) {
            $ticked = true;
        } );

        wldelay_run_async_cron();

        $this->assertTrue( $ticked );
    }
}
