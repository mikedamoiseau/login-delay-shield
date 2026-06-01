<?php
/**
 * Unit tests for the unified async task queue + event dispatch layer (F-4-9).
 *
 * These exercise the pure queue/registry logic with Brain Monkey mocks for the
 * thin WordPress seam (do_action / add_action). No WordPress runtime required.
 */

use Brain\Monkey\Functions;

class AsyncTaskTest extends LDS_Unit_Test_Case {

    protected function setUp(): void {
        parent::setUp();

        Functions\when( 'wp_json_encode' )->alias( function ( $data ) {
            return json_encode( $data );
        } );

        if ( ! function_exists( 'wldelay_defer_task' ) ) {
            require_once dirname( dirname( __DIR__ ) ) . '/wldelay-async.php';
        }

        // Start every test from an empty in-memory queue.
        wldelay_reset_deferred_tasks();
    }

    /**
     * emit_event dispatches through the WordPress action seam with the payload.
     */
    public function test_emit_event_dispatches_named_and_generic_actions() {
        $captured = array();

        Functions\expect( 'do_action' )
            ->once()
            ->with( 'wldelay_event_failed_login', array( 'ip' => '1.2.3.4' ) );

        Functions\expect( 'do_action' )
            ->once()
            ->with( 'wldelay_event', 'failed_login', array( 'ip' => '1.2.3.4' ) );

        wldelay_emit_event( 'failed_login', array( 'ip' => '1.2.3.4' ) );

        // The expectations above are verified on tearDown; assert here so the
        // test is not flagged risky for performing no PHPUnit assertions.
        $this->assertTrue( true );
    }

    /**
     * on_event registers a listener on the namespaced action hook.
     */
    public function test_on_event_registers_listener_on_namespaced_hook() {
        // atLeast(): the async file registers hooks at load time too, so we
        // assert the specific call happened rather than an exact total count.
        Functions\expect( 'add_action' )
            ->atLeast()
            ->once()
            ->with( 'wldelay_event_lockout', 'my_callback', 10, 1 );

        wldelay_on_event( 'lockout', 'my_callback' );

        $this->assertTrue( true );
    }

    /**
     * Deferring a task accumulates it in the in-memory queue.
     */
    public function test_defer_task_accumulates_in_queue() {
        $this->assertSame( 0, wldelay_count_deferred_tasks() );

        wldelay_defer_task( 'purge_expired_lockouts' );
        wldelay_defer_task( 'cleanup_logs', array( 'days' => 30 ) );

        $this->assertSame( 2, wldelay_count_deferred_tasks() );
    }

    /**
     * Identical (callback_id + args) tasks are deduplicated within a request.
     */
    public function test_defer_task_dedupes_identical_tasks() {
        wldelay_defer_task( 'purge_expired_lockouts' );
        wldelay_defer_task( 'purge_expired_lockouts' );
        wldelay_defer_task( 'purge_expired_lockouts', array( 'force' => true ) );

        // Two identical no-arg enqueues collapse to one; the arg variant is distinct.
        $this->assertSame( 2, wldelay_count_deferred_tasks() );
    }

    /**
     * Two distinct tasks whose args cannot be JSON-encoded (invalid UTF-8) must
     * NOT collapse onto md5( false ). When encoding fails the enqueue gets a
     * unique per-request key, so distinct unencodable arg arrays stay distinct.
     * F-4-9 round-5 review fix.
     */
    public function test_defer_task_keeps_distinct_unencodable_args() {
        // Invalid UTF-8 byte sequences — wp_json_encode()/json_encode() return
        // false for these, so the dedupe key comes from the unique-key fallback.
        $bad_a = array( 'ip' => "\xB1\x31" );
        $bad_b = array( 'ip' => "\xC3\x28" );

        // Sanity: these genuinely fail to JSON-encode in this harness.
        $this->assertFalse( wp_json_encode( $bad_a ) );
        $this->assertFalse( wp_json_encode( $bad_b ) );

        wldelay_defer_task( 'record', $bad_a );
        wldelay_defer_task( 'record', $bad_b );

        // Distinct args → two queued tasks, not one overwriting the other.
        $this->assertSame( 2, wldelay_count_deferred_tasks() );
    }

    /**
     * Two distinct OPEN RESOURCES must not collapse into one queue entry.
     * serialize() converts every resource to the same "i:0;" representation, so
     * a serialize()-based fallback would silently overwrite the first task with
     * the second. The unique per-enqueue fallback key keeps them distinct.
     * F-4-9 round-6 review fix.
     */
    public function test_defer_task_keeps_distinct_resource_args() {
        $res_a = fopen( 'php://memory', 'rb' );
        $res_b = fopen( 'php://memory', 'rb' );

        // Sanity: resources cannot be JSON-encoded, so the fallback path runs.
        $this->assertFalse( wp_json_encode( array( 'h' => $res_a ) ) );

        wldelay_defer_task( 'record', array( 'h' => $res_a ) );
        wldelay_defer_task( 'record', array( 'h' => $res_b ) );

        // Distinct resources → two queued tasks, not one overwriting the other
        // (which is exactly what a serialize() "i:0;" fallback would have done).
        $this->assertSame( 2, wldelay_count_deferred_tasks() );

        fclose( $res_a );
        fclose( $res_b );
    }

    /**
     * Flushing runs each registered handler with its stored args and then
     * empties the queue so a second flush is a cheap no-op (idempotent).
     */
    public function test_flush_runs_registered_handlers_and_clears_queue() {
        $runs = array();

        wldelay_register_task_handler( 'record', function ( $args ) use ( &$runs ) {
            $runs[] = $args;
        } );

        wldelay_defer_task( 'record', array( 'n' => 1 ) );
        wldelay_defer_task( 'record', array( 'n' => 2 ) );

        wldelay_flush_deferred_tasks();

        $this->assertCount( 2, $runs );
        $this->assertSame( array( 'n' => 1 ), $runs[0] );
        $this->assertSame( array( 'n' => 2 ), $runs[1] );

        // Queue is drained; a second flush does nothing.
        $this->assertSame( 0, wldelay_count_deferred_tasks() );
        wldelay_flush_deferred_tasks();
        $this->assertCount( 2, $runs );
    }

    /**
     * A task with no registered handler is skipped without fatal and still
     * drains from the queue.
     */
    public function test_flush_skips_unregistered_handler() {
        wldelay_defer_task( 'no_such_handler' );

        // Should not throw.
        wldelay_flush_deferred_tasks();

        $this->assertSame( 0, wldelay_count_deferred_tasks() );
    }

    /**
     * Flushing an empty queue is a cheap no-op (early return, no handler lookup).
     */
    public function test_flush_empty_queue_is_noop() {
        $this->assertSame( 0, wldelay_count_deferred_tasks() );
        wldelay_flush_deferred_tasks();
        $this->assertSame( 0, wldelay_count_deferred_tasks() );
    }

    /**
     * A task deferred by another task during the flush still runs within the
     * same flush (bounded re-entrant drain), rather than being stranded in the
     * request-local queue until a flush that never comes. F-4-9 review fix.
     */
    public function test_flush_runs_task_deferred_by_another_task() {
        $ran_b = false;

        wldelay_register_task_handler( 'task_a', function () {
            // Handler A enqueues B mid-flush.
            wldelay_defer_task( 'task_b' );
        } );
        wldelay_register_task_handler( 'task_b', function () use ( &$ran_b ) {
            $ran_b = true;
        } );

        wldelay_defer_task( 'task_a' );
        wldelay_flush_deferred_tasks();

        $this->assertTrue( $ran_b, 'task B deferred by task A should run in the same flush' );
        $this->assertSame( 0, wldelay_count_deferred_tasks() );
    }

    /**
     * A handler that unconditionally re-enqueues itself is bounded by the pass
     * cap instead of looping forever; the flush returns and leaves the pending
     * task queued rather than spinning. F-4-9 review fix.
     */
    public function test_flush_self_requeue_is_bounded_by_pass_cap() {
        $runs = 0;

        wldelay_register_task_handler( 'greedy', function () use ( &$runs ) {
            $runs++;
            // Re-enqueue every pass — would loop forever without the cap.
            wldelay_defer_task( 'greedy' );
        } );

        wldelay_defer_task( 'greedy' );
        wldelay_flush_deferred_tasks();

        // Ran exactly once per pass, capped — not unbounded.
        $this->assertSame( WLDELAY_MAX_FLUSH_PASSES, $runs );
        // The still-pending re-enqueue is left for a later flush, not dropped.
        $this->assertSame( 1, wldelay_count_deferred_tasks() );
    }
}
