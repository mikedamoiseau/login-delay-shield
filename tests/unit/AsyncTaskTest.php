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
}
