<?php
/**
 * Unified deferred task queue + event dispatch layer (F-4-9).
 *
 * SCOPE / RELIABILITY CONTRACT (read before adding a handler):
 * This is BEST-EFFORT, request-shutdown batching — NOT a durable async queue.
 * The queue lives in request-local memory and runs on the `shutdown` hook.
 * Work that is still queued when the PHP process exits (a task that fails, or a
 * self-requeue that hits the pass cap) is DROPPED — there is no persistence and
 * no retry, and the cron tick CANNOT recover it (cron runs a fresh process with
 * an empty queue). Do NOT defer reliability-sensitive work (e.g. security audit
 * writes whose loss matters) through this layer until it is backed by a durable
 * store. See the F-4-9 review notes for the deferred persistence/retry decision.
 *
 * This is the keystone plumbing that downstream features build on. It absorbs
 * four merged proposals: the telemetry event bus (F-2-3), the event registry
 * (F-2-9), the transient-GC cleanup cron (F-3-8), and async cache warming
 * (F-4-3). It is intentionally minimal and additive — it adds NO downstream
 * feature; it only exposes the reusable seam.
 *
 * Two complementary capabilities:
 *
 *   1. Event dispatch — a thin, documented wrapper over WordPress'
 *      do_action / add_action so call sites and future SIEM / webhook / audit
 *      subscribers (F-2-7) have a stable seam that will not move when the
 *      monolith is refactored:
 *
 *        wldelay_emit_event( $name, array $payload )  // fire
 *        wldelay_on_event( $name, $callback, ... )    // subscribe
 *
 *      Every emit fires two hooks: the namespaced `wldelay_event_{$name}`
 *      (subscribe to one event) and the generic `wldelay_event` (subscribe to
 *      all events — the audit/SIEM firehose).
 *
 *   2. Deferred task queue — enqueue work during a request that runs LATE in
 *      the request, on the `shutdown` hook. Tasks accumulate in an in-memory
 *      queue and flush there. Note: `shutdown` fires as the request ends but
 *      does NOT guarantee the HTTP response has been flushed to the client
 *      (no fastcgi_finish_request()), so a slow handler can still add to
 *      response latency — keep handlers cheap. A daily cron tick fires the same
 *      flush for periodic maintenance, but is NOT a recovery path for a
 *      specific request's queued work (see the reliability contract above):
 *
 *        wldelay_register_task_handler( $callback_id, callable )  // once, at boot
 *        wldelay_defer_task( $callback_id, array $args )          // enqueue in-request
 *
 *      The point: off-hot-path audit writes, fail2ban batching, and transient
 *      / expired-lockout GC, so the per-request critical path stays lean. When
 *      nothing is deferred the shutdown handler early-returns before touching
 *      the handler registry, so the empty-queue case costs a single isset().
 *
 * @package login-delay-shield
 */

defined( 'ABSPATH' ) || exit;

// ==========================================================================
// Event dispatch
// ==========================================================================

/**
 * Emit a plugin event.
 *
 * Thin wrapper over do_action that fires two hooks per event so subscribers can
 * listen to one named event or to every event (the audit / SIEM firehose):
 *
 *   - `wldelay_event_{$event_name}` — receives the payload array.
 *   - `wldelay_event`               — receives ( $event_name, $payload ).
 *
 * @param string $event_name Machine event name, e.g. 'failed_login', 'lockout'.
 * @param array  $payload    Arbitrary associative data describing the event.
 */
function wldelay_emit_event( $event_name, array $payload = array() ) {
    $event_name = (string) $event_name;
    if ( '' === $event_name ) {
        return;
    }

    do_action( 'wldelay_event_' . $event_name, $payload );
    do_action( 'wldelay_event', $event_name, $payload );
}

/**
 * Subscribe a listener to a named plugin event.
 *
 * Thin wrapper over add_action on the namespaced `wldelay_event_{$name}` hook.
 * To observe every event, hook the generic `wldelay_event` action directly
 * (its callback receives the event name as the first argument).
 *
 * @param string   $event_name    Event name to listen for.
 * @param callable $callback      Listener; receives the payload array.
 * @param int      $priority      Hook priority (default 10).
 * @param int      $accepted_args Number of args passed to the listener (default 1).
 */
function wldelay_on_event( $event_name, $callback, $priority = 10, $accepted_args = 1 ) {
    add_action( 'wldelay_event_' . (string) $event_name, $callback, $priority, $accepted_args );
}

// ==========================================================================
// Deferred task queue
// ==========================================================================

/**
 * Accessor for the in-memory deferred-task queue.
 *
 * Stored in a function-static so the queue lives for the duration of one
 * request only — deferred work is request-scoped and flushed on shutdown.
 *
 * @return array Reference to the queue array (keyed by dedupe hash).
 */
function &wldelay_deferred_task_queue() {
    static $queue = array();
    return $queue;
}

/**
 * Accessor for the registered task-handler map.
 *
 * @return array Reference to the handler map ( callback_id => callable ).
 */
function &wldelay_task_handler_registry() {
    static $handlers = array();
    return $handlers;
}

/**
 * Register the callable that runs a deferred task of the given id.
 *
 * Tasks are enqueued by a stable string id (not a closure) so the queue stays
 * cheap to dedupe and so handlers can be registered once at boot. Re-registering
 * the same id replaces the handler.
 *
 * @param string   $callback_id Stable task identifier, e.g. 'purge_expired_lockouts'.
 * @param callable $callback    Handler; receives the task args array.
 */
function wldelay_register_task_handler( $callback_id, $callback ) {
    $handlers = &wldelay_task_handler_registry();
    $handlers[ (string) $callback_id ] = $callback;
}

/**
 * Enqueue a task to run off the hot path (on shutdown / cron flush).
 *
 * Identical ( callback_id + args ) enqueues within a single request are
 * deduplicated so repeated work in a hot loop coalesces into one run.
 *
 * @param string $callback_id Id of a handler registered via wldelay_register_task_handler().
 * @param array  $args        Args passed to the handler when it runs.
 */
function wldelay_defer_task( $callback_id, array $args = array() ) {
    $callback_id = (string) $callback_id;
    if ( '' === $callback_id ) {
        return;
    }

    $queue = &wldelay_deferred_task_queue();

    // Dedupe key: id + a stable hash of the args.
    $key = $callback_id . ':' . md5( wp_json_encode( $args ) );

    $queue[ $key ] = array(
        'id'   => $callback_id,
        'args' => $args,
    );
}

/**
 * Number of tasks currently queued. Cheap; used by callers and tests.
 *
 * @return int
 */
function wldelay_count_deferred_tasks() {
    $queue = &wldelay_deferred_task_queue();
    return count( $queue );
}

/**
 * Empty the in-memory queue without running anything.
 *
 * Used by tests and any caller that needs to discard pending work.
 */
function wldelay_reset_deferred_tasks() {
    $queue = &wldelay_deferred_task_queue();
    $queue = array();
}

/**
 * Hard cap on flush passes, so a handler that re-enqueues itself every pass
 * cannot spin the shutdown sequence into an infinite loop.
 */
if ( ! defined( 'WLDELAY_MAX_FLUSH_PASSES' ) ) {
    define( 'WLDELAY_MAX_FLUSH_PASSES', 10 );
}

/**
 * Run every queued task through its registered handler, then drain the queue.
 *
 * Drains in bounded passes: a handler that itself defers more work has that
 * work picked up by a subsequent pass within the SAME flush (re-entrant safe),
 * rather than being stranded in the request-local queue until a flush that
 * never comes. Passes are capped at WLDELAY_MAX_FLUSH_PASSES so a handler that
 * unconditionally re-enqueues itself cannot loop forever; any still-pending
 * tasks at the cap are DROPPED when the process exits (the in-memory queue does
 * not survive the request, and the cron tick runs a fresh process with an empty
 * queue — it cannot recover them). The truncation is logged so the loss is
 * visible rather than silent.
 *
 * Idempotent: a second flush with nothing pending is a cheap no-op. Tasks whose
 * handler is not registered are skipped (no fatal). Each handler is guarded so
 * one failing task does not abort the rest of the flush; failures always emit
 * the `task_failed` event and are logged. Note: the failed task is NOT retried
 * or persisted — the event/log give visibility, not recovery.
 */
function wldelay_flush_deferred_tasks() {
    $queue = &wldelay_deferred_task_queue();

    // Empty-queue fast path: no handler-registry lookup, no work.
    if ( empty( $queue ) ) {
        return;
    }

    $handlers = &wldelay_task_handler_registry();
    $passes   = 0;

    // Drain in bounded passes so tasks deferred by a handler still run in this
    // flush instead of being silently dropped at request termination.
    while ( ! empty( $queue ) && $passes < WLDELAY_MAX_FLUSH_PASSES ) {
        $passes++;

        // Snapshot and clear before running so re-entrant defers land in the
        // freshly-emptied queue and are picked up by the next while iteration.
        $pending = $queue;
        $queue   = array();

        foreach ( $pending as $task ) {
            $id = $task['id'];
            if ( ! isset( $handlers[ $id ] ) || ! is_callable( $handlers[ $id ] ) ) {
                continue;
            }

            try {
                call_user_func( $handlers[ $id ], $task['args'] );
            } catch ( \Throwable $e ) {
                // A deferred task must never take down the shutdown sequence.
                // Always emit a failure event so reliability-sensitive callers
                // (audit, fail2ban batching) can observe and recover, then log.
                wldelay_emit_event( 'task_failed', array(
                    'id'      => $id,
                    'args'    => $task['args'],
                    'message' => $e->getMessage(),
                ) );
                error_log( 'wldelay deferred task "' . $id . '" failed: ' . $e->getMessage() ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
            }
        }
    }

    // If work is still pending we hit the pass cap: a handler is re-enqueueing
    // on every pass. Stop looping; the leftover is dropped at process exit (the
    // queue is request-local memory). Log it so the loss is visible.
    if ( ! empty( $queue ) ) {
        error_log( 'wldelay deferred flush hit pass cap (' . WLDELAY_MAX_FLUSH_PASSES . '); ' . count( $queue ) . ' task(s) left queued' ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
    }
}

// Flush deferred work on shutdown (late in the request; does not guarantee the
// response has already been flushed to the client — keep handlers cheap).
add_action( 'shutdown', 'wldelay_flush_deferred_tasks' );

// ==========================================================================
// Cron backstop
// ==========================================================================

/**
 * Schedule the daily async cron backstop.
 *
 * The deferred queue flushes on every request's shutdown; this recurring tick
 * is a backstop for periodic MAINTENANCE (e.g. expired-lockout GC) on
 * low-traffic sites where shutdown-time work may be rare. It re-defers that
 * maintenance from scratch each tick — it does NOT recover work stranded in a
 * past request's in-memory queue. It fires the `cron_tick` event so subscribers
 * can hook recurring maintenance off a single scheduled event rather than each
 * registering their own.
 */
function wldelay_schedule_async_cron() {
    if ( ! wp_next_scheduled( 'wldelay_async_cron' ) ) {
        wp_schedule_event( time(), 'daily', 'wldelay_async_cron' );
    }
}
add_action( 'wp', 'wldelay_schedule_async_cron' );

/**
 * Remove the async cron backstop. Called on deactivation.
 */
function wldelay_unschedule_async_cron() {
    $timestamp = wp_next_scheduled( 'wldelay_async_cron' );
    if ( $timestamp ) {
        wp_unschedule_event( $timestamp, 'wldelay_async_cron' );
    }
}

/**
 * Cron callback: emit the recurring tick event, then flush any work it queued.
 *
 * Subscribers to the `cron_tick` event (via wldelay_on_event) can enqueue
 * deferred tasks here; we flush immediately so the cron run drains them rather
 * than waiting for an unrelated request's shutdown.
 */
function wldelay_run_async_cron() {
    wldelay_emit_event( 'cron_tick', array( 'ts' => time() ) );
    wldelay_flush_deferred_tasks();
}
add_action( 'wldelay_async_cron', 'wldelay_run_async_cron' );

// ==========================================================================
// Built-in task handlers (proof-of-use wiring)
// ==========================================================================

/**
 * Built-in handler: purge expired rows from the durable lockout store (F-2-1).
 *
 * This is the F-3-8 transient/expired-lockout GC folded into F-4-9. It is
 * registered here so any code path can defer the purge off the hot path
 * instead of running it inline.
 *
 * @param array $args Unused; signature kept uniform for the handler contract.
 */
function wldelay_task_purge_expired_lockouts( $args = array() ) {
    if ( function_exists( 'wldelay_get_persistence_store' ) ) {
        wldelay_get_persistence_store()->purge_expired();
    }
}
wldelay_register_task_handler( 'purge_expired_lockouts', 'wldelay_task_purge_expired_lockouts' );

/**
 * Proof-of-use wiring (F-3-8 folded into F-4-9).
 *
 * On every async cron tick, defer an expired-lockout purge. This is ADDITIVE
 * and does not touch the existing synchronous purge in wldelay_cleanup_old_logs()
 * (which CronTest covers): it simply gives the GC a second, queue-driven
 * backstop that runs off the hot path. Deferring (rather than purging inline)
 * keeps the cron callback itself lean and routes the work through the same
 * shutdown/flush machinery every other deferred task uses. Idempotent: the
 * purge is a bounded DELETE of already-expired rows, safe to run repeatedly.
 */
function wldelay_async_purge_on_cron_tick() {
    wldelay_defer_task( 'purge_expired_lockouts' );
}
wldelay_on_event( 'cron_tick', 'wldelay_async_purge_on_cron_tick' );
