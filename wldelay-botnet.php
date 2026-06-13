<?php
/**
 * Cross-IP botnet / credential-stuffing detection (F-1-9).
 *
 * Per-IP counters cannot see an attack that rotates IPs: N addresses making
 * (threshold - 1) attempts each never trip a lockout. This module watches the
 * other axis — distinct source IPs per TARGET USERNAME inside a sliding
 * window — and ALERTS (audit log, dashboard banner, optional email). It never
 * blocks: detection informs, enforcement stays per-IP by design.
 *
 * Hot-path cost: one transient read (cooldown gate) on the failed_attempt
 * event; the COUNT(DISTINCT ip_address) query is deferred to the shutdown
 * flush via the F-4-9 task queue, which also coalesces duplicate usernames
 * per request so N failures for one username in one request trigger one check.
 *
 * Transient registry choice for cooldown and detections feed:
 * These are self-expiring, non-critical transients whose loss is recoverable:
 *   - Cooldown: if set_transient succeeds but the registry write fails, the
 *     worst case is a duplicate alert during the next window. That is a false
 *     positive, not a security gap — acceptable. We therefore DO NOT delete
 *     the transient on a failed registration (unlike the failure-counter in
 *     wldelay_track_failed_attempt, where an un-registered counter can escape
 *     a global flush). Keeping a "floating" cooldown is safer than dropping
 *     it (dropping would cause immediate re-alerting).
 *   - Detections feed: same reasoning. A floating feed entry is benign; it
 *     will TTL out in 24h. Deleting on registration failure would cause the
 *     banner to silently miss the alert — worse than showing a stale entry.
 *   Both transients are therefore set without delete-on-failure.
 *
 * Concurrency notes (both accepted for an alert-only, best-effort feature):
 *   - The detections-feed transient is a read-modify-write (get → array_unshift
 *     → set). Two flushes for DIFFERENT usernames completing simultaneously can
 *     lose one entry (last write wins). Acceptable: the authoritative record is
 *     the synchronous audit-log row (written inline, not deferred); the feed is
 *     only the dashboard convenience banner.
 *   - The per-username cooldown is set at the tightest safe point (right after
 *     the COUNT confirms threshold, before fan-out) but without a lock, so two
 *     concurrent same-username flushes can both alert once. Worst case is one
 *     duplicate alert — a false positive, not a security gap.
 *   - The (int)/(array) casts on the $wpdb query results intentionally treat a
 *     null/error result as "no detection" (0 distinct IPs, empty samples) — the
 *     fail-safe direction for an alert-only feature.
 *
 * @package login-delay-shield
 */

defined( 'ABSPATH' ) || exit;

/**
 * Transient name for the rolling list of recent botnet detections (dashboard
 * banner feed). Newest-first array, max 20 entries, 24h TTL.
 */
define( 'WLDELAY_BOTNET_DETECTIONS_TRANSIENT', 'wldelay_botnet_detections' );

// ==========================================================================
// Option accessors
// ==========================================================================

/**
 * Whether botnet detection is enabled.
 *
 * @return bool
 */
function wldelay_botnet_is_enabled() {
    $options = wldelay_get_options();
    return ! empty( $options['wldelay_botnet_enabled'] );
}

/**
 * Distinct-IP threshold that triggers a detection alert.
 *
 * The raw option is clamped to [2, 100], then passed through the
 * `wldelay_botnet_ip_threshold` filter. The post-filter value is also
 * floored at 2 so a filter returning 0 or 1 cannot bypass the minimum.
 *
 * @return int
 */
function wldelay_botnet_get_ip_threshold() {
    $options   = wldelay_get_options();
    $threshold = isset( $options['wldelay_botnet_ip_threshold'] )
        ? (int) $options['wldelay_botnet_ip_threshold']
        : 5;

    // Clamp the stored option before handing it to the filter.
    $threshold = max( 2, min( 100, $threshold ) );

    /**
     * Filter the distinct-IP count that triggers a botnet detection.
     *
     * @param int $threshold Clamped option value (default 5).
     */
    $threshold = (int) apply_filters( 'wldelay_botnet_ip_threshold', $threshold );

    // Re-floor after the filter: a filter returning 0 or 1 must not bypass
    // the minimum of 2 (a threshold of 1 would flag every single-IP failure).
    return max( 2, $threshold );
}

/**
 * Sliding detection window in seconds.
 *
 * Raw option clamped to [5, 60] minutes, then filtered. Post-filter value
 * is floored at MINUTE_IN_SECONDS (1 min) so a filter cannot shrink it to 0.
 *
 * @return int Seconds.
 */
function wldelay_botnet_get_window_seconds() {
    $options = wldelay_get_options();
    $minutes = isset( $options['wldelay_botnet_window_minutes'] )
        ? (int) $options['wldelay_botnet_window_minutes']
        : 15;

    $minutes = max( 5, min( 60, $minutes ) );

    /**
     * Filter the detection window in seconds.
     *
     * @param int $seconds Clamped option value in seconds (default 900).
     */
    $seconds = (int) apply_filters( 'wldelay_botnet_window', $minutes * MINUTE_IN_SECONDS );

    return max( MINUTE_IN_SECONDS, $seconds );
}

// ==========================================================================
// Cooldown key
// ==========================================================================

/**
 * Per-username alert cooldown transient name.
 *
 * Keyed by the lower-cased, md5'd username so the transient name is always
 * within WordPress' 172-char limit and is case-insensitive.
 *
 * @param string $username Target username.
 * @return string Transient name.
 */
function wldelay_botnet_cooldown_key( $username ) {
    return 'wldelay_botnet_cd_' . md5( strtolower( (string) $username ) );
}

// ==========================================================================
// Hot-path listener (failed_attempt event)
// ==========================================================================

/**
 * Listen for the failed_attempt pipeline event and schedule the deferred check.
 *
 * Gates (cheap, in order):
 *   1. Botnet detection enabled flag.
 *   2. Non-empty trimmed username.
 *   3. Per-username cooldown transient — already alerted recently; skip.
 *
 * If all gates pass, enqueue the COUNT query via the F-4-9 task queue.
 * Identical (botnet_check, {username}) enqueues within the same request are
 * coalesced by the queue, so 100 rapid failures for 'admin' trigger one query.
 *
 * @param array $payload Event payload: { ip, username, source, failed_attempts }
 */
function wldelay_botnet_on_failed_attempt( $payload ) {
    if ( ! wldelay_botnet_is_enabled() ) {
        return;
    }

    $username = isset( $payload['username'] ) ? trim( (string) $payload['username'] ) : '';
    if ( '' === $username ) {
        return;
    }

    // Cooldown gate — one transient read per event.
    if ( false !== get_transient( wldelay_botnet_cooldown_key( $username ) ) ) {
        return;
    }

    wldelay_defer_task( 'botnet_check', array( 'username' => $username ) );
}

// ==========================================================================
// Deferred task: run the detection query and fan-out alerts
// ==========================================================================

/**
 * Deferred task handler: query distinct attacking IPs and alert when threshold
 * is met. Runs on the shutdown flush, off the HTTP hot path.
 *
 * Re-checks the cooldown inside the task so a concurrent request that already
 * alerted (and set the cooldown transient between the enqueue and this flush)
 * does not trigger a duplicate alert.
 *
 * @param array $args { @type string $username Target login username. }
 */
function wldelay_botnet_task( $args ) {
    global $wpdb;

    $username = isset( $args['username'] ) ? trim( (string) $args['username'] ) : '';
    if ( '' === $username || ! wldelay_botnet_is_enabled() ) {
        return;
    }

    $cooldown_key = wldelay_botnet_cooldown_key( $username );
    if ( false !== get_transient( $cooldown_key ) ) {
        // Another request alerted between enqueue and flush; skip.
        return;
    }

    $window = wldelay_botnet_get_window_seconds();

    // CRITICAL: attempted_at is stored as current_time('mysql') — site-local
    // time, NOT UTC. Build the cutoff from the same clock so the window does
    // not silently shift by the site's UTC offset.
    $cutoff = gmdate( 'Y-m-d H:i:s', current_time( 'timestamp' ) - $window );
    $table  = wldelay_get_log_table_name();

    $distinct_ips = (int) $wpdb->get_var( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
        $wpdb->prepare(
            "SELECT COUNT(DISTINCT ip_address) FROM {$table} WHERE username = %s AND attempted_at >= %s",
            $username,
            $cutoff
        )
    );

    $threshold = wldelay_botnet_get_ip_threshold();
    if ( $distinct_ips < $threshold ) {
        return;
    }

    // --- Threshold met: set cooldown, sample IPs, fan out alerts. ---

    /**
     * Filter the alert cooldown (seconds) after a detection for one username.
     *
     * After a detection fires, this window suppresses repeat alerts for the
     * same username. Default: one hour.
     *
     * @param int $seconds Cooldown in seconds (default HOUR_IN_SECONDS).
     */
    $cooldown = (int) apply_filters( 'wldelay_botnet_alert_cooldown', HOUR_IN_SECONDS );
    set_transient( $cooldown_key, time(), $cooldown );
    // Registration choice: see file-level docblock. We do NOT delete on a
    // failed registration — a floating cooldown is preferable to a repeat
    // alert flood. The TTL matches set_transient's $expiration.
    wldelay_register_transient_key( $cooldown_key, time() + $cooldown );

    $sample_ips = (array) $wpdb->get_col( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
        $wpdb->prepare(
            "SELECT DISTINCT ip_address FROM {$table} WHERE username = %s AND attempted_at >= %s LIMIT 5",
            $username,
            $cutoff
        )
    );

    wldelay_botnet_record_detection( $username, $distinct_ips, $sample_ips );
}

// ==========================================================================
// Detection fan-out: audit + dashboard feed + email
// ==========================================================================

/**
 * Fan a confirmed detection out to the three alert surfaces.
 *
 * @param string $username     Target username under attack.
 * @param int    $distinct_ips Number of distinct source IPs detected.
 * @param array  $sample_ips   Up to 5 sample attacker IPs.
 */
function wldelay_botnet_record_detection( $username, $distinct_ips, array $sample_ips ) {
    $window_minutes = (int) round( wldelay_botnet_get_window_seconds() / MINUTE_IN_SECONDS );

    // 1. Audit trail — synchronous write; actor defaults to 0/system.
    wldelay_audit_log(
        'botnet_detected',
        array(
            'object'    => $username,
            'new_value' => array(
                'distinct_ips'   => $distinct_ips,
                'window_minutes' => $window_minutes,
                'sample_ips'     => $sample_ips,
            ),
        )
    );

    // 2. Dashboard banner feed — rolling list, newest first, max 20, 24h TTL.
    $detections = get_transient( WLDELAY_BOTNET_DETECTIONS_TRANSIENT );
    if ( ! is_array( $detections ) ) {
        $detections = array();
    }
    array_unshift(
        $detections,
        array(
            'username'       => $username,
            'distinct_ips'   => $distinct_ips,
            'window_minutes' => $window_minutes,
            'detected_at'    => time(),
        )
    );
    $detections = array_slice( $detections, 0, 20 );
    set_transient( WLDELAY_BOTNET_DETECTIONS_TRANSIENT, $detections, DAY_IN_SECONDS );
    // Registration choice: see file-level docblock. Floating feed entry TTLs
    // out in 24 h — no delete on failed registration.
    wldelay_register_transient_key( WLDELAY_BOTNET_DETECTIONS_TRANSIENT, time() + DAY_IN_SECONDS );

    // 3. Email alert — only when the site owner has opted into email alerts.
    $options = wldelay_get_options();
    if ( ! empty( $options['wldelay_email_enabled'] ) ) {
        wldelay_botnet_send_email( $username, $distinct_ips, $window_minutes, $sample_ips );
    }
}

/**
 * Send a distributed-attack alert email.
 *
 * Mirrors the to-address / wp_mail() conventions in wldelay_send_notification_email():
 * custom address from options, fallback to admin_email, plain-text body.
 *
 * @param string $username       Targeted username.
 * @param int    $distinct_ips   Number of distinct attacking IPs.
 * @param int    $window_minutes Detection window in minutes.
 * @param array  $sample_ips     Up to 5 sample attacker IPs.
 */
function wldelay_botnet_send_email( $username, $distinct_ips, $window_minutes, array $sample_ips ) {
    $options = wldelay_get_options();
    $to      = ! empty( $options['wldelay_email_address'] )
        ? $options['wldelay_email_address']
        : get_option( 'admin_email' );

    $site_name = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );

    /* translators: %s: site name */
    $subject = sprintf(
        __( '[%s] Distributed login attack detected', 'login-delay-shield' ),
        $site_name
    );

    /* translators: 1: username targeted by the attack, 2: number of distinct source IPs, 3: detection window in minutes, 4: comma-separated sample IP list, 5: dashboard URL */
    $message = sprintf(
        __(
            "Login Delay Shield detected a distributed attack.\n\nTargeted username: %1\$s\nDistinct source IPs: %2\$d within %3\$d minutes\nSample IPs: %4\$s\n\nThis is an alert only - per-IP delays and lockouts remain active. Review the dashboard widget for details: %5\$s\n",
            'login-delay-shield'
        ),
        $username,
        $distinct_ips,
        $window_minutes,
        implode( ', ', array_map( 'sanitize_text_field', $sample_ips ) ),
        admin_url( 'index.php' )
    );

    wp_mail( $to, $subject, $message );
}

// ==========================================================================
// Read API (dashboard banner)
// ==========================================================================

/**
 * Recent botnet detections for the dashboard banner.
 *
 * Returns the rolling list written by wldelay_botnet_record_detection(),
 * newest first, up to 20 entries, valid for up to 24 hours.
 *
 * @return array<int,array{username:string,distinct_ips:int,window_minutes:int,detected_at:int}>
 */
function wldelay_botnet_get_recent_detections() {
    $detections = get_transient( WLDELAY_BOTNET_DETECTIONS_TRANSIENT );
    return is_array( $detections ) ? $detections : array();
}

// ==========================================================================
// Boot wiring
// ==========================================================================

// Register the deferred task handler so any request can queue a botnet check.
// Guarded: wldelay_register_task_handler() lives in wldelay-async.php which
// is required before this file in wp-login-delay.php; the guard keeps this
// file loadable in unit tests where async.php is NOT loaded.
if ( function_exists( 'wldelay_register_task_handler' ) ) {
    wldelay_register_task_handler( 'botnet_check', 'wldelay_botnet_task' );
}

// Subscribe to the pipeline's failed_attempt event. Same guard pattern.
if ( function_exists( 'wldelay_on_event' ) ) {
    wldelay_on_event( 'failed_attempt', 'wldelay_botnet_on_failed_attempt' );
}
