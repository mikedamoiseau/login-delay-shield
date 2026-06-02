<?php
/**
 * Admin/security action audit log (F-2-7).
 *
 * Records sensitive administrative and security actions — settings changes,
 * manual lockout clears, whitelist edits — in a dedicated, append-only table so
 * the site owner has a forensic trail of who changed what, when, and from where.
 * The view layer surfaces the rows read-only; nothing in this file (or the admin
 * UI) edits or deletes individual entries.
 *
 * Compliance: this is the audit trail required by SOC 2 CC7.2 (detection and
 * monitoring of security-relevant events), GDPR Art. 32 (security of processing),
 * and PCI-DSS Req. 10 (track and monitor access to system components).
 *
 * RELIABILITY: audit WRITES are SYNCHRONOUS — wldelay_audit_log() inserts the
 * row inline on the action path (wldelay_audit_write_row). A compliance trail
 * must not be lossy, and the F-4-9 deferred queue is best-effort (queued work is
 * dropped when the process exits) and coalesces identical (id+args) enqueues,
 * which would collapse two identical actions in the same second to one row —
 * both unacceptable here. Admin/security actions are low-frequency (a handful
 * per session, never in a hot loop), so the inline INSERT adds no meaningful
 * latency. A failed INSERT is logged (never silently swallowed) so a gap in the
 * trail is detectable.
 *
 * @package login-delay-shield
 */

defined( 'ABSPATH' ) || exit;

/**
 * Deferred-task id under which audit-row writes are enqueued.
 */
if ( ! defined( 'WLDELAY_AUDIT_TASK_ID' ) ) {
    define( 'WLDELAY_AUDIT_TASK_ID', 'audit_log_write' );
}

/**
 * Get the audit-log table name.
 *
 * Cached per active prefix (not once globally) so a switch_to_blog() under
 * multisite resolves the current site's table rather than pinning the first
 * site's, mirroring wldelay_get_lockout_table_name() (F-2-7).
 *
 * @return string
 */
function wldelay_get_audit_table_name() {
    global $wpdb;

    static $table_names = array();

    $prefix = $wpdb->prefix;
    if ( ! isset( $table_names[ $prefix ] ) ) {
        $table_names[ $prefix ] = $prefix . 'wldelay_audit_log';
    }

    return $table_names[ $prefix ];
}

/**
 * Create (or upgrade) the audit-log table.
 *
 * Idempotent — safe to call on every activation and on the dbDelta upgrade
 * path. Mirrors the log/lockout table approach so dbDelta can evolve the schema.
 */
function wldelay_create_audit_table() {
    global $wpdb;

    $table_name      = wldelay_get_audit_table_name();
    $charset_collate = $wpdb->get_charset_collate();

    $sql = "CREATE TABLE $table_name (
        id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
        actor_id bigint(20) unsigned NOT NULL DEFAULT 0,
        actor_login varchar(60) NOT NULL DEFAULT '',
        action varchar(50) NOT NULL,
        object varchar(191) NOT NULL DEFAULT '',
        old_value text DEFAULT NULL,
        new_value text DEFAULT NULL,
        ip_address varchar(45) NOT NULL DEFAULT '',
        created_at datetime NOT NULL,
        PRIMARY KEY  (id),
        KEY created_at (created_at),
        KEY action (action),
        KEY actor_id (actor_id)
    ) $charset_collate;";

    require_once( ABSPATH . 'wp-admin/includes/upgrade.php' );
    dbDelta( $sql );
}

/**
 * Record an admin/security action in the audit log.
 *
 * Resolves the current actor (WP user, or 0/system when none), captures the
 * client IP, then enqueues the INSERT through the F-4-9 deferred queue so it
 * runs off the hot path on shutdown. The row is assembled NOW (actor, IP, and
 * timestamp are request-context that may not survive to shutdown) and only the
 * DB write is deferred.
 *
 * @param string $action Action key, e.g. 'settings_changed', 'lockout_cleared',
 *                       'whitelist_changed'. Truncated to 50 chars.
 * @param array  $args {
 *     Optional. Action context.
 *
 *     @type string $object    The thing acted on (truncated to 191 chars).
 *     @type mixed  $old_value Previous value (scalar or array; arrays are JSON-encoded).
 *     @type mixed  $new_value New value (scalar or array; arrays are JSON-encoded).
 * }
 * @return int|false Inserted row id, or false when the audit write failed.
 */
function wldelay_audit_log( $action, array $args = array() ) {
    $action = substr( (string) $action, 0, 50 );
    if ( '' === $action ) {
        return;
    }

    $actor_id    = 0;
    $actor_login = '';
    if ( function_exists( 'wp_get_current_user' ) ) {
        $user = wp_get_current_user();
        if ( $user instanceof WP_User && $user->ID > 0 ) {
            $actor_id    = (int) $user->ID;
            $actor_login = substr( (string) $user->user_login, 0, 60 );
        }
    }

    $ip = function_exists( 'wldelay_get_client_ip' ) ? (string) wldelay_get_client_ip() : '';

    $row = array(
        'actor_id'    => $actor_id,
        'actor_login' => $actor_login,
        'action'      => $action,
        'object'      => isset( $args['object'] ) ? substr( (string) $args['object'], 0, 191 ) : '',
        'old_value'   => isset( $args['old_value'] ) ? wldelay_audit_stringify_value( $args['old_value'] ) : null,
        'new_value'   => isset( $args['new_value'] ) ? wldelay_audit_stringify_value( $args['new_value'] ) : null,
        'ip_address'  => substr( $ip, 0, 45 ),
        'created_at'  => current_time( 'mysql', true ),
    );

    // Write synchronously. A compliance trail must not be lossy: the F-4-9
    // deferred queue is best-effort (work still queued when the process exits is
    // dropped) and coalesces identical (id+args) enqueues, so two identical
    // actions within the same second would collapse to one row. Both are
    // unacceptable for an audit log, so the INSERT runs inline on the action
    // path rather than being deferred. Admin/security actions are low-frequency
    // (a handful per session, never in a hot loop), so the synchronous write
    // adds no meaningful latency.
    //
    // The write result is returned so callers (and the integrity marker below)
    // can react to a failed audit INSERT rather than discarding it.
    return wldelay_audit_write_row( $row );
}

/**
 * Normalise an audit value for storage.
 *
 * Arrays/objects are JSON-encoded so a structured diff round-trips; scalars are
 * cast to string. null is preserved so an absent value stays NULL in the column.
 *
 * @param mixed $value Raw value.
 * @return string|null
 */
function wldelay_audit_stringify_value( $value ) {
    if ( null === $value ) {
        return null;
    }
    if ( is_array( $value ) || is_object( $value ) ) {
        $encoded = wp_json_encode( $value );
        return false === $encoded ? '' : $encoded;
    }
    if ( is_bool( $value ) ) {
        return $value ? '1' : '0';
    }
    return (string) $value;
}

/**
 * Deferred-task handler: write one assembled audit row to the table.
 *
 * Registered with the F-4-9 queue under WLDELAY_AUDIT_TASK_ID. Also callable
 * directly (synchronous fallback, and in tests).
 *
 * @param array $args { @type array $row Pre-assembled column => value map. }
 */
function wldelay_audit_task_write( $args = array() ) {
    if ( empty( $args['row'] ) || ! is_array( $args['row'] ) ) {
        return;
    }
    wldelay_audit_write_row( $args['row'] );
}

/**
 * Insert one fully-assembled audit row.
 *
 * @param array $row Column => value map produced by wldelay_audit_log().
 * @return int|false Inserted row id, or false on failure.
 */
function wldelay_audit_write_row( array $row ) {
    global $wpdb;

    $table_name = wldelay_get_audit_table_name();

    $data = array(
        'actor_id'    => isset( $row['actor_id'] ) ? (int) $row['actor_id'] : 0,
        'actor_login' => isset( $row['actor_login'] ) ? (string) $row['actor_login'] : '',
        'action'      => isset( $row['action'] ) ? (string) $row['action'] : '',
        'object'      => isset( $row['object'] ) ? (string) $row['object'] : '',
        'old_value'   => array_key_exists( 'old_value', $row ) ? $row['old_value'] : null,
        'new_value'   => array_key_exists( 'new_value', $row ) ? $row['new_value'] : null,
        'ip_address'  => isset( $row['ip_address'] ) ? (string) $row['ip_address'] : '',
        'created_at'  => isset( $row['created_at'] ) ? (string) $row['created_at'] : current_time( 'mysql', true ),
    );

    $formats = array( '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%s' );

    $result = $wpdb->insert( $table_name, $data, $formats );

    if ( false === $result ) {
        // A swallowed audit INSERT is an invisible gap in the compliance trail
        // (table outage, schema failure, strict-mode rejection). Surface it on
        // the operator log so the gap is detectable rather than silent. Not
        // gated on WP_DEBUG: production sites (WP_DEBUG off) must still see a
        // failed audit write. Mirrors wldelay_note_persistence_failure().
        $last_error = is_object( $wpdb ) && isset( $wpdb->last_error ) ? $wpdb->last_error : 'unknown error';

        error_log( // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
            sprintf(
                'WP Login Delay: audit-log write failed for action "%s" (%s) — entry not recorded.',
                isset( $data['action'] ) ? $data['action'] : '',
                $last_error
            )
        );

        // Persist an admin-visible integrity marker so the gap is detectable
        // from the plugin UI, not just the operator log (which may be
        // unavailable or unmonitored in production). The marker is stored as a
        // standalone option — NOT in the audit table — so it survives the very
        // failure it records (table outage / schema fault).
        wldelay_record_audit_write_failure( isset( $data['action'] ) ? (string) $data['action'] : '', $last_error );

        return false;
    }

    // A verified successful write records pipeline RECOVERY but must NOT erase
    // the integrity marker. The row(s) lost during the outage are permanently
    // gone; a later success proves the pipeline works again, not that the trail
    // is complete. Conflating the two would let an apparently authoritative
    // audit log hide a known gap. The trail-incomplete warning therefore
    // persists until an administrator explicitly acknowledges the gap
    // (nonce-protected); recovery is tracked separately as recovered_at.
    wldelay_note_audit_write_recovered();

    return (int) $wpdb->insert_id;
}

/**
 * Option key for the audit-integrity health marker.
 *
 * Stored as a standalone wp_option (NOT a row in the audit table) so the signal
 * survives the failure it records — a table outage or schema fault that blocks
 * audit INSERTs must not also blank the "trail is incomplete" warning.
 */
if ( ! defined( 'WLDELAY_AUDIT_HEALTH_OPTION' ) ) {
    define( 'WLDELAY_AUDIT_HEALTH_OPTION', 'wldelay_audit_health' );
}

/**
 * Option key for the audit-gap acknowledgement watermark.
 *
 * Deliberately a SEPARATE option from WLDELAY_AUDIT_HEALTH_OPTION: the failure
 * recorder writes only the health option and the acknowledgement writes only
 * this one, so the two paths never perform a read-modify-write on the same
 * option. That makes a concurrent failure impossible to clobber with a stale
 * acknowledgement (the prior single-option design lost the newer failure and
 * its count). Degraded state is derived by comparing the failure generation
 * (health 'count') against the acknowledged generation here.
 */
if ( ! defined( 'WLDELAY_AUDIT_ACK_OPTION' ) ) {
    define( 'WLDELAY_AUDIT_ACK_OPTION', 'wldelay_audit_ack' );
}

/**
 * Record that an audit write failed, for admin-visible surfacing.
 *
 * Fires an action (parity with wldelay_note_persistence_failure so monitoring
 * can hook it) and persists a durable marker capturing the last failure time,
 * the action that was lost, and a running failure count since the last
 * recovery. Best-effort: if the options store is itself the failure, the marker
 * may not stick — the error_log line is the backstop in that case.
 *
 * @param string $action Action key whose audit row could not be written.
 * @param string $error  DB error string (for operator context; not displayed raw).
 */
function wldelay_record_audit_write_failure( $action, $error = '' ) {
    if ( function_exists( 'do_action' ) ) {
        /**
         * Fires when an audit-log row could not be written.
         *
         * @param string $action Action key whose audit row was lost.
         * @param string $error  DB error string.
         */
        do_action( 'wldelay_audit_write_failed', $action, $error );
    }

    if ( ! function_exists( 'update_option' ) || ! function_exists( 'get_option' ) ) {
        return;
    }

    $existing  = get_option( WLDELAY_AUDIT_HEALTH_OPTION, array() );
    $existing  = is_array( $existing ) ? $existing : array();
    $count     = isset( $existing['count'] ) ? (int) $existing['count'] : 0;
    $now       = current_time( 'mysql', true );
    // gap_since is sticky: the moment the FIRST unacknowledged write failed.
    // It survives recoveries so the durable record shows when the gap opened.
    $gap_since = ( isset( $existing['gap_since'] ) && '' !== (string) $existing['gap_since'] )
        ? $existing['gap_since']
        : $now;

    update_option(
        WLDELAY_AUDIT_HEALTH_OPTION,
        array(
            'gap_since'    => $gap_since,
            'failed_at'    => $now,
            'last_action'  => substr( (string) $action, 0, 50 ),
            'count'        => $count + 1,
            // A fresh failure bumps the generation past any acknowledged
            // watermark, so wldelay_audit_log_is_degraded() reopens the warning
            // automatically — no need to touch the (separate) ack option here.
            // Drop the prior recovery note so a stale recovered_at can't imply
            // this new failure already healed.
            'recovered_at' => null,
        ),
        false // Not autoloaded: only read on the plugin admin screen.
    );
}

/**
 * Note that the audit pipeline recovered (a write succeeded after a failure).
 *
 * Records the recovery time on the existing integrity marker but deliberately
 * does NOT delete it: the rows lost during the outage stay lost, so the
 * trail-incomplete warning must persist until an administrator acknowledges the
 * gap. Cheap on the healthy path — when no marker exists this is a single read.
 */
function wldelay_note_audit_write_recovered() {
    if ( ! function_exists( 'get_option' ) || ! function_exists( 'update_option' ) ) {
        return;
    }

    $marker = get_option( WLDELAY_AUDIT_HEALTH_OPTION, false );
    if ( ! is_array( $marker ) || empty( $marker ) ) {
        return; // Healthy: nothing to annotate.
    }

    if ( ! empty( $marker['recovered_at'] ) ) {
        return; // Recovery already noted since the last failure; no write needed.
    }

    $marker['recovered_at'] = current_time( 'mysql', true );
    update_option( WLDELAY_AUDIT_HEALTH_OPTION, $marker, false );
}

/**
 * Acknowledge a known audit-trail gap (explicit, nonce-protected admin action).
 *
 * Clears the admin-visible warning WITHOUT discarding the forensic record: the
 * marker is retained with an acknowledged_at stamp (and the original gap_since
 * / count), so the fact that a gap existed remains durably recorded. Only this
 * deliberate operator action — never an automatic successful write — silences
 * the warning. A subsequent write failure reopens the gap (recorder drops
 * acknowledged_at), so the warning returns.
 *
 * Concurrency: the acknowledgement is written to its OWN option
 * (WLDELAY_AUDIT_ACK_OPTION), never to the health option the failure recorder
 * mutates, so a failure that lands while an admin is acknowledging cannot be
 * overwritten (and its count cannot be lost). The acknowledgement records the
 * generation the admin actually saw ($observed_count): a newer, still-unseen
 * failure pushes the health 'count' past that watermark, so the warning stays
 * raised rather than being silently dismissed.
 *
 * @param int      $actor_id       Acknowledging user id (0/system when unknown).
 * @param int|null $observed_count Failure generation the admin saw (health
 *                                 'count' at render time). Null acknowledges the
 *                                 current generation.
 * @return bool True when an outstanding gap was acknowledged.
 */
function wldelay_acknowledge_audit_gap( $actor_id = 0, $observed_count = null ) {
    if ( ! function_exists( 'get_option' ) || ! function_exists( 'update_option' ) ) {
        return false;
    }

    $health = get_option( WLDELAY_AUDIT_HEALTH_OPTION, false );
    if ( ! is_array( $health ) || empty( $health ) ) {
        return false; // Nothing outstanding to acknowledge.
    }

    $count    = isset( $health['count'] ) ? (int) $health['count'] : 0;
    $ack      = wldelay_get_audit_ack_watermark();
    $prev_ack = isset( $ack['acknowledged_count'] ) ? (int) $ack['acknowledged_count'] : 0;

    if ( $count <= $prev_ack ) {
        return false; // No unacknowledged failure outstanding.
    }

    // Acknowledge only up to the generation the admin actually saw. Clamp into
    // [$prev_ack, $count] so the watermark never regresses and never jumps past
    // a failure the admin could not have seen.
    $ack_count = ( null === $observed_count ) ? $count : (int) $observed_count;
    if ( $ack_count > $count ) {
        $ack_count = $count;
    }
    if ( $ack_count < $prev_ack ) {
        $ack_count = $prev_ack;
    }

    update_option(
        WLDELAY_AUDIT_ACK_OPTION,
        array(
            'acknowledged_at'    => current_time( 'mysql', true ),
            'acknowledged_by'    => (int) $actor_id,
            'acknowledged_count' => $ack_count,
        ),
        false // Not autoloaded: only read on the plugin admin screen.
    );

    return true;
}

/**
 * Raw acknowledgement watermark (separate option from the health marker).
 *
 * @return array Empty array when nothing has been acknowledged.
 */
function wldelay_get_audit_ack_watermark() {
    if ( ! function_exists( 'get_option' ) ) {
        return array();
    }

    $ack = get_option( WLDELAY_AUDIT_ACK_OPTION, array() );

    return is_array( $ack ) ? $ack : array();
}

/**
 * Current audit-integrity health state.
 *
 * Reports a read-only MERGE of the failure marker and the (separate)
 * acknowledgement watermark so callers see one coherent record. The two are
 * stored apart only to keep their writers from clobbering each other; for
 * display/inspection they are recombined here without any write.
 *
 * @return array|false Marker array (gap_since/failed_at/last_action/count/
 *                     recovered_at/acknowledged_at/acknowledged_by/
 *                     acknowledged_count), or false when no gap has ever been
 *                     recorded.
 */
function wldelay_get_audit_health() {
    if ( ! function_exists( 'get_option' ) ) {
        return false;
    }

    $marker = get_option( WLDELAY_AUDIT_HEALTH_OPTION, false );
    if ( ! is_array( $marker ) || empty( $marker ) ) {
        return false;
    }

    $ack = wldelay_get_audit_ack_watermark();
    if ( ! empty( $ack ) ) {
        $marker = array_merge( $marker, $ack );
    }

    return $marker;
}

/**
 * Whether the audit trail is known to be incomplete: a write has failed and the
 * resulting gap has NOT yet been acknowledged by an administrator.
 *
 * Derived by comparing the failure generation (health 'count') against the
 * acknowledged generation. Stays true across a later successful write (the lost
 * rows do not come back), and a fresh failure that bumps 'count' past the
 * acknowledged watermark reopens it automatically — only an acknowledgement
 * that covers the current generation makes it false.
 *
 * @return bool
 */
function wldelay_audit_log_is_degraded() {
    if ( ! function_exists( 'get_option' ) ) {
        return false;
    }

    $health = get_option( WLDELAY_AUDIT_HEALTH_OPTION, false );
    if ( ! is_array( $health ) || empty( $health ) ) {
        return false; // Never failed.
    }

    $count     = isset( $health['count'] ) ? (int) $health['count'] : 0;
    $ack       = wldelay_get_audit_ack_watermark();
    $ack_count = isset( $ack['acknowledged_count'] ) ? (int) $ack['acknowledged_count'] : 0;

    return $count > $ack_count;
}

// Register the deferred audit-write handler at boot so any request can enqueue a
// write. Guarded so the file stays loadable in the unit suite (no async layer).
if ( function_exists( 'wldelay_register_task_handler' ) ) {
    wldelay_register_task_handler( WLDELAY_AUDIT_TASK_ID, 'wldelay_audit_task_write' );
}

// ==========================================================================
// Read / query
// ==========================================================================

/**
 * Sanitize audit-log filter input (admin UI).
 *
 * Accepts either raw request keys (wldelay_audit_*) or short keys.
 *
 * @param array $input Raw filter input from $_GET or short-key array.
 * @return array{action:string,actor:string,from:string,to:string}
 */
function wldelay_sanitize_audit_filters( $input ) {
    if ( ! is_array( $input ) ) {
        $input = array();
    }

    $key_map = array(
        'action' => 'wldelay_audit_action',
        'actor'  => 'wldelay_audit_actor',
        'from'   => 'wldelay_audit_from',
        'to'     => 'wldelay_audit_to',
    );

    $raw = array();
    foreach ( $key_map as $short => $long ) {
        if ( isset( $input[ $long ] ) ) {
            $raw[ $short ] = $input[ $long ];
        } elseif ( isset( $input[ $short ] ) ) {
            $raw[ $short ] = $input[ $short ];
        } else {
            $raw[ $short ] = '';
        }
    }

    $action = strtolower( trim( sanitize_text_field( (string) $raw['action'] ) ) );
    if ( $action !== '' && ! preg_match( '/^[a-z0-9_-]{1,50}$/', $action ) ) {
        $action = '';
    }

    $actor = trim( sanitize_text_field( (string) $raw['actor'] ) );
    if ( strlen( $actor ) > 60 ) {
        $actor = substr( $actor, 0, 60 );
    }

    $from = trim( sanitize_text_field( (string) $raw['from'] ) );
    $to   = trim( sanitize_text_field( (string) $raw['to'] ) );

    if ( ! wldelay_is_valid_date( $from ) ) {
        $from = '';
    }
    if ( ! wldelay_is_valid_date( $to ) ) {
        $to = '';
    }

    if ( $from !== '' && $to !== '' && $from > $to ) {
        $tmp  = $from;
        $from = $to;
        $to   = $tmp;
    }

    return array(
        'action' => $action,
        'actor'  => $actor,
        'from'   => $from,
        'to'     => $to,
    );
}

/**
 * Get sanitized audit-log filters from the current request.
 *
 * @return array{action:string,actor:string,from:string,to:string}
 */
function wldelay_get_audit_filters_from_request() {
    $expected_keys = array(
        'wldelay_audit_action',
        'wldelay_audit_actor',
        'wldelay_audit_from',
        'wldelay_audit_to',
    );

    return wldelay_sanitize_audit_filters(
        wp_unslash( array_intersect_key( $_GET, array_flip( $expected_keys ) ) )
    );
}

/**
 * Build a reusable WHERE clause for audit-log filters.
 *
 * @param array $filters Raw or sanitized filter values.
 * @return array{where:string,params:array}
 */
function wldelay_build_audit_where_clause( $filters ) {
    global $wpdb;

    $filters = wldelay_sanitize_audit_filters( $filters );

    $where  = array();
    $params = array();

    if ( $filters['action'] !== '' ) {
        $where[]  = 'action = %s';
        $params[] = $filters['action'];
    }

    if ( $filters['actor'] !== '' ) {
        if ( ctype_digit( $filters['actor'] ) ) {
            // Numeric input: match either the login or the exact actor id.
            $where[]  = '( actor_login LIKE %s OR actor_id = %d )';
            $params[] = '%' . $wpdb->esc_like( $filters['actor'] ) . '%';
            $params[] = (int) $filters['actor'];
        } else {
            // Non-numeric input: login match ONLY. Folding in `actor_id = 0`
            // here would return every system-generated row (actor_id 0) on any
            // text search, producing misleading forensic results and counts.
            $where[]  = 'actor_login LIKE %s';
            $params[] = '%' . $wpdb->esc_like( $filters['actor'] ) . '%';
        }
    }

    // Rows are stored in UTC (current_time( 'mysql', true )). The date filters
    // are site-local calendar dates, so convert each local boundary to UTC
    // before comparing — otherwise events near a day boundary are wrongly
    // included or omitted on non-UTC sites.
    if ( $filters['from'] !== '' ) {
        $where[]  = 'created_at >= %s';
        $params[] = get_gmt_from_date( $filters['from'] . ' 00:00:00' );
    }

    if ( $filters['to'] !== '' ) {
        $where[]  = 'created_at <= %s';
        $params[] = get_gmt_from_date( $filters['to'] . ' 23:59:59' );
    }

    return array(
        'where'  => ! empty( $where ) ? ' WHERE ' . implode( ' AND ', $where ) : '',
        'params' => $params,
    );
}

/**
 * Count audit entries matching optional filters.
 *
 * @param array $filters Raw or sanitized filter values.
 * @return int Matching row count.
 */
function wldelay_count_audit_log( $filters = array() ) {
    global $wpdb;

    $table_name   = wldelay_get_audit_table_name();
    $where_parts  = wldelay_build_audit_where_clause( $filters );
    $where_clause = $where_parts['where'];
    $params       = $where_parts['params'];

    $sql = "SELECT COUNT(*) FROM $table_name{$where_clause}";

    if ( empty( $params ) ) {
        return (int) $wpdb->get_var( $sql );
    }

    return (int) $wpdb->get_var( $wpdb->prepare( $sql, $params ) );
}

/**
 * Query audit-log entries with optional filters and pagination.
 *
 * Mirrors wldelay_get_login_log_attempts(): filters are always sanitized
 * internally, so callers may pass raw request data.
 *
 * @param array $filters  Raw or sanitized filter values.
 * @param int   $page     1-based page number. Default 1.
 * @param int   $per_page Rows per page. Default 25.
 * @return array Array of result objects ordered by created_at DESC, id DESC.
 */
function wldelay_query_audit_log( array $filters = array(), $page = 1, $per_page = 25 ) {
    global $wpdb;

    $page     = max( 1, absint( $page ) );
    $per_page = max( 1, absint( $per_page ) );
    $offset   = ( $page - 1 ) * $per_page;

    $table_name   = wldelay_get_audit_table_name();
    $where_parts  = wldelay_build_audit_where_clause( $filters );
    $where_clause = $where_parts['where'];
    $params       = $where_parts['params'];

    // $table_name is derived from $wpdb->prefix (not user input). The id tie-break
    // keeps ordering deterministic when several rows share a created_at second.
    $sql = "SELECT * FROM $table_name{$where_clause} ORDER BY created_at DESC, id DESC LIMIT %d OFFSET %d";

    $params[] = $per_page;
    $params[] = $offset;

    return $wpdb->get_results( $wpdb->prepare( $sql, $params ) );
}

/**
 * List the distinct action keys present in the audit log.
 *
 * Used to populate the admin filter dropdown without hard-coding the full set.
 *
 * @param int $limit Maximum distinct actions to return.
 * @return string[]
 */
function wldelay_get_audit_action_options( $limit = 50 ) {
    global $wpdb;

    $limit      = max( 1, absint( $limit ) );
    $table_name = wldelay_get_audit_table_name();

    $rows = $wpdb->get_col(
        $wpdb->prepare(
            "SELECT DISTINCT action FROM $table_name ORDER BY action ASC LIMIT %d",
            $limit
        )
    );

    return is_array( $rows ) ? array_values( array_filter( array_map( 'strval', $rows ) ) ) : array();
}

/**
 * Human-readable label for a known audit action key.
 *
 * @param string $action Action key.
 * @return string Translated label, or the raw key when unknown.
 */
function wldelay_get_audit_action_label( $action ) {
    $action = (string) $action;
    $labels = array(
        'settings_changed'  => __( 'Settings changed', 'login-delay-shield' ),
        'lockout_cleared'   => __( 'Lockout cleared', 'login-delay-shield' ),
        'lockouts_flushed'  => __( 'All lockouts flushed', 'login-delay-shield' ),
        'whitelist_changed' => __( 'Whitelist changed', 'login-delay-shield' ),
        'audit_gap_acknowledged' => __( 'Audit gap acknowledged', 'login-delay-shield' ),
    );

    return isset( $labels[ $action ] ) ? $labels[ $action ] : $action;
}

// ==========================================================================
// Capture points
// ==========================================================================

/**
 * Option keys that hold token-like secrets and must be masked in the diff
 * rather than written verbatim to the audit trail.
 *
 * @return string[]
 */
function wldelay_audit_secret_option_keys() {
    return array( 'wldelay_fail2ban_default_token' );
}

/**
 * Build a compact diff of changed option keys for the audit trail.
 *
 * Compares the old and new wldelay_options arrays and returns only the keys
 * whose value actually changed, each as array( 'old' => ..., 'new' => ... ).
 * Token-like values are masked so secrets never land in the trail. Pure logic
 * (no WordPress calls) so it is unit-testable.
 *
 * @param array $old Previous options array.
 * @param array $new New options array.
 * @return array<string,array{old:mixed,new:mixed}> Changed keys only.
 */
function wldelay_build_settings_diff( $old, $new ) {
    $old = is_array( $old ) ? $old : array();
    $new = is_array( $new ) ? $new : array();

    $secret_keys = wldelay_audit_secret_option_keys();
    $all_keys    = array_unique( array_merge( array_keys( $old ), array_keys( $new ) ) );
    $diff        = array();

    foreach ( $all_keys as $key ) {
        $old_value = array_key_exists( $key, $old ) ? $old[ $key ] : null;
        $new_value = array_key_exists( $key, $new ) ? $new[ $key ] : null;

        // Loose-but-typed comparison: normalise scalars so true/1 and false/''
        // bool<->int toggles still register, but identical values do not.
        if ( wldelay_audit_values_equal( $old_value, $new_value ) ) {
            continue;
        }

        if ( in_array( $key, $secret_keys, true ) || wldelay_audit_key_is_secret( $key ) ) {
            $diff[ $key ] = array(
                'old' => null === $old_value ? null : '***',
                'new' => null === $new_value ? null : '***',
            );
            continue;
        }

        $diff[ $key ] = array(
            'old' => $old_value,
            'new' => $new_value,
        );
    }

    return $diff;
}

/**
 * Whether an option key name looks token/secret-like and should be masked.
 *
 * @param string $key Option key.
 * @return bool
 */
function wldelay_audit_key_is_secret( $key ) {
    return (bool) preg_match( '/(token|secret|password|api[_-]?key)/i', (string) $key );
}

/**
 * Compare two stored option values for audit-diff purposes.
 *
 * Arrays compare by JSON encoding (order-sensitive, which matches how settings
 * are stored); scalars compare loosely after casting bool to int so a
 * checkbox false/'' or true/1 round-trip is treated as unchanged.
 *
 * @param mixed $a Old value.
 * @param mixed $b New value.
 * @return bool True when equal for audit purposes.
 */
function wldelay_audit_values_equal( $a, $b ) {
    if ( is_array( $a ) || is_array( $b ) ) {
        return wp_json_encode( $a ) === wp_json_encode( $b );
    }

    $norm = static function ( $v ) {
        if ( is_bool( $v ) ) {
            return $v ? '1' : '0';
        }
        if ( null === $v ) {
            return '';
        }
        return (string) $v;
    };

    return $norm( $a ) === $norm( $b );
}

/**
 * Capture point: settings changed.
 *
 * Hooked to update_option_wldelay_options (fires only when the stored option
 * actually changes), so a no-op save records nothing. Records a single
 * settings_changed entry whose new_value is the compact changed-key diff and
 * whose object is the comma-separated list of changed keys. Whitelist edits are
 * covered here (the whitelist key appears in the diff) rather than double-logged.
 *
 * @param mixed $old_value Previous option value.
 * @param mixed $new_value New option value.
 */
function wldelay_audit_on_settings_update( $old_value, $new_value ) {
    $diff = wldelay_build_settings_diff( $old_value, $new_value );

    if ( empty( $diff ) ) {
        return;
    }

    wldelay_audit_log(
        'settings_changed',
        array(
            'object'    => implode( ', ', array_keys( $diff ) ),
            'new_value' => $diff,
        )
    );
}
/**
 * Capture point: settings created (fresh install / first save).
 *
 * Hooked to add_option_wldelay_options. On a fresh activation wldelay_options
 * is intentionally absent, so the first save goes through WordPress's
 * add-option path and fires add_option_{$option}, NOT update_option_{$option}.
 * Without this hook the initial security configuration (e.g. enabling proxy
 * trust or adding whitelist entries) would have no forensic baseline. Routes
 * an empty old value and the added value through the shared diff capture.
 *
 * @param string $option Option name (unused; the hook is option-specific).
 * @param mixed  $value  Added option value.
 */
function wldelay_audit_on_settings_add( $option, $value ) {
    wldelay_audit_on_settings_update( array(), $value );
}
// Guarded so the module stays loadable in the unit suite (no WP runtime). In
// production add_action and the option-name constant are always present.
if ( function_exists( 'add_action' ) && defined( 'WLDELAY_OPTION_NAME' ) ) {
    add_action( 'update_option_' . WLDELAY_OPTION_NAME, 'wldelay_audit_on_settings_update', 10, 2 );
    add_action( 'add_option_' . WLDELAY_OPTION_NAME, 'wldelay_audit_on_settings_add', 10, 2 );
}

/**
 * Capture point: manual lockout clear.
 *
 * Fired by the unlock handler after it clears the current admin's IP. Records a
 * lockout_cleared entry naming the cleared IP/username target.
 *
 * @param string $ip       Cleared IP address.
 * @param string $username Cleared username (may be empty).
 * @param int    $removed  Number of lockout rows removed.
 */
function wldelay_audit_lockout_cleared( $ip, $username = '', $removed = 0 ) {
    $target = (string) $ip;
    if ( '' !== (string) $username ) {
        $target .= ' / ' . (string) $username;
    }

    wldelay_audit_log(
        'lockout_cleared',
        array(
            'object'    => $target,
            'new_value' => array( 'removed_rows' => (int) $removed ),
        )
    );
}

/**
 * Admin notice: warn that the audit trail is known to be incomplete.
 *
 * Renders a dismissible-free error notice on the plugin settings screen when an
 * audit write has failed and not yet recovered. This is the admin-visible
 * integrity signal: without it the read-only Audit Log UI would look
 * authoritative while silently missing security-relevant events. Scoped to the
 * plugin page (the inline warning above the log carries the same signal in
 * context) and to users who can act on it.
 */
function wldelay_render_audit_health_notice() {
    if ( ! is_admin() || ! current_user_can( 'manage_options' ) ) {
        return;
    }

    if ( ! isset( $_GET['page'] ) || 'login-delay-shield-admin' !== $_GET['page'] ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        return;
    }

    if ( ! wldelay_audit_log_is_degraded() ) {
        return;
    }

    echo '<div class="notice notice-error"><p><strong>'
        . esc_html__( 'Login Delay Shield', 'login-delay-shield' ) . '</strong> — '
        . esc_html__( 'One or more audit-log entries could not be written, so the audit trail below is permanently incomplete. The lost events cannot be recovered. Check your database/error log, then acknowledge the gap to dismiss this warning.', 'login-delay-shield' )
        . ' <a href="' . esc_url( wldelay_get_audit_ack_gap_url() ) . '">'
        . esc_html__( 'Acknowledge gap', 'login-delay-shield' ) . '</a>'
        . '</p></div>';
}

/**
 * Nonce-protected URL for acknowledging a known audit-trail gap.
 *
 * @return string
 */
function wldelay_get_audit_ack_gap_url() {
    // Embed the failure generation the admin is currently looking at so the
    // handler acknowledges only that generation. A failure that lands after the
    // page was rendered bumps the live count past this value and keeps the
    // warning raised rather than being dismissed unseen.
    $health = wldelay_get_audit_health();
    $gen    = is_array( $health ) && isset( $health['count'] ) ? (int) $health['count'] : 0;

    $url = add_query_arg(
        array(
            'action'           => 'wldelay_ack_audit_gap',
            'wldelay_audit_gen' => $gen,
        ),
        admin_url( 'admin-post.php' )
    );

    return wp_nonce_url( $url, 'wldelay_ack_audit_gap' );
}

/**
 * admin-post handler: acknowledge a known audit-trail gap.
 *
 * Explicit, capability- and nonce-checked. Retains the forensic marker (with an
 * acknowledged_at stamp) while dismissing the admin warning. The acknowledgement
 * itself is audited so the dismissal is part of the trail.
 */
function wldelay_handle_ack_audit_gap() {
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_die( esc_html__( 'You are not allowed to perform this action.', 'login-delay-shield' ) );
    }

    check_admin_referer( 'wldelay_ack_audit_gap' );

    $actor_id = function_exists( 'get_current_user_id' ) ? (int) get_current_user_id() : 0;

    // Generation the admin saw when the acknowledge link was rendered. Only that
    // generation is dismissed; a newer failure keeps the warning raised.
    $observed_gen = isset( $_GET['wldelay_audit_gen'] ) ? absint( wp_unslash( $_GET['wldelay_audit_gen'] ) ) : null;

    if ( wldelay_acknowledge_audit_gap( $actor_id, $observed_gen ) ) {
        // Audit the acknowledgement itself so the dismissal is on the record.
        wldelay_audit_log(
            'audit_gap_acknowledged',
            array( 'object' => 'audit_log' )
        );
    }

    $redirect_url = add_query_arg(
        array(
            'page'                  => 'login-delay-shield-admin',
            'wldelay_audit_gap_ack' => '1',
        ),
        admin_url( 'options-general.php' )
    );

    wp_safe_redirect( $redirect_url );

    if ( defined( 'WP_TESTS_DOMAIN' ) ) {
        return;
    }
    exit;
}

// Guarded so the module stays loadable in the unit suite (no WP runtime).
if ( function_exists( 'add_action' ) ) {
    add_action( 'admin_notices', 'wldelay_render_audit_health_notice' );
    add_action( 'admin_post_wldelay_ack_audit_gap', 'wldelay_handle_ack_audit_gap' );
}
