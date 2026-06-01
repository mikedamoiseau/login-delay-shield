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
 * RELIABILITY: audit WRITES are routed through the F-4-9 deferred task queue
 * (wldelay-async.php) so the INSERT stays off the request critical path. That
 * queue is best-effort — work still queued when the process exits is dropped
 * (see the reliability contract in wldelay-async.php). For admin-rate actions
 * (a handful per session, never in a hot loop) that trade-off is acceptable: the
 * actions are low-frequency and the writes coalesce/flush on shutdown. If a
 * future capture point is high-frequency or loss-sensitive, write it
 * synchronously via wldelay_audit_write_row() instead of deferring.
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

    if ( function_exists( 'wldelay_defer_task' ) ) {
        wldelay_defer_task( WLDELAY_AUDIT_TASK_ID, array( 'row' => $row ) );
    } else {
        // No async layer (should not happen in production) — write synchronously
        // so the action is never silently dropped.
        wldelay_audit_write_row( $row );
    }
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

    return false === $result ? false : (int) $wpdb->insert_id;
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
        // Match either the login or the numeric actor id.
        $where[]  = '( actor_login LIKE %s OR actor_id = %d )';
        $params[] = '%' . $wpdb->esc_like( $filters['actor'] ) . '%';
        $params[] = ctype_digit( $filters['actor'] ) ? (int) $filters['actor'] : 0;
    }

    if ( $filters['from'] !== '' ) {
        $where[]  = 'created_at >= %s';
        $params[] = $filters['from'] . ' 00:00:00';
    }

    if ( $filters['to'] !== '' ) {
        $where[]  = 'created_at <= %s';
        $params[] = $filters['to'] . ' 23:59:59';
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
        'whitelist_changed' => __( 'Whitelist changed', 'login-delay-shield' ),
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
// Guarded so the module stays loadable in the unit suite (no WP runtime). In
// production add_action and the option-name constant are always present.
if ( function_exists( 'add_action' ) && defined( 'WLDELAY_OPTION_NAME' ) ) {
    add_action( 'update_option_' . WLDELAY_OPTION_NAME, 'wldelay_audit_on_settings_update', 10, 2 );
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
