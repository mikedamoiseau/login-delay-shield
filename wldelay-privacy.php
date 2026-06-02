<?php
/**
 * GDPR / CCPA data-subject export & erasure (F-3-1).
 *
 * Registers this plugin's PII with WordPress core Privacy Tools so the site
 * owner can fulfil a data-subject request (Tools → Export / Erase Personal
 * Data) without hand-querying the plugin's tables. Three categories of personal
 * data are covered:
 *
 *   - login-log rows  (wldelay_login_log): failed-login attempts keyed by the
 *                      attempted username — IP, username, timestamp, source.
 *   - audit-log rows  (wldelay_audit_log): admin/security actions the subject
 *                      performed, keyed by actor_login — action, IP, time.
 *   - active lockouts (wldelay_lockouts): the subject's in-force lockouts.
 *
 * SCOPING CHOICE (export & erase). The login log records the username TYPED at a
 * failed attempt, which is arbitrary attacker-controlled input and frequently is
 * NOT a registered account (typos, enumeration probes, bot dictionaries). A
 * data-subject request is made by a verified email address, so this module
 * resolves the email to a registered WP user and operates ONLY on data tied to
 * that user's user_login. Rows logged under a non-account username are deliberately
 * left untouched: they are not personal data of the requesting subject (they may
 * belong to no one, or to an attacker impersonating the subject), and exporting
 * them on an email match would leak unrelated attempt data. An unknown email
 * therefore yields an empty, done result.
 *
 * DELETE-vs-ANONYMIZE CHOICE (erase). The login log and audit log are security
 * telemetry, not business records the site must retain, so erasure DELETES the
 * subject's rows outright rather than anonymising them — anonymising an IP /
 * username in a brute-force log would leave a useless husk while still claiming
 * to honour the erasure. Lockouts are removed through a USERNAME-SCOPED recovery
 * API (wldelay_delete_lockouts_for_user), NOT a raw DELETE and NOT the IP-wide
 * wldelay_delete_lockout_for_ip, so the M5b generation-aware compare-and-delete
 * and the transient-registry flush run while ONLY the subject's rows are touched
 * — an IP-wide delete would clear an unrelated account's lockout on a shared NAT
 * IP, and a hand-rolled delete would orphan the lockout's transient fast-path
 * and leave the subject locked. Expired rows (still carrying the subject's
 * username + IP) are removed too.
 *
 * Hook registration is guarded (function_exists / defined) so the pure helpers
 * stay loadable in the WP-free unit suite, mirroring wldelay-audit.php.
 *
 * @package login-delay-shield
 */

defined( 'ABSPATH' ) || exit;

/**
 * Page size for the paginated exporter / eraser.
 *
 * WordPress drives both in pages, re-invoking the callback with an incrementing
 * $page until it returns done=true. 100 keeps each pass bounded on a large log.
 */
if ( ! defined( 'WLDELAY_PRIVACY_PAGE_SIZE' ) ) {
    define( 'WLDELAY_PRIVACY_PAGE_SIZE', 100 );
}

/**
 * Upper bound on the active-lockout enumeration used by export & erasure.
 *
 * A single subject only has a handful of in-force lockouts, so this is generous
 * headroom that still avoids the unbounded PHP_INT_MAX scan flagged in review
 * (memory/timeout risk on a large table).
 */
if ( ! defined( 'WLDELAY_PRIVACY_LOCKOUT_SCAN_LIMIT' ) ) {
    define( 'WLDELAY_PRIVACY_LOCKOUT_SCAN_LIMIT', 1000 );
}

/**
 * Resolve a data-subject email to the registered user's login name.
 *
 * The login log keys on the username TYPED at the attempt (arbitrary input), so
 * the only safe anchor for a verified-email request is the registered account.
 * Returns '' when no user matches the email — callers then return an empty,
 * done result rather than guessing which arbitrary log usernames belong to the
 * subject. Extracted as a single seam so both the exporter and eraser resolve
 * identically and so the resolution is unit-testable.
 *
 * @param string $email_address Data-subject email address.
 * @return string The matched user's user_login, or '' when no user matches.
 */
function wldelay_privacy_resolve_login_from_email( $email_address ) {
    $email_address = (string) $email_address;

    if ( '' === $email_address || ! function_exists( 'get_user_by' ) ) {
        return '';
    }

    $user = get_user_by( 'email', $email_address );

    if ( ! $user || empty( $user->user_login ) ) {
        return '';
    }

    return (string) $user->user_login;
}

/**
 * Map a login-log row to a WP exporter "item" data array.
 *
 * Pure logic (no WordPress calls beyond the translation wrappers, which are
 * mocked in the unit suite) so the row→item mapping is unit-testable. Returns
 * the list of { name, value } pairs WordPress renders for one exported record.
 *
 * @param object|array $row Login-log row (ip_address, username, attempted_at, source).
 * @return array<int,array{name:string,value:mixed}>
 */
function wldelay_privacy_login_log_row_to_data( $row ) {
    $row = (array) $row;

    return array(
        array(
            'name'  => __( 'IP address', 'login-delay-shield' ),
            'value' => isset( $row['ip_address'] ) ? $row['ip_address'] : '',
        ),
        array(
            'name'  => __( 'Username', 'login-delay-shield' ),
            'value' => isset( $row['username'] ) ? $row['username'] : '',
        ),
        array(
            'name'  => __( 'Attempted at', 'login-delay-shield' ),
            'value' => isset( $row['attempted_at'] ) ? $row['attempted_at'] : '',
        ),
        array(
            'name'  => __( 'Source', 'login-delay-shield' ),
            'value' => isset( $row['source'] ) ? $row['source'] : '',
        ),
    );
}

/**
 * Map an audit-log row to a WP exporter "item" data array.
 *
 * @param object|array $row Audit-log row (action, ip_address, created_at, object).
 * @return array<int,array{name:string,value:mixed}>
 */
function wldelay_privacy_audit_log_row_to_data( $row ) {
    $row = (array) $row;

    return array(
        array(
            'name'  => __( 'Action', 'login-delay-shield' ),
            'value' => isset( $row['action'] ) ? $row['action'] : '',
        ),
        array(
            'name'  => __( 'Object', 'login-delay-shield' ),
            'value' => isset( $row['object'] ) ? $row['object'] : '',
        ),
        array(
            'name'  => __( 'IP address', 'login-delay-shield' ),
            'value' => isset( $row['ip_address'] ) ? $row['ip_address'] : '',
        ),
        array(
            'name'  => __( 'Recorded at', 'login-delay-shield' ),
            'value' => isset( $row['created_at'] ) ? $row['created_at'] : '',
        ),
    );
}

/**
 * Map an active-lockout row to a WP exporter "item" data array.
 *
 * @param object|array $row Lockout row (ip_address, lockout_type, expires_at).
 * @return array<int,array{name:string,value:mixed}>
 */
function wldelay_privacy_lockout_row_to_data( $row ) {
    $row = (array) $row;

    return array(
        array(
            'name'  => __( 'IP address', 'login-delay-shield' ),
            'value' => isset( $row['ip_address'] ) ? $row['ip_address'] : '',
        ),
        array(
            'name'  => __( 'Lockout type', 'login-delay-shield' ),
            'value' => isset( $row['lockout_type'] ) ? $row['lockout_type'] : '',
        ),
        array(
            'name'  => __( 'Expires at', 'login-delay-shield' ),
            'value' => isset( $row['expires_at'] )
                ? gmdate( 'Y-m-d H:i:s', (int) $row['expires_at'] )
                : '',
        ),
    );
}

/**
 * Register this plugin's exporter with WordPress core Privacy Tools.
 *
 * @param array $exporters Registered exporters keyed by id.
 * @return array
 */
function wldelay_register_privacy_exporter( $exporters ) {
    $exporters['login-delay-shield'] = array(
        'exporter_friendly_name' => __( 'Login Delay Shield', 'login-delay-shield' ),
        'callback'               => 'wldelay_privacy_exporter',
    );

    return $exporters;
}

/**
 * Register this plugin's eraser with WordPress core Privacy Tools.
 *
 * @param array $erasers Registered erasers keyed by id.
 * @return array
 */
function wldelay_register_privacy_eraser( $erasers ) {
    $erasers['login-delay-shield'] = array(
        'eraser_friendly_name' => __( 'Login Delay Shield', 'login-delay-shield' ),
        'callback'             => 'wldelay_privacy_eraser',
    );

    return $erasers;
}

/**
 * WP Privacy exporter callback.
 *
 * Resolves the email to a registered user and exports, in WordPress's paginated
 * shape, that user's login-log rows, audit-log rows and active lockouts.
 *
 * Pagination model: the login log is the only group that can grow large (one row
 * per failed attempt), so it is paginated PAGE_SIZE rows at a time. The audit log
 * and active lockouts are small, bounded sets, so they are emitted together once
 * the login log is fully drained — appended to the final login-log page when it
 * has room, or on the page immediately after the last login-log page. WordPress
 * accumulates every page's data until the callback returns done=true, so a
 * subject whose data fits within one page receives all three groups in a single
 * pass.
 *
 * @param string $email_address Data-subject email.
 * @param int    $page          1-based page number.
 * @return array{data:array,done:bool}
 */
function wldelay_privacy_exporter( $email_address, $page = 1 ) {
    $page  = max( 1, (int) $page );
    $login = wldelay_privacy_resolve_login_from_email( $email_address );

    // Unknown email: no registered subject, nothing tied to this person to
    // export. Returning done immediately (rather than scanning arbitrary
    // attempt usernames) is the documented scoping choice.
    if ( '' === $login ) {
        return array(
            'data' => array(),
            'done' => true,
        );
    }

    $page_size = (int) WLDELAY_PRIVACY_PAGE_SIZE;

    // Treat the three groups as one concatenated logical sequence:
    //   [ login-log rows ][ audit-log rows ][ lockout rows ]
    // and emit a deterministic PAGE_SIZE-row window of it per WP page. Every
    // group is paginated (no PHP_INT_MAX fetch), so a subject with a large login
    // OR audit trail never loads the whole table into memory. done=false until
    // the window reaches the end of the last group, so WP keeps accumulating
    // pages. All three counts/queries are EXACT-match on the subject's login —
    // never the admin substring LIKE — so no adjacent account leaks (F-3-1).
    $login_total = wldelay_count_login_log_for_username( $login );
    $audit_total = wldelay_count_audit_log_for_actor( $login );

    // Lockouts are a small, bounded set (one per active IP/type for the subject),
    // materialised once and sliced in PHP. They carry no stable DB id exposed
    // here, so their export item_id is derived from the durable lockout_key.
    $lockout_rows  = wldelay_privacy_get_lockouts_for_login( $login );
    $lockout_total = count( $lockout_rows );

    $total  = $login_total + $audit_total + $lockout_total;
    $offset = ( $page - 1 ) * $page_size;

    if ( $offset >= $total ) {
        // Past the end (e.g. WP requested an extra page, or no data at all).
        return array(
            'data' => array(),
            'done' => true,
        );
    }

    $window_end   = min( $offset + $page_size, $total );
    $export_items = array();

    // ---- Group 1: login-log rows -----------------------------------------
    if ( $offset < $login_total ) {
        $g_offset = $offset;
        $g_limit  = min( $window_end, $login_total ) - $g_offset;
        $rows     = wldelay_get_login_log_for_username( $login, $g_limit, $g_offset );

        foreach ( $rows as $row ) {
            $row = (array) $row;
            $export_items[] = array(
                'group_id'    => 'wldelay-login-log',
                'group_label' => __( 'Login Delay Shield — failed login attempts', 'login-delay-shield' ),
                // item_id from the stable DB row id, not a positional index, so
                // it never collides or shifts across pages.
                'item_id'     => 'wldelay-login-log-' . ( isset( $row['id'] ) ? (int) $row['id'] : 0 ),
                'data'        => wldelay_privacy_login_log_row_to_data( $row ),
            );
        }
    }

    // ---- Group 2: audit-log rows (exact actor_login match) ----------------
    $audit_start = $login_total;
    $audit_end   = $login_total + $audit_total;
    if ( $offset < $audit_end && $window_end > $audit_start ) {
        $g_offset = max( 0, $offset - $audit_start );
        $g_limit  = ( min( $window_end, $audit_end ) - $audit_start ) - $g_offset;
        if ( $g_limit > 0 ) {
            $rows = wldelay_get_audit_log_for_actor( $login, $g_limit, $g_offset );
            foreach ( $rows as $row ) {
                $row = (array) $row;
                $export_items[] = array(
                    'group_id'    => 'wldelay-audit-log',
                    'group_label' => __( 'Login Delay Shield — security audit log', 'login-delay-shield' ),
                    'item_id'     => 'wldelay-audit-log-' . ( isset( $row['id'] ) ? (int) $row['id'] : 0 ),
                    'data'        => wldelay_privacy_audit_log_row_to_data( $row ),
                );
            }
        }
    }

    // ---- Group 3: active lockouts -----------------------------------------
    $lock_start = $audit_end;
    if ( $window_end > $lock_start ) {
        $g_offset = max( 0, $offset - $lock_start );
        $g_limit  = $window_end - $lock_start - $g_offset;
        $slice    = array_slice( $lockout_rows, $g_offset, $g_limit );
        foreach ( $slice as $row ) {
            $row = (array) $row;
            $key = isset( $row['lockout_key'] ) ? (string) $row['lockout_key'] : '';
            if ( '' === $key ) {
                // Legacy/synthetic row without a key — fall back to a stable
                // hash of its identifying columns so the item_id is still unique.
                $key = substr(
                    md5(
                        ( isset( $row['ip_address'] ) ? $row['ip_address'] : '' ) . '|' .
                        ( isset( $row['lockout_type'] ) ? $row['lockout_type'] : '' )
                    ),
                    0,
                    16
                );
            }
            $export_items[] = array(
                'group_id'    => 'wldelay-lockouts',
                'group_label' => __( 'Login Delay Shield — active lockouts', 'login-delay-shield' ),
                'item_id'     => 'wldelay-lockout-' . $key,
                'data'        => wldelay_privacy_lockout_row_to_data( $row ),
            );
        }
    }

    return array(
        'data' => $export_items,
        'done' => $window_end >= $total,
    );
}

/**
 * WP Privacy eraser callback.
 *
 * Resolves the email to a registered user, then DELETES that user's login-log
 * and audit-log rows (security telemetry — deletion is the right disposition,
 * see file header) and removes the user's lockouts (active AND expired) through
 * the username-scoped recovery API so the M5b generation-aware delete +
 * transient flush run without touching other accounts' lockouts.
 *
 * A failed delete ($wpdb->query() returning FALSE, distinct from "0 rows") sets
 * items_retained and appends an actionable message rather than reporting a clean
 * completion.
 *
 * Erasure is not paginated into many passes here: the deletes are bounded SQL
 * (one statement per table) plus a username-scoped recovery call over the
 * subject's lockouts, so a single pass completes the request. done=true is
 * returned on the first page; later pages (should WordPress request them) no-op.
 *
 * @param string $email_address Data-subject email.
 * @param int    $page          1-based page number.
 * @return array{items_removed:bool,items_retained:bool,messages:array,done:bool}
 */
function wldelay_privacy_eraser( $email_address, $page = 1 ) {
    $page  = max( 1, (int) $page );
    $login = wldelay_privacy_resolve_login_from_email( $email_address );

    $result = array(
        'items_removed'  => false,
        'items_retained' => false,
        'messages'       => array(),
        'done'           => true,
    );

    // Unknown email, or a second page after the single-pass erase already ran:
    // nothing to do.
    if ( '' === $login || $page > 1 ) {
        return $result;
    }

    global $wpdb;

    $removed = false;

    // ---- Login-log rows: hard delete (security telemetry) ----------------
    // $wpdb->query() returns the affected-row count, or FALSE on a DB error.
    // FALSE is NOT "0 rows deleted": treating a failed delete as a clean
    // completion would tell WP the subject's data is gone while it remains on
    // disk. Detect FALSE explicitly, flag items_retained and surface an
    // actionable message rather than claiming success (F-3-1).
    $log_table   = wldelay_get_log_table_name();
    $log_deleted = $wpdb->query(
        $wpdb->prepare(
            "DELETE FROM $log_table WHERE username = %s", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name derived from $wpdb->prefix.
            $login
        )
    );
    if ( false === $log_deleted ) {
        $result['items_retained'] = true;
        $result['messages'][]     = __( 'Login Delay Shield could not delete the failed-login records for this user; they were retained. Check the database and retry the erasure.', 'login-delay-shield' );
    } elseif ( $log_deleted > 0 ) {
        $removed = true;
    }

    // ---- Audit-log rows: hard delete -------------------------------------
    $audit_table   = wldelay_get_audit_table_name();
    $audit_deleted = $wpdb->query(
        $wpdb->prepare(
            "DELETE FROM $audit_table WHERE actor_login = %s", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name derived from $wpdb->prefix.
            $login
        )
    );
    if ( false === $audit_deleted ) {
        $result['items_retained'] = true;
        $result['messages'][]     = __( 'Login Delay Shield could not delete the security audit records for this user; they were retained. Check the database and retry the erasure.', 'login-delay-shield' );
    } elseif ( $audit_deleted > 0 ) {
        $removed = true;
    }

    // ---- Lockouts: username-scoped, generation-aware removal -------------
    // wldelay_delete_lockouts_for_user() removes ONLY the subject's durable
    // lockout rows (active AND expired) and clears only their transient
    // fast-path keys, preserving the M5b compare-and-delete + registry flush.
    // The former wldelay_delete_lockout_for_ip() call was IP-WIDE, so it erased
    // an unrelated account's lockout when two users shared a NAT IP — weakening
    // protection for a non-subject. Scoping to the username fixes that and also
    // reaches expired rows (which still bear the subject's username + IP) that
    // an active-only enumeration left behind (F-3-1).
    if ( wldelay_delete_lockouts_for_user( $login ) > 0 ) {
        $removed = true;
    }

    $result['items_removed'] = $removed;

    return $result;
}

/**
 * Active lockouts whose stored username matches a login.
 *
 * Enumerates the durable store's active rows and filters to those whose username
 * column equals the subject's login (the value wldelay_lock_ip persisted via
 * wldelay_get_effective_lockout_username). Returns associative rows carrying at
 * least ip_address, lockout_type and expires_at.
 *
 * @param string $login user_login.
 * @return array[] Matching active lockout rows.
 */
function wldelay_privacy_get_lockouts_for_login( $login ) {
    $login = (string) $login;

    $store = wldelay_get_persistence_store();

    // A single subject has at most a handful of in-force lockouts (one per IP /
    // type they are currently locked from), so a bounded enumeration covers them
    // without the unbounded PHP_INT_MAX scan that would risk a large-table
    // memory/timeout. WLDELAY_PRIVACY_LOCKOUT_SCAN_LIMIT is generous headroom.
    $rows = $store->get_active_lockouts( WLDELAY_PRIVACY_LOCKOUT_SCAN_LIMIT );

    $matched = array();
    foreach ( $rows as $row ) {
        $row = (array) $row;
        if ( isset( $row['username'] ) && (string) $row['username'] === $login ) {
            $matched[] = $row;
        }
    }

    return $matched;
}

// Register exporter/eraser. Guarded so the module stays loadable in the WP-free
// unit suite (no add_filter), mirroring wldelay-audit.php.
if ( function_exists( 'add_filter' ) ) {
    add_filter( 'wp_privacy_personal_data_exporters', 'wldelay_register_privacy_exporter' );
    add_filter( 'wp_privacy_personal_data_erasers', 'wldelay_register_privacy_eraser' );
}
