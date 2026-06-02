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
 * to honour the erasure. Lockouts are removed through the EXISTING recovery API
 * (wldelay_delete_lockout_for_ip), NOT a raw DELETE, so the M5b generation-aware
 * compare-and-delete and the transient-registry flush run — a hand-rolled delete
 * would orphan the lockout's transient fast-path and leave the subject locked.
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

    $page_size    = (int) WLDELAY_PRIVACY_PAGE_SIZE;
    $offset       = ( $page - 1 ) * $page_size;
    $login_total  = wldelay_count_login_log_attempts( array( 'username' => $login ) );
    $export_items = array();

    // ---- Group 1: login-log rows (paginated) -----------------------------
    if ( $offset < $login_total ) {
        $rows = wldelay_get_login_log_attempts(
            array(
                'filters' => array( 'username' => $login ),
                'limit'   => $page_size,
                'offset'  => $offset,
            )
        );

        foreach ( $rows as $i => $row ) {
            $export_items[] = array(
                'group_id'    => 'wldelay-login-log',
                'group_label' => __( 'Login Delay Shield — failed login attempts', 'login-delay-shield' ),
                'item_id'     => 'wldelay-login-log-' . ( $offset + $i ),
                'data'        => wldelay_privacy_login_log_row_to_data( $row ),
            );
        }

        // If more login-log pages remain, defer the small groups to a later
        // page so this page stays bounded.
        if ( ( $offset + $page_size ) < $login_total ) {
            return array(
                'data' => $export_items,
                'done' => false,
            );
        }
    } elseif ( $offset > $login_total ) {
        // Past both the login log and the single small-groups page: nothing
        // left. (Reached only if WordPress requests an extra page.)
        return array(
            'data' => array(),
            'done' => true,
        );
    }

    // ---- Final page: append the small, bounded groups --------------------
    // audit-log rows (exact actor_login match; the store filter is a LIKE).
    $audit_rows = wldelay_query_audit_log( array( 'actor' => $login ), 1, PHP_INT_MAX );
    foreach ( $audit_rows as $i => $row ) {
        $row = (array) $row;
        if ( ! isset( $row['actor_login'] ) || (string) $row['actor_login'] !== $login ) {
            continue;
        }
        $export_items[] = array(
            'group_id'    => 'wldelay-audit-log',
            'group_label' => __( 'Login Delay Shield — security audit log', 'login-delay-shield' ),
            'item_id'     => 'wldelay-audit-log-' . $i,
            'data'        => wldelay_privacy_audit_log_row_to_data( $row ),
        );
    }

    // active lockouts.
    foreach ( wldelay_privacy_get_lockouts_for_login( $login ) as $i => $row ) {
        $export_items[] = array(
            'group_id'    => 'wldelay-lockouts',
            'group_label' => __( 'Login Delay Shield — active lockouts', 'login-delay-shield' ),
            'item_id'     => 'wldelay-lockout-' . $i,
            'data'        => wldelay_privacy_lockout_row_to_data( $row ),
        );
    }

    return array(
        'data' => $export_items,
        'done' => true,
    );
}

/**
 * WP Privacy eraser callback.
 *
 * Resolves the email to a registered user, then DELETES that user's login-log
 * and audit-log rows (security telemetry — deletion is the right disposition,
 * see file header) and removes the user's active lockouts through the existing
 * recovery API so the M5b generation-aware delete + transient flush run.
 *
 * Erasure is not paginated into many passes here: the deletes are bounded SQL
 * (one statement per table) plus a per-IP recovery call over the handful of
 * active lockouts, so a single pass completes the request. done=true is returned
 * on the first page; later pages (should WordPress request them) no-op.
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
    $log_table   = wldelay_get_log_table_name();
    $log_deleted = $wpdb->query(
        $wpdb->prepare(
            "DELETE FROM $log_table WHERE username = %s", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name derived from $wpdb->prefix.
            $login
        )
    );
    if ( $log_deleted ) {
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
    if ( $audit_deleted ) {
        $removed = true;
    }

    // ---- Lockouts: route through the recovery API ------------------------
    // wldelay_delete_lockout_for_ip() performs the M5b generation-aware durable
    // delete AND flushes the transient fast-path / registry, so the subject is
    // not left locked on an orphaned cache-only transient. A raw DELETE on the
    // lockout table would bypass that and is explicitly avoided.
    foreach ( wldelay_privacy_get_lockouts_for_login( $login ) as $row ) {
        $ip = isset( $row['ip_address'] ) ? (string) $row['ip_address'] : '';
        if ( '' === $ip ) {
            continue;
        }
        if ( wldelay_delete_lockout_for_ip( $ip, $login ) > 0 ) {
            $removed = true;
        }
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
    $rows  = $store->get_active_lockouts( PHP_INT_MAX );

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
