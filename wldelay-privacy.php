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
 * Run-state transient key for a paginated export of one subject.
 *
 * The exporter holds its keyset cursors + the page-1 ceilings across WP's
 * page-by-page invocations in a short-lived transient (WP only hands the callback
 * an incrementing $page, so the snapshot/cursor state must live somewhere it can
 * read back). Keyed by a hash of the subject login so concurrent export runs for
 * different subjects never collide. The login is hashed (not embedded raw) to
 * keep the option/transient name within length limits and free of odd chars.
 *
 * @param string $login Subject user_login.
 * @return string Transient name.
 */
function wldelay_privacy_export_state_key( $login ) {
    return 'wldelay_pexport_' . sha1( (string) $login );
}

/**
 * Build the per-subject export run state captured on page 1.
 *
 * Snapshots the immutable-id ceilings for the login and audit logs (so the run
 * sees a fixed view of the subject's rows; rows inserted after this point are
 * excluded) and materialises the small, bounded lockout item list once. The
 * cursors start "just past" each ceiling so the first keyset window opens at the
 * ceiling itself. Stored in a transient and advanced page to page (F-3-1).
 *
 * @param string $login Subject user_login.
 * @return array Run state.
 */
function wldelay_privacy_build_export_state( $login ) {
    $login_max = wldelay_get_max_login_log_id_for_username( $login );
    $audit_max = wldelay_get_max_audit_log_id_for_actor( $login );

    return array(
        'login_max'      => $login_max,
        'login_cursor'   => $login_max + 1,
        'login_done'     => ( 0 === $login_max ),
        'audit_max'      => $audit_max,
        'audit_cursor'   => $audit_max + 1,
        'audit_done'     => ( 0 === $audit_max ),
        // Lockouts are tiny and bounded; snapshot the fully-formed export items
        // once on page 1 so later pages slice from a frozen list (no per-page
        // re-query that a concurrent lock/unlock could shift).
        'lockout_items'  => wldelay_privacy_build_lockout_items( $login ),
        'lockout_offset' => 0,
    );
}

/**
 * Build the export items for a subject's active lockouts (page-1 snapshot).
 *
 * @param string $login Subject user_login.
 * @return array[] Export-item arrays.
 */
function wldelay_privacy_build_lockout_items( $login ) {
    $lockout_rows = wldelay_privacy_get_lockouts_for_login( $login );

    // Deterministic order so a snapshot is reproducible and item_ids are stable.
    usort(
        $lockout_rows,
        static function ( $a, $b ) {
            $ka = isset( $a['lockout_key'] ) ? (string) $a['lockout_key'] : '';
            $kb = isset( $b['lockout_key'] ) ? (string) $b['lockout_key'] : '';
            return strcmp( $ka, $kb );
        }
    );

    $items = array();
    foreach ( $lockout_rows as $row ) {
        $row = (array) $row;
        $key = isset( $row['lockout_key'] ) ? (string) $row['lockout_key'] : '';
        if ( '' === $key ) {
            // Legacy/synthetic row without a key — fall back to a stable hash of
            // its identifying columns so the item_id is still unique.
            $key = substr(
                md5(
                    ( isset( $row['ip_address'] ) ? $row['ip_address'] : '' ) . '|' .
                    ( isset( $row['lockout_type'] ) ? $row['lockout_type'] : '' )
                ),
                0,
                16
            );
        }
        $items[] = array(
            'group_id'    => 'wldelay-lockouts',
            'group_label' => __( 'Login Delay Shield — active lockouts', 'login-delay-shield' ),
            'item_id'     => 'wldelay-lockout-' . $key,
            'data'        => wldelay_privacy_lockout_row_to_data( $row ),
        );
    }

    return $items;
}

/**
 * WP Privacy exporter callback.
 *
 * Resolves the email to a registered user and exports, in WordPress's paginated
 * shape, that user's login-log rows, audit-log rows and active lockouts.
 *
 * Pagination model: KEYSET over the immutable row id, NOT offset. Offset
 * pagination over a DESC-sorted log is unstable on an active (brute-force
 * targeted) site — new rows landing at the top between page calls shift the
 * offset window, duplicating a boundary row and skipping an older one (a
 * concurrent retention-purge causes the inverse). Instead, page 1 snapshots a
 * max_id ceiling per log and the run pages by keyset under it (`id <= ceiling AND
 * id < cursor`), carrying the cursor across WP's page calls in a short-lived
 * run-state transient. Rows inserted after the run started (id > ceiling) are
 * excluded (correct — they post-date the request); deletes only shrink the set
 * and can never shift the cursor onto an already-emitted row. The three groups
 * are drained in order — login-log, then audit-log, then the page-1 lockout
 * snapshot — packing up to PAGE_SIZE items per WP page. All log queries are
 * EXACT-match on the subject's login (never the admin substring LIKE) so no
 * adjacent account leaks (F-3-1).
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
    $state_key = wldelay_privacy_export_state_key( $login );

    // Page 1 starts a fresh run: capture the ceilings + lockout snapshot and
    // overwrite any stale state from a prior, abandoned run. Later pages read the
    // carried cursors back. If the state transient was evicted mid-run (rare;
    // object-cache pressure), rebuild it — the ceilings re-snapshot at the
    // current MAX(id), which is monotonic for an append-only log, so a late
    // re-snapshot never re-emits rows already past the cursor.
    if ( 1 === $page ) {
        $state = wldelay_privacy_build_export_state( $login );
    } else {
        $state = get_transient( $state_key );
        if ( ! is_array( $state ) ) {
            $state = wldelay_privacy_build_export_state( $login );
        }
    }

    $export_items = array();
    $remaining    = $page_size;

    // ---- Group 1: login-log rows (keyset under the page-1 ceiling) --------
    if ( empty( $state['login_done'] ) && $remaining > 0 ) {
        $had_room = $remaining;
        $rows     = wldelay_get_login_log_for_username(
            $login,
            $had_room,
            (int) $state['login_max'],
            (int) $state['login_cursor']
        );

        foreach ( $rows as $row ) {
            $row    = (array) $row;
            $row_id = isset( $row['id'] ) ? (int) $row['id'] : 0;
            $export_items[] = array(
                'group_id'    => 'wldelay-login-log',
                'group_label' => __( 'Login Delay Shield — failed login attempts', 'login-delay-shield' ),
                // item_id from the immutable DB row id, not a positional index, so
                // it never collides or shifts across pages.
                'item_id'     => 'wldelay-login-log-' . $row_id,
                'data'        => wldelay_privacy_login_log_row_to_data( $row ),
            );
            // Advance the keyset cursor to the lowest id emitted so the next page
            // resumes strictly below it.
            $state['login_cursor'] = $row_id;
        }

        $fetched    = count( $rows );
        $remaining -= $fetched;

        // Fewer rows than the slot offered → the group is drained under the
        // ceiling. A full slot may still leave rows; they come on the next page.
        if ( $fetched < $had_room ) {
            $state['login_done'] = true;
        }
    }

    // ---- Group 2: audit-log rows (keyset under the page-1 ceiling) --------
    if ( empty( $state['audit_done'] ) && $remaining > 0 ) {
        $rows = wldelay_get_audit_log_for_actor(
            $login,
            $remaining,
            (int) $state['audit_max'],
            (int) $state['audit_cursor']
        );

        foreach ( $rows as $row ) {
            $row    = (array) $row;
            $row_id = isset( $row['id'] ) ? (int) $row['id'] : 0;
            $export_items[] = array(
                'group_id'    => 'wldelay-audit-log',
                'group_label' => __( 'Login Delay Shield — security audit log', 'login-delay-shield' ),
                'item_id'     => 'wldelay-audit-log-' . $row_id,
                'data'        => wldelay_privacy_audit_log_row_to_data( $row ),
            );
            $state['audit_cursor'] = $row_id;
        }

        $fetched    = count( $rows );
        $had_room   = $remaining;
        $remaining -= $fetched;

        if ( $fetched < $had_room ) {
            $state['audit_done'] = true;
        }
    }

    // ---- Group 3: active lockouts (page-1 snapshot, sliced) ---------------
    $lockout_items = isset( $state['lockout_items'] ) && is_array( $state['lockout_items'] )
        ? $state['lockout_items']
        : array();
    $lockout_total = count( $lockout_items );

    if ( $remaining > 0 && (int) $state['lockout_offset'] < $lockout_total ) {
        $slice = array_slice( $lockout_items, (int) $state['lockout_offset'], $remaining );
        foreach ( $slice as $item ) {
            $export_items[]           = $item;
            $state['lockout_offset'] = (int) $state['lockout_offset'] + 1;
        }
        $remaining -= count( $slice );
    }

    // The run is complete once all three groups are drained.
    $done = ! empty( $state['login_done'] )
        && ! empty( $state['audit_done'] )
        && (int) $state['lockout_offset'] >= $lockout_total;

    if ( $done ) {
        delete_transient( $state_key );
    } else {
        // Hold the cursors for the next page. A generous TTL covers a slow,
        // multi-page admin export; the run self-heals if it is ever evicted.
        set_transient( $state_key, $state, HOUR_IN_SECONDS );
    }

    return array(
        'data' => $export_items,
        'done' => $done,
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
    //
    // A FALSE return (NOT a count) means a durable SELECT or DELETE failed at
    // the DB layer, so the subject's lockout PII may still be on disk. Mirror
    // the login/audit branches above: flag items_retained and surface an
    // actionable message rather than reporting a clean completion (F-3-1).
    $lockouts_removed = wldelay_delete_lockouts_for_user( $login );
    if ( false === $lockouts_removed ) {
        $result['items_retained'] = true;
        $result['messages'][]     = __( 'Login Delay Shield could not delete the lockout records for this user; they were retained. Check the database and retry the erasure.', 'login-delay-shield' );
    } elseif ( $lockouts_removed > 0 ) {
        $removed = true;
    }

    $result['items_removed'] = $removed;

    return $result;
}

/**
 * Active lockouts whose stored username matches a login (export view).
 *
 * Scopes at SQL via get_lockouts_for_username() — WHERE username = %s — then
 * keeps only the in-force rows for the export. The earlier implementation scanned
 * the GLOBAL active-lockout prefix (get_active_lockouts(LIMIT) is
 * `WHERE expires_at > now ORDER BY expires_at DESC LIMIT n`) and filtered by
 * username in PHP, so on a busy site the subject's own lockout could sit OUTSIDE
 * that global window and never be exported at all. Scoping by username first
 * guarantees the subject's lockouts are fetched regardless of how many unrelated
 * lockouts the site holds; any bound is applied AFTER the username scope (F-3-1).
 *
 * get_lockouts_for_username() returns rows whose expires_at is a string datetime
 * (active AND expired); this view keeps only the active rows and normalises
 * expires_at to a UNIX timestamp so the export item formatter renders it
 * consistently with the rest of the plugin.
 *
 * @param string $login user_login.
 * @return array[] Matching active lockout rows (empty on a failed read).
 */
function wldelay_privacy_get_lockouts_for_login( $login ) {
    $login = (string) $login;

    $store = wldelay_get_persistence_store();

    // Username-scoped read (active + expired). A failed read returns FALSE; for
    // the EXPORT view we degrade to an empty set rather than fatal — the eraser
    // path (wldelay_delete_lockouts_for_user) is where a failed read is surfaced
    // as items_retained.
    $rows = $store->get_lockouts_for_username( $login );
    if ( ! is_array( $rows ) ) {
        return array();
    }

    $now     = time();
    $matched = array();
    foreach ( $rows as $row ) {
        $row = (array) $row;

        // Skip rows for a different username (defensive — the SQL already scopes
        // to username = %s, but a future store could relax the contract).
        if ( ! isset( $row['username'] ) || (string) $row['username'] !== $login ) {
            continue;
        }

        // Keep only in-force rows for the export view. expires_at arrives as a
        // string datetime stored in UTC.
        $expires_ts = isset( $row['expires_at'] ) ? strtotime( (string) $row['expires_at'] . ' UTC' ) : false;
        if ( false === $expires_ts || $expires_ts <= $now ) {
            continue;
        }

        // Normalise to a UNIX timestamp so wldelay_privacy_lockout_row_to_data()
        // (which casts expires_at to int) renders the date correctly.
        $row['expires_at'] = $expires_ts;
        $matched[]         = $row;

        // Bound the export set AFTER the username scope. A single subject only
        // has a handful of in-force lockouts; the cap is generous headroom that
        // still avoids materialising an unbounded result for a pathological case.
        if ( count( $matched ) >= (int) WLDELAY_PRIVACY_LOCKOUT_SCAN_LIMIT ) {
            break;
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
