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
 * Stale-lock timeout (seconds) for the per-request processing lock.
 *
 * Two concurrent AJAX page calls for the SAME privacy request must not both
 * consume the keyset cursor (a duplicate-submit / double-fire race would skip
 * rows). The exporter takes a short-lived per-request lock around the
 * read-cursor-advance-write critical section. If a prior page crashed mid-run
 * and never released its lock, a lock older than this timeout is reclaimable so
 * the run is not wedged forever (F-3-1). The window is generous relative to a
 * single page's work yet short enough that a genuinely crashed page recovers on
 * the operator's next click.
 */
if ( ! defined( 'WLDELAY_PRIVACY_LOCK_TIMEOUT' ) ) {
    define( 'WLDELAY_PRIVACY_LOCK_TIMEOUT', 300 );
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
 * The privacy REQUEST id for the AJAX call currently being served, or 0.
 *
 * WordPress hands the exporter/eraser callback only ( $email, $page ) — NOT the
 * user_request post id that identifies THIS run. But during the privacy AJAX
 * handlers (wp_ajax_wp_privacy_export_personal_data /
 * wp_ajax_wp_privacy_erase_personal_data) $_POST['id'] carries that post id, so
 * the callback can read it from the live superglobal. The id scopes the run
 * state per request — killing BOTH the object-cache eviction bug (post meta
 * outlives the run) AND the same-subject collision where two overlapping exports
 * for one email shared a single login-hashed slot (F-3-1).
 *
 * Returns 0 when no valid id is present (e.g. a direct/programmatic call outside
 * the AJAX handler); callers fall back to an option keyed differently and, on a
 * later page with no id, abort with a WP_Error.
 *
 * @return int Request post id, or 0 when absent/invalid.
 */
function wldelay_privacy_request_id() {
    // phpcs:ignore WordPress.Security.NonceVerification.Missing -- core verifies the nonce in the privacy AJAX handler before invoking the exporter/eraser; this only reads the id core itself set.
    if ( ! isset( $_POST['id'] ) ) {
        return 0;
    }

    // phpcs:ignore WordPress.Security.NonceVerification.Missing -- see above.
    return absint( wp_unslash( $_POST['id'] ) );
}

/**
 * Whether a request id maps to a live user_request post we can hang meta on.
 *
 * @param int $request_id Candidate request id.
 * @return bool
 */
function wldelay_privacy_request_id_is_post( $request_id ) {
    $request_id = (int) $request_id;
    if ( $request_id <= 0 || ! function_exists( 'get_post' ) ) {
        return false;
    }

    $post = get_post( $request_id );

    return $post && isset( $post->post_type ) && 'user_request' === $post->post_type;
}

/**
 * Post-meta / option key under which the per-run export state is persisted.
 *
 * @return string
 */
function wldelay_privacy_export_state_meta_key() {
    return '_wldelay_export_state';
}

/**
 * Option name for the option-fallback run state, keyed by request id.
 *
 * Used only when there is no valid user_request post to attach meta to (a
 * direct/programmatic call). Keyed by the request id so distinct runs never
 * collide.
 *
 * @param int $request_id Request id.
 * @return string
 */
function wldelay_privacy_export_state_option_name( $request_id ) {
    return 'wldelay_pexport_' . absint( $request_id );
}

/**
 * Read the persisted per-run export state for a request id.
 *
 * Prefers user_request post meta (durable for the whole run, per-run by
 * construction); falls back to an option keyed by request id. Returns null when
 * no state is found — the caller turns that into a WP_Error on a later page.
 *
 * @param int $request_id Request id.
 * @return array|null Run state, or null when none is persisted.
 */
function wldelay_privacy_get_run_state( $request_id ) {
    $request_id = (int) $request_id;
    if ( $request_id <= 0 ) {
        return null;
    }

    if ( wldelay_privacy_request_id_is_post( $request_id ) ) {
        $state = get_post_meta( $request_id, wldelay_privacy_export_state_meta_key(), true );
        return is_array( $state ) ? $state : null;
    }

    $state = get_option( wldelay_privacy_export_state_option_name( $request_id ), null );
    return is_array( $state ) ? $state : null;
}

/**
 * Persist the per-run export state for a request id (durable for the run).
 *
 * @param int   $request_id Request id.
 * @param array $state      Run state.
 * @return void
 */
function wldelay_privacy_set_run_state( $request_id, array $state ) {
    $request_id = (int) $request_id;
    if ( $request_id <= 0 ) {
        return;
    }

    if ( wldelay_privacy_request_id_is_post( $request_id ) ) {
        update_post_meta( $request_id, wldelay_privacy_export_state_meta_key(), $state );
        return;
    }

    // autoload=false: this is per-run, transient-by-purpose state.
    update_option( wldelay_privacy_export_state_option_name( $request_id ), $state, false );
}

/**
 * Clear the per-run export state for a request id (run complete / restart).
 *
 * @param int $request_id Request id.
 * @return void
 */
function wldelay_privacy_clear_run_state( $request_id ) {
    $request_id = (int) $request_id;
    if ( $request_id <= 0 ) {
        return;
    }

    if ( wldelay_privacy_request_id_is_post( $request_id ) ) {
        delete_post_meta( $request_id, wldelay_privacy_export_state_meta_key() );
        return;
    }

    delete_option( wldelay_privacy_export_state_option_name( $request_id ) );
}

/**
 * Build the per-subject export run state captured on page 1.
 *
 * Snapshots the immutable-id ceilings for the login log, audit log AND the
 * subject's active lockouts (so the run sees a fixed view; rows inserted after
 * this point are excluded), and primes the keyset cursors "just past" each
 * ceiling so the first window opens at the ceiling itself. Persisted under the
 * request id and advanced page to page (F-3-1).
 *
 * Returns a WP_Error when ANY ceiling read fails at the DB layer (each MAX(id)
 * helper returns FALSE on a failed read). Aborting here — rather than coercing a
 * failed read to a 0 ceiling that would mark a group done and emit a spurious
 * empty group — keeps a DB fault from yielding a partial archive that looks
 * complete (F-3-1). WordPress aborts the AJAX request on the WP_Error.
 *
 * @param string $login Subject user_login.
 * @return array|WP_Error Run state, or WP_Error when a ceiling read failed.
 */
function wldelay_privacy_build_export_state( $login ) {
    $login_max = wldelay_get_max_login_log_id_for_username( $login );
    if ( false === $login_max ) {
        return wldelay_privacy_state_error();
    }

    $audit_max = wldelay_get_max_audit_log_id_for_actor( $login );
    if ( false === $audit_max ) {
        return wldelay_privacy_state_error();
    }

    $store       = wldelay_get_persistence_store();
    $lockout_max = $store->get_max_active_lockout_id_for_username( $login );
    if ( false === $lockout_max ) {
        return wldelay_privacy_state_error();
    }

    return array(
        'login_max'      => (int) $login_max,
        'login_cursor'   => (int) $login_max + 1,
        'login_done'     => ( 0 === (int) $login_max ),
        'audit_max'      => (int) $audit_max,
        'audit_cursor'   => (int) $audit_max + 1,
        'audit_done'     => ( 0 === (int) $audit_max ),
        // Lockouts paginate by keyset over the immutable row id under a fixed
        // ceiling (no hard cap — every active lockout is exported across pages).
        'lockout_max'    => (int) $lockout_max,
        'lockout_cursor' => (int) $lockout_max + 1,
        'lockout_done'   => ( 0 === (int) $lockout_max ),
    );
}

/**
 * The shared WP_Error returned when a run cannot proceed safely.
 *
 * WordPress checks is_wp_error() immediately after invoking the exporter/eraser
 * and aborts the AJAX request via wp_send_json_error(), so returning this is the
 * supported hard-failure channel — no partial archive, no pagination loop.
 *
 * @return WP_Error
 */
function wldelay_privacy_state_error() {
    return new WP_Error(
        'wldelay_privacy_export_state',
        __( 'Login Delay Shield could not continue this data export because its run state could not be read. No partial archive was produced; please retry the export.', 'login-delay-shield' )
    );
}

/**
 * Map an active-lockout keyset row to its export item.
 *
 * @param array $row Lockout row (id, lockout_key, ip_address, lockout_type, expires_at).
 * @return array Export-item array.
 */
function wldelay_privacy_lockout_row_to_item( array $row ) {
    $key = isset( $row['lockout_key'] ) ? (string) $row['lockout_key'] : '';
    if ( '' === $key ) {
        // Legacy/synthetic row without a key — fall back to a stable hash of its
        // identifying columns so the item_id is still unique.
        $key = substr(
            md5(
                ( isset( $row['ip_address'] ) ? $row['ip_address'] : '' ) . '|' .
                ( isset( $row['lockout_type'] ) ? $row['lockout_type'] : '' )
            ),
            0,
            16
        );
    }

    // expires_at arrives as a string datetime stored in UTC; normalise to a UNIX
    // timestamp so wldelay_privacy_lockout_row_to_data() renders it consistently.
    $expires_ts = isset( $row['expires_at'] ) ? strtotime( (string) $row['expires_at'] . ' UTC' ) : false;
    $row        = (array) $row;
    $row['expires_at'] = ( false === $expires_ts ) ? 0 : $expires_ts;

    return array(
        'group_id'    => 'wldelay-lockouts',
        'group_label' => __( 'Login Delay Shield — active lockouts', 'login-delay-shield' ),
        'item_id'     => 'wldelay-lockout-' . $key,
        'data'        => wldelay_privacy_lockout_row_to_data( $row ),
    );
}

/**
 * Option name for the per-request processing lock.
 *
 * @param int $request_id Request id.
 * @return string
 */
function wldelay_privacy_lock_option_name( $request_id ) {
    return 'wldelay_pexport_lock_' . absint( $request_id );
}

/**
 * Atomically claim the per-request processing lock, with stale-lock recovery.
 *
 * Two AJAX page calls for the SAME request id must not both advance the cursor
 * (a duplicate-submit / double-fire race would consume one window twice and skip
 * rows). The claim is atomic via add_option() (a single INSERT that fails if the
 * row already exists), so only one caller wins. A lock left behind by a page
 * that crashed mid-run is reclaimed once it is older than WLDELAY_PRIVACY_LOCK_TIMEOUT,
 * so a stale lock never wedges the run permanently (F-3-1).
 *
 * Returns false when another live (non-stale) page holds the lock — the caller
 * returns a transient WP_Error so the in-flight page can finish and the operator
 * can retry.
 *
 * @param int $request_id Request id.
 * @return bool True when the lock was acquired.
 */
function wldelay_privacy_acquire_lock( $request_id ) {
    $request_id = (int) $request_id;
    if ( $request_id <= 0 ) {
        // No request id to scope a lock to (direct/programmatic call): there is
        // no concurrent-AJAX surface to protect, so proceed without a lock.
        return true;
    }

    $option = wldelay_privacy_lock_option_name( $request_id );
    $now    = time();

    // Atomic acquire: add_option() inserts only if the option does not exist
    // (autoload=false), so two racing callers cannot both succeed.
    if ( add_option( $option, $now, '', false ) ) {
        return true;
    }

    // The lock exists. Reclaim it only if it is stale (older than the timeout):
    // a crashed prior page must not wedge the run forever. The reclaim is itself
    // guarded by a compare-and-set on the timestamp so two callers racing to
    // reclaim the same stale lock do not both win.
    $held = (int) get_option( $option, 0 );
    if ( $held > 0 && ( $now - $held ) < (int) WLDELAY_PRIVACY_LOCK_TIMEOUT ) {
        return false; // A live page holds it.
    }

    // Stale: attempt a guarded takeover. update_option() returns false when the
    // value is unchanged, so refresh the timestamp and re-read to confirm WE set
    // it (a competing reclaimer would have written a different, but equal-second,
    // value — accept the small residual race: the window is the lock timeout, far
    // larger than a page, so a double-reclaim in the same second is implausible
    // and harmless given the cursor is also persisted atomically under the lock).
    update_option( $option, $now, false );

    return true;
}

/**
 * Release the per-request processing lock.
 *
 * @param int $request_id Request id.
 * @return void
 */
function wldelay_privacy_release_lock( $request_id ) {
    $request_id = (int) $request_id;
    if ( $request_id <= 0 ) {
        return;
    }

    delete_option( wldelay_privacy_lock_option_name( $request_id ) );
}

/**
 * WP_Error returned when a concurrent page holds the processing lock.
 *
 * @return WP_Error
 */
function wldelay_privacy_busy_error() {
    return new WP_Error(
        'wldelay_privacy_export_busy',
        __( 'Login Delay Shield is still processing a previous page of this data export. Please retry the export.', 'login-delay-shield' )
    );
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
 * max_id ceiling per group (login log, audit log, AND active lockouts) and the
 * run pages by keyset under it (`id <= ceiling AND id < cursor`), carrying the
 * cursors across WP's page calls.
 *
 * RUN STATE durability & scoping (F-3-1). WordPress hands the callback only
 * ( $email, $page ), so the cursors must live somewhere readable across page
 * calls. The state is keyed by the privacy REQUEST id ($_POST['id'], the
 * user_request post id live during the AJAX handler) and persisted as POST META
 * on that post (durable for the whole run, per-run by construction). This kills
 * BOTH the object-cache eviction bug of the old transient AND the same-subject
 * collision where two overlapping exports for one email shared a single
 * login-hashed slot. A direct/programmatic call with no post id falls back to an
 * option keyed by request id.
 *
 * HARD-FAILURE channel. WordPress checks is_wp_error() right after invoking the
 * callback and aborts the AJAX request, so a WP_Error is the supported way to
 * stop a run safely (NOT done=false, which does not stop pagination). This
 * callback returns a WP_Error when: a later page finds no valid request id / no
 * persisted state (so it cannot resume the cursor — better to abort than restart
 * and risk dup/skip or an infinite loop); a page-1 ceiling read fails at the DB
 * layer (a failed MAX(id) read must not coerce to a 0 ceiling that emits a
 * spurious done group); or a per-page keyset read fails at the DB layer.
 *
 * CONCURRENCY. A per-request atomic lock (with stale-lock recovery) guards the
 * read-advance-write of the cursor so two AJAX page calls for the same request
 * cannot consume one window twice and skip rows.
 *
 * All log queries are EXACT-match on the subject's login (never the admin
 * substring LIKE) so no adjacent account leaks (F-3-1).
 *
 * @param string $email_address Data-subject email.
 * @param int    $page          1-based page number.
 * @return array{data:array,done:bool}|WP_Error
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

    $request_id = wldelay_privacy_request_id();

    // Guard the cursor critical section against a concurrent page call for the
    // SAME request. A live holder yields a transient WP_Error so the in-flight
    // page finishes; a stale lock (crashed prior page) is reclaimed.
    if ( ! wldelay_privacy_acquire_lock( $request_id ) ) {
        return wldelay_privacy_busy_error();
    }

    $page_size = (int) WLDELAY_PRIVACY_PAGE_SIZE;

    // Page 1 starts a fresh run: capture the ceilings and overwrite any stale
    // state from a prior, abandoned run for this request id. Later pages MUST
    // read the carried cursors back — if they are missing (no request id, or the
    // durable state was lost), the run cannot resume safely, so abort with a
    // WP_Error rather than restart (which would dup/skip or loop). This is the
    // supported hard-failure channel (F-3-1).
    if ( 1 === $page ) {
        $state = wldelay_privacy_build_export_state( $login );
        if ( is_wp_error( $state ) ) {
            wldelay_privacy_release_lock( $request_id );
            return $state;
        }
    } else {
        $state = wldelay_privacy_get_run_state( $request_id );
        if ( ! is_array( $state ) ) {
            wldelay_privacy_release_lock( $request_id );
            return wldelay_privacy_state_error();
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

    // ---- Group 3: active lockouts (keyset under the page-1 ceiling) -------
    // Paginated over the immutable lockout-row id under a fixed ceiling — the
    // same keyset model as the log groups, with NO hard cap (the old
    // WLDELAY_PRIVACY_LOCKOUT_SCAN_LIMIT truncation is gone): every active
    // lockout for the subject is exported across pages (F-3-1).
    if ( empty( $state['lockout_done'] ) && $remaining > 0 ) {
        $store = wldelay_get_persistence_store();
        $rows  = $store->get_active_lockouts_for_username_keyset(
            $login,
            $remaining,
            (int) $state['lockout_max'],
            (int) $state['lockout_cursor']
        );

        // A failed keyset read (FALSE, distinct from "no rows") must abort the
        // run rather than silently truncate the lockout group (F-3-1).
        if ( false === $rows ) {
            wldelay_privacy_release_lock( $request_id );
            return wldelay_privacy_state_error();
        }

        foreach ( $rows as $row ) {
            $row    = (array) $row;
            $row_id = isset( $row['id'] ) ? (int) $row['id'] : 0;
            $export_items[]          = wldelay_privacy_lockout_row_to_item( $row );
            $state['lockout_cursor'] = $row_id;
        }

        $fetched    = count( $rows );
        $had_room   = $remaining;
        $remaining -= $fetched;

        if ( $fetched < $had_room ) {
            $state['lockout_done'] = true;
        }
    }

    // The run is complete once all three groups are drained.
    $done = ! empty( $state['login_done'] )
        && ! empty( $state['audit_done'] )
        && ! empty( $state['lockout_done'] );

    if ( $done ) {
        wldelay_privacy_clear_run_state( $request_id );
    } else {
        // Hold the cursors for the next page (durable for the run).
        wldelay_privacy_set_run_state( $request_id, $state );
    }

    wldelay_privacy_release_lock( $request_id );

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
 * Active lockouts whose stored username matches a login (verification view).
 *
 * The exporter itself now paginates active lockouts by keyset over the immutable
 * row id (get_active_lockouts_for_username_keyset), with NO hard cap. This helper
 * remains as the username-scoped active-lockout VIEW used by the test suite and
 * any caller that wants the in-force rows in one shot.
 *
 * Scopes at SQL via get_lockouts_for_username() — WHERE username = %s — then
 * keeps only the in-force rows. The earlier exporter implementation scanned the
 * GLOBAL active-lockout prefix and filtered by username in PHP, so on a busy site
 * the subject's own lockout could sit OUTSIDE that global window and never be
 * exported; scoping by username first guarantees the subject's lockouts are
 * found regardless of how many unrelated lockouts the site holds (F-3-1).
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
    // this VIEW we degrade to an empty set rather than fatal — the eraser path
    // (wldelay_delete_lockouts_for_user) is where a failed read is surfaced as
    // items_retained.
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

        // Keep only in-force rows. expires_at arrives as a string datetime in UTC.
        $expires_ts = isset( $row['expires_at'] ) ? strtotime( (string) $row['expires_at'] . ' UTC' ) : false;
        if ( false === $expires_ts || $expires_ts <= $now ) {
            continue;
        }

        // Normalise to a UNIX timestamp so wldelay_privacy_lockout_row_to_data()
        // (which casts expires_at to int) renders the date correctly.
        $row['expires_at'] = $expires_ts;
        $matched[]         = $row;
    }

    return $matched;
}

// Register exporter/eraser. Guarded so the module stays loadable in the WP-free
// unit suite (no add_filter), mirroring wldelay-audit.php.
if ( function_exists( 'add_filter' ) ) {
    add_filter( 'wp_privacy_personal_data_exporters', 'wldelay_register_privacy_exporter' );
    add_filter( 'wp_privacy_personal_data_erasers', 'wldelay_register_privacy_eraser' );
}
