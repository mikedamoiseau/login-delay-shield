<?php
if ( ! defined( 'ABSPATH' ) ) exit;

define( 'WLDELAY_VERSION', '2.4.1' );
define( 'WLDELAY_PLUGIN_FILE', __FILE__ );
define( 'WLDELAY_OPTION_NAME', 'wldelay_options' );

// Schema version for the plugin-owned tables. Bumped whenever the DB schema
// changes (F-2-1: gen 2 added the lockout table; gen 3 widened its username
// column to varchar(255) and replaced the unused (ip_address, username) index
// with an IP-only index; gen 4 added the transient_key column so IP-level
// recovery can delete the exact lockout transient without reconstructing it
// from the truncated username column; gen 5 was the audit table; gen 6 added the
// generation column so recovery can snapshot-then-conditionally-delete durable
// rows and skip any a concurrent relock refreshed during the flush window;
// gen 7 added the composite (username, attempted_at) index on the log table so
// botnet detection (F-1-9) can count distinct IPs per username in a time
// window without a full scan).
// Kept separate from WLDELAY_VERSION so a schema upgrade fires on existing
// installs without depending on a user-facing release version bump.
define( 'WLDELAY_DB_VERSION', '7' );

// Dashboard widget sub-cache keys (F-4-1). The widget data was previously held
// in a single transient that was deleted on every failed login, which thrashed
// the expensive 7-day trends aggregate under a brute-force attack. The data is
// now split into two independent transients with their own TTLs so a failed
// attempt invalidates only the cheap fast-moving "recent attempts" list while
// the expensive aggregate rides its own TTL (slight staleness is acceptable on
// a dashboard).
define( 'WLDELAY_DASH_RECENT_CACHE', 'wldelay_dash_recent' );
define( 'WLDELAY_DASH_TRENDS_CACHE', 'wldelay_dash_trends' );
// Recent attempts change on every failed login; keep the TTL short.
define( 'WLDELAY_DASH_RECENT_TTL', MINUTE_IN_SECONDS );
// Trends are expensive aggregates; let them age out on their own longer TTL and
// never get invalidated by an individual failed attempt.
define( 'WLDELAY_DASH_TRENDS_TTL', 5 * MINUTE_IN_SECONDS );

/*
Plugin Name: Login Delay Shield
Plugin URI: https://damoiseau.me
Description: Protects against brute-force attacks with login delays, progressive throttling, IP lockout, whitelist, XML-RPC/password-reset protection, custom login URL, and email alerts.
Version: 2.4.1
Author: Mike
Author URI: https://damoiseau.me
License: GPL2
Text Domain: login-delay-shield
*/

/**
 * Load plugin textdomain for translations
 */
function wldelay_load_textdomain() {
    load_plugin_textdomain(
        'login-delay-shield',
        false,
        dirname( plugin_basename( WLDELAY_PLUGIN_FILE ) ) . '/languages'
    );
}
add_action( 'plugins_loaded', 'wldelay_load_textdomain' );

/**
 * Settings
 * @see http://codex.wordpress.org/Settings_API
 */
require_once dirname( __FILE__ ) . '/wldelay-persistence.php';
require_once dirname( __FILE__ ) . '/wldelay-features.php';
require_once dirname( __FILE__ ) . '/wldelay-migration.php';
require_once dirname( __FILE__ ) . '/wldelay-async.php';
require_once dirname( __FILE__ ) . '/wldelay-pipeline.php';
require_once dirname( __FILE__ ) . '/wldelay-settings-view.php';
require_once dirname( __FILE__ ) . '/wldelay-settings.php';
require_once dirname( __FILE__ ) . '/wldelay-enumeration.php';
require_once dirname( __FILE__ ) . '/wldelay-audit.php';
require_once dirname( __FILE__ ) . '/wldelay-botnet.php';
require_once dirname( __FILE__ ) . '/wldelay-privacy.php';
require_once dirname( __FILE__ ) . '/wldelay-changelog.php';
if( is_admin() ) {
    $wldelay_settings_page = new LDS_Settings();
}

/**
 * Add Settings link on plugins page
 */
function wldelay_plugin_action_links( $links ) {
    $settings_link = sprintf(
        '<a href="%s">%s</a>',
        admin_url( 'options-general.php?page=login-delay-shield-admin' ),
        __( 'Settings', 'login-delay-shield' )
    );
    array_unshift( $links, $settings_link );
    return $links;
}
add_filter( 'plugin_action_links_' . plugin_basename( WLDELAY_PLUGIN_FILE ), 'wldelay_plugin_action_links' );

/**
 * Dashboard Widget
 */
function wldelay_add_dashboard_widget() {
    if ( ! current_user_can( 'manage_options' ) ) {
        return;
    }

    wp_add_dashboard_widget(
        'wldelay_failed_logins_widget',
        __( 'Recent Failed Login Attempts', 'login-delay-shield' ),
        'wldelay_dashboard_widget_content'
    );
}
add_action( 'wp_dashboard_setup', 'wldelay_add_dashboard_widget' );

/**
 * Enqueue admin assets.
 *
 * Loads JavaScript across admin pages for dismissible notices and settings-page
 * interactions, while limiting styles to the dashboard and plugin settings page.
 *
 * @param string $hook Current admin page hook.
 */
function wldelay_enqueue_admin_assets( $hook ) {
    wp_enqueue_script(
        'wldelay-admin-script',
        plugin_dir_url( WLDELAY_PLUGIN_FILE ) . 'admin.js',
        array( 'jquery' ),
        WLDELAY_VERSION,
        true
    );

    $health = wldelay_get_security_score();
    $score_weights = array();
    foreach ( $health['features'] as $key => $feat ) {
        $score_weights[ $key ] = array(
            'points' => $feat['points'],
            'label'  => $feat['label'],
        );
    }

    wp_localize_script(
        'wldelay-admin-script',
        'wldelayAdmin',
        array(
            'ajaxUrl'            => admin_url( 'admin-ajax.php' ),
            'dismissNoticeNonce' => wp_create_nonce( 'wldelay_dismiss_notice' ),
            'badgeEnabled'       => __( 'Enabled', 'login-delay-shield' ),
            'badgeDisabled'      => __( 'Disabled', 'login-delay-shield' ),
            'scoreWeights'       => $score_weights,
            'recommendPrefix'    => __( 'Next recommended: enable', 'login-delay-shield' ),
            /* translators: %d: points value */
            'recommendSuffix'    => __( '(+%d points)', 'login-delay-shield' ),
        )
    );

    // Only load styles on dashboard, our settings page, and the changelog page.
    if ( $hook !== 'index.php'
        && $hook !== 'settings_page_login-delay-shield-admin'
        && $hook !== 'settings_page_' . WLDELAY_CHANGELOG_SLUG ) {
        return;
    }

    wp_enqueue_style(
        'wldelay-admin',
        plugin_dir_url( WLDELAY_PLUGIN_FILE ) . 'admin.css',
        array(),
        WLDELAY_VERSION
    );
}
add_action( 'admin_enqueue_scripts', 'wldelay_enqueue_admin_assets' );

/**
 * Build the unlock-current-IP admin action URL.
 *
 * @return string URL to admin-post endpoint with nonce.
 */
function wldelay_get_unlock_current_ip_url() {
    $url = add_query_arg(
        array(
            'action' => 'wldelay_unlock_current_ip',
        ),
        admin_url( 'admin-post.php' )
    );

    return wp_nonce_url( $url, 'wldelay_unlock_current_ip' );
}


/**
 * Convert sanitized login-log filters to public query arguments.
 *
 * @param array $filters Raw or sanitized filter values.
 * @return array Query arguments using wldelay_log_* keys.
 */
function wldelay_login_log_filters_to_query_args( $filters = array() ) {
    $filters = wldelay_sanitize_login_log_filters( $filters );

    $query_args = array();
    $key_map    = array(
        'source'   => 'wldelay_log_source',
        'ip'       => 'wldelay_log_ip',
        'username' => 'wldelay_log_username',
        'from'     => 'wldelay_log_from',
        'to'       => 'wldelay_log_to',
    );

    foreach ( $key_map as $short_key => $query_key ) {
        if ( $filters[ $short_key ] !== '' ) {
            $query_args[ $query_key ] = $filters[ $short_key ];
        }
    }

    return $query_args;
}

/**
 * Build the export-login-log admin action URL.
 *
 * @return string URL to admin-post endpoint with nonce.
 */
function wldelay_get_export_login_log_url( $filters = array() ) {
    $query_args = array_merge(
        array( 'action' => 'wldelay_export_login_log' ),
        wldelay_login_log_filters_to_query_args( $filters )
    );

    $url = add_query_arg( $query_args, admin_url( 'admin-post.php' ) );

    return wp_nonce_url( $url, 'wldelay_export_login_log' );
}

/**
 * Get registry option name for transient keys managed by this plugin.
 *
 * @return string
 */
function wldelay_get_transient_registry_option_name() {
    return 'wldelay_transient_registry';
}

/**
 * Option-name prefix for the per-key transient registry records.
 *
 * Each tracked transient is recorded as its OWN option ( value = the transient
 * name ) rather than as one entry in a single shared array. The shared array
 * was updated with a non-atomic read-modify-write, so two concurrent lockouts
 * or counter increments could clobber each other's entry; the lost entry then
 * left its transient undiscoverable by the recovery flush when transients live
 * in an EXTERNAL object cache (Redis/Memcached) — the options-table sweep finds
 * nothing — so a user stayed locked, or a stale failure counter survived, even
 * though recovery reported success. Per-key options never share a row, so
 * concurrent registrations cannot overwrite one another, and the records live
 * in the options table regardless of where the transients themselves are
 * stored, keeping the flush enumeration reliable under an external cache
 * (F-2-1 review).
 *
 * @return string
 */
function wldelay_get_transient_registry_key_prefix() {
    return 'wldelay_treg_';
}

/**
 * Track a transient key in the plugin registry.
 *
 * Writes one option per key ( keyed by md5 of the transient name ) so
 * concurrent registrations cannot clobber one another. Autoload is off so these
 * short-lived records never enter the alloptions cache.
 *
 * The record value is array( 'key' => $transient_name, 'exp' => $expires_at,
 * 'gen' => $generation ) so scheduled cleanup can reap records whose transient
 * has expired. Without a stored expiry the records only died on explicit
 * flush/unlock/uninstall, so an attacker rotating IPs or usernames could grow
 * wp_options without bound — every failed attempt registers a key whose 1-hour
 * transient expires while the option row lived forever (Codex-2 round-3 review).
 *
 * Each write also stamps a fresh random GENERATION token. A flush/unlock
 * snapshots the records it intends to remove and conditionally unregisters only
 * those whose full (key,exp,gen) still match the snapshot. Because a concurrent
 * same-second relock rewrites the record with a NEW gen, the compare can now
 * tell the refreshed record from the stale one and leaves it in place — the
 * live external-cache transient stays discoverable by later flushes, closing the
 * orphaning race that a key+second-resolution-exp record could not detect
 * (F-2-1 hardening).
 *
 * Returns whether the write actually persisted, verified by reading the record
 * back. update_option() returns false BOTH on failure and when the stored value
 * was already identical, so its return value cannot tell the two apart; callers
 * that must know whether the transient is now discoverable (so they can fail
 * open and drop an otherwise-orphaned cache-only transient during a DB outage)
 * rely on this readback instead (Codex round-3 review).
 *
 * @param string $transient_name Transient key name (without WordPress prefix).
 * @param int    $expires_at     Absolute UNIX timestamp the transient expires
 *                               at, or 0 when unknown (record is never
 *                               auto-purged, only flushed/unlocked).
 * @return bool True when a registry record for this key AND this expiry is
 *              present after the write (newly written, or already present and
 *              unchanged). False when the write did not persist, including a
 *              refresh whose new expiry did not reach the DB.
 */
function wldelay_register_transient_key( $transient_name, $expires_at = 0 ) {
    if ( empty( $transient_name ) ) {
        return false;
    }

    $transient_name = (string) $transient_name;
    $record_name    = wldelay_get_transient_registry_key_prefix() . md5( $transient_name );

    // A unique per-write generation lets the recovery compare-and-delete tell a
    // concurrent same-second relock (new gen) apart from the stale record it
    // snapshotted (F-2-1 hardening). wldelay_generate_lockout_generation() lives
    // in wldelay-persistence.php, required before this file runs.
    $generation = function_exists( 'wldelay_generate_lockout_generation' )
        ? wldelay_generate_lockout_generation()
        : substr( md5( uniqid( (string) wp_rand(), true ) ), 0, 24 );

    update_option(
        $record_name,
        array(
            'key' => $transient_name,
            'exp' => (int) $expires_at,
            'gen' => $generation,
        ),
        false
    );

    // Verify the record is actually present AND carries the expiry we just
    // wrote. On a failed write (e.g. the DB is down while an external object
    // cache still accepted the set_transient), the record cache is not primed
    // and get_option() falls through to the failing DB. On a re-lock that
    // merely refreshed an existing record, the cached array still carries the
    // right key, so this correctly reports the transient as discoverable.
    //
    // The expiry MUST match too, not just the key: a refresh that bumps an
    // existing record from exp=T1 to exp=T2 but whose write fails leaves the
    // stale T1 record in the DB. A key-only check would accept it as "current"
    // while the live transient now expires at the later T2 — the scheduled
    // reaper (which keys off the stored exp) would then delete the registry
    // row at T1 while the cache-only transient is still active until T2,
    // leaving it undiscoverable by a global flush. Comparing exp makes the
    // caller drop that orphan instead (Codex-2 round-4 review).
    $stored = get_option( $record_name, false );

    return is_array( $stored )
        && isset( $stored['key'], $stored['exp'] )
        && $stored['key'] === $transient_name
        && (int) $stored['exp'] === (int) $expires_at
        && isset( $stored['gen'] )
        && $stored['gen'] === $generation;
}

/**
 * Remove a transient key from the plugin registry.
 *
 * @param string $transient_name Transient key name (without WordPress prefix).
 */
function wldelay_unregister_transient_key( $transient_name ) {
    if ( empty( $transient_name ) ) {
        return;
    }

    delete_option( wldelay_get_transient_registry_key_prefix() . md5( (string) $transient_name ) );
}

/**
 * Read the current registry record for a transient name.
 *
 * Returns the live per-key record so a recovery path can SNAPSHOT it before
 * clearing transients and later prove it is unchanged. Returns null when no
 * per-key record exists (e.g. a legacy shared-array-only entry).
 *
 * @param string $transient_name Transient key name (without WordPress prefix).
 * @return array|null Record array (key/exp/gen) or null when absent.
 */
function wldelay_get_transient_registry_record( $transient_name ) {
    if ( empty( $transient_name ) ) {
        return null;
    }

    $record_name = wldelay_get_transient_registry_key_prefix() . md5( (string) $transient_name );
    $stored      = get_option( $record_name, false );

    return is_array( $stored ) ? $stored : null;
}

/**
 * Atomically delete an option ONLY when its stored value is byte-for-byte the
 * value captured in a snapshot.
 *
 * The compare and the delete are a single SQL statement
 * (DELETE ... WHERE option_name = %s AND option_value = %s), so there is no
 * read-then-delete window for a concurrent writer to slip a new value into. A
 * relock that rewrote the option between the snapshot and this call changed
 * option_value, so the WHERE no longer matches and the row survives. The object
 * cache is invalidated only when a row was actually removed, keeping a later
 * get_option() from resurrecting the deleted value from cache (F-2-1 hardening).
 *
 * @param string $option_name    Full option name.
 * @param string $expected_value Serialized option_value captured at snapshot
 *                               time (as stored in the options table).
 * @return bool True when the row was removed (value still matched).
 */
function wldelay_delete_option_if_value_unchanged( $option_name, $expected_value ) {
    global $wpdb;

    $deleted = $wpdb->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $wpdb->prepare(
            "DELETE FROM {$wpdb->options} WHERE option_name = %s AND option_value = %s",
            $option_name,
            $expected_value
        )
    );

    if ( $deleted ) {
        // Keep the object cache coherent with the row we just removed; otherwise
        // a later get_option() would resurrect the deleted value from cache.
        wp_cache_delete( $option_name, 'options' );
        return true;
    }

    return false;
}

/**
 * Conditionally unregister a transient record only when it is UNCHANGED since a
 * snapshot.
 *
 * Recovery (flush / IP unlock) snapshots the record it intends to remove, clears
 * the transient, then calls this with the snapshot. The record is deleted
 * through an ATOMIC compare-and-delete keyed on the exact serialized snapshot
 * value — there is no read-then-delete window. A concurrent same-second relock
 * rewrites the record with a NEW gen (and therefore a new serialized value), so
 * the delete no longer matches and the refreshed record (and its live
 * external-cache transient) is left discoverable for the next flush — closing
 * the orphaning race a key+second-resolution-exp record could not detect, and
 * the read-compare-then-unconditional-delete window the earlier helper still
 * left open (F-2-1 hardening; Codex & Codex-2 review).
 *
 * Backward compatibility: a legacy no-gen snapshot serializes to the legacy
 * (key,exp) form, so the atomic delete matches ONLY an unchanged legacy record
 * and never a record a relock upgraded to a gen-bearing value — the upgrade
 * window cannot reopen the race. A null snapshot means no per-key record existed
 * when the caller snapshotted (legacy shared-array entry or untracked
 * transient): there is nothing to compare-and-delete, and deleting the per-key
 * record unconditionally would clobber one a concurrent relock created inside
 * the recovery window, so this is a no-op. The legacy shared array is cleared
 * wholesale by the flush path, so the per-key slot is correctly left untouched.
 *
 * @param string     $transient_name Transient key name (without WordPress prefix).
 * @param array|null $snapshot       Record captured before the transient was
 *                                   cleared, or null when no per-key record
 *                                   existed at snapshot time.
 * @return bool True when the record was removed.
 */
function wldelay_unregister_transient_record_if_unchanged( $transient_name, $snapshot ) {
    if ( empty( $transient_name ) ) {
        return false;
    }

    // No per-key record existed at snapshot time: nothing to compare-and-delete.
    // An unconditional delete here would clobber a record a concurrent relock
    // created inside the recovery window (Codex/Codex-2 review).
    if ( ! is_array( $snapshot ) ) {
        return false;
    }

    $record_name = wldelay_get_transient_registry_key_prefix() . md5( (string) $transient_name );

    // Atomic compare-and-delete against the exact serialized snapshot value.
    return wldelay_delete_option_if_value_unchanged( $record_name, maybe_serialize( $snapshot ) );
}

/**
 * Enumerate every tracked transient name.
 *
 * Reads the per-key registry records (the current concurrency-safe format)
 * and, for backward compatibility, the legacy shared-array option written by
 * older versions. Registry records live in the options table regardless of
 * where the transients themselves are stored, so this enumeration stays
 * reliable even with an external object cache (F-2-1 review).
 *
 * @return string[] Unique transient names.
 */
function wldelay_get_registered_transient_keys() {
    global $wpdb;

    $keys = array();

    // Current per-key records. The value is array( 'key' => name, 'exp' => ts );
    // a plain string is a legacy per-key record (round-2 format) whose value was
    // the transient name itself. Handle both.
    $like   = $wpdb->esc_like( wldelay_get_transient_registry_key_prefix() ) . '%';
    $values = $wpdb->get_col(
        $wpdb->prepare(
            "SELECT option_value FROM {$wpdb->options} WHERE option_name LIKE %s",
            $like
        )
    );
    if ( is_array( $values ) ) {
        foreach ( $values as $raw ) {
            $value = maybe_unserialize( $raw );
            if ( is_array( $value ) && isset( $value['key'] ) && '' !== $value['key'] ) {
                $keys[] = (string) $value['key'];
            } elseif ( is_string( $value ) && '' !== $value ) {
                $keys[] = $value;
            }
        }
    }

    // Legacy shared-array registry (installs that predate the per-key format).
    $legacy = get_option( wldelay_get_transient_registry_option_name(), array() );
    if ( is_array( $legacy ) ) {
        foreach ( $legacy as $value ) {
            if ( is_string( $value ) && '' !== $value ) {
                $keys[] = $value;
            }
        }
    }

    return array_values( array_unique( $keys ) );
}

/**
 * Purge per-key registry records whose transient has already expired.
 *
 * Each per-key record carries the absolute expiry of the transient it tracks.
 * The transient itself expires on its own (WordPress TTL), but the options-table
 * record does not — so without this reaper an attacker rotating IPs/usernames
 * would grow wp_options without bound (every failed attempt leaves a permanent
 * row whose 1-hour transient is long gone). Run from the daily cleanup cron.
 *
 * Only records with a positive, elapsed expiry are removed. Records with exp = 0
 * (legacy round-2 string records, or registrations with an unknown TTL) are left
 * for explicit flush/unlock so this reaper never deletes a still-live marker
 * (Codex-2 round-3 review).
 *
 * @return int Number of expired registry records removed.
 */
function wldelay_purge_expired_transient_registry_records() {
    global $wpdb;

    $like = $wpdb->esc_like( wldelay_get_transient_registry_key_prefix() ) . '%';
    $rows = $wpdb->get_results(
        $wpdb->prepare(
            "SELECT option_name, option_value FROM {$wpdb->options} WHERE option_name LIKE %s",
            $like
        )
    );

    if ( ! is_array( $rows ) ) {
        return 0;
    }

    $now     = time();
    $removed = 0;
    foreach ( $rows as $row ) {
        $value = maybe_unserialize( $row->option_value );
        if (
            is_array( $value )
            && isset( $value['exp'] )
            && (int) $value['exp'] > 0
            && (int) $value['exp'] <= $now
        ) {
            // Atomic compare-and-delete against the exact serialized value read
            // above, not an unconditional delete_option() by name. A concurrent
            // relock that refreshed this record (new exp/gen) between the SELECT
            // and here changed option_value, so the delete no longer matches and
            // the refreshed live record survives — the reaper can no longer
            // strand a freshly re-registered cache-only transient (Codex F3).
            if ( wldelay_delete_option_if_value_unchanged( $row->option_name, $row->option_value ) ) {
                $removed++;
            }
        }
    }

    return $removed;
}

/**
 * Derive the failure-counter transient name that pairs with a lockout transient.
 *
 * A lockout transient and its failure counter share the same md5 identifier
 * suffix and differ only in prefix ( wldelay_lockout_ ↔ wldelay_fails_,
 * wldelay_reset_lockout_ ↔ wldelay_reset_fails_ ). Swapping the prefix is
 * therefore exact and length-proof — it never rebuilds the md5 from a
 * (possibly truncated) stored username. Returns null when the name is not a
 * recognised lockout transient (F-2-1 review).
 *
 * @param string $lockout_transient_name Lockout transient name.
 * @return string|null Paired failure-counter transient name, or null.
 */
function wldelay_derive_failure_transient_key( $lockout_transient_name ) {
    $lockout_transient_name = (string) $lockout_transient_name;

    // Check the reset prefix first so a reset lockout key is never mistaken for
    // a login one.
    if ( strpos( $lockout_transient_name, 'wldelay_reset_lockout_' ) === 0 ) {
        return 'wldelay_reset_fails_' . substr( $lockout_transient_name, strlen( 'wldelay_reset_lockout_' ) );
    }

    if ( strpos( $lockout_transient_name, 'wldelay_lockout_' ) === 0 ) {
        return 'wldelay_fails_' . substr( $lockout_transient_name, strlen( 'wldelay_lockout_' ) );
    }

    return null;
}

/**
 * Remove lockout and failure transients for a specific IP.
 *
 * In IP+username strategy mode, this also clears tuple keys for the given
 * username (if provided), while keeping backward compatibility with IP-only mode.
 *
 * A FALSE return (NOT a count) means the durable conditional delete failed at
 * the DB layer ($wpdb->delete() returned FALSE, distinct from "0 rows"): the
 * target lockout rows may still be on disk. Callers (admin unlock / WP-CLI
 * unlock-ip) must surface that as a failure rather than reporting a clean
 * removal, mirroring the GDPR eraser's items_retained handling (F-3-1).
 *
 * @param string $ip IP address.
 * @param string $username Optional username.
 * @return int|false Number of transients + durable rows removed, or FALSE when
 *                   the durable conditional delete failed at the DB layer.
 */
function wldelay_delete_lockout_for_ip( $ip, $username = '' ) {
    if ( empty( $ip ) ) {
        return 0;
    }

    $deleted = 0;

    $lockout_ip_key       = wldelay_get_lockout_transient_key( $ip, '' );
    $fails_ip_key         = wldelay_get_failure_transient_key( $ip, '' );
    $reset_lockout_ip_key = wldelay_get_password_reset_lockout_transient_key( $ip, '' );
    $reset_fails_ip_key   = wldelay_get_password_reset_failure_transient_key( $ip, '' );

    // Snapshot each registry record BEFORE clearing its transient, then
    // conditionally unregister through the atomic compare-and-delete. These
    // directly-derived IP/pair keys previously called unconditional
    // wldelay_unregister_transient_key(), so a concurrent failed login that
    // re-registered a key between delete_transient() and the unregister had its
    // fresh record deleted — orphaning a cache-only transient/failure counter
    // that unlock then reported gone (Codex F4 / Codex-2 F1).
    $lockout_ip_snapshot = wldelay_get_transient_registry_record( $lockout_ip_key );
    if ( delete_transient( $lockout_ip_key ) ) {
        $deleted++;
    }
    wldelay_unregister_transient_record_if_unchanged( $lockout_ip_key, $lockout_ip_snapshot );

    $fails_ip_snapshot = wldelay_get_transient_registry_record( $fails_ip_key );
    if ( delete_transient( $fails_ip_key ) ) {
        $deleted++;
    }
    wldelay_unregister_transient_record_if_unchanged( $fails_ip_key, $fails_ip_snapshot );

    $reset_lockout_ip_snapshot = wldelay_get_transient_registry_record( $reset_lockout_ip_key );
    if ( delete_transient( $reset_lockout_ip_key ) ) {
        $deleted++;
    }
    wldelay_unregister_transient_record_if_unchanged( $reset_lockout_ip_key, $reset_lockout_ip_snapshot );

    $reset_fails_ip_snapshot = wldelay_get_transient_registry_record( $reset_fails_ip_key );
    if ( delete_transient( $reset_fails_ip_key ) ) {
        $deleted++;
    }
    wldelay_unregister_transient_record_if_unchanged( $reset_fails_ip_key, $reset_fails_ip_snapshot );

    if ( ! empty( $username ) ) {
        $pair_options = array( 'wldelay_lockout_attempt_strategy' => 'ip_username' );

        $lockout_pair_key      = wldelay_get_lockout_transient_key( $ip, $username, $pair_options );
        $lockout_pair_snapshot = wldelay_get_transient_registry_record( $lockout_pair_key );
        if ( $lockout_pair_key !== $lockout_ip_key && delete_transient( $lockout_pair_key ) ) {
            $deleted++;
        }
        wldelay_unregister_transient_record_if_unchanged( $lockout_pair_key, $lockout_pair_snapshot );

        $fails_pair_key      = wldelay_get_failure_transient_key( $ip, $username, $pair_options );
        $fails_pair_snapshot = wldelay_get_transient_registry_record( $fails_pair_key );
        if ( $fails_pair_key !== $fails_ip_key && delete_transient( $fails_pair_key ) ) {
            $deleted++;
        }
        wldelay_unregister_transient_record_if_unchanged( $fails_pair_key, $fails_pair_snapshot );

        $reset_lockout_pair_key      = wldelay_get_password_reset_lockout_transient_key( $ip, $username, $pair_options );
        $reset_lockout_pair_snapshot = wldelay_get_transient_registry_record( $reset_lockout_pair_key );
        if ( $reset_lockout_pair_key !== $reset_lockout_ip_key && delete_transient( $reset_lockout_pair_key ) ) {
            $deleted++;
        }
        wldelay_unregister_transient_record_if_unchanged( $reset_lockout_pair_key, $reset_lockout_pair_snapshot );

        $reset_fails_pair_key      = wldelay_get_password_reset_failure_transient_key( $ip, $username, $pair_options );
        $reset_fails_pair_snapshot = wldelay_get_transient_registry_record( $reset_fails_pair_key );
        if ( $reset_fails_pair_key !== $reset_fails_ip_key && delete_transient( $reset_fails_pair_key ) ) {
            $deleted++;
        }
        wldelay_unregister_transient_record_if_unchanged( $reset_fails_pair_key, $reset_fails_pair_snapshot );
    }

    $store = wldelay_get_persistence_store();

    // Clear username-scoped lockout transients that IP-only recovery cannot
    // derive on its own (F-2-1). Under the ip_username strategy the lockout
    // transient is keyed on md5("ip|username"); with no username supplied the
    // IP-keyed deletions above (md5("ip")) never match it, so the user stays
    // locked on the transient fast-path until it expires — even after the
    // durable row is gone. The durable rows are the IP→username index the
    // transient registry lacks (the registry stores only opaque md5 hashes).
    //
    // Each gen-4 row records the EXACT transient name set at lock time, so we
    // delete that verbatim. This is length-proof: reconstructing the key from
    // the stored username would miss a canonical identifier longer than the
    // varchar(255) username column (the column is clamped, but the transient is
    // keyed on the full identifier) — the very bug this column closes. Legacy
    // gen-3 rows carry no transient_key, so for those we fall back to
    // reconstructing the key from the stored username/type (exact for
    // identifiers within the column width), reusing the canonical builders with
    // ip_username forced so the derived key matches what wldelay_lock_ip() set.
    //
    // Snapshot the durable rows ONCE (capturing each row's lockout_key +
    // generation) before touching anything, then drive both the transient
    // cleanup and the conditional durable delete from that single snapshot. A
    // concurrent failed login that refreshes a row during this window writes a
    // NEW generation, so the compare-and-delete below leaves it in force and the
    // user is not silently re-orphaned by recovery (F-2-1 hardening).
    $snapshot = $store->get_lockouts_for_ip( $ip );

    // FALSE (NOT an empty array) means the durable read failed at the DB layer:
    // rows the IP recovery must clear may still be on disk. Propagate it as a
    // failure rather than clearing only the (incomplete) transient fast-path and
    // reporting a clean unlock (F-3-1 read contract).
    if ( false === $snapshot ) {
        return false;
    }

    $deleted += wldelay_clear_lockout_transients_for_snapshot( $ip, $snapshot );

    // Clear the durable store (F-2-1) for the snapshotted rows only, and only
    // while their generation still matches — so a row a concurrent relock
    // refreshed during recovery (new generation) survives instead of being
    // orphaned. Replaces the former unconditional remove_lockouts_for_ip($ip),
    // which deleted every row for the IP including a just-created re-lock,
    // leaving the user locked on a durable row that recovery had reported gone
    // (F-2-1 hardening). Count these removals so recovery still reports success
    // when the transient was evicted but a durable row was in force.
    //
    // A FALSE return (NOT a count) means a durable $wpdb->delete() failed. Do
    // NOT let it coerce to 0 via +=, which would mask a failed durable delete
    // and report a clean unlock while the row is still on disk. Propagate FALSE
    // so the unlock handler surfaces the failure (F-3-1).
    $durable_removed = $store->remove_lockouts_matching_generation( $snapshot );
    if ( false === $durable_removed ) {
        return false;
    }

    return $deleted + $durable_removed;
}

/**
 * Generation-aware, transient-registry-safe removal of a single lockout subject
 * identified by its durable lockout_key (F-1-1).
 *
 * The Active Lockout Manager's per-row Unlock targets ONE row. Matching on the
 * stored username is unsafe: the username column is clamped to varchar(255)
 * (wldelay_add_lockout / F-2-1) while the lockout_key hashes the FULL canonical
 * identifier, so two distinct subjects on one IP that share a 255-char prefix
 * collide on the truncated username — unlocking one would release the co-tenant.
 * The lockout_key is lossless, so matching on it is exact at any identifier
 * length. The IP is still required to derive the legacy transient keys for rows
 * predating transient_key (gen-3).
 *
 * Returns the count of DURABLE rows removed (the subject count surfaced in the
 * admin notice and the audit removed_rows), NOT inflated by transient-cleanup
 * deletions (F-1-1 review). Transients are still cleared as a side effect.
 * Returns FALSE (not a count) when the durable conditional delete fails at the
 * DB layer — the row may still be on disk — so the caller surfaces a failure
 * instead of reporting a clean unlock (F-3-1).
 *
 * @param string $ip          IP address the row belongs to.
 * @param string $lockout_key Lossless durable lockout key identifying the row.
 * @return int|false Durable rows removed, or FALSE on read/durable failure.
 */
function wldelay_delete_lockout_by_key( $ip, $lockout_key ) {
    $ip          = (string) $ip;
    $lockout_key = (string) $lockout_key;
    if ( '' === $ip || '' === $lockout_key ) {
        return 0;
    }

    $store = wldelay_get_persistence_store();

    // Snapshot the IP's durable rows ONCE (lockout_key + generation captured) and
    // narrow to the exact lockout_key. A FALSE return is a DB read failure, NOT
    // an empty IP: propagate it so the handler reports a failure rather than
    // "none" while the row may still be on disk (F-3-1 read contract).
    $snapshot = $store->get_lockouts_for_ip( $ip );
    if ( false === $snapshot ) {
        return false;
    }

    $subject_rows = array();
    foreach ( $snapshot as $row ) {
        $row_key = isset( $row['lockout_key'] ) ? (string) $row['lockout_key'] : '';
        if ( '' !== $row_key && $row_key === $lockout_key ) {
            $subject_rows[] = $row;
        }
    }

    return wldelay_remove_lockout_subject_rows( $ip, $subject_rows );
}

/**
 * Generation-aware, transient-registry-safe removal of a single (IP, username)
 * lockout subject (F-1-1).
 *
 * Used by Clear-all, which enumerates every active row and removes each by its
 * (IP, username). IP-level recovery (wldelay_delete_lockout_for_ip) clears EVERY
 * row on the IP, which would also release a co-tenant sharing a NAT IP; the
 * username-only GDPR path (wldelay_delete_lockouts_for_user) spans every IP the
 * subject ever locked from. This snapshots the IP's durable rows, narrows them
 * to the matching username (empty username = the IP-only subject), then drives
 * the SAME M5b machinery: clear each row's transient fast-path via the per-key
 * compare-and-delete, then conditionally delete only rows whose generation still
 * matches.
 *
 * Returns the count of DURABLE rows removed (the subject count surfaced in the
 * notice and audit), NOT inflated by transient-cleanup deletions (F-1-1 review).
 * Returns FALSE on a read/durable failure so the caller surfaces it (F-3-1).
 *
 * @param string $ip       IP address.
 * @param string $username Subject username ('' for the IP-only subject).
 * @return int|false Durable rows removed, or FALSE on read/durable failure.
 */
function wldelay_delete_lockout_subject( $ip, $username = '' ) {
    $ip = (string) $ip;
    if ( '' === $ip ) {
        return 0;
    }

    $username = (string) $username;
    $store    = wldelay_get_persistence_store();

    // Snapshot the IP's durable rows ONCE (lockout_key + generation captured) and
    // narrow to the requested subject. A FALSE return is a DB read failure: keep
    // it distinct from an empty match so the caller reports a failure (F-3-1).
    $snapshot = $store->get_lockouts_for_ip( $ip );
    if ( false === $snapshot ) {
        return false;
    }

    $subject_rows = array();
    foreach ( $snapshot as $row ) {
        $row_username = isset( $row['username'] ) ? (string) $row['username'] : '';
        if ( $row_username === $username ) {
            $subject_rows[] = $row;
        }
    }

    return wldelay_remove_lockout_subject_rows( $ip, $subject_rows );
}

/**
 * Shared core: clear transients + conditionally delete a set of snapshot rows.
 *
 * Returns the DURABLE rows removed (subject count) so notices/audit are not
 * inflated by transient-cleanup deletions. FALSE on durable-delete failure.
 *
 * @param string  $ip           IP address the rows belong to.
 * @param array[] $subject_rows Pre-narrowed snapshot rows for one subject.
 * @return int|false Durable rows removed, or FALSE on durable failure.
 */
function wldelay_remove_lockout_subject_rows( $ip, array $subject_rows ) {
    if ( empty( $subject_rows ) ) {
        return 0;
    }

    // Transients are cleared for the side effect of releasing the fast-path; the
    // return value is deliberately discarded so the reported count reflects only
    // the durable subject rows removed (F-1-1 review: 1 subject must report 1).
    wldelay_clear_lockout_transients_for_snapshot( $ip, $subject_rows );

    $store           = wldelay_get_persistence_store();
    $durable_removed = $store->remove_lockouts_matching_generation( $subject_rows );
    if ( false === $durable_removed ) {
        return false;
    }

    return $durable_removed;
}

/**
 * Clear the transient fast-path keys for a set of snapshotted durable rows.
 *
 * Shared by IP-level recovery (wldelay_delete_lockout_for_ip) and the
 * username-scoped GDPR path (wldelay_delete_lockouts_for_user). For each row in
 * the snapshot it clears the lockout transient and its paired failure counter,
 * using the per-key registry compare-and-delete so a concurrent same-second
 * relock that rewrote a record with a new generation keeps its live transient
 * discoverable instead of being orphaned (F-2-1 hardening).
 *
 * Each gen-4 row records the EXACT transient name set at lock time, deleted
 * verbatim (length-proof: reconstructing from the clamped varchar username could
 * miss a canonical identifier longer than the column). Legacy gen-3 rows carry
 * no transient_key, so the key is reconstructed from the stored username/type
 * with the ip_username strategy forced, matching what wldelay_lock_ip() set.
 *
 * @param string  $ip       IP address the snapshot rows belong to.
 * @param array[] $snapshot Durable rows, each with at least transient_key,
 *                          username and lockout_type keys.
 * @return int Number of transients removed.
 */
function wldelay_clear_lockout_transients_for_snapshot( $ip, array $snapshot ) {
    $deleted      = 0;
    $pair_options = array( 'wldelay_lockout_attempt_strategy' => 'ip_username' );

    foreach ( $snapshot as $row ) {
        $stored_key = isset( $row['transient_key'] ) ? (string) $row['transient_key'] : '';

        if ( '' !== $stored_key ) {
            $transient_name = $stored_key;
        } else {
            $row_username = isset( $row['username'] ) ? (string) $row['username'] : '';
            $row_type     = isset( $row['lockout_type'] ) ? (string) $row['lockout_type'] : 'login';

            $transient_name = ( 'password-reset' === $row_type )
                ? wldelay_get_password_reset_lockout_transient_key( $ip, $row_username, $pair_options )
                : wldelay_get_lockout_transient_key( $ip, $row_username, $pair_options );
        }

        // Snapshot the registry record BEFORE clearing the transient, then
        // conditionally unregister: a concurrent relock that rewrites the record
        // with a new gen must keep its live transient discoverable.
        $record_snapshot = wldelay_get_transient_registry_record( $transient_name );
        if ( delete_transient( $transient_name ) ) {
            $deleted++;
        }
        wldelay_unregister_transient_record_if_unchanged( $transient_name, $record_snapshot );

        // Also clear the matching failure-counter transient. wldelay_lock_ip()
        // does NOT reset the per-attempt counter when it fires, so dropping only
        // the lockout leaves the counter at the threshold — the very next failed
        // attempt re-locks the user immediately. The counter shares the lockout
        // transient's md5 suffix and differs only in prefix, so deriving it from
        // the (verbatim, length-proof) lockout transient name reaches the exact
        // key production set (F-2-1 review).
        $fails_name = wldelay_derive_failure_transient_key( $transient_name );
        if ( null !== $fails_name ) {
            $fails_record_snapshot = wldelay_get_transient_registry_record( $fails_name );
            if ( delete_transient( $fails_name ) ) {
                $deleted++;
            }
            wldelay_unregister_transient_record_if_unchanged( $fails_name, $fails_record_snapshot );
        }
    }

    return $deleted;
}

/**
 * Username-scoped, generation-aware lockout recovery (GDPR erasure).
 *
 * IP-level recovery (wldelay_delete_lockout_for_ip) clears EVERY lockout on the
 * IP, which would erase an unrelated account's lockout when two users share a
 * NAT IP — weakening protection for a non-subject. GDPR erasure must remove only
 * the subject's lockouts, so this scopes the snapshot to the durable rows whose
 * username matches the subject, then drives the SAME M5b machinery over that
 * subset: clear each row's transient fast-path (compare-and-delete) and
 * conditionally delete only rows whose generation still matches. Rows for other
 * usernames on the same IP are never touched, so their lockouts stay in force.
 *
 * Enumerates ALL durable rows for the username — active AND expired — so an
 * expired row still bearing the subject's username + IP (personal data) is
 * removed too (F-3-1).
 *
 * Returns FALSE (not a count) when the durable layer fails: a failed SELECT
 * (get_lockouts_for_username() returning FALSE) or a failed conditional DELETE
 * (remove_lockouts_matching_generation() returning FALSE) means the subject's
 * lockout PII may still be on disk. The eraser must surface that as
 * items_retained rather than claiming a clean erasure (F-3-1).
 *
 * @param string $username Subject's user_login (the value persisted at lock time).
 * @return int|false Number of transients + durable rows removed, or FALSE when a
 *                   durable read/delete failed at the DB layer.
 */
function wldelay_delete_lockouts_for_user( $username ) {
    $username = (string) $username;
    if ( '' === $username ) {
        return 0;
    }

    $store    = wldelay_get_persistence_store();
    $snapshot = $store->get_lockouts_for_username( $username );

    // A failed SELECT (distinct from "no rows" array()) means we cannot know
    // which durable rows exist for the subject, so we must not report success.
    if ( false === $snapshot ) {
        return false;
    }

    if ( empty( $snapshot ) ) {
        return 0;
    }

    $deleted = 0;

    // The snapshot may span several IPs (the subject failed from more than one
    // address). Transient keys are per-IP, so clear them grouped by the row's IP.
    $by_ip = array();
    foreach ( $snapshot as $row ) {
        $ip = isset( $row['ip_address'] ) ? (string) $row['ip_address'] : '';
        if ( '' === $ip ) {
            continue;
        }
        $by_ip[ $ip ][] = $row;
    }

    foreach ( $by_ip as $ip => $rows ) {
        $deleted += wldelay_clear_lockout_transients_for_snapshot( $ip, $rows );
    }

    // Conditional durable delete over ONLY the subject's snapshot rows. A
    // concurrent relock that refreshed one of these rows wrote a new generation,
    // so it survives the compare-and-delete — preserving the M5b race fix while
    // leaving every other user's rows untouched (F-3-1).
    $durable_removed = $store->remove_lockouts_matching_generation( $snapshot );

    // A failed DELETE (FALSE, distinct from 0 rows) means the durable PII may
    // remain; propagate it so the eraser flags items_retained (F-3-1).
    if ( false === $durable_removed ) {
        return false;
    }

    return $deleted + $durable_removed;
}

/**
 * Flush all lockout and failure transients managed by this plugin.
 *
 * A FALSE return (NOT a count) means the durable conditional delete failed at
 * the DB layer: some lockout rows may still be on disk. The CLI flush command
 * surfaces that as an error rather than reporting a clean flush (F-3-1).
 *
 * @return int|false Number of transients + durable rows removed, or FALSE when
 *                   the durable conditional delete failed at the DB layer.
 */
function wldelay_flush_lockout_transients() {
    global $wpdb;

    $deleted = 0;

    // Enumerate the concurrency-safe per-key registry records (plus the legacy
    // shared array). The records live in the options table regardless of where
    // transients are stored, so a cache-only transient whose old shared-array
    // entry was clobbered by a concurrent write is still discoverable here
    // (F-2-1 review).
    foreach ( wldelay_get_registered_transient_keys() as $transient_name ) {
        if (
            strpos( $transient_name, 'wldelay_lockout_' ) !== 0
            && strpos( $transient_name, 'wldelay_fails_' ) !== 0
            && strpos( $transient_name, 'wldelay_reset_lockout_' ) !== 0
            && strpos( $transient_name, 'wldelay_reset_fails_' ) !== 0
        ) {
            continue;
        }

        // Snapshot the record BEFORE clearing the transient, then conditionally
        // unregister via the atomic compare-and-delete. A concurrent same-second
        // relock rewrites the record with a new gen; the compare-and-delete
        // leaves that refreshed record in place so its live external-cache
        // transient stays discoverable by the next flush instead of being
        // orphaned (F-2-1 hardening). The legacy shared array is cleared
        // wholesale below, so a shared-array-only entry (null snapshot) needs no
        // per-key delete — see wldelay_unregister_transient_record_if_unchanged().
        $record_snapshot = wldelay_get_transient_registry_record( $transient_name );
        if ( delete_transient( $transient_name ) ) {
            $deleted++;
        }
        wldelay_unregister_transient_record_if_unchanged( $transient_name, $record_snapshot );
    }

    // Fallback cleanup for DB-backed transients not present in the registry.
    $option_name_like_lockouts       = $wpdb->esc_like( '_transient_wldelay_lockout_' ) . '%';
    $option_name_like_fails          = $wpdb->esc_like( '_transient_wldelay_fails_' ) . '%';
    $option_name_like_reset_lockouts = $wpdb->esc_like( '_transient_wldelay_reset_lockout_' ) . '%';
    $option_name_like_reset_fails    = $wpdb->esc_like( '_transient_wldelay_reset_fails_' ) . '%';

    $option_names = $wpdb->get_col(
        $wpdb->prepare(
            "SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s OR option_name LIKE %s OR option_name LIKE %s",
            $option_name_like_lockouts,
            $option_name_like_fails,
            $option_name_like_reset_lockouts,
            $option_name_like_reset_fails
        )
    );

    foreach ( $option_names as $option_name ) {
        $transient_name = str_replace( '_transient_', '', $option_name );
        if ( delete_transient( $transient_name ) ) {
            $deleted++;
        }
    }

    update_option( wldelay_get_transient_registry_option_name(), array(), false );

    $store = wldelay_get_persistence_store();

    // Snapshot every active durable row ONCE (capturing lockout_key +
    // generation) and drive both the transient cleanup and the conditional
    // durable delete from it. The registry + options-table sweep above cannot
    // reach a cache-only transient (Redis/Memcached object cache) whose registry
    // entry was lost to the non-atomic read-modify-write in
    // wldelay_register_transient_key(): the options-table LIKE finds nothing,
    // so without this the orphaned transient would keep a user locked until it
    // expired — even though flush reported success. The durable rows hold the
    // verbatim transient_key, so deleting through it reaches the object cache
    // regardless of registry state (mirrors wldelay_delete_lockout_for_ip).
    // A high limit ensures the safety net covers every active row, not just the
    // default page; deleting an already-expired transient is harmless.
    $snapshot = $store->get_active_lockouts( PHP_INT_MAX );

    // FALSE (NOT an empty array) means the durable read failed: the safety-net
    // sweep cannot run and rows may persist. Propagate it so flush reports a
    // failure rather than a clean flush while a cache-only transient lingers
    // (F-3-1 read contract).
    if ( false === $snapshot ) {
        return false;
    }

    foreach ( $snapshot as $row ) {
        if ( empty( $row['transient_key'] ) ) {
            continue;
        }
        $record_snapshot = wldelay_get_transient_registry_record( $row['transient_key'] );
        if ( delete_transient( $row['transient_key'] ) ) {
            $deleted++;
        }
        wldelay_unregister_transient_record_if_unchanged( $row['transient_key'], $record_snapshot );
    }

    // Clear the durable store for the snapshotted rows only, and only while
    // their generation still matches. Replaces the former unconditional
    // clear_all(), which deleted EVERY row including a re-lock a concurrent
    // failed login created after the snapshot — orphaning the new lockout's
    // transient and leaving that user locked even though flush reported success
    // (F-2-1 hardening). A row refreshed mid-flush carries a new generation, so
    // it survives and is reaped by the next flush / its own expiry.
    //
    // A FALSE return (NOT a count) means a durable $wpdb->delete() failed. Do
    // NOT coerce it to 0 via +=, which would report a clean flush while rows
    // remain on disk; propagate FALSE so the CLI command surfaces it (F-3-1).
    $durable_removed = $store->remove_lockouts_matching_generation( $snapshot );
    if ( false === $durable_removed ) {
        return false;
    }

    return $deleted + $durable_removed;
}

/**
 * Handle admin action to unlock the current IP.
 */
function wldelay_handle_unlock_current_ip() {
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_die( esc_html__( 'You are not allowed to perform this action.', 'login-delay-shield' ) );
    }

    check_admin_referer( 'wldelay_unlock_current_ip' );

    $ip = wldelay_get_client_ip();
    $username = '';

    if ( function_exists( 'wp_get_current_user' ) ) {
        $current_user = wp_get_current_user();
        if ( $current_user instanceof WP_User ) {
            $username = wldelay_normalize_username( $current_user->user_login );
        }
    }

    $deleted = wldelay_delete_lockout_for_ip( $ip, $username );

    // FALSE (NOT a count) means the durable conditional delete failed at the DB
    // layer: the lockout row may still be on disk, so the user could still be
    // locked. Surface a distinct failure status rather than reporting success or
    // a benign "none" (F-3-1).
    $failed = ( false === $deleted );

    // Record the manual unlock in the audit trail (F-2-7). Logged on every
    // attempt, not only on a hit, so the action itself is auditable. A failed
    // delete records 0 removed rows.
    if ( function_exists( 'wldelay_audit_lockout_cleared' ) ) {
        wldelay_audit_lockout_cleared( $ip, $username, $failed ? 0 : (int) $deleted );
    }

    if ( $failed ) {
        $status = 'failed';
    } elseif ( $deleted > 0 ) {
        $status = 'success';
    } else {
        $status = 'none';
    }

    $redirect_url = add_query_arg(
        array(
            'page' => 'login-delay-shield-admin',
            'wldelay_unlock_ip' => $status,
        ),
        admin_url( 'options-general.php' )
    );

    wp_safe_redirect( $redirect_url );

    if ( defined( 'WP_TESTS_DOMAIN' ) ) {
        return;
    }
    exit;
}
add_action( 'admin_post_wldelay_unlock_current_ip', 'wldelay_handle_unlock_current_ip' );

/**
 * Handle admin action to unlock a single active lockout subject (F-1-1).
 *
 * Self-service recovery for "I locked out a real user": removes the targeted
 * (IP, username) lockout only, leaving any co-tenant lockout on a shared NAT IP
 * in force. Routes through wldelay_delete_lockout_for_ip() so the durable row,
 * the transient fast-path and the transient registry are all reconciled in the
 * generation-aware way M5b established.
 */
function wldelay_handle_unlock_lockout() {
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_die( esc_html__( 'You are not allowed to perform this action.', 'login-delay-shield' ) );
    }

    check_admin_referer( 'wldelay_unlock_lockout' );

    $ip          = isset( $_POST['wldelay_lockout_ip'] ) ? sanitize_text_field( wp_unslash( $_POST['wldelay_lockout_ip'] ) ) : '';
    $lockout_key = isset( $_POST['wldelay_lockout_key'] ) ? sanitize_text_field( wp_unslash( $_POST['wldelay_lockout_key'] ) ) : '';
    // Forensic label for the audit entry ONLY; never used to match the row.
    $username    = isset( $_POST['wldelay_lockout_username'] ) ? wldelay_normalize_username( wp_unslash( $_POST['wldelay_lockout_username'] ) ) : '';

    // Match on the lossless durable lockout_key, NOT the clamped display
    // username: two distinct subjects on one IP sharing a 255-char prefix would
    // otherwise both match and release a co-tenant (F-1-1 SECURITY).
    $deleted = wldelay_delete_lockout_by_key( $ip, $lockout_key );

    // FALSE (NOT a count) means the durable conditional delete failed at the DB
    // layer: the lockout row may still be on disk. Treat it as a distinct
    // failure rather than reporting a clean removal (F-3-1 / unlock-current-IP
    // pattern).
    $failed = ( false === $deleted );

    if ( function_exists( 'wldelay_audit_lockout_cleared' ) ) {
        wldelay_audit_lockout_cleared( $ip, $username, $failed ? 0 : (int) $deleted );
    }

    if ( $failed ) {
        $status = 'failed';
    } elseif ( $deleted > 0 ) {
        $status = 'success';
    } else {
        $status = 'none';
    }

    $redirect_url = add_query_arg(
        array(
            'page'                 => 'login-delay-shield-admin',
            'wldelay_unlock_subject' => $status,
        ),
        admin_url( 'options-general.php' )
    );

    wp_safe_redirect( $redirect_url );

    if ( defined( 'WP_TESTS_DOMAIN' ) ) {
        return;
    }
    exit;
}
add_action( 'admin_post_wldelay_unlock_lockout', 'wldelay_handle_unlock_lockout' );

/**
 * Sweep every registered lockout transient (and its paired failure counter).
 *
 * Clear-all enumerates DURABLE rows to remove each subject, but wldelay_lock_ip()
 * intentionally KEEPS a registered transient lockout when the durable
 * add_lockout() fails yet the registry write succeeds — an active lockout with NO
 * durable row that the durable-row loop can never reach. This sweeps the per-key
 * transient registry for lockout-prefixed keys (login + password-reset) and
 * clears each, plus the matching failure counter so the very next failed attempt
 * does not immediately re-lock. Uses the per-key snapshot + compare-and-delete so
 * a concurrent same-second relock that refreshed a record keeps its live transient
 * discoverable rather than being orphaned (F-1-1 / F-2-1 hardening).
 *
 * @return int Number of transients removed.
 */
function wldelay_sweep_registered_lockout_transients() {
    $deleted = 0;

    foreach ( wldelay_get_registered_transient_keys() as $transient_name ) {
        // Only the lockout fast-path keys: the paired failure counter is derived
        // and cleared alongside each below. A bare fails_/reset_fails_ key with no
        // lockout is just an in-progress attempt counter, not an active lockout.
        if (
            strpos( $transient_name, 'wldelay_lockout_' ) !== 0
            && strpos( $transient_name, 'wldelay_reset_lockout_' ) !== 0
        ) {
            continue;
        }

        // Snapshot the record BEFORE clearing, then conditionally unregister via
        // the atomic compare-and-delete (mirrors wldelay_flush_lockout_transients).
        $record_snapshot = wldelay_get_transient_registry_record( $transient_name );
        if ( delete_transient( $transient_name ) ) {
            $deleted++;
        }
        wldelay_unregister_transient_record_if_unchanged( $transient_name, $record_snapshot );

        // Clear the paired failure counter so the threshold is reset; otherwise the
        // next failed attempt re-locks immediately (same rationale as the snapshot
        // path in wldelay_clear_lockout_transients_for_snapshot).
        $fails_name = wldelay_derive_failure_transient_key( $transient_name );
        if ( null !== $fails_name ) {
            $fails_record_snapshot = wldelay_get_transient_registry_record( $fails_name );
            if ( delete_transient( $fails_name ) ) {
                $deleted++;
            }
            wldelay_unregister_transient_record_if_unchanged( $fails_name, $fails_record_snapshot );
        }
    }

    return $deleted;
}

/**
 * Handle admin action to clear every currently-active lockout (F-1-1).
 *
 * Reuses the single get_active_lockouts() snapshot already read: clears each
 * subject's transient fast-path from that snapshot (grouped by IP) and batches
 * the durable compare-and-delete into one pass, rather than re-reading and
 * deleting per subject (R2-3 — avoids the ~2N+1 query fan-out on a site with
 * thousands of active lockouts). Also sweeps registered lockout transients with
 * no durable row (the wldelay_lock_ip() fail-open path). Still generation-aware
 * and transient-registry-safe — deliberately NOT a raw clear_all() on the table
 * (which would leave orphaned transients and bypass the compare-and-delete
 * contract, consistent with M5b). A durable-delete or read failure makes the
 * whole operation report a failure rather than a clean flush (F-3-1).
 *
 * NON-ATOMIC (R2-4): the batched durable delete carries no transaction, so a
 * mid-run DB failure can leave a PARTIAL clear — some lockouts released, the
 * rest still on disk — and is reported to the admin as a failure (not a clean
 * flush). Re-running clear-all is safe and idempotent: it re-snapshots and
 * retries the survivors. See remove_lockouts_matching_generation()'s interface
 * docblock for the full failure contract.
 */
function wldelay_handle_clear_all_lockouts() {
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_die( esc_html__( 'You are not allowed to perform this action.', 'login-delay-shield' ) );
    }

    check_admin_referer( 'wldelay_clear_all_lockouts' );

    $store    = wldelay_get_persistence_store();
    $lockouts = $store->get_active_lockouts( PHP_INT_MAX );

    // FALSE (NOT an empty array) is a DB read failure: rows may persist on disk.
    // Report a failure rather than "nothing to clear" while the user stays locked
    // (F-3-1 read contract). Still sweep the registry-only transients below so a
    // cache-only lockout is released even when the durable read is down.
    $read_failed = ( false === $lockouts );
    if ( $read_failed ) {
        $lockouts = array();
    }

    // Track durable subjects removed SEPARATELY from transient-only sweeps so the
    // admin notice and audit removed_rows reflect lockout rows, not an inflated
    // transient+durable sum (F-1-1 review).
    $removed = 0;
    $failed  = $read_failed;

    if ( ! empty( $lockouts ) ) {
        // Group the already-read rows by IP so each IP's transient fast-path is
        // cleared from the snapshot in hand — no per-subject re-read. Rows with
        // no IP are skipped (nothing to release / match).
        $by_ip      = array();
        $valid_rows = array();
        foreach ( $lockouts as $lockout ) {
            $ip = isset( $lockout['ip_address'] ) ? (string) $lockout['ip_address'] : '';
            if ( '' === $ip ) {
                continue;
            }
            $by_ip[ $ip ][] = $lockout;
            $valid_rows[]   = $lockout;
        }

        // Clear transients for their side effect (release the fast path); the
        // return value is discarded so the reported count tracks durable rows
        // only (F-1-1 review: 1 subject must report 1).
        foreach ( $by_ip as $ip => $rows ) {
            wldelay_clear_lockout_transients_for_snapshot( $ip, $rows );
        }

        // One generation-gated batched delete for every durable row. FALSE is a
        // DB error: rows may persist on disk, so report a failure rather than a
        // clean flush while the user stays locked (F-3-1).
        $durable_removed = $store->remove_lockouts_matching_generation( $valid_rows );
        if ( false === $durable_removed ) {
            $failed = true;
        } else {
            $removed = (int) $durable_removed;
        }
    }

    // Sweep registered lockout transient keys (and their paired failure counters)
    // that have NO durable row. wldelay_lock_ip() intentionally KEEPS a registered
    // transient lockout when the durable add_lockout() fails but the registry write
    // succeeds — a genuinely-active, durable-row-less lockout. The durable-row loop
    // above can never reach it, so clear-all would report success while the user
    // stays locked. Reuse the registry-enumeration + compare-and-delete machinery
    // to release it (F-1-1 review). These transient deletions are NOT added to
    // $removed: the notice/audit count tracks durable subjects.
    wldelay_sweep_registered_lockout_transients();

    if ( function_exists( 'wldelay_audit_log' ) ) {
        wldelay_audit_log(
            'lockout_cleared',
            array(
                'object'    => __( 'All active lockouts', 'login-delay-shield' ),
                'new_value' => array(
                    'removed_rows' => $removed,
                    'source'       => 'clear-all',
                    'failed'       => $failed,
                ),
            )
        );
    }

    if ( $failed ) {
        $status = 'failed';
    } elseif ( $removed > 0 ) {
        $status = 'success';
    } else {
        $status = 'none';
    }

    $redirect_url = add_query_arg(
        array(
            'page'                  => 'login-delay-shield-admin',
            'wldelay_clear_all'     => $status,
            'wldelay_clear_count'   => $removed,
        ),
        admin_url( 'options-general.php' )
    );

    wp_safe_redirect( $redirect_url );

    if ( defined( 'WP_TESTS_DOMAIN' ) ) {
        return;
    }
    exit;
}
add_action( 'admin_post_wldelay_clear_all_lockouts', 'wldelay_handle_clear_all_lockouts' );

/**
 * Mitigate CSV formula injection for values opened in spreadsheet tools.
 *
 * @param string $value
 * @return string
 */
function wldelay_csv_sanitize_cell( $value ) {
    $value = (string) $value;
    if ( $value !== '' && preg_match( '/^[ \\t]*[=+\\-@]/', $value ) ) {
        return "'" . $value;
    }
    return $value;
}

/**
 * Validate a Y-m-d date string.
 *
 * @param string $value Date string to validate.
 * @return bool True if the value is a valid Y-m-d date.
 */
function wldelay_is_valid_date( $value ) {
    if ( $value === '' || ! preg_match( '/^\\d{4}-\\d{2}-\\d{2}$/', $value ) ) {
        return false;
    }
    $dt = DateTimeImmutable::createFromFormat( 'Y-m-d', $value );
    if ( ! $dt ) {
        return false;
    }
    return $dt->format( 'Y-m-d' ) === $value;
}

/**
 * Sanitize login-log filter input (admin UI + CSV export).
 *
 * Accepts either raw request keys (wldelay_log_*) or short keys (source, ip, etc.).
 *
 * @param array $input Raw filter input from $_GET or short-key array.
 * @return array{source:string,ip:string,username:string,from:string,to:string}
 */
function wldelay_sanitize_login_log_filters( $input ) {
    if ( ! is_array( $input ) ) {
        $input = array();
    }

    $key_map = array(
        'source'   => 'wldelay_log_source',
        'ip'       => 'wldelay_log_ip',
        'username' => 'wldelay_log_username',
        'from'     => 'wldelay_log_from',
        'to'       => 'wldelay_log_to',
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

    $source = strtolower( trim( sanitize_text_field( (string) $raw['source'] ) ) );
    if ( $source !== '' && ! preg_match( '/^[a-z0-9-]{1,20}$/', $source ) ) {
        $source = '';
    }

    $ip = trim( sanitize_text_field( (string) $raw['ip'] ) );
    if ( $ip !== '' && ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
        $ip = '';
    }

    $username = trim( sanitize_text_field( (string) $raw['username'] ) );
    if ( strlen( $username ) > 60 ) {
        $username = substr( $username, 0, 60 );
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
        'source'   => $source,
        'ip'       => $ip,
        'username' => $username,
        'from'     => $from,
        'to'       => $to,
    );
}

/**
 * Get sanitized login-log filters from the current request.
 *
 * Only reads expected wldelay_log_* keys from $_GET to avoid collisions
 * with unrelated query parameters.
 *
 * @return array{source:string,ip:string,username:string,from:string,to:string}
 */
function wldelay_get_login_log_filters_from_request() {
    $expected_keys = array(
        'wldelay_log_source',
        'wldelay_log_ip',
        'wldelay_log_username',
        'wldelay_log_from',
        'wldelay_log_to',
    );

    return wldelay_sanitize_login_log_filters(
        wp_unslash( array_intersect_key( $_GET, array_flip( $expected_keys ) ) )
    );
}

/**
 * Query failed login attempts with optional filters.
 *
 * Filters are always sanitized internally — callers may pass raw request data.
 *
 * @param array $args {
 *     @type array  $filters Raw or sanitized filter values (sanitized internally).
 *     @type int    $limit   Maximum rows to return. Default 20.
 *     @type int    $offset  Offset for pagination. Default 0.
 *     @type string $fields  SQL fields to select (must match allowlist).
 * }
 * @return array Array of result objects.
 */
function wldelay_get_login_log_attempts( $args = array() ) {
    global $wpdb;

    $args = wp_parse_args(
        $args,
        array(
            'filters' => array(),
            'limit'   => 20,
            'offset'  => 0,
            'fields'  => '*',
        )
    );

    $filters = wldelay_sanitize_login_log_filters( $args['filters'] );

    $allowed_fields = array(
        '*',
        'source, ip_address, username, attempted_at',
    );
    $fields = in_array( $args['fields'], $allowed_fields, true ) ? $args['fields'] : '*';

    $table_name   = wldelay_get_log_table_name();
    $where_parts  = wldelay_build_login_log_where_clause( $filters );
    $where_clause = $where_parts['where'];
    $params       = $where_parts['params'];

    // $fields and $table_name are safe to interpolate: $fields is validated against
    // a strict allowlist above, and $table_name is derived from $wpdb->prefix (not
    // user input). $wpdb->prepare() cannot parameterize SQL identifiers.
    $sql = "SELECT $fields FROM $table_name{$where_clause} ORDER BY attempted_at DESC";

    $limit = absint( $args['limit'] );
    if ( $limit < 1 ) {
        $limit = 1;
    }
    $sql     .= ' LIMIT %d';
    $params[] = $limit;

    $offset = absint( $args['offset'] );
    if ( $offset > 0 ) {
        $sql     .= ' OFFSET %d';
        $params[] = $offset;
    }

    return $wpdb->get_results( $wpdb->prepare( $sql, $params ) );
}


/**
 * Fetch a keyset page of login-log rows for an EXACT username (privacy export).
 *
 * The admin-search path (wldelay_build_login_log_where_clause) matches username
 * with a substring LIKE so an operator can find "admin*" probes. That is wrong
 * for a GDPR export: exporting the subject `ann` would also return rows for
 * `joann`, `ann-admin`, etc., disclosing unrelated users' IPs and timestamps.
 * This path matches `username = %s` exactly so only the subject's own rows are
 * returned.
 *
 * Pagination is KEYSET over the immutable id, NOT offset. WordPress drives the
 * exporter in pages, but offset pagination over `attempted_at DESC` is unstable:
 * on a brute-force-targeted site new rows land at the top BETWEEN page calls, so
 * the offset window shifts and a boundary row is duplicated while an older row is
 * skipped (a concurrent retention-purge causes the inverse). The exporter
 * snapshots a max_id ceiling on page 1 and pages by keyset under it: every page
 * fetches `WHERE username = %s AND id <= ceiling AND id < cursor ORDER BY id DESC
 * LIMIT n`. Rows inserted after the run started (id > ceiling) are excluded
 * (correct — they post-date the request); deletes can only shrink the set, never
 * shift the cursor onto an already-emitted row. Ordering by id (not attempted_at)
 * keeps the keyset cursor monotonic and unambiguous (F-3-1).
 *
 * @param string $username   Exact username to match.
 * @param int    $limit      Maximum rows for this page.
 * @param int    $max_id     Ceiling: only rows with id <= this are considered.
 * @param int    $after_id   Keyset cursor: only rows with id < this are returned
 *                           (pass the smallest id from the previous page; pass
 *                           $max_id + 1 / 0-means-no-cursor for the first page).
 * @return array Result rows (id, ip_address, username, attempted_at, source),
 *               ordered id DESC.
 */
function wldelay_get_login_log_for_username( $username, $limit, $max_id, $after_id = 0 ) {
    global $wpdb;

    $username = (string) $username;
    $limit    = max( 1, absint( $limit ) );
    $max_id   = max( 0, absint( $max_id ) );
    $after_id = max( 0, absint( $after_id ) );

    if ( 0 === $max_id ) {
        return array();
    }

    // The cursor defaults to "just past the ceiling" on the first page so the
    // first keyset window starts at the ceiling itself.
    if ( 0 === $after_id ) {
        $after_id = $max_id + 1;
    }

    $table_name = wldelay_get_log_table_name();

    // $table_name is derived from $wpdb->prefix (not user input). id is the
    // immutable PK, so the keyset window is stable under concurrent insert/delete.
    $sql = "SELECT id, ip_address, username, attempted_at, source FROM $table_name WHERE username = %s AND id <= %d AND id < %d ORDER BY id DESC LIMIT %d";

    return $wpdb->get_results( $wpdb->prepare( $sql, $username, $max_id, $after_id, $limit ) );
}

/**
 * Highest login-log id for an EXACT username — the keyset export ceiling.
 *
 * Captured once on export page 1 and held across pages so the export run sees a
 * fixed snapshot of the subject's rows; rows inserted after this point (id above
 * the ceiling) are excluded from the run (F-3-1).
 *
 * Returns FALSE (NOT 0) when the read FAILS at the DB layer. A failed query and
 * "subject has no rows" both make get_var() return null → (int) 0; collapsing a
 * failed read to 0 would mark the group done=true on page 1 and emit a spurious
 * empty group while the subject's rows are still on disk. The export caller turns
 * a FALSE ceiling into a WP_Error so WordPress aborts the request instead of
 * handing the admin a partial archive (F-3-1).
 *
 * @param string $username Exact username to match.
 * @return int|false Highest matching id, 0 when the subject has no rows, or
 *                   FALSE when the read failed at the DB layer.
 */
function wldelay_get_max_login_log_id_for_username( $username ) {
    global $wpdb;

    $table_name = wldelay_get_log_table_name();

    // Clear last_error so a stale error from an earlier query on this request is
    // not misread as a failure of this read.
    $wpdb->last_error = '';

    $max = $wpdb->get_var(
        $wpdb->prepare( "SELECT MAX(id) FROM $table_name WHERE username = %s", (string) $username )
    );

    // get_var() returns null both for "no rows" (MAX of an empty set) AND for a
    // SELECT that errored. Distinguish via last_error: a failed read returns
    // FALSE so the exporter can abort with a WP_Error (F-3-1).
    if ( '' !== (string) $wpdb->last_error ) {
        return false;
    }

    return (int) $max;
}

/**
 * Count login-log rows for an EXACT username up to the export ceiling.
 *
 * Companion to wldelay_get_login_log_for_username(): an exact `username = %s`
 * count, bounded by the same max_id ceiling the keyset pages use, so the export's
 * group total is stable across pages and never includes substring-adjacent
 * accounts (F-3-1). A 0 ceiling (subject has no rows) yields 0.
 *
 * @param string $username Exact username to match.
 * @param int    $max_id   Ceiling: only rows with id <= this are counted.
 * @return int Matching row count.
 */
function wldelay_count_login_log_for_username( $username, $max_id ) {
    global $wpdb;

    $max_id = max( 0, absint( $max_id ) );
    if ( 0 === $max_id ) {
        return 0;
    }

    $table_name = wldelay_get_log_table_name();

    return (int) $wpdb->get_var(
        $wpdb->prepare( "SELECT COUNT(*) FROM $table_name WHERE username = %s AND id <= %d", (string) $username, $max_id )
    );
}

/**
 * Build a reusable WHERE clause for login-log filters.
 *
 * @param array $filters Raw or sanitized filter values.
 * @return array{where:string,params:array}
 */
function wldelay_build_login_log_where_clause( $filters ) {
    global $wpdb;

    $filters = wldelay_sanitize_login_log_filters( $filters );

    $where  = array();
    $params = array();

    if ( $filters['source'] !== '' ) {
        $where[]  = 'source = %s';
        $params[] = $filters['source'];
    }

    if ( $filters['ip'] !== '' ) {
        $where[]  = 'ip_address = %s';
        $params[] = $filters['ip'];
    }

    if ( $filters['username'] !== '' ) {
        $where[]  = 'username LIKE %s';
        $params[] = '%' . $wpdb->esc_like( $filters['username'] ) . '%';
    }

    if ( $filters['from'] !== '' ) {
        $where[]  = 'attempted_at >= %s';
        $params[] = $filters['from'] . ' 00:00:00';
    }

    if ( $filters['to'] !== '' ) {
        $where[]  = 'attempted_at <= %s';
        $params[] = $filters['to'] . ' 23:59:59';
    }

    return array(
        'where'  => ! empty( $where ) ? ' WHERE ' . implode( ' AND ', $where ) : '',
        'params' => $params,
    );
}

/**
 * Count failed login attempts matching optional filters.
 *
 * @param array $filters Raw or sanitized filter values.
 * @return int Matching row count.
 */
function wldelay_count_login_log_attempts( $filters = array() ) {
    global $wpdb;

    $table_name   = wldelay_get_log_table_name();
    $where_parts  = wldelay_build_login_log_where_clause( $filters );
    $where_clause = $where_parts['where'];
    $params       = $where_parts['params'];

    $sql = "SELECT COUNT(*) FROM $table_name{$where_clause}";

    if ( empty( $params ) ) {
        return (int) $wpdb->get_var( $sql );
    }

    return (int) $wpdb->get_var( $wpdb->prepare( $sql, $params ) );
}

/**
 * Compute a lightweight snapshot hash for telemetry pagination.
 *
 * @param int   $total   Total matching rows.
 * @param array $filters Active filters.
 * @return string 8-char hex hash.
 */
function wldelay_get_telemetry_snapshot_hash( $total, $filters = array() ) {
    global $wpdb;

    $filters      = wldelay_sanitize_login_log_filters( $filters );
    $table_name   = wldelay_get_log_table_name();
    $where_parts  = wldelay_build_login_log_where_clause( $filters );
    $where_clause = $where_parts['where'];
    $params       = $where_parts['params'];

    $sql    = "SELECT MAX(id) FROM $table_name{$where_clause}";
    $max_id = empty( $params )
        ? (int) $wpdb->get_var( $sql )
        : (int) $wpdb->get_var( $wpdb->prepare( $sql, $params ) );

    $payload = $total . '|' . $max_id . '|' . implode( '|', $filters );
    return substr( md5( $payload ), 0, 8 );
}

/**
 * Get filtered telemetry summary data for the login log admin view.
 *
 * @param array $filters Raw or sanitized filter values.
 * @param int   $limit   Maximum grouped rows for source/IP lists.
 * @return array{total_attempts:int,daily_counts:array<array{date:string,count:int}>,source_counts:array<array{source:string,count:int}>,top_ips:array<array{ip_address:string,count:int}>,top_usernames:array<array{username:string,count:int}>,top_target_pairs:array<array{ip_address:string,username:string,count:int}>}
 */
function wldelay_get_login_log_summary( $filters = array(), $limit = 5 ) {
    global $wpdb;

    $limit        = max( 1, absint( $limit ) );
    $table_name   = wldelay_get_log_table_name();
    $where_parts  = wldelay_build_login_log_where_clause( $filters );
    $where_clause = $where_parts['where'];
    $params       = $where_parts['params'];

    $run_query = function ( $sql, $extra_params = array() ) use ( $wpdb, $params ) {
        $all_params = array_merge( $params, $extra_params );
        if ( empty( $all_params ) ) {
            return $wpdb->get_results( $sql );
        }

        return $wpdb->get_results( $wpdb->prepare( $sql, $all_params ) );
    };

    $daily_rows = $run_query(
        "SELECT DATE(attempted_at) AS attempted_date, COUNT(*) AS failures
        FROM $table_name{$where_clause}
        GROUP BY DATE(attempted_at)
        ORDER BY attempted_date DESC
        LIMIT %d",
        array( 31 )
    );

    $daily_rows = array_reverse( $daily_rows );

    $daily_counts = array();
    foreach ( $daily_rows as $row ) {
        $daily_counts[] = array(
            'date'  => (string) $row->attempted_date,
            'count' => (int) $row->failures,
        );
    }

    $source_rows = $run_query(
        "SELECT source, COUNT(*) AS failures
        FROM $table_name{$where_clause}
        GROUP BY source
        ORDER BY failures DESC, source ASC
        LIMIT %d",
        array( $limit )
    );

    $source_counts = array();
    foreach ( $source_rows as $row ) {
        $source_counts[] = array(
            'source' => (string) $row->source,
            'count'  => (int) $row->failures,
        );
    }

    $ip_rows = $run_query(
        "SELECT ip_address, COUNT(*) AS failures
        FROM $table_name{$where_clause}
        GROUP BY ip_address
        ORDER BY failures DESC, ip_address ASC
        LIMIT %d",
        array( $limit )
    );

    $top_ips = array();
    foreach ( $ip_rows as $row ) {
        $top_ips[] = array(
            'ip_address' => (string) $row->ip_address,
            'count'      => (int) $row->failures,
        );
    }

    // Exclude NULL and blank/whitespace-only usernames from ranking — these are
    // noise from bots that submit empty credentials.  Other aggregations (IPs,
    // sources) keep all rows because those columns are always meaningful.
    $username_where_clause = $where_clause === ''
        ? ' WHERE username IS NOT NULL AND TRIM(username) <> %s'
        : $where_clause . ' AND username IS NOT NULL AND TRIM(username) <> %s';

    $username_rows = $run_query(
        "SELECT username, COUNT(*) AS failures
        FROM $table_name{$username_where_clause}
        GROUP BY username
        ORDER BY failures DESC, username ASC
        LIMIT %d",
        array( '', $limit )
    );

    $top_usernames = array();
    foreach ( $username_rows as $row ) {
        $top_usernames[] = array(
            'username' => (string) $row->username,
            'count'    => (int) $row->failures,
        );
    }

    $target_pair_rows = $run_query(
        "SELECT ip_address, username, COUNT(*) AS failures
        FROM $table_name{$username_where_clause}
        GROUP BY ip_address, username
        ORDER BY failures DESC, ip_address ASC, username ASC
        LIMIT %d",
        array( '', $limit )
    );

    $top_target_pairs = array();
    foreach ( $target_pair_rows as $row ) {
        $top_target_pairs[] = array(
            'ip_address' => (string) $row->ip_address,
            'username'   => (string) $row->username,
            'count'      => (int) $row->failures,
        );
    }

    return array(
        'total_attempts'    => wldelay_count_login_log_attempts( $filters ),
        'daily_counts'      => $daily_counts,
        'source_counts'     => $source_counts,
        'top_ips'           => $top_ips,
        'top_usernames'     => $top_usernames,
        'top_target_pairs'  => $top_target_pairs,
    );
}

/**
 * Handle admin action to export login log as CSV.
 *
 * Streams results in batches to avoid loading the entire log table into memory.
 */
function wldelay_handle_export_login_log() {
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_die( esc_html__( 'You are not allowed to perform this action.', 'login-delay-shield' ) );
    }

    check_admin_referer( 'wldelay_export_login_log' );

    $batch_size = 1000;

    // In CLI/test runtime, headers may already be sent by bootstrap output.
    // Avoid PHP warnings while still streaming CSV content for test assertions.
    if ( ! headers_sent() ) {
        nocache_headers();
        header( 'Content-Type: text/csv; charset=utf-8' );
        header( 'Content-Disposition: attachment; filename="login-delay-shield-login-log-' . gmdate( 'Y-m-d' ) . '.csv"' );
    }

    $out = fopen( 'php://output', 'w' );
    if ( $out ) {
        fputcsv( $out, array( 'source', 'ip', 'username', 'timestamp' ) );

        $offset = 0;

        do {
            $attempts = wldelay_get_login_log_attempts(
                array(
                    'filters' => wldelay_get_login_log_filters_from_request(),
                    'limit'   => $batch_size,
                    'offset'  => $offset,
                    'fields'  => 'source, ip_address, username, attempted_at',
                )
            );

            foreach ( $attempts as $attempt ) {
                fputcsv(
                    $out,
                    array(
                        wldelay_csv_sanitize_cell( $attempt->source ),
                        wldelay_csv_sanitize_cell( $attempt->ip_address ),
                        wldelay_csv_sanitize_cell( $attempt->username ),
                        wldelay_csv_sanitize_cell( $attempt->attempted_at ),
                    )
                );
            }

            $offset += $batch_size;
        } while ( count( $attempts ) === $batch_size );

        fclose( $out );
    }

    $should_exit = apply_filters( 'wldelay_export_login_log_should_exit', true );
    if ( $should_exit ) {
        exit;
    }
}
add_action( 'admin_post_wldelay_export_login_log', 'wldelay_handle_export_login_log' );

/**
 * Render admin notice after unlock-current-IP action.
 */
function wldelay_render_unlock_notice() {
    if ( ! is_admin() || ! current_user_can( 'manage_options' ) ) {
        return;
    }

    if ( ! isset( $_GET['page'] ) || $_GET['page'] !== 'login-delay-shield-admin' ) {
        return;
    }

    if ( ! isset( $_GET['wldelay_unlock_ip'] ) ) {
        return;
    }

    $status = sanitize_text_field( wp_unslash( $_GET['wldelay_unlock_ip'] ) );

    if ( 'success' === $status ) {
        $class   = 'notice-success';
        $message = __( 'Current IP lockout removed.', 'login-delay-shield' );
    } elseif ( 'failed' === $status ) {
        // A durable delete failed at the DB layer; the lockout may still be in
        // force. Report an error (not a benign "none") so the admin retries
        // rather than assuming the IP was cleared (F-3-1).
        $class   = 'notice-error';
        $message = __( 'Login Delay Shield could not clear the lockout for your current IP — a database error occurred and the lockout may still be in force. Check the database and try again.', 'login-delay-shield' );
    } else {
        $class   = 'notice-warning';
        $message = __( 'No active lockout was found for your current IP.', 'login-delay-shield' );
    }

    echo '<div class="notice ' . esc_attr( $class ) . ' is-dismissible"><p>' . esc_html( $message ) . '</p></div>';
}
add_action( 'admin_notices', 'wldelay_render_unlock_notice' );

/**
 * Render the admin notice for per-subject and clear-all lockout actions (F-1-1).
 *
 * Mirrors wldelay_render_unlock_notice(): scoped to the plugin page and to users
 * who can act, with aria-live so the status is announced to screen readers.
 */
function wldelay_render_lockout_manager_notice() {
    if ( ! is_admin() || ! current_user_can( 'manage_options' ) ) {
        return;
    }

    if ( ! isset( $_GET['page'] ) || $_GET['page'] !== 'login-delay-shield-admin' ) {
        return;
    }

    $class   = '';
    $message = '';

    if ( isset( $_GET['wldelay_unlock_subject'] ) ) {
        $status = sanitize_text_field( wp_unslash( $_GET['wldelay_unlock_subject'] ) );

        if ( 'success' === $status ) {
            $class   = 'notice-success';
            $message = __( 'Lockout removed.', 'login-delay-shield' );
        } elseif ( 'failed' === $status ) {
            $class   = 'notice-error';
            $message = __( 'Login Delay Shield could not remove this lockout — a database error occurred and it may still be in force. Check the database and try again.', 'login-delay-shield' );
        } else {
            $class   = 'notice-warning';
            $message = __( 'No active lockout was found for that subject.', 'login-delay-shield' );
        }
    } elseif ( isset( $_GET['wldelay_clear_all'] ) ) {
        $status = sanitize_text_field( wp_unslash( $_GET['wldelay_clear_all'] ) );
        $count  = isset( $_GET['wldelay_clear_count'] ) ? absint( wp_unslash( $_GET['wldelay_clear_count'] ) ) : 0;

        if ( 'failed' === $status ) {
            $class = 'notice-error';
            $message = sprintf(
                /* translators: %s: number of lockouts that were removed before the error */
                __( 'Login Delay Shield cleared %s lockout(s), but a database error stopped it from clearing the rest — some lockouts may still be in force. Check the database and try again.', 'login-delay-shield' ),
                number_format_i18n( $count )
            );
        } elseif ( 'success' === $status ) {
            $class = 'notice-success';
            $message = sprintf(
                /* translators: %s: number of lockouts removed */
                _n( '%s active lockout cleared.', '%s active lockouts cleared.', $count, 'login-delay-shield' ),
                number_format_i18n( $count )
            );
        } else {
            $class   = 'notice-warning';
            $message = __( 'There were no active lockouts to clear.', 'login-delay-shield' );
        }
    }

    if ( '' === $message ) {
        return;
    }

    echo '<div class="notice ' . esc_attr( $class ) . ' is-dismissible" role="status" aria-live="polite"><p>' . esc_html( $message ) . '</p></div>';
}
add_action( 'admin_notices', 'wldelay_render_lockout_manager_notice' );

if ( defined( 'WP_CLI' ) && WP_CLI ) {
    /**
     * WP-CLI commands for Login Delay Shield.
     */
    class WLDelay_CLI_Command {
        /**
         * Unlock a specific IP.
         *
         * ## OPTIONS
         *
         * <ip>
         * : IP address to unlock.
         *
         * ## EXAMPLES
         *
         *     wp login-delay-shield unlock-ip 203.0.113.10
         *
         * @when after_wp_load
         */
        public function unlock_ip( $args ) {
            list( $ip ) = $args;

            if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
                WP_CLI::error( __( 'Invalid IP address provided.', 'login-delay-shield' ) );
            }

            $deleted = wldelay_delete_lockout_for_ip( $ip );

            // FALSE (NOT a count) means the durable conditional delete failed at
            // the DB layer: the lockout row may still be on disk. Surface a hard
            // error rather than reporting a clean removal (F-3-1). WP_CLI::error()
            // halts with a non-zero exit so a script driving the unlock can tell
            // it did not succeed.
            if ( false === $deleted ) {
                if ( function_exists( 'wldelay_audit_log' ) ) {
                    wldelay_audit_log(
                        'lockout_cleared',
                        array(
                            'object'    => $ip,
                            'new_value' => array(
                                'removed_rows' => 0,
                                'source'       => 'wp-cli',
                                'failed'       => true,
                            ),
                        )
                    );
                }
                WP_CLI::error(
                    sprintf(
                        /* translators: %s: IP address */
                        __( 'A database error occurred while clearing the lockout for %s; it may still be in force. Check the database and retry.', 'login-delay-shield' ),
                        $ip
                    )
                );
            }

            // Record the CLI unlock in the audit trail (F-2-7). Logged on every
            // invocation, not only on a hit, so the privileged action itself is
            // auditable — a compromised shell clearing lockouts must leave a
            // forensic record, same as the web admin unlock handler.
            if ( function_exists( 'wldelay_audit_log' ) ) {
                wldelay_audit_log(
                    'lockout_cleared',
                    array(
                        'object'    => $ip,
                        'new_value' => array(
                            'removed_rows' => (int) $deleted,
                            'source'       => 'wp-cli',
                        ),
                    )
                );
            }

            if ( $deleted > 0 ) {
                WP_CLI::success(
                    sprintf(
                        /* translators: %1$s: IP address, %2$d: number of removed entries */
                        _n(
                            'Removed lockout/failure data for %1$s (%2$d entry).',
                            'Removed lockout/failure data for %1$s (%2$d entries).',
                            $deleted,
                            'login-delay-shield'
                        ),
                        $ip,
                        $deleted
                    )
                );
                return;
            }

            WP_CLI::warning(
                sprintf(
                    /* translators: %s: IP address */
                    __( 'No active lockout found for %s.', 'login-delay-shield' ),
                    $ip
                )
            );
        }

        /**
         * Flush all lockouts.
         *
         * ## EXAMPLES
         *
         *     wp login-delay-shield flush-lockouts
         *
         * @when after_wp_load
         */
        public function flush_lockouts() {
            $deleted = wldelay_flush_lockout_transients();

            // FALSE (NOT a count) means the durable conditional delete failed at
            // the DB layer: some lockout rows may still be on disk. Surface a
            // hard error rather than reporting a clean flush (F-3-1).
            if ( false === $deleted ) {
                if ( function_exists( 'wldelay_audit_log' ) ) {
                    wldelay_audit_log(
                        'lockouts_flushed',
                        array(
                            'object'    => 'all',
                            'new_value' => array(
                                'removed_rows' => 0,
                                'source'       => 'wp-cli',
                                'failed'       => true,
                            ),
                        )
                    );
                }
                WP_CLI::error(
                    __( 'A database error occurred while flushing lockouts; some may still be in force. Check the database and retry.', 'login-delay-shield' )
                );
            }

            // Audit the bulk clear under a distinct action so a wholesale flush
            // is never mistaken for a single-IP unlock in the forensic trail
            // (F-2-7). Includes the removed count and the CLI source.
            if ( function_exists( 'wldelay_audit_log' ) ) {
                wldelay_audit_log(
                    'lockouts_flushed',
                    array(
                        'object'    => 'all',
                        'new_value' => array(
                            'removed_rows' => (int) $deleted,
                            'source'       => 'wp-cli',
                        ),
                    )
                );
            }

            WP_CLI::success(
                sprintf(
                    /* translators: %d: number of removed lockout/failure entries */
                    _n(
                        'Removed %d lockout/failure entry.',
                        'Removed %d lockout/failure entries.',
                        $deleted,
                        'login-delay-shield'
                    ),
                    $deleted
                )
            );
        }
    }

    WP_CLI::add_command( 'login-delay-shield', 'WLDelay_CLI_Command' );
}

function wldelay_dashboard_widget_content() {
    if ( ! current_user_can( 'manage_options' ) ) {
        echo '<p>' . esc_html__( 'You do not have permission to view Login Delay Shield telemetry.', 'login-delay-shield' ) . '</p>';
        return;
    }

    // Onboarding CTA (F-1-7): render BEFORE the no-attempts early return so a
    // brand-new install (0 attempts, 0% score) still sees the prompt to run the
    // Setup Wizard. The CTA self-suppresses once the score reaches 50%.
    wldelay_render_dashboard_onboarding_cta();

    // Botnet / distributed-attack detection banner (F-1-9). Rendered before the
    // no-attempts early return so a brand-new attack (no history yet but the
    // detection transient already set) is still surfaced.
    $botnet_detections = function_exists( 'wldelay_botnet_get_recent_detections' )
        ? wldelay_botnet_get_recent_detections()
        : array();
    if ( ! empty( $botnet_detections ) ) {
        echo '<div class="wldelay-botnet-alert notice notice-warning inline" aria-live="polite">';
        echo '<p><span class="dashicons dashicons-warning" aria-hidden="true"></span> <strong>'
            . esc_html__( 'Distributed attack detected', 'login-delay-shield' ) . '</strong></p><ul>';
        foreach ( array_slice( $botnet_detections, 0, 3 ) as $d ) {
            echo '<li>' . esc_html( sprintf(
                /* translators: 1: username targeted by the attack, 2: number of distinct source IPs, 3: detection window in minutes, 4: human-readable time since detection */
                __( '%1$s targeted from %2$d IPs within %3$d min — %4$s ago', 'login-delay-shield' ),
                $d['username'],
                $d['distinct_ips'],
                $d['window_minutes'],
                human_time_diff( $d['detected_at'], time() )
            ) ) . '</li>';
        }
        echo '</ul></div>';
    }

    // Independent sub-caches (F-4-1): the cheap recent-attempts list and the
    // expensive 7-day trends aggregate each have their own key and TTL, and each
    // is rebuilt independently on miss so invalidating one never recomputes the
    // other.
    $attempts = get_transient( WLDELAY_DASH_RECENT_CACHE );
    if ( false === $attempts || ! is_array( $attempts ) ) {
        $attempts = wldelay_get_recent_failed_attempts( 10 );
        set_transient( WLDELAY_DASH_RECENT_CACHE, $attempts, WLDELAY_DASH_RECENT_TTL );
    }

    $trends = get_transient( WLDELAY_DASH_TRENDS_CACHE );
    if ( false === $trends || ! is_array( $trends ) ) {
        $trends = wldelay_get_failed_login_trends( 7 );
        set_transient( WLDELAY_DASH_TRENDS_CACHE, $trends, WLDELAY_DASH_TRENDS_TTL );
    }

    if ( empty( $attempts ) ) {
        echo '<p>' . esc_html__( 'No failed login attempts recorded.', 'login-delay-shield' ) . '</p>';
        return;
    }

    wldelay_render_dashboard_trends( $trends );

    echo '<table class="widefat striped">';
    echo '<caption class="screen-reader-text">' . esc_html__( 'Recent failed login attempts', 'login-delay-shield' ) . '</caption>';
    echo '<thead><tr>';
    echo '<th scope="col">' . esc_html__( 'Time', 'login-delay-shield' ) . '</th>';
    echo '<th scope="col">' . esc_html__( 'Username', 'login-delay-shield' ) . '</th>';
    echo '<th scope="col">' . esc_html__( 'IP Address', 'login-delay-shield' ) . '</th>';
    echo '<th scope="col">' . esc_html__( 'Source', 'login-delay-shield' ) . '</th>';
    echo '</tr></thead>';
    echo '<tbody>';

    foreach ( $attempts as $attempt ) {
        $time_ago = human_time_diff( strtotime( $attempt->attempted_at ), time() );
        $source = isset( $attempt->source ) ? $attempt->source : 'wp-login';
        $source_class = 'wldelay-source-' . sanitize_html_class( $source );
        $source_label = wldelay_get_login_source_label( $source );

        echo '<tr>';
        /* translators: %1$s: time ago, %2$s: exact timestamp */
        $time_text = sprintf( __( '%1$s ago', 'login-delay-shield' ), $time_ago );
        echo '<td><time datetime="' . esc_attr( $attempt->attempted_at ) . '" title="' . esc_attr( $attempt->attempted_at ) . '">' . esc_html( $time_text ) . '</time></td>';
        echo '<td>' . esc_html( $attempt->username ) . '</td>';
        echo '<td>' . esc_html( $attempt->ip_address ) . '</td>';
        echo '<td><span class="wldelay-source-badge ' . esc_attr( $source_class ) . '">' . esc_html( $source_label ) . '</span></td>';
        echo '</tr>';
    }

    echo '</tbody></table>';

    $settings_url = admin_url( 'options-general.php?page=login-delay-shield-admin' );
    echo '<p class="wldelay-widget-footer" style="margin-top: 10px; text-align: right;">';
    echo '<a href="' . esc_url( $settings_url ) . '">' . esc_html__( 'Settings', 'login-delay-shield' ) . '</a>';
    echo '</p>';

    wldelay_render_referral_card();
}

/**
 * Render a lightweight "recommend this plugin" card in the dashboard widget.
 */
function wldelay_render_referral_card() {
    $plugin_url  = 'https://wordpress.org/plugins/login-delay-shield/';
    $review_url  = 'https://wordpress.org/support/plugin/login-delay-shield/reviews/#new-post';
    $support_url = 'https://wordpress.org/support/plugin/login-delay-shield/';

    echo '<div class="wldelay-referral-card">';
    echo '<p class="wldelay-referral-text">';
    echo esc_html__( 'Find Login Delay Shield useful?', 'login-delay-shield' );
    echo '</p>';
    echo '<p class="wldelay-referral-links">';
    echo '<a href="' . esc_url( $review_url ) . '" target="_blank" rel="noopener noreferrer">';
    echo '<span class="dashicons dashicons-star-filled" aria-hidden="true"></span> ';
    echo esc_html__( 'Leave a review', 'login-delay-shield' );
    echo '</a>';
    echo '<a href="' . esc_url( $support_url ) . '" target="_blank" rel="noopener noreferrer">';
    echo '<span class="dashicons dashicons-sos" aria-hidden="true"></span> ';
    echo esc_html__( 'Get support', 'login-delay-shield' );
    echo '</a>';
    echo '</p>';
    echo '</div>';
}

/**
 * Render an onboarding call-to-action card when the security posture is weak.
 *
 * When the Health Score is below 50% (which always covers a brand-new all-off
 * install) this surfaces a prominent card at the top of the dashboard widget
 * pointing the admin at the Setup Wizard. Rather than dumping every disabled
 * protection with a raw deficit score, it frames the gap as an achievable goal:
 * the smallest set of highest-value protections that reaches the 50% "strong
 * setup" line (R4-4). Once enough protection is configured to reach 50% the card
 * disappears on its own, so there is no dismiss state.
 */
function wldelay_render_dashboard_onboarding_cta() {
    $score_data = wldelay_get_security_score();
    $score      = isset( $score_data['score'] ) ? (int) $score_data['score'] : 0;
    $max        = isset( $score_data['max'] ) ? (int) $score_data['max'] : 0;
    $pct        = (int) round( $score / max( 1, $max ) * 100 );

    // Self-resolving: a sufficiently configured install hides the CTA.
    if ( $pct >= 50 ) {
        return;
    }

    // Collect the disabled features, ranked by defensive weight.
    $missing = array();
    if ( ! empty( $score_data['features'] ) && is_array( $score_data['features'] ) ) {
        foreach ( $score_data['features'] as $feature ) {
            if ( empty( $feature['enabled'] ) ) {
                $missing[] = $feature;
            }
        }
    }

    usort(
        $missing,
        static function ( $a, $b ) {
            return (int) $b['points'] - (int) $a['points'];
        }
    );

    // Frame the card around an achievable goal, not a raw deficit: pick the
    // smallest set of the highest-value disabled protections that carries the
    // install across the 50% "strong setup" line, and show those as the next
    // steps. A short, finish-able list reads as "enable 2 things" rather than an
    // overwhelming dump of everything that is off (R4-4). Capped at 5 so a wildly
    // misconfigured install still shows a bounded list.
    $threshold_points = (int) ceil( $max * 0.5 );
    $needed           = max( 0, $threshold_points - $score );
    $recommended      = array();
    $accumulated      = 0;
    foreach ( $missing as $feature ) {
        $recommended[] = $feature;
        $accumulated  += isset( $feature['points'] ) ? (int) $feature['points'] : 0;
        if ( $accumulated >= $needed || count( $recommended ) >= 5 ) {
            break;
        }
    }
    $steps = count( $recommended );

    $wizard_url = add_query_arg(
        'page',
        'login-delay-shield-admin',
        admin_url( 'options-general.php' )
    ) . '#wldelay-setup-wizard-title';

    echo '<section class="wldelay-onboarding-cta" aria-labelledby="wldelay-onboarding-cta-title">';

    echo '<h3 class="wldelay-onboarding-cta-title" id="wldelay-onboarding-cta-title">';
    echo '<span class="dashicons dashicons-shield-alt" aria-hidden="true"></span> ';
    echo esc_html__( 'Finish setting up your login protection', 'login-delay-shield' );
    echo '</h3>';

    echo '<p class="wldelay-onboarding-cta-score">';
    if ( $steps > 0 ) {
        echo esc_html(
            sprintf(
                /* translators: 1: current security score percentage, 2: number of protections to enable to reach a strong setup */
                _n(
                    'You\'re at %1$d%%. Enable the protection below to reach a strong setup.',
                    'You\'re at %1$d%%. Enable the %2$d protections below to reach a strong setup.',
                    $steps,
                    'login-delay-shield'
                ),
                $pct,
                $steps
            )
        );
    } else {
        echo esc_html(
            sprintf(
                /* translators: %d: current security score percentage */
                __( 'You\'re at %d%%. Turn on a few more protections to harden your login.', 'login-delay-shield' ),
                $pct
            )
        );
    }
    echo '</p>';

    if ( ! empty( $recommended ) ) {
        echo '<p class="wldelay-onboarding-cta-subhead">' . esc_html__( 'Recommended next steps:', 'login-delay-shield' ) . '</p>';
        echo '<ul class="wldelay-onboarding-cta-list">';
        foreach ( $recommended as $feature ) {
            $label  = isset( $feature['label'] ) ? $feature['label'] : '';
            $points = isset( $feature['points'] ) ? (int) $feature['points'] : 0;
            echo '<li>';
            echo '<span class="dashicons dashicons-warning" aria-hidden="true"></span> ';
            echo esc_html( $label );
            echo ' <span class="wldelay-onboarding-cta-points">';
            echo esc_html(
                sprintf(
                    /* translators: %d: number of security-score points the feature is worth */
                    _n( '+%d point', '+%d points', $points, 'login-delay-shield' ),
                    $points
                )
            );
            echo '</span>';
            echo '</li>';
        }
        echo '</ul>';
    }

    echo '<p class="wldelay-onboarding-cta-action">';
    echo '<a class="button button-primary" href="' . esc_url( $wizard_url ) . '">';
    echo esc_html__( 'Run the Setup Wizard', 'login-delay-shield' );
    echo '<span class="screen-reader-text"> ' . esc_html__( '(opens the Login Delay Shield settings page)', 'login-delay-shield' ) . '</span>';
    echo '</a>';
    echo '</p>';

    echo '</section>';
}

/**
 * Get lightweight failed-login trends for the dashboard widget.
 *
 * Queries are scoped to a recent date window and keep grouped results small.
 *
 * @param int $days Number of days to include.
 * @return array{
 *     window_days:int,
 *     total_attempts:int,
 *     peak_day:array{date:string,count:int},
 *     daily_counts:array<int,array{date:string,count:int}>,
 *     source_counts:array<int,array{source:string,count:int}>,
 *     top_ips:array<int,array{ip_address:string,count:int}>,
 *     top_usernames:array<int,array{username:string,count:int}>
 * }
 */
function wldelay_get_failed_login_trends( $days = 7 ) {
    global $wpdb;

    $days = absint( $days );
    if ( $days < 1 ) {
        $days = 1;
    }

    $table_name = wldelay_get_log_table_name();
    $cutoff     = gmdate( 'Y-m-d H:i:s', current_time( 'timestamp' ) - ( $days * DAY_IN_SECONDS ) );

    $daily_rows = $wpdb->get_results(
        $wpdb->prepare(
            "SELECT DATE(attempted_at) AS attempted_date, COUNT(*) AS failures
            FROM $table_name
            WHERE attempted_at >= %s
            GROUP BY DATE(attempted_at)
            ORDER BY attempted_date ASC",
            $cutoff
        )
    );

    $counts_by_date = array();
    foreach ( $daily_rows as $row ) {
        $counts_by_date[ $row->attempted_date ] = (int) $row->failures;
    }

    $daily_counts    = array();
    $total_attempts  = 0;
    $peak_day        = array(
        'date'  => '',
        'count' => 0,
    );
    $current_time_ts = current_time( 'timestamp' );

    for ( $offset = $days - 1; $offset >= 0; $offset-- ) {
        $date_key = gmdate( 'Y-m-d', $current_time_ts - ( $offset * DAY_IN_SECONDS ) );
        $count    = isset( $counts_by_date[ $date_key ] ) ? (int) $counts_by_date[ $date_key ] : 0;

        $daily_counts[] = array(
            'date'  => $date_key,
            'count' => $count,
        );

        $total_attempts += $count;

        if ( $count >= $peak_day['count'] ) {
            $peak_day = array(
                'date'  => $date_key,
                'count' => $count,
            );
        }
    }

    $source_rows = $wpdb->get_results(
        $wpdb->prepare(
            "SELECT source, COUNT(*) AS failures
            FROM $table_name
            WHERE attempted_at >= %s
            GROUP BY source
            ORDER BY failures DESC, source ASC
            LIMIT 3",
            $cutoff
        )
    );

    $source_counts = array();
    foreach ( $source_rows as $row ) {
        $source_counts[] = array(
            'source' => (string) $row->source,
            'count'  => (int) $row->failures,
        );
    }

    $ip_rows = $wpdb->get_results(
        $wpdb->prepare(
            "SELECT ip_address, COUNT(*) AS failures
            FROM $table_name
            WHERE attempted_at >= %s
            GROUP BY ip_address
            ORDER BY failures DESC, ip_address ASC
            LIMIT 3",
            $cutoff
        )
    );

    $top_ips = array();
    foreach ( $ip_rows as $row ) {
        $top_ips[] = array(
            'ip_address' => (string) $row->ip_address,
            'count'      => (int) $row->failures,
        );
    }

    $username_rows = $wpdb->get_results(
        $wpdb->prepare(
            "SELECT username, COUNT(*) AS failures
            FROM $table_name
            WHERE attempted_at >= %s
                AND username IS NOT NULL
                AND TRIM(username) <> ''
            GROUP BY username
            ORDER BY failures DESC, username ASC
            LIMIT 3",
            $cutoff
        )
    );

    $top_usernames = array();
    foreach ( $username_rows as $row ) {
        $top_usernames[] = array(
            'username' => (string) $row->username,
            'count'    => (int) $row->failures,
        );
    }

    return array(
        'window_days'    => $days,
        'total_attempts' => $total_attempts,
        'peak_day'       => $peak_day,
        'daily_counts'   => $daily_counts,
        'source_counts'  => $source_counts,
        'top_ips'        => $top_ips,
        'top_usernames'  => $top_usernames,
    );
}

/**
 * Render the dashboard trends panel.
 *
 * @param array $trends Trend data from wldelay_get_failed_login_trends().
 */
function wldelay_render_dashboard_trends( $trends ) {
    $window_days = isset( $trends['window_days'] ) ? (int) $trends['window_days'] : 7;
    $total       = isset( $trends['total_attempts'] ) ? (int) $trends['total_attempts'] : 0;
    $peak_day    = isset( $trends['peak_day'] ) && is_array( $trends['peak_day'] ) ? $trends['peak_day'] : array();
    $daily_counts = isset( $trends['daily_counts'] ) && is_array( $trends['daily_counts'] ) ? $trends['daily_counts'] : array();
    $source_counts = isset( $trends['source_counts'] ) && is_array( $trends['source_counts'] ) ? $trends['source_counts'] : array();
    $top_ips = isset( $trends['top_ips'] ) && is_array( $trends['top_ips'] ) ? $trends['top_ips'] : array();
    $top_usernames = isset( $trends['top_usernames'] ) && is_array( $trends['top_usernames'] ) ? $trends['top_usernames'] : array();

    echo '<div class="wldelay-widget-trends" aria-labelledby="wldelay-widget-trends-title">';
    echo '<h3 id="wldelay-widget-trends-title" class="wldelay-widget-trends-title">';
    printf(
        /* translators: %d: number of days in the dashboard trends window */
        esc_html__( 'Failed login trends: last %d days', 'login-delay-shield' ),
        esc_html( $window_days )
    );
    echo '</h3>';

    echo '<p class="wldelay-widget-trends-summary">';
    printf(
        /* translators: %s: number of failed login attempts */
        esc_html__( '%s failed attempts recorded in the selected window.', 'login-delay-shield' ),
        '<strong>' . esc_html( number_format_i18n( $total ) ) . '</strong>'
    );

    if ( ! empty( $peak_day['date'] ) && ! empty( $peak_day['count'] ) ) {
        $peak_label = date_i18n(
            _x( 'M j', 'date format for failed login trend labels', 'login-delay-shield' ),
            strtotime( $peak_day['date'] . ' 00:00:00' )
        );

        echo ' ';
        printf(
            /* translators: 1: date label, 2: number of failed attempts */
            esc_html__( 'Busiest day: %1$s (%2$s).', 'login-delay-shield' ),
            esc_html( $peak_label ),
            esc_html( number_format_i18n( (int) $peak_day['count'] ) )
        );
    }
    echo '</p>';

    echo '<div class="wldelay-widget-trends-grid">';

    echo '<section class="wldelay-trend-card" aria-labelledby="wldelay-trend-daily-title">';
    echo '<h4 id="wldelay-trend-daily-title">' . esc_html__( 'Daily activity', 'login-delay-shield' ) . '</h4>';
    echo '<ul class="wldelay-trend-list">';
    foreach ( $daily_counts as $day ) {
        $day_label = date_i18n(
            _x( 'M j', 'date format for failed login trend labels', 'login-delay-shield' ),
            strtotime( $day['date'] . ' 00:00:00' )
        );
        echo '<li><span>' . esc_html( $day_label ) . '</span><strong>' . esc_html( number_format_i18n( (int) $day['count'] ) ) . '</strong></li>';
    }
    echo '</ul>';
    echo '</section>';

    echo '<section class="wldelay-trend-card" aria-labelledby="wldelay-trend-sources-title">';
    echo '<h4 id="wldelay-trend-sources-title">' . esc_html__( 'Top sources', 'login-delay-shield' ) . '</h4>';
    echo '<ul class="wldelay-trend-list">';
    if ( empty( $source_counts ) ) {
        echo '<li><span>' . esc_html__( 'No recent data', 'login-delay-shield' ) . '</span><strong>0</strong></li>';
    } else {
        foreach ( $source_counts as $source_count ) {
            echo '<li><span>' . esc_html( wldelay_get_login_source_label( $source_count['source'] ) ) . '</span><strong>' . esc_html( number_format_i18n( (int) $source_count['count'] ) ) . '</strong></li>';
        }
    }
    echo '</ul>';
    echo '</section>';

    echo '<section class="wldelay-trend-card" aria-labelledby="wldelay-trend-ips-title">';
    echo '<h4 id="wldelay-trend-ips-title">' . esc_html__( 'Top IPs', 'login-delay-shield' ) . '</h4>';
    echo '<ol class="wldelay-trend-list wldelay-trend-list-ordered">';
    if ( empty( $top_ips ) ) {
        echo '<li><span>' . esc_html__( 'No recent data', 'login-delay-shield' ) . '</span><strong>0</strong></li>';
    } else {
        foreach ( $top_ips as $ip_count ) {
            echo '<li><span>' . esc_html( $ip_count['ip_address'] ) . '</span><strong>' . esc_html( number_format_i18n( (int) $ip_count['count'] ) ) . '</strong></li>';
        }
    }
    echo '</ol>';
    echo '</section>';

    echo '<section class="wldelay-trend-card" aria-labelledby="wldelay-trend-usernames-title">';
    echo '<h4 id="wldelay-trend-usernames-title">' . esc_html__( 'Top usernames', 'login-delay-shield' ) . '</h4>';
    echo '<ol class="wldelay-trend-list wldelay-trend-list-ordered">';
    if ( empty( $top_usernames ) ) {
        echo '<li><span>' . esc_html__( 'No recent data', 'login-delay-shield' ) . '</span><strong>0</strong></li>';
    } else {
        foreach ( $top_usernames as $username_count ) {
            echo '<li><span>' . esc_html( $username_count['username'] ) . '</span><strong>' . esc_html( number_format_i18n( (int) $username_count['count'] ) ) . '</strong></li>';
        }
    }
    echo '</ol>';
    echo '</section>';

    echo '</div>';
    echo '</div>';
}

/**
 * Database table functions
 */
function wldelay_get_log_table_name() {
    static $table_name = null;

    if ( $table_name === null ) {
        global $wpdb;
        $table_name = $wpdb->prefix . 'wldelay_login_log';
    }

    return $table_name;
}

function wldelay_create_log_table() {
    global $wpdb;

    $table_name = wldelay_get_log_table_name();
    $charset_collate = $wpdb->get_charset_collate();

    $sql = "CREATE TABLE $table_name (
        id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
        ip_address varchar(45) NOT NULL,
        username varchar(60) NOT NULL,
        attempted_at datetime NOT NULL,
        source varchar(20) NOT NULL DEFAULT 'wp-login',
        PRIMARY KEY  (id),
        KEY attempted_at (attempted_at),
        KEY ip_address (ip_address),
        KEY username (username),
        KEY source (source),
        KEY username_attempted (username, attempted_at)
    ) $charset_collate;";

    require_once( ABSPATH . 'wp-admin/includes/upgrade.php' );
    dbDelta( $sql );
}

/**
 * Create every plugin-owned table.
 *
 * Used on activation and on the DB upgrade path so the log table and the
 * durable lockout store (F-2-1) are provisioned together behind one schema
 * version. Kept separate from wldelay_create_log_table() so creating the
 * lockout table (DDL, which implicitly commits) is not triggered on every
 * call to the log-table helper.
 *
 * The schema version is recorded only after both tables are confirmed to
 * exist AND the gen-3 username widening has actually taken effect AND the gen-4
 * transient_key column is present, so a failed or interrupted CREATE — or an
 * ALTER that could not widen the column (e.g. a 767-byte index-limit failure on
 * old MySQL) or add the column — leaves the stored version untouched and
 * wldelay_maybe_upgrade_db() retries on the next request instead of masking a
 * half-applied schema (F-2-1).
 */
function wldelay_create_tables() {
    global $wpdb;

    wldelay_create_log_table();
    wldelay_create_lockout_table();
    wldelay_create_audit_table();

    $log_table     = wldelay_get_log_table_name();
    $lockout_table = wldelay_get_lockout_table_name();
    $audit_table   = wldelay_get_audit_table_name();

    $log_exists     = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $log_table ) ) === $log_table;
    $lockout_exists = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $lockout_table ) ) === $lockout_table;
    $audit_exists   = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $audit_table ) ) === $audit_table;

    if (
        $log_exists
        && $lockout_exists
        && $audit_exists
        && wldelay_lockout_username_is_widened()
        && wldelay_lockout_has_transient_key_column()
        && wldelay_lockout_has_generation_column()
    ) {
        update_option( 'wldelay_db_version', WLDELAY_DB_VERSION );
    }
}

register_activation_hook( WLDELAY_PLUGIN_FILE, 'wldelay_create_tables' );

/**
 * Stamp a fresh activation at the latest settings version so a brand-new
 * install never replays historical settings migrations (F-2-6).
 *
 * Only stamps a genuinely fresh install — no recorded settings version AND no
 * stored options — matching WLDelay_Migration::is_fresh_install(). A legacy
 * install (stored options present, version absent) must NOT be stamped here:
 * doing so would mark it current and make the plugins_loaded migration runner
 * skip the v1 default-key backfill, permanently. Such installs are left
 * unstamped so WLDelay_Migration::run() migrates them on the next load.
 */
function wldelay_stamp_settings_version_on_activation() {
    if (
        false === get_option( WLDELAY_SETTINGS_VERSION_OPTION, false )
        && false === get_option( WLDELAY_OPTION_NAME, false )
    ) {
        update_option( WLDELAY_SETTINGS_VERSION_OPTION, WLDELAY_SETTINGS_VERSION );
    }
}
register_activation_hook( WLDELAY_PLUGIN_FILE, 'wldelay_stamp_settings_version_on_activation' );

// ==========================================================================
// Trend Analytics Queries
// ==========================================================================

/**
 * Get the top IP addresses by failed login count within a period.
 *
 * @param int $days  Number of days to look back (defaults to 7 if <= 0).
 * @param int $limit Maximum rows to return (defaults to 10 if <= 0).
 * @return array Array of objects with ip_address and attempt_count properties.
 */
function wldelay_get_top_ips( $days = 7, $limit = 10 ) {
    global $wpdb;

    $days  = max( 1, (int) $days );
    $limit = max( 1, (int) $limit );

    $table_name = wldelay_get_log_table_name();
    $since = gmdate( 'Y-m-d H:i:s', time() - ( $days * DAY_IN_SECONDS ) );

    return $wpdb->get_results( $wpdb->prepare(
        "SELECT ip_address, COUNT(*) AS attempt_count
         FROM $table_name
         WHERE attempted_at >= %s
         GROUP BY ip_address
         ORDER BY attempt_count DESC
         LIMIT %d",
        $since,
        $limit
    ) );
}

/**
 * Get the top usernames by failed login count within a period.
 *
 * @param int $days  Number of days to look back (defaults to 7 if <= 0).
 * @param int $limit Maximum rows to return (defaults to 10 if <= 0).
 * @return array Array of objects with username and attempt_count properties.
 */
function wldelay_get_top_usernames( $days = 7, $limit = 10 ) {
    global $wpdb;

    $days  = max( 1, (int) $days );
    $limit = max( 1, (int) $limit );

    $table_name = wldelay_get_log_table_name();
    $since = gmdate( 'Y-m-d H:i:s', time() - ( $days * DAY_IN_SECONDS ) );

    return $wpdb->get_results( $wpdb->prepare(
        "SELECT username, COUNT(*) AS attempt_count
         FROM $table_name
         WHERE attempted_at >= %s
         GROUP BY username
         ORDER BY attempt_count DESC
         LIMIT %d",
        $since,
        $limit
    ) );
}

/**
 * Get daily failed login attempt counts within a period.
 *
 * @param int $days Number of days to look back (defaults to 7 if <= 0).
 * @return array Array of objects with log_date (Y-m-d) and attempt_count properties, ordered ASC.
 */
function wldelay_get_daily_attempts( $days = 7 ) {
    global $wpdb;

    $days = max( 1, (int) $days );

    $table_name = wldelay_get_log_table_name();
    $since = gmdate( 'Y-m-d H:i:s', time() - ( $days * DAY_IN_SECONDS ) );

    return $wpdb->get_results( $wpdb->prepare(
        "SELECT DATE(attempted_at) AS log_date, COUNT(*) AS attempt_count
         FROM $table_name
         WHERE attempted_at >= %s
         GROUP BY log_date
         ORDER BY log_date ASC",
        $since
    ) );
}

/**
 * Log cleanup cron job
 */
function wldelay_schedule_cleanup() {
    if ( ! wp_next_scheduled( 'wldelay_cleanup_logs' ) ) {
        wp_schedule_event( time(), 'daily', 'wldelay_cleanup_logs' );
    }
}
add_action( 'wp', 'wldelay_schedule_cleanup' );

function wldelay_unschedule_cleanup() {
    $timestamp = wp_next_scheduled( 'wldelay_cleanup_logs' );
    if ( $timestamp ) {
        wp_unschedule_event( $timestamp, 'wldelay_cleanup_logs' );
    }
}
register_deactivation_hook( WLDELAY_PLUGIN_FILE, 'wldelay_unschedule_cleanup' );

// Schedule the F-4-9 async cron backstop on activation so the maintenance tick
// exists immediately, without waiting for a front-end `wp` action that may never
// fire on admin-only, AJAX, or externally-cronned sites. The scheduling function
// is idempotent (no-op if already scheduled). Both scheduling/callback live in
// wldelay-async.php; the hook is registered here alongside the deactivation
// teardown so both plugin-owned cron events are managed together.
register_activation_hook( WLDELAY_PLUGIN_FILE, 'wldelay_schedule_async_cron' );

// Unschedule the F-4-9 async cron backstop on deactivation as well. The
// scheduling/callback live in wldelay-async.php; the deactivation hook is
// registered here alongside the existing cleanup-cron deactivation so both
// plugin-owned cron events are torn down together.
register_deactivation_hook( WLDELAY_PLUGIN_FILE, 'wldelay_unschedule_async_cron' );

/**
 * Delete log entries older than the retention period
 */
function wldelay_cleanup_old_logs() {
    global $wpdb;

    // Purge expired rows from the durable lockout store (F-2-1) first, before
    // any retention-based early return. Lockout rows are bounded by their own
    // expiry rather than the log retention setting, so they must be reaped even
    // when logs are kept forever (retention = 0) — otherwise a rotating-IP
    // attack grows the lockout table without bound.
    wldelay_get_persistence_store()->purge_expired();

    // Reap per-key transient registry records whose transient has expired, so a
    // rotating-identity attack cannot grow wp_options without bound. Bounded by
    // its own expiry, independent of log retention (Codex-2 round-3 review).
    wldelay_purge_expired_transient_registry_records();

    $options = get_option( WLDELAY_OPTION_NAME );
    $retention_days = isset( $options['wldelay_log_retention_days'] )
        ? (int) $options['wldelay_log_retention_days']
        : LDS_Settings::_DEFAULT_LOG_RETENTION_DAYS;

    // 0 means keep forever
    if ( $retention_days <= 0 ) {
        return;
    }

    $table_name = wldelay_get_log_table_name();
    $cutoff_date = gmdate( 'Y-m-d H:i:s', strtotime( "-{$retention_days} days" ) );

    // Delete in batches to avoid locking large tables
    $batch_size = 1000;
    $total_deleted = 0;

    do {
        $deleted = $wpdb->query(
            $wpdb->prepare(
                "DELETE FROM $table_name WHERE attempted_at < %s LIMIT %d",
                $cutoff_date,
                $batch_size
            )
        );

        if ( $deleted > 0 ) {
            $total_deleted += $deleted;
        }
    } while ( $deleted === $batch_size );

    // A bulk log deletion changes both fast-moving and aggregate data, so unlike
    // a single failed attempt this correctly invalidates BOTH sub-caches (F-4-1)
    // — the 7-day trends are genuinely stale once old rows are gone.
    if ( $total_deleted > 0 ) {
        delete_transient( WLDELAY_DASH_RECENT_CACHE );
        delete_transient( WLDELAY_DASH_TRENDS_CACHE );
    }
}
add_action( 'wldelay_cleanup_logs', 'wldelay_cleanup_old_logs' );

/**
 * Check if database needs upgrade
 */
function wldelay_maybe_upgrade_db() {
    $installed_version = get_option( 'wldelay_db_version' );
    if ( $installed_version !== WLDELAY_DB_VERSION ) {
        wldelay_create_tables();
    }
}
add_action( 'plugins_loaded', 'wldelay_maybe_upgrade_db' );

/**
 * Run pending settings (options-array) migrations.
 *
 * Distinct from the DB schema upgrade above: this transforms the stored
 * wldelay_options array via the ordered WLDelay_Migration registry (F-2-6).
 * Hooked at priority 11 so it runs after wldelay_maybe_upgrade_db (priority 10)
 * yet still on plugins_loaded — before any admin/front-end code reads settings.
 * The runner early-returns cheaply when already current, so the per-request
 * cost on a migrated install is a single get_option() comparison.
 */
function wldelay_maybe_migrate_settings() {
    WLDelay_Migration::run();
}
add_action( 'plugins_loaded', 'wldelay_maybe_migrate_settings', 11 );

/**
 * Show upgrade notice for name change
 */
function wldelay_show_upgrade_notice() {
    // Only show to users who can manage options
    if ( ! current_user_can( 'manage_options' ) ) {
        return;
    }

    // Check if notice was dismissed
    if ( get_option( 'wldelay_name_change_notice_dismissed' ) ) {
        return;
    }

    // Only show if upgrading from an older version (before 1.8.0)
    $previous_version = get_option( 'wldelay_previous_version' );
    if ( $previous_version && version_compare( $previous_version, '1.8.0', '>=' ) ) {
        return;
    }

    // Check if this is an existing installation (has options saved)
    $options = get_option( WLDELAY_OPTION_NAME );
    if ( empty( $options ) ) {
        // New installation, no need to show notice
        update_option( 'wldelay_name_change_notice_dismissed', true );
        return;
    }

    ?>
    <div class="notice notice-info is-dismissible wldelay-name-change-notice">
        <p>
            <strong><?php esc_html_e( 'Login Delay Shield', 'login-delay-shield' ); ?></strong> —
            <?php esc_html_e( 'This plugin was formerly known as "WP Login Delay". The name has changed, but all your settings have been preserved.', 'login-delay-shield' ); ?>
        </p>
    </div>
    <?php
}
add_action( 'admin_notices', 'wldelay_show_upgrade_notice' );

function wldelay_dismiss_name_change_notice() {
    check_ajax_referer( 'wldelay_dismiss_notice', '_wpnonce' );

    if ( ! current_user_can( 'manage_options' ) ) {
        wp_die();
    }

    update_option( 'wldelay_name_change_notice_dismissed', true );
    wp_die();
}
add_action( 'wp_ajax_wldelay_dismiss_name_change_notice', 'wldelay_dismiss_name_change_notice' );

/**
 * Show a "What's New" banner after plugin upgrade.
 *
 * Feature highlights only — no security fix details.
 */
function wldelay_show_whats_new_notice() {
    if ( ! current_user_can( 'manage_options' ) ) {
        return;
    }

    $dismissed_version = get_option( 'wldelay_whats_new_dismissed', '' );
    if ( $dismissed_version === WLDELAY_VERSION ) {
        return;
    }

    $previous_version = get_option( 'wldelay_previous_version', '' );
    if ( empty( $previous_version ) || version_compare( $previous_version, WLDELAY_VERSION, '>=' ) ) {
        return;
    }

    $highlights = wldelay_get_version_highlights( WLDELAY_VERSION );
    if ( empty( $highlights ) ) {
        return;
    }

    ?>
    <div class="notice notice-info is-dismissible wldelay-whats-new-notice" data-version="<?php echo esc_attr( WLDELAY_VERSION ); ?>">
        <p>
            <strong><?php
                printf(
                    /* translators: %s: plugin version number */
                    esc_html__( "What's new in Login Delay Shield %s", 'login-delay-shield' ),
                    esc_html( WLDELAY_VERSION )
                );
            ?></strong>
        </p>
        <ul style="list-style: disc; margin-left: 20px;">
            <?php foreach ( $highlights as $highlight ) : ?>
                <li><?php echo esc_html( $highlight ); ?></li>
            <?php endforeach; ?>
        </ul>
    </div>
    <?php
}
add_action( 'admin_notices', 'wldelay_show_whats_new_notice' );

/**
 * Get feature highlights for a given version.
 *
 * Returns an empty array for versions without curated highlights.
 *
 * @param string $version Version string.
 * @return array<int,string>
 */
function wldelay_get_version_highlights( $version ) {
    $highlights = array(
        '2.4.0' => array(
            __( 'Proxy/CDN-aware IP detection — Cloudflare, Sucuri, and nginx headers are now supported, with spoof-proof validation of CF-Connecting-IP.', 'login-delay-shield' ),
            __( 'A proxy health check warns about the misconfigurations that cause mass lockouts or IP spoofing.', 'login-delay-shield' ),
            __( 'New safety nets: the WLDELAY_SAFE_MODE emergency constant, and a Custom Login URL self-check that auto-disables instead of locking everyone out.', 'login-delay-shield' ),
        ),
        '2.3.3' => array(
            __( 'Security Setup Wizard — apply Conservative, Balanced, or Aggressive protection profiles in one step.', 'login-delay-shield' ),
            __( 'Profiles configure delay, lockout, alerts, and authentication endpoints while keeping every control editable.', 'login-delay-shield' ),
        ),
        '2.3.2' => array(
            __( 'Password reset protection — apply delay, lockout, and logging to reset requests.', 'login-delay-shield' ),
            __( 'Password reset throttling uses isolated counters to avoid locking users out of normal login.', 'login-delay-shield' ),
        ),
        '2.3.0' => array(
            __( 'Security Health Score — see your protection posture at a glance.', 'login-delay-shield' ),
            __( 'Whitelist IP lookups are now cached for faster login checks.', 'login-delay-shield' ),
            __( 'CI/CD pipeline — tests run automatically on every code change.', 'login-delay-shield' ),
        ),
        '2.2.4' => array(
            __( 'Top targeted usernames in login telemetry.', 'login-delay-shield' ),
            __( 'Faster database queries with username index.', 'login-delay-shield' ),
        ),
    );

    return isset( $highlights[ $version ] ) ? $highlights[ $version ] : array();
}

/**
 * Dismiss the "What's New" notice via AJAX.
 */
function wldelay_dismiss_whats_new_notice() {
    check_ajax_referer( 'wldelay_dismiss_notice', '_wpnonce' );

    if ( ! current_user_can( 'manage_options' ) ) {
        wp_die();
    }

    $version = isset( $_POST['version'] ) ? sanitize_text_field( wp_unslash( $_POST['version'] ) ) : WLDELAY_VERSION;
    update_option( 'wldelay_whats_new_dismissed', $version );
    wp_die();
}
add_action( 'wp_ajax_wldelay_dismiss_whats_new_notice', 'wldelay_dismiss_whats_new_notice' );

function wldelay_track_version() {
    $stored_version = get_option( 'wldelay_plugin_version' );
    if ( $stored_version !== WLDELAY_VERSION ) {
        if ( $stored_version ) {
            update_option( 'wldelay_previous_version', $stored_version );
        }
        update_option( 'wldelay_plugin_version', WLDELAY_VERSION );
    }
}
add_action( 'plugins_loaded', 'wldelay_track_version' );

/**
 * Return guided setup protection profiles.
 *
 * @return array<string,array{label:string,tagline:string,description:string,settings:array<string,mixed>}>
 */
function wldelay_get_protection_profiles() {
    return array(
        'conservative' => array(
            'label'       => __( 'Conservative', 'login-delay-shield' ),
            'tagline'     => __( 'Low friction', 'login-delay-shield' ),
            'description' => __( 'Adds core throttling with gentler thresholds for sites that prioritize fewer support requests.', 'login-delay-shield' ),
            'settings'    => array(
                'wldelay_delay'                         => 1,
                'wldelay_delay_random'                  => false,
                'wldelay_delay_random_min'              => 1,
                'wldelay_delay_random_max'              => 3,
                'wldelay_progressive_enabled'           => true,
                'wldelay_progressive_increment'         => 1,
                'wldelay_progressive_max'               => 15,
                'wldelay_lockout_enabled'               => true,
                'wldelay_lockout_threshold'             => 10,
                'wldelay_lockout_duration'              => 30,
                'wldelay_lockout_attempt_strategy'      => 'ip',
                'wldelay_email_enabled'                 => true,
                'wldelay_email_threshold'               => 10,
                'wldelay_email_cooldown'                => 10,
                'wldelay_xmlrpc_enabled'                => true,
                'wldelay_xmlrpc_block'                  => false,
                'wldelay_rest_enabled'                  => true,
                'wldelay_application_password_enabled'  => false,
                'wldelay_password_reset_enabled'        => true,
            ),
        ),
        'balanced'     => array(
            'label'       => __( 'Balanced', 'login-delay-shield' ),
            'tagline'     => __( 'Recommended', 'login-delay-shield' ),
            'description' => __( 'Turns on the main protections with thresholds that fit most WordPress sites.', 'login-delay-shield' ),
            'settings'    => array(
                'wldelay_delay'                         => 2,
                'wldelay_delay_random'                  => true,
                'wldelay_delay_random_min'              => 1,
                'wldelay_delay_random_max'              => 4,
                'wldelay_progressive_enabled'           => true,
                'wldelay_progressive_increment'         => 1,
                'wldelay_progressive_max'               => 30,
                'wldelay_lockout_enabled'               => true,
                'wldelay_lockout_threshold'             => 7,
                'wldelay_lockout_duration'              => 60,
                'wldelay_lockout_attempt_strategy'      => 'ip',
                'wldelay_email_enabled'                 => true,
                'wldelay_email_threshold'               => 5,
                'wldelay_email_cooldown'                => 5,
                'wldelay_xmlrpc_enabled'                => true,
                'wldelay_xmlrpc_block'                  => false,
                'wldelay_rest_enabled'                  => true,
                'wldelay_application_password_enabled'  => true,
                'wldelay_password_reset_enabled'        => true,
            ),
        ),
        'aggressive'   => array(
            'label'       => __( 'Aggressive', 'login-delay-shield' ),
            'tagline'     => __( 'Maximum protection', 'login-delay-shield' ),
            'description' => __( 'Uses stricter lockouts and blocks XML-RPC authentication for sites under frequent attack.', 'login-delay-shield' ),
            'settings'    => array(
                'wldelay_delay'                         => 3,
                'wldelay_delay_random'                  => true,
                'wldelay_delay_random_min'              => 2,
                'wldelay_delay_random_max'              => 6,
                'wldelay_progressive_enabled'           => true,
                'wldelay_progressive_increment'         => 2,
                'wldelay_progressive_max'               => 45,
                'wldelay_lockout_enabled'               => true,
                'wldelay_lockout_threshold'             => 5,
                'wldelay_lockout_duration'              => 120,
                'wldelay_lockout_attempt_strategy'      => 'ip',
                'wldelay_email_enabled'                 => true,
                'wldelay_email_threshold'               => 3,
                'wldelay_email_cooldown'                => 5,
                'wldelay_xmlrpc_enabled'                => true,
                'wldelay_xmlrpc_block'                  => true,
                'wldelay_rest_enabled'                  => true,
                'wldelay_application_password_enabled'  => true,
                'wldelay_password_reset_enabled'        => true,
            ),
        ),
    );
}

/**
 * Validate a protection profile ID.
 *
 * @param string $profile_id Raw profile ID.
 * @return string Valid profile ID, or empty string.
 */
function wldelay_sanitize_protection_profile_id( $profile_id ) {
    $profile_id = preg_replace( '/[^a-z0-9_-]/', '', strtolower( (string) $profile_id ) );
    $profiles   = wldelay_get_protection_profiles();

    return isset( $profiles[ $profile_id ] ) ? $profile_id : '';
}

/**
 * Compute a 0–100 security health score based on enabled features.
 *
 * Each feature carries a weight reflecting its defensive value. Returns
 * the score, the list of scored features, and the top disabled feature
 * to recommend next.
 *
 * @param array|null $options Optional options array.
 * @return array{score:int,max:int,features:array,recommendation:array{key:string,label:string,points:int}|null}
 */
function wldelay_get_security_score( $options = null ) {
    if ( $options === null ) {
        $options = wldelay_get_options();
    }

    $features = array(
        'wldelay_lockout_enabled'              => array( 'label' => __( 'IP Lockout', 'login-delay-shield' ), 'points' => 20 ),
        'wldelay_progressive_enabled'          => array( 'label' => __( 'Progressive Delay', 'login-delay-shield' ), 'points' => 15 ),
        'wldelay_custom_login_enabled'         => array( 'label' => __( 'Custom Login URL', 'login-delay-shield' ), 'points' => 15 ),
        'wldelay_xmlrpc_enabled'               => array( 'label' => __( 'XML-RPC Protection', 'login-delay-shield' ), 'points' => 10 ),
        'wldelay_email_enabled'                => array( 'label' => __( 'Email Alerts', 'login-delay-shield' ), 'points' => 10 ),
        'wldelay_whitelist_enabled'            => array( 'label' => __( 'IP Whitelist', 'login-delay-shield' ), 'points' => 5 ),
        'wldelay_rest_enabled'                 => array( 'label' => __( 'REST API Protection', 'login-delay-shield' ), 'points' => 5 ),
        'wldelay_application_password_enabled' => array( 'label' => __( 'Application Password Protection', 'login-delay-shield' ), 'points' => 5 ),
        'wldelay_password_reset_enabled'       => array( 'label' => __( 'Password Reset Protection', 'login-delay-shield' ), 'points' => 5 ),
        'wldelay_enumeration_hardening_enabled' => array( 'label' => __( 'Username Enumeration Hardening', 'login-delay-shield' ), 'points' => 5 ),
        'wldelay_fail2ban_enabled'             => array( 'label' => __( 'fail2ban Logging', 'login-delay-shield' ), 'points' => 5 ),
    );

    $score          = 0;
    $max            = 0;
    $recommendation = null;
    $scored         = array();

    foreach ( $features as $key => $feature ) {
        $enabled       = ! empty( $options[ $key ] );
        $max          += $feature['points'];
        $scored[ $key ] = array(
            'label'   => $feature['label'],
            'points'  => $feature['points'],
            'enabled' => $enabled,
        );

        if ( $enabled ) {
            $score += $feature['points'];
        } elseif ( $recommendation === null || $feature['points'] > $recommendation['points'] ) {
            $recommendation = array(
                'key'    => $key,
                'label'  => $feature['label'],
                'points' => $feature['points'],
            );
        }
    }

    return array(
        'score'          => $score,
        'max'            => $max,
        'features'       => $scored,
        'recommendation' => $recommendation,
    );
}

// @see http://codex.wordpress.org/Function_Reference/add_filter
// @see https://codex.wordpress.org/Plugin_API/Filter_Reference/wp_authenticate_user

function wldelay_get_options() {
    if ( ! isset( $GLOBALS['wldelay_options_cache'] ) ) {
        $options = get_option( WLDELAY_OPTION_NAME );
        if ( ! is_array( $options ) ) {
            $options = array();
        }

        // Materialise the opt-in security feature defaults from the declarative
        // registry (F-2-2). Only registry keys flagged for injection are filled,
        // and only when absent, exactly like the array_key_exists guards this
        // replaced — so the cached option shape and every default stay identical.
        foreach ( WLDelay_Features::injected_defaults() as $registry_key => $registry_default ) {
            if ( ! array_key_exists( $registry_key, $options ) ) {
                $options[ $registry_key ] = $registry_default;
            }
        }

        $GLOBALS['wldelay_options_cache'] = $options;
    }

    return $GLOBALS['wldelay_options_cache'];
}

/**
 * Clear the options cache. Useful for testing.
 */
function wldelay_clear_options_cache() {
    unset( $GLOBALS['wldelay_options_cache'] );
}

// Auto-clear cache when option is updated
add_action( 'update_option_wldelay_options', 'wldelay_clear_options_cache' );
add_action( 'add_option_wldelay_options', 'wldelay_clear_options_cache' );
add_action( 'delete_option_wldelay_options', 'wldelay_clear_options_cache' );

/**
 * Calculate the delay value based on settings
 *
 * @param int $failure_count Number of previous failed attempts (for progressive delay)
 * @return int Delay in seconds
 */
function wldelay_get_delay_value( $failure_count = 0 ) {

    $options = wldelay_get_options();

    // Get base delay (random or fixed)
    $useRandomDelay = ! empty( $options['wldelay_delay_random'] );
    if( $useRandomDelay ) {
        $min = isset( $options['wldelay_delay_random_min'] ) ? (int) $options['wldelay_delay_random_min'] : LDS_Settings::_DEFAULT_RANDOM_MIN;
        $max = isset( $options['wldelay_delay_random_max'] ) ? (int) $options['wldelay_delay_random_max'] : LDS_Settings::_DEFAULT_RANDOM_MAX;
        $base_delay = wp_rand( $min, $max );
    } else {
        $base_delay = isset( $options['wldelay_delay'] ) ? (int) $options['wldelay_delay'] : LDS_Settings::_DEFAULT_DELAY_IN_SECONDS;
    }

    // Apply progressive delay if enabled
    $progressive_enabled = ! empty( $options['wldelay_progressive_enabled'] );
    if ( $progressive_enabled && $failure_count > 0 ) {
        $increment = isset( $options['wldelay_progressive_increment'] )
            ? (int) $options['wldelay_progressive_increment']
            : LDS_Settings::_DEFAULT_PROGRESSIVE_INCREMENT;
        $max_delay = isset( $options['wldelay_progressive_max'] )
            ? (int) $options['wldelay_progressive_max']
            : LDS_Settings::_DEFAULT_PROGRESSIVE_MAX;

        $progressive_delay = $base_delay + ( $increment * $failure_count );
        $delay = min( $progressive_delay, $max_delay );
    } else {
        $delay = $base_delay;
    }

    return $delay;
}

/**
 * Cloudflare edge IP ranges, bundled statically so validating the
 * CF-Connecting-IP header never requires an external request.
 *
 * Source: https://www.cloudflare.com/ips/ — these ranges change very rarely;
 * override or extend with the `wldelay_cloudflare_ip_ranges` filter if they
 * drift before a plugin update catches up.
 *
 * @return string[] CIDR ranges (IPv4 and IPv6).
 */
function wldelay_get_cloudflare_ip_ranges() {
    $ranges = array(
        // IPv4.
        '173.245.48.0/20',
        '103.21.244.0/22',
        '103.22.200.0/22',
        '103.31.4.0/22',
        '141.101.64.0/18',
        '108.162.192.0/18',
        '190.93.240.0/20',
        '188.114.96.0/20',
        '197.234.240.0/22',
        '198.41.128.0/17',
        '162.158.0.0/15',
        '104.16.0.0/13',
        '104.24.0.0/14',
        '172.64.0.0/13',
        '131.0.72.0/22',
        // IPv6.
        '2400:cb00::/32',
        '2606:4700::/32',
        '2803:f800::/32',
        '2405:b500::/32',
        '2405:8100::/32',
        '2a06:98c0::/29',
        '2c0f:f248::/32',
    );

    /**
     * Filters the Cloudflare IP ranges used to validate CF-Connecting-IP.
     *
     * @param string[] $ranges CIDR ranges.
     */
    return apply_filters( 'wldelay_cloudflare_ip_ranges', $ranges );
}

/**
 * Whether the TCP peer (REMOTE_ADDR) is a Cloudflare edge server.
 *
 * @param string $remote_addr The REMOTE_ADDR value.
 * @return bool
 */
function wldelay_is_cloudflare_remote_addr( $remote_addr ) {
    if ( '' === $remote_addr || false === filter_var( $remote_addr, FILTER_VALIDATE_IP ) ) {
        return false;
    }

    foreach ( wldelay_get_cloudflare_ip_ranges() as $range ) {
        if ( wldelay_ip_in_range( $remote_addr, $range ) ) {
            return true;
        }
    }

    return false;
}

function wldelay_get_client_ip() {
    $options = get_option( WLDELAY_OPTION_NAME, [] );
    $trust_proxy = ! empty( $options['wldelay_trust_proxy_headers'] );

    $remote_addr = isset( $_SERVER['REMOTE_ADDR'] ) ? trim( $_SERVER['REMOTE_ADDR'] ) : '';
    $ip = '';

    // Only check proxy headers if explicitly trusted (they can be spoofed).
    if ( $trust_proxy ) {
        $candidates = array();

        // CF-Connecting-IP is only honored when the TCP peer really is a
        // Cloudflare edge — anyone can send the header, only Cloudflare can
        // send it from a Cloudflare IP. Most specific header, checked first.
        if ( isset( $_SERVER['HTTP_CF_CONNECTING_IP'] ) && wldelay_is_cloudflare_remote_addr( $remote_addr ) ) {
            $candidates[] = $_SERVER['HTTP_CF_CONNECTING_IP'];
        }

        // Sucuri firewall.
        if ( isset( $_SERVER['HTTP_X_SUCURI_CLIENTIP'] ) ) {
            $candidates[] = $_SERVER['HTTP_X_SUCURI_CLIENTIP'];
        }

        if ( isset( $_SERVER['HTTP_CLIENT_IP'] ) ) {
            $candidates[] = $_SERVER['HTTP_CLIENT_IP'];
        }

        // nginx reverse-proxy convention.
        if ( isset( $_SERVER['HTTP_X_REAL_IP'] ) ) {
            $candidates[] = $_SERVER['HTTP_X_REAL_IP'];
        }

        if ( isset( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
            // Take the first IP (client IP) from the chain.
            $candidates[] = explode( ',', $_SERVER['HTTP_X_FORWARDED_FOR'] )[0];
        }

        foreach ( $candidates as $candidate ) {
            $candidate = trim( $candidate );
            // A garbage header value falls through to the next candidate (and
            // ultimately REMOTE_ADDR) instead of poisoning lockout keys.
            if ( '' !== $candidate && false !== filter_var( $candidate, FILTER_VALIDATE_IP ) ) {
                $ip = $candidate;
                break;
            }
        }
    }

    // Fall back to REMOTE_ADDR (the actual TCP connection IP)
    if ( empty( $ip ) && '' !== $remote_addr ) {
        $ip = $remote_addr;
    }

    return sanitize_text_field( trim( $ip ) );
}

/**
 * Detect proxy/CDN forwarding headers on the current request.
 *
 * @return string[] Human-readable names of the headers present.
 */
function wldelay_detect_proxy_headers() {
    $known = array(
        'HTTP_CF_CONNECTING_IP'  => 'CF-Connecting-IP',
        'HTTP_X_SUCURI_CLIENTIP' => 'X-Sucuri-ClientIP',
        'HTTP_X_REAL_IP'         => 'X-Real-IP',
        'HTTP_X_FORWARDED_FOR'   => 'X-Forwarded-For',
        'HTTP_CLIENT_IP'         => 'Client-IP',
    );

    $present = array();
    foreach ( $known as $key => $label ) {
        if ( ! empty( $_SERVER[ $key ] ) ) {
            $present[] = $label;
        }
    }

    return $present;
}

/**
 * Proxy-configuration health status for the settings page.
 *
 * Mass lockouts on Cloudflare sites are the most painful misconfiguration
 * this plugin can cause: with proxy trust disabled every visitor shares the
 * CDN's IP, so one attacker locks out everyone. The inverse is just as bad —
 * trust enabled on a direct-connection site lets attackers spoof any IP.
 * This check surfaces both, next to the security score.
 *
 * @return array {
 *     @type string   $status  'misconfigured-cdn' | 'spoofable' | 'ok' | 'none'.
 *     @type string[] $headers Proxy headers present on the current request.
 * }
 */
function wldelay_get_proxy_health_status() {
    $options     = wldelay_get_options();
    $trust_proxy = ! empty( $options['wldelay_trust_proxy_headers'] );
    $headers     = wldelay_detect_proxy_headers();

    if ( ! $trust_proxy && ! empty( $headers ) ) {
        $status = 'misconfigured-cdn';
    } elseif ( $trust_proxy && empty( $headers ) ) {
        $status = 'spoofable';
    } elseif ( $trust_proxy ) {
        $status = 'ok';
    } else {
        $status = 'none';
    }

    return array(
        'status'  => $status,
        'headers' => $headers,
    );
}

/**
 * Get lockout attempt strategy.
 *
 * @param array|null $options Optional options array.
 * @return string Strategy: ip or ip_username.
 */
function wldelay_get_lockout_attempt_strategy( $options = null ) {
    if ( $options === null ) {
        $options = wldelay_get_options();
    }

    $strategy = isset( $options['wldelay_lockout_attempt_strategy'] )
        ? (string) $options['wldelay_lockout_attempt_strategy']
        : LDS_Settings::_DEFAULT_LOCKOUT_ATTEMPT_STRATEGY;

    if ( ! in_array( $strategy, array( 'ip', 'ip_username' ), true ) ) {
        $strategy = LDS_Settings::_DEFAULT_LOCKOUT_ATTEMPT_STRATEGY;
    }

    return $strategy;
}

/**
 * Normalize username for attempt tracking keys.
 *
 * Applies the default WordPress normalization (lowercase + sanitize_user),
 * then passes the result through `wldelay_normalize_username` filter so
 * plugins with custom auth backends (LDAP, email-as-login) can override.
 *
 * @param string $username Username input.
 * @return string Normalized username.
 */
function wldelay_normalize_username( $username ) {
    $username = is_string( $username ) ? trim( $username ) : '';
    if ( $username === '' ) {
        return '';
    }

    $normalized = strtolower( sanitize_user( wp_unslash( $username ), true ) );

    /**
     * Filter the normalized username used for lockout and failure tracking.
     *
     * Allows plugins with custom authentication backends (LDAP, email-based
     * login, SSO) to map login input to a canonical identifier before it
     * enters the lockout/failure tracking key.
     *
     * Returning an empty string is treated as invalid and falls back to the
     * default normalization. Callbacks must be idempotent — the filter fires
     * exactly once per raw input, but callers must not depend on that changing.
     *
     * @param string $normalized The default-normalized username.
     * @param string $username   The raw username input before normalization.
     */
    $filtered = (string) apply_filters( 'wldelay_normalize_username', $normalized, $username );

    return $filtered !== '' ? $filtered : $normalized;
}

/**
 * Get the identifier string for failure/lockout tracking.
 *
 * @param string $ip IP address.
 * @param string $username Username attempted.
 * @param array|null $options Optional options array.
 * @return string Identifier string used for transient keys.
 */
function wldelay_get_attempt_identifier( $ip, $username = '', $options = null ) {
    $strategy = wldelay_get_lockout_attempt_strategy( $options );

    if ( $strategy === 'ip_username' && $username !== '' ) {
        return $ip . '|' . $username;
    }

    return $ip;
}

/**
 * Get transient key used for failed-attempt counter.
 *
 * @param string $ip IP address.
 * @param string $username Username attempted.
 * @param array|null $options Optional options array.
 * @return string Transient key.
 */
function wldelay_get_failure_transient_key( $ip, $username = '', $options = null ) {
    return 'wldelay_fails_' . md5( wldelay_get_attempt_identifier( $ip, $username, $options ) );
}

/**
 * Get transient key used for lockouts.
 *
 * @param string $ip IP address.
 * @param string $username Username attempted.
 * @param array|null $options Optional options array.
 * @return string Transient key.
 */
function wldelay_get_lockout_transient_key( $ip, $username = '', $options = null ) {
    return 'wldelay_lockout_' . md5( wldelay_get_attempt_identifier( $ip, $username, $options ) );
}

/**
 * Get the effective username used for persistent-store lockout keys.
 *
 * Mirrors the transient keying: under the IP-only strategy the username is
 * dropped so the transient fast-path and the durable store agree on identity.
 *
 * @param string     $username Username attempted.
 * @param array|null $options  Optional options array.
 * @return string Effective username ('' under the IP-only strategy).
 */
function wldelay_get_effective_lockout_username( $username = '', $options = null ) {
    $strategy = wldelay_get_lockout_attempt_strategy( $options );

    return ( $strategy === 'ip_username' ) ? (string) $username : '';
}

/**
 * Get username from current login request.
 *
 * @return string Normalized username or empty string.
 */
function wldelay_get_requested_login_username() {
    if ( isset( $_POST['log'] ) ) {
        return wldelay_normalize_username( $_POST['log'] );
    }

    return '';
}

/**
 * Get lockout duration in seconds.
 *
 * @param array|null $options Optional options array.
 * @return int Duration in seconds.
 */
function wldelay_get_lockout_duration_seconds( $options = null ) {
    if ( $options === null ) {
        $options = wldelay_get_options();
    }

    $duration_minutes = isset( $options['wldelay_lockout_duration'] )
        ? (int) $options['wldelay_lockout_duration']
        : LDS_Settings::_DEFAULT_LOCKOUT_DURATION;

    $duration_minutes = max( 1, min( 1440, $duration_minutes ) );

    return $duration_minutes * MINUTE_IN_SECONDS;
}

/**
 * Get remaining lockout time in seconds.
 *
 * @param string|null $ip Optional IP. Defaults to current client IP.
 * @param string $username Optional username for IP+username strategy.
 * @return int Remaining seconds. 0 if not locked.
 */
function wldelay_get_lockout_remaining_seconds( $ip = null, $username = '' ) {
    if ( $ip === null ) {
        $ip = wldelay_get_client_ip();
    }
    if ( empty( $ip ) ) {
        return 0;
    }

    $transient_key = wldelay_get_lockout_transient_key( $ip, $username );
    $locked_at = get_transient( $transient_key );
    if ( false === $locked_at ) {
        // Durable fallback (F-2-1): derive the countdown from the persistent
        // store when the transient has been evicted. Called through the
        // interface so any filtered backend supplies the countdown too.
        $remaining = wldelay_get_persistence_store()->get_remaining_seconds(
            $ip,
            wldelay_get_effective_lockout_username( $username ),
            'login'
        );

        return max( 0, (int) $remaining );
    }

    $lockout_duration = wldelay_get_lockout_duration_seconds();
    if ( is_numeric( $locked_at ) ) {
        $remaining = $lockout_duration - ( time() - (int) $locked_at );
        return max( 1, (int) $remaining );
    }

    // Fallback for unexpected transient values.
    return $lockout_duration;
}

/**
 * Build lockout error message including a countdown when available.
 *
 * @param string|null $ip Optional IP.
 * @param string $username Optional username.
 * @return string Error message.
 */
function wldelay_get_lockout_error_message( $ip = null, $username = '' ) {
    $remaining = wldelay_get_lockout_remaining_seconds( $ip, $username );
    if ( $remaining > 0 ) {
        $time_text = human_time_diff( time(), time() + $remaining );
        return sprintf(
            /* translators: %s: remaining lockout duration, e.g. "2 minutes" */
            __( 'Too many failed login attempts. Please try again in %s.', 'login-delay-shield' ),
            $time_text
        );
    }

    return __( 'Too many failed login attempts. Please try again later.', 'login-delay-shield' );
}

/**
 * Check if the current request is an XMLRPC request
 *
 * @return bool True if this is an XMLRPC request
 */
function wldelay_is_xmlrpc_request() {
    // Check WordPress constant first (set early in xmlrpc.php)
    if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
        return true;
    }

    // Fallback: check the request URI
    if ( isset( $_SERVER['REQUEST_URI'] ) && strpos( $_SERVER['REQUEST_URI'], 'xmlrpc.php' ) !== false ) {
        return true;
    }

    return false;
}

/**
 * Check if the current request is a REST API request.
 *
 * @return bool True if this is a REST request.
 */
function wldelay_is_rest_request() {
    if ( defined( 'REST_REQUEST' ) && REST_REQUEST ) {
        return true;
    }

    if ( isset( $_SERVER['REQUEST_URI'] ) && strpos( $_SERVER['REQUEST_URI'], '/wp-json/' ) !== false ) {
        return true;
    }

    return false;
}

/**
 * Get username from PHP auth headers.
 *
 * @return string Normalized username or empty string.
 */
function wldelay_get_php_auth_username() {
    if ( isset( $_SERVER['PHP_AUTH_USER'] ) ) {
        return wldelay_normalize_username( wp_unslash( $_SERVER['PHP_AUTH_USER'] ) );
    }

    return '';
}

/**
 * Detect whether current request is attempting application-password auth.
 *
 * @return bool True when PHP auth headers are present.
 */
function wldelay_is_application_password_attempt() {
    return isset( $_SERVER['PHP_AUTH_USER'] ) && isset( $_SERVER['PHP_AUTH_PW'] );
}

/**
 * Get the source of the login attempt.
 *
 * @return string Source key: xmlrpc, rest, or wp-login.
 */
function wldelay_get_login_source() {
    if ( wldelay_is_xmlrpc_request() ) {
        return 'xmlrpc';
    }

    if ( wldelay_is_rest_request() ) {
        return 'rest';
    }

    return 'wp-login';
}

/**
 * Get display label for a login source value.
 *
 * @param string $source Source key.
 * @return string Human-readable label.
 */
function wldelay_get_login_source_label( $source ) {
    switch ( $source ) {
        case 'xmlrpc':
            return 'XML-RPC';
        case 'rest':
            return __( 'REST API', 'login-delay-shield' );
        case 'application-password':
            return __( 'Application Password', 'login-delay-shield' );
        case 'password-reset':
            return __( 'Password Reset', 'login-delay-shield' );
        case 'wp-login':
        default:
            return __( 'Login', 'login-delay-shield' );
    }
}


/**
 * Detect known 2FA plugin provider from active plugin list.
 *
 * @param array<int,string> $active_plugins Active plugin basenames.
 * @return string Provider key or empty string when not detected.
 */
function wldelay_detect_2fa_provider( $active_plugins ) {
    if ( ! is_array( $active_plugins ) ) {
        return '';
    }

    $active = array();
    foreach ( $active_plugins as $plugin_file ) {
        if ( is_scalar( $plugin_file ) ) {
            $active[] = strtolower( (string) $plugin_file );
        }
    }

    $providers = array(
        'two-factor' => array(
            'two-factor/two-factor.php',
        ),
        'wp-2fa' => array(
            'wp-2fa/wp-2fa.php',
        ),
        'mini-orange' => array(
            'miniorange-2-factor-authentication/miniorange_2_factor_settings.php',
        ),
        'google-authenticator' => array(
            'google-authenticator/google-authenticator.php',
        ),
    );

    /**
     * Filter the list of known 2FA plugin providers.
     *
     * Each key is a provider slug and each value is an array of plugin basenames
     * (e.g. 'my-2fa/my-2fa.php') that map to that provider.
     *
     * @param array<string,array<int,string>> $providers Provider map.
     */
    $providers = apply_filters( 'wldelay_2fa_providers', $providers );

    if ( ! is_array( $providers ) ) {
        return '';
    }

    foreach ( $providers as $provider => $candidates ) {
        if ( ! is_string( $provider ) || ! is_array( $candidates ) ) {
            continue;
        }
        foreach ( $candidates as $plugin_file ) {
            if ( is_string( $plugin_file ) && in_array( strtolower( $plugin_file ), $active, true ) ) {
                return $provider;
            }
        }
    }

    return '';
}

/**
 * Build lightweight 2FA health status for admin UI.
 *
 * @param array<int,string>|null $active_plugins Optional active plugin basenames override (for tests).
 * @return array<string,mixed>
 */
function wldelay_get_2fa_health_status( $active_plugins = null ) {
    if ( ! is_array( $active_plugins ) ) {
        $active_plugins = (array) get_option( 'active_plugins', array() );

        if ( is_multisite() ) {
            $sitewide = (array) get_site_option( 'active_sitewide_plugins', array() );
            $active_plugins = array_merge( $active_plugins, array_keys( $sitewide ) );
        }
    }

    $provider = wldelay_detect_2fa_provider( $active_plugins );
    $coverage = wldelay_get_2fa_privileged_user_coverage( $provider );

    return array(
        'enabled'         => $provider !== '',
        'provider'        => $provider,
        'provider_label'  => wldelay_get_2fa_provider_label( $provider ),
        'coverage'        => $coverage,
    );
}

/**
 * Get privileged user 2FA coverage data for a detected provider.
 *
 * The returned array is safe for admin UI consumption even when the provider
 * does not expose coverage details. Third parties can add support for custom
 * providers through the `wldelay_2fa_coverage_checkers` filter.
 *
 * @param string $provider Provider key.
 * @return array{supported:bool,privileged_total:int,protected:int,unprotected:int,unknown:int}
 */
function wldelay_get_2fa_privileged_user_coverage( $provider ) {
    $empty = array(
        'supported'        => false,
        'privileged_total' => 0,
        'protected'        => 0,
        'unprotected'      => 0,
        'unknown'          => 0,
    );

    if ( ! is_string( $provider ) || '' === $provider ) {
        return $empty;
    }

    $checkers = array(
        'two-factor' => 'wldelay_get_two_factor_privileged_user_coverage',
    );

    /**
     * Filter provider-specific privileged-user 2FA coverage callbacks.
     *
     * Each callback should return an array with keys: supported,
     * privileged_total, protected, unprotected, unknown.
     *
     * @param array<string,callable|string> $checkers Coverage checker map.
     */
    $checkers = apply_filters( 'wldelay_2fa_coverage_checkers', $checkers );

    if ( ! is_array( $checkers ) || empty( $checkers[ $provider ] ) || ! is_callable( $checkers[ $provider ] ) ) {
        return $empty;
    }

    $coverage = call_user_func( $checkers[ $provider ] );

    if ( ! is_array( $coverage ) ) {
        return $empty;
    }

    return array(
        'supported'        => ! empty( $coverage['supported'] ),
        'privileged_total' => max( 0, (int) ( $coverage['privileged_total'] ?? 0 ) ),
        'protected'        => max( 0, (int) ( $coverage['protected'] ?? 0 ) ),
        'unprotected'      => max( 0, (int) ( $coverage['unprotected'] ?? 0 ) ),
        'unknown'          => max( 0, (int) ( $coverage['unknown'] ?? 0 ) ),
    );
}

/**
 * Get coverage details for privileged users when the Two-Factor plugin is active.
 *
 * @return array{supported:bool,privileged_total:int,protected:int,unprotected:int,unknown:int}
 */
function wldelay_get_two_factor_privileged_user_coverage() {
    $user_ids = get_users(
        array(
            'role__in'    => array( 'administrator' ),
            'fields'      => 'ID',
            'number'      => -1,
            'count_total' => false,
        )
    );

    $coverage = array(
        'supported'        => true,
        'privileged_total' => count( $user_ids ),
        'protected'        => 0,
        'unprotected'      => 0,
        'unknown'          => 0,
    );

    foreach ( $user_ids as $user_id ) {
        $user_id = (int) $user_id;

        if ( $user_id <= 0 ) {
            continue;
        }

        if ( wldelay_is_two_factor_enabled_for_user( $user_id ) ) {
            $coverage['protected']++;
            continue;
        }

        $coverage['unprotected']++;
    }

    return $coverage;
}

/**
 * Determine whether the Two-Factor plugin appears enabled for a specific user.
 *
 * @param int $user_id User ID.
 * @return bool
 */
function wldelay_is_two_factor_enabled_for_user( $user_id ) {
    $user_id = (int) $user_id;

    if ( $user_id <= 0 ) {
        return false;
    }

    if ( class_exists( 'Two_Factor_Core' ) && method_exists( 'Two_Factor_Core', 'get_enabled_providers_for_user' ) ) {
        $user = get_userdata( $user_id );

        if ( $user instanceof WP_User ) {
            $providers = Two_Factor_Core::get_enabled_providers_for_user( $user );

            return is_array( $providers ) && ! empty( $providers );
        }
    }

    $enabled = get_user_meta( $user_id, '_two_factor_enabled_providers', true );

    if ( is_array( $enabled ) ) {
        return ! empty( array_filter( $enabled ) );
    }

    return is_string( $enabled ) && '' !== trim( $enabled );
}

/**
 * Get a human-readable label for a detected 2FA provider key.
 *
 * @param string $provider Provider key.
 * @return string Label for admin UI.
 */
function wldelay_get_2fa_provider_label( $provider ) {
    switch ( $provider ) {
        case 'two-factor':
            return __( 'Two-Factor', 'login-delay-shield' );
        case 'wp-2fa':
            return __( 'WP 2FA', 'login-delay-shield' );
        case 'mini-orange':
            return __( 'miniOrange 2-Factor Authentication', 'login-delay-shield' );
        case 'google-authenticator':
            return __( 'Google Authenticator', 'login-delay-shield' );
        default:
            return '';
    }
}

/**
 * Check if an IP address is within a CIDR range
 *
 * @param string $ip The IP address to check
 * @param string $range The CIDR range (e.g., 192.168.1.0/24)
 * @return bool True if IP is in range
 */
function wldelay_ip_in_range( $ip, $range ) {
    // Check for CIDR notation
    if ( strpos( $range, '/' ) === false ) {
        // Exact match
        return $ip === $range;
    }

    list( $range_ip, $netmask ) = explode( '/', $range, 2 );
    $netmask = (int) $netmask;

    // IPv4
    if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) &&
         filter_var( $range_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
        if ( $netmask < 0 || $netmask > 32 ) {
            return false;
        }
        $ip_long = ip2long( $ip );
        $range_long = ip2long( $range_ip );
        $mask = -1 << ( 32 - $netmask );
        return ( $ip_long & $mask ) === ( $range_long & $mask );
    }

    // IPv6
    if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) &&
         filter_var( $range_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
        if ( $netmask < 0 || $netmask > 128 ) {
            return false;
        }
        $ip_bin = inet_pton( $ip );
        $range_bin = inet_pton( $range_ip );

        // Build a 128-bit (16-byte) binary mask for IPv6 CIDR comparison.
        // Full 0xff bytes cover complete octets ($netmask / 8).
        // For any partial octet, left-shift 0xff by (8 - remaining bits) to
        // zero out the host bits within that byte (e.g. /68 → 4 remainder bits
        // → 0xff << 4 = 0xf0). The mask is then zero-padded to 16 bytes so
        // bitwise AND with inet_pton() output isolates the network prefix.
        $mask = str_repeat( "\xff", (int) floor( $netmask / 8 ) );
        if ( $netmask % 8 ) {
            $mask .= chr( 0xff << ( 8 - ( $netmask % 8 ) ) );
        }
        $mask = str_pad( $mask, 16, "\x00" );

        return ( $ip_bin & $mask ) === ( $range_bin & $mask );
    }

    return false;
}

/**
 * Parse the whitelist into exact IPs and CIDR ranges.
 *
 * Result is cached per-request in $GLOBALS and invalidated when options change.
 *
 * @return array{exact:array<string,true>,cidr:array<int,string>}
 */
function wldelay_get_parsed_whitelist() {
    if ( isset( $GLOBALS['wldelay_parsed_whitelist'] ) ) {
        return $GLOBALS['wldelay_parsed_whitelist'];
    }

    $options = wldelay_get_options();
    $whitelist = isset( $options['wldelay_whitelist_ips'] ) ? $options['wldelay_whitelist_ips'] : '';

    $exact = array();
    $cidr  = array();

    if ( $whitelist !== '' ) {
        foreach ( explode( "\n", $whitelist ) as $line ) {
            $line = trim( $line );
            if ( $line === '' ) {
                continue;
            }
            if ( strpos( $line, '/' ) !== false ) {
                $cidr[] = $line;
            } else {
                $exact[ $line ] = true;
            }
        }
    }

    $GLOBALS['wldelay_parsed_whitelist'] = array( 'exact' => $exact, 'cidr' => $cidr );

    return $GLOBALS['wldelay_parsed_whitelist'];
}

/**
 * Clear the parsed whitelist cache.
 */
function wldelay_clear_whitelist_cache() {
    unset( $GLOBALS['wldelay_parsed_whitelist'] );
}

add_action( 'update_option_wldelay_options', 'wldelay_clear_whitelist_cache' );
add_action( 'add_option_wldelay_options', 'wldelay_clear_whitelist_cache' );
add_action( 'delete_option_wldelay_options', 'wldelay_clear_whitelist_cache' );

/**
 * Check if the client IP is whitelisted
 *
 * Uses a parsed cache: exact IPs are checked via hash lookup (O(1)),
 * CIDR ranges are checked only if the exact lookup misses.
 *
 * @param string|null $ip Optional IP to check. Defaults to client IP.
 * @return bool True if IP is whitelisted
 */
/**
 * Check whether safe mode is active.
 *
 * Safe mode is an emergency kill switch for admins locked out of their own
 * site: defining `WLDELAY_SAFE_MODE` as true in wp-config.php disables every
 * delay, lockout, and tracking path (login, XML-RPC, REST, application
 * passwords, password reset) — the plugin behaves as if every IP were
 * whitelisted. Mirrors the WLDELAY_DISABLE_CUSTOM_LOGIN recovery pattern.
 *
 * A persistent admin notice is shown while safe mode is active so the
 * disabled protection cannot go unnoticed (see wldelay_safe_mode_admin_notice).
 *
 * @return bool True when safe mode is active.
 */
function wldelay_is_safe_mode() {
    $safe_mode = defined( 'WLDELAY_SAFE_MODE' ) && WLDELAY_SAFE_MODE;

    if ( defined( 'WP_TESTS_DOMAIN' ) ) {
        // Test-only override, ignored in production (same pattern as the
        // WP_TESTS_DOMAIN exit guards): constants cannot be undefined, so the
        // integration suite toggles safe mode through this filter instead.
        $safe_mode = (bool) apply_filters( 'wldelay_test_safe_mode', $safe_mode );
    }

    return $safe_mode;
}

/**
 * Warn administrators while safe mode is active.
 *
 * Protection silently disabled is worse than no protection: an admin who
 * defines WLDELAY_SAFE_MODE to recover access and forgets to remove it would
 * otherwise run unprotected indefinitely. Intentionally not dismissible.
 */
function wldelay_safe_mode_admin_notice() {
    if ( ! wldelay_is_safe_mode() || ! current_user_can( 'manage_options' ) ) {
        return;
    }

    printf(
        '<div class="notice notice-warning"><p><strong>%s</strong> %s</p></div>',
        esc_html__( 'Login Delay Shield safe mode is active.', 'login-delay-shield' ),
        sprintf(
            /* translators: 1: WLDELAY_SAFE_MODE constant name, 2: wp-config.php file name. */
            esc_html__( 'All delays and lockouts are disabled. Remove the %1$s constant from %2$s to re-enable protection.', 'login-delay-shield' ),
            '<code>WLDELAY_SAFE_MODE</code>',
            '<code>wp-config.php</code>'
        )
    );
}
add_action( 'admin_notices', 'wldelay_safe_mode_admin_notice' );

function wldelay_is_ip_whitelisted( $ip = null ) {
    $options = wldelay_get_options();

    if ( empty( $options['wldelay_whitelist_enabled'] ) ) {
        return false;
    }

    $whitelist = isset( $options['wldelay_whitelist_ips'] ) ? $options['wldelay_whitelist_ips'] : '';
    if ( empty( $whitelist ) ) {
        return false;
    }

    if ( $ip === null ) {
        $ip = wldelay_get_client_ip();
    }
    if ( empty( $ip ) ) {
        return false;
    }

    $parsed = wldelay_get_parsed_whitelist();

    if ( isset( $parsed['exact'][ $ip ] ) ) {
        return true;
    }

    foreach ( $parsed['cidr'] as $range ) {
        if ( wldelay_ip_in_range( $ip, $range ) ) {
            return true;
        }
    }

    return false;
}

/**
 * Check if the current IP/username is locked.
 *
 * @param string|null $ip Optional IP. Defaults to current client IP.
 * @param string $username Optional username for IP+username strategy.
 * @return bool True if locked.
 */
function wldelay_is_ip_locked( $ip = null, $username = '' ) {
    if ( $ip === null ) {
        $ip = wldelay_get_client_ip();
    }

    if ( empty( $ip ) ) {
        return false;
    }

    $transient_key = wldelay_get_lockout_transient_key( $ip, $username );

    // Hot-path fast read: the transient (object cache) answers most requests.
    if ( get_transient( $transient_key ) !== false ) {
        return true;
    }

    // Durable fallback (F-2-1): the transient may have been evicted while the
    // lockout is still in force — the DB-backed store is authoritative.
    return wldelay_get_persistence_store()->is_locked(
        $ip,
        wldelay_get_effective_lockout_username( $username ),
        'login'
    );
}

/**
 * Get the current failure count for an IP address
 *
 * @param string|null $ip Optional IP to check. Defaults to client IP.
 * @param string $username Optional username for IP+username strategy.
 * @return int Number of failed attempts
 */
function wldelay_get_failure_count( $ip = null, $username = '' ) {
    if ( $ip === null ) {
        $ip = wldelay_get_client_ip();
    }
    if ( empty( $ip ) ) {
        return 0;
    }

    $transient_key = wldelay_get_failure_transient_key( $ip, $username );
    $failed_attempts = get_transient( $transient_key );

    return ( false === $failed_attempts ) ? 0 : (int) $failed_attempts;
}

/**
 * Lock a specific IP/username combination based on configured strategy.
 *
 * @param string $ip IP address.
 * @param string $username Optional username for IP+username strategy.
 * @param string|null $source Optional source of the lockout event.
 */
function wldelay_lock_ip( $ip, $username = '', $source = null ) {
    $options = wldelay_get_options();
    $lockout_duration = wldelay_get_lockout_duration_seconds( $options );
    $transient_key = wldelay_get_lockout_transient_key( $ip, $username, $options );
    set_transient( $transient_key, time(), $lockout_duration );
    $registered = wldelay_register_transient_key( $transient_key, time() + $lockout_duration );

    // Persist to the durable store (F-2-1) so the lockout survives transient /
    // object-cache eviction and can be enumerated. The transient above remains
    // the hot-path fast read; this is the authoritative fallback.
    $persisted = wldelay_get_persistence_store()->add_lockout(
        $ip,
        wldelay_get_effective_lockout_username( $username, $options ),
        $lockout_duration,
        'login',
        $source,
        $transient_key
    );

    if ( ! $persisted ) {
        wldelay_note_persistence_failure( $ip, 'login' );

        // When the durable write AND the registry write both failed (a DB
        // outage while an external object cache still accepted the transient),
        // the lockout exists only as a cache-only transient with no record in
        // SQL or the durable table — recovery could never discover or clear it,
        // so it would strand the user until the transient expires. Fail fully
        // open: drop the orphan rather than create an unrecoverable lockout
        // (Codex round-3 review).
        if ( ! $registered ) {
            delete_transient( $transient_key );
        }
    }

    wldelay_write_fail2ban_log( 'lockout', $ip, $username, $source );
}

/**
 * Surface a durable lockout-write failure (F-2-1).
 *
 * When the persistent store cannot record a lockout (missing table mid-upgrade,
 * or a DB error), the lockout is protected only by the transient fast-path and
 * will NOT survive object-cache eviction. Both reviewers flagged that this
 * degradation was silent.
 *
 * Policy is fail-open by design: the transient lockout still applies and login
 * is NOT blocked on a persistence error — failing closed would lock out
 * legitimate users during any DB hiccup. This helper makes the degraded state
 * observable without changing that policy: it fires an action so monitoring can
 * alert, and ALWAYS writes an operator log line (not gated behind WP_DEBUG, so
 * production sites — where WP_DEBUG is normally off — still surface the degraded
 * security state). The log is rate-limited to one line per type per 5 minutes so
 * a sustained DB/store outage cannot flood the error log. Whether to adopt a
 * fail-closed policy instead is a security-vs-availability decision left to the
 * site owner.
 *
 * @param string $ip   IP address whose durable lockout write failed.
 * @param string $type Lockout type ('login' or 'password-reset').
 */
function wldelay_note_persistence_failure( $ip, $type ) {
    /**
     * Fires when a lockout could not be written to the durable store.
     *
     * @param string $ip   IP address whose durable lockout write failed.
     * @param string $type Lockout type ('login' or 'password-reset').
     */
    do_action( 'wldelay_persistence_write_failed', $ip, $type );

    // Rate-limit the operator log to one line per type per 5 minutes. The guard
    // is best-effort: if the transient store is itself the failure, set_transient
    // may not stick and we log on every failure — acceptable during an outage.
    $throttle_key = 'wldelay_persist_fail_logged_' . md5( (string) $type );
    if ( false === get_transient( $throttle_key ) ) {
        set_transient( $throttle_key, 1, 5 * MINUTE_IN_SECONDS );

        error_log( // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
            sprintf(
                'WP Login Delay: durable lockout write failed for %s (%s); lockout is transient-only until the store recovers.',
                $ip,
                $type
            )
        );
    }
}

/**
 * Log a failed login attempt to the database
 *
 * @param string $ip IP address
 * @param string $username Username attempted
 * @param string $source Optional source of the attempt (wp-login, xmlrpc)
 */
function wldelay_log_failed_attempt( $ip, $username, $source = null ) {
    global $wpdb;

    if ( $source === null ) {
        $source = wldelay_get_login_source();
    }

    $table_name = wldelay_get_log_table_name();

    $wpdb->insert(
        $table_name,
        array(
            'ip_address'   => $ip,
            'username'     => $username,
            'attempted_at' => current_time( 'mysql' ),
            'source'       => $source,
        ),
        array( '%s', '%s', '%s', '%s' )
    );

    // Invalidate ONLY the cheap recent-attempts sub-cache so the new attempt
    // appears immediately (F-4-1). The expensive 7-day trends aggregate is
    // intentionally left to expire on its own TTL — invalidating it per attempt
    // is what thrashed the cache under brute-force load.
    delete_transient( WLDELAY_DASH_RECENT_CACHE );

    wldelay_write_fail2ban_log( 'failed login', $ip, $username, $source );
}

/**
 * Get recent failed login attempts
 *
 * @param int $limit Number of attempts to retrieve
 * @return array Array of failed attempt records
 */
function wldelay_get_recent_failed_attempts( $limit = 20 ) {
    return wldelay_get_login_log_attempts(
        array(
            'limit'  => $limit,
            'fields' => '*',
        )
    );
}

/**
 * Handle wp_login_failed action - logs all failed attempts
 *
 * @param string $username Username attempted
 */
function wldelay_on_login_failed( $username ) {
    // Log-only path: for wp-login the wp_authenticate_user handler owns tracking
    // and delay; other sources' own handlers do.
    // The pipeline gates safe-mode/whitelist/empty-IP internally.
    wldelay_process_failed_attempt(
        $username,
        wldelay_get_login_source(),
        array( 'track' => false, 'delay' => false, 'lockout' => false )
    );
}
add_action( 'wp_login_failed', 'wldelay_on_login_failed' );

/**
 * Block XMLRPC authentication if configured
 * This runs AFTER WordPress authentication (priority 99) to intercept successful logins
 *
 * @param null|WP_User|WP_Error $user
 * @param string $username
 * @param string $password
 * @return null|WP_User|WP_Error
 */
function wldelay_block_xmlrpc_auth( $user, $username, $password ) {
    // Only apply to XMLRPC requests
    if ( ! wldelay_is_xmlrpc_request() ) {
        return $user;
    }

    // Check if XMLRPC protection is enabled
    $options = get_option( WLDELAY_OPTION_NAME ); // Get fresh options, not cached

    // If XMLRPC protection is disabled, let the request through
    if ( empty( $options['wldelay_xmlrpc_enabled'] ) ) {
        return $user;
    }

    // Check if IP is whitelisted
    if ( wldelay_is_safe_mode() || wldelay_is_ip_whitelisted() ) {
        return $user;
    }

    $username = wldelay_normalize_username( $username );

    // Check if XMLRPC auth should be completely blocked
    if ( ! empty( $options['wldelay_xmlrpc_block'] ) ) {
        // Log the blocked attempt (only if this is a real auth attempt with username)
        if ( ! empty( $username ) ) {
            // Block branch: log + event only — the request is rejected outright,
            // so no counter, delay, or lockout lookup.
            wldelay_process_failed_attempt( $username, 'xmlrpc', array( 'track' => false, 'delay' => false, 'lockout' => false ) );
        }

        return new WP_Error(
            'wldelay_xmlrpc_blocked',
            __( 'XML-RPC authentication is disabled on this site.', 'login-delay-shield' )
        );
    }

    // Check if IP is locked out
    if ( ! empty( $options['wldelay_lockout_enabled'] ) && wldelay_is_ip_locked( null, $username ) ) {
        return new WP_Error(
            'wldelay_ip_locked',
            wldelay_get_lockout_error_message( null, $username )
        );
    }

    return $user;
}
// Run late (priority 99) to intercept after WordPress authentication
add_filter( 'authenticate', 'wldelay_block_xmlrpc_auth', 99, 3 );

/**
 * Handle REST authentication failures and lockout checks.
 *
 * @param null|WP_Error|WP_User $errors Existing REST auth result.
 * @return null|WP_Error|WP_User
 */
function wldelay_handle_rest_authentication( $errors ) {
    $options = wldelay_get_options();
    if ( empty( $options['wldelay_rest_enabled'] ) ) {
        return $errors;
    }

    if ( ! wldelay_is_rest_request() ) {
        return $errors;
    }

    if ( wldelay_is_safe_mode() || wldelay_is_ip_whitelisted() ) {
        return $errors;
    }

    // Let application-password protection own those attempts only when WordPress can actually process them.
    $app_passwords_available = function_exists( 'wp_is_application_passwords_available' )
        ? wp_is_application_passwords_available()
        : true;

    if ( ! empty( $options['wldelay_application_password_enabled'] ) && $app_passwords_available && wldelay_is_application_password_attempt() ) {
        return $errors;
    }

    $username = wldelay_get_php_auth_username();
    $ip       = wldelay_get_client_ip();

    if ( ! empty( $options['wldelay_lockout_enabled'] ) && wldelay_is_ip_locked( null, $username ) ) {
        return new WP_Error(
            'wldelay_ip_locked',
            wldelay_get_lockout_error_message( null, $username ),
            array( 'status' => 403 )
        );
    }

    if ( ! is_wp_error( $errors ) || empty( $ip ) ) {
        return $errors;
    }

    $pipeline = wldelay_process_failed_attempt( $username, 'rest' );
    sleep( $pipeline['delay'] );

    if ( $pipeline['failed_attempts'] > 0 && $pipeline['locked'] ) {
        return new WP_Error(
            'wldelay_ip_locked',
            wldelay_get_lockout_error_message( null, $username ),
            array( 'status' => 403 )
        );
    }

    return $errors;
}
add_filter( 'rest_authentication_errors', 'wldelay_handle_rest_authentication', 20 );

/**
 * Handle application-password authentication failures and lockout checks.
 *
 * @param null|WP_User|WP_Error $user Existing auth result.
 * @param string $username Username.
 * @param string $password Password.
 * @return null|WP_User|WP_Error
 */
function wldelay_handle_application_password_auth( $user, $username, $password ) {
    $options = wldelay_get_options();
    if ( empty( $options['wldelay_application_password_enabled'] ) ) {
        return $user;
    }

    if ( ! wldelay_is_application_password_attempt() ) {
        return $user;
    }

    if ( wldelay_is_safe_mode() || wldelay_is_ip_whitelisted() ) {
        return $user;
    }

    $username = wldelay_normalize_username( $username );
    if ( empty( $username ) ) {
        $username = wldelay_get_php_auth_username();
    }

    $ip = wldelay_get_client_ip();
    if ( empty( $ip ) ) {
        return $user;
    }

    if ( ! empty( $options['wldelay_lockout_enabled'] ) && wldelay_is_ip_locked( null, $username ) ) {
        return new WP_Error(
            'wldelay_ip_locked',
            wldelay_get_lockout_error_message( null, $username )
        );
    }

    if ( ! is_wp_error( $user ) ) {
        return $user;
    }

    $pipeline = wldelay_process_failed_attempt( $username, 'application-password' );
    sleep( $pipeline['delay'] );

    if ( $pipeline['failed_attempts'] > 0 && $pipeline['locked'] ) {
        return new WP_Error(
            'wldelay_ip_locked',
            wldelay_get_lockout_error_message( null, $username )
        );
    }

    return $user;
}
add_filter( 'authenticate', 'wldelay_handle_application_password_auth', 25, 3 );

/**
 * Get username from current password reset request.
 *
 * @return string Normalized username or empty string.
 */
function wldelay_get_password_reset_username() {
    if ( isset( $_POST['user_login'] ) ) {
        return wldelay_normalize_username( $_POST['user_login'] );
    }

    return '';
}

/**
 * Get transient key used for password reset failed-attempt counter.
 *
 * @param string $ip IP address.
 * @param string $username Username attempted.
 * @param array|null $options Optional options array.
 * @return string Transient key.
 */
function wldelay_get_password_reset_failure_transient_key( $ip, $username = '', $options = null ) {
    return 'wldelay_reset_fails_' . md5( wldelay_get_attempt_identifier( $ip, $username, $options ) );
}

/**
 * Get transient key used for password reset lockouts.
 *
 * @param string $ip IP address.
 * @param string $username Username attempted.
 * @param array|null $options Optional options array.
 * @return string Transient key.
 */
function wldelay_get_password_reset_lockout_transient_key( $ip, $username = '', $options = null ) {
    return 'wldelay_reset_lockout_' . md5( wldelay_get_attempt_identifier( $ip, $username, $options ) );
}

/**
 * Get the current password reset failure count.
 *
 * @param string|null $ip Optional IP. Defaults to current client IP.
 * @param string $username Optional username for IP+username strategy.
 * @return int Number of failed password reset attempts.
 */
function wldelay_get_password_reset_failure_count( $ip = null, $username = '' ) {
    if ( $ip === null ) {
        $ip = wldelay_get_client_ip();
    }
    if ( empty( $ip ) ) {
        return 0;
    }

    $transient_key = wldelay_get_password_reset_failure_transient_key( $ip, $username );
    $failed_attempts = get_transient( $transient_key );

    return ( false === $failed_attempts ) ? 0 : (int) $failed_attempts;
}

/**
 * Check if the current IP/username is locked for password reset submissions.
 *
 * @param string|null $ip Optional IP. Defaults to current client IP.
 * @param string $username Optional username for IP+username strategy.
 * @return bool True if locked.
 */
function wldelay_is_password_reset_locked( $ip = null, $username = '' ) {
    if ( $ip === null ) {
        $ip = wldelay_get_client_ip();
    }
    if ( empty( $ip ) ) {
        return false;
    }

    $transient_key = wldelay_get_password_reset_lockout_transient_key( $ip, $username );

    if ( get_transient( $transient_key ) !== false ) {
        return true;
    }

    // Durable fallback (F-2-1).
    return wldelay_get_persistence_store()->is_locked(
        $ip,
        wldelay_get_effective_lockout_username( $username ),
        'password-reset'
    );
}

/**
 * Lock a specific IP/username combination for password reset submissions.
 *
 * @param string $ip IP address.
 * @param string $username Optional username for IP+username strategy.
 */
function wldelay_lock_password_reset( $ip, $username = '' ) {
    $options = wldelay_get_options();
    $lockout_duration = wldelay_get_lockout_duration_seconds( $options );
    $transient_key = wldelay_get_password_reset_lockout_transient_key( $ip, $username, $options );
    set_transient( $transient_key, time(), $lockout_duration );
    $registered = wldelay_register_transient_key( $transient_key, time() + $lockout_duration );

    // Persist to the durable store (F-2-1) under the password-reset type so it
    // is isolated from login lockouts but equally survives cache eviction.
    $persisted = wldelay_get_persistence_store()->add_lockout(
        $ip,
        wldelay_get_effective_lockout_username( $username, $options ),
        $lockout_duration,
        'password-reset',
        'password-reset',
        $transient_key
    );

    if ( ! $persisted ) {
        wldelay_note_persistence_failure( $ip, 'password-reset' );

        // Both durable and registry writes failed: drop the orphaned cache-only
        // transient so recovery is never left with an undiscoverable lockout
        // (see wldelay_lock_ip; Codex round-3 review).
        if ( ! $registered ) {
            delete_transient( $transient_key );
        }
    }

    wldelay_write_fail2ban_log( 'lockout', $ip, $username, 'password-reset' );
}

/**
 * Get remaining password reset lockout time in seconds.
 *
 * @param string|null $ip Optional IP. Defaults to current client IP.
 * @param string $username Optional username.
 * @return int Remaining seconds. 0 if not locked.
 */
function wldelay_get_password_reset_lockout_remaining_seconds( $ip = null, $username = '' ) {
    if ( $ip === null ) {
        $ip = wldelay_get_client_ip();
    }
    if ( empty( $ip ) ) {
        return 0;
    }

    $transient_key = wldelay_get_password_reset_lockout_transient_key( $ip, $username );
    $locked_at = get_transient( $transient_key );
    if ( false === $locked_at ) {
        // Durable fallback (F-2-1). Called through the interface so any
        // filtered backend supplies the countdown too.
        $remaining = wldelay_get_persistence_store()->get_remaining_seconds(
            $ip,
            wldelay_get_effective_lockout_username( $username ),
            'password-reset'
        );

        return max( 0, (int) $remaining );
    }

    $lockout_duration = wldelay_get_lockout_duration_seconds();
    if ( is_numeric( $locked_at ) ) {
        $remaining = $lockout_duration - ( time() - (int) $locked_at );
        return max( 1, (int) $remaining );
    }

    return $lockout_duration;
}

/**
 * Build password reset lockout error message.
 *
 * @param string|null $ip Optional IP.
 * @param string $username Optional username.
 * @return string Error message.
 */
function wldelay_get_password_reset_lockout_error_message( $ip = null, $username = '' ) {
    $remaining = wldelay_get_password_reset_lockout_remaining_seconds( $ip, $username );
    if ( $remaining > 0 ) {
        $time_text = human_time_diff( time(), time() + $remaining );
        return sprintf(
            /* translators: %s: remaining lockout duration, e.g. "2 minutes" */
            __( 'Too many password reset attempts. Please try again in %s.', 'login-delay-shield' ),
            $time_text
        );
    }

    return __( 'Too many password reset attempts. Please try again later.', 'login-delay-shield' );
}

/**
 * Track a password reset attempt for reset-specific counters and lockout.
 *
 * @param string $username Username attempted.
 * @return int Updated failure count for the current reset tracking key. 0 if tracking is skipped.
 */
function wldelay_track_password_reset_attempt( $username ) {
    $ip = wldelay_get_client_ip();
    if ( empty( $ip ) ) {
        return 0;
    }

    $options = wldelay_get_options();
    $lockout_enabled = ! empty( $options['wldelay_lockout_enabled'] );
    $progressive_enabled = ! empty( $options['wldelay_progressive_enabled'] );

    if ( ! $lockout_enabled && ! $progressive_enabled ) {
        return 0;
    }

    $transient_key = wldelay_get_password_reset_failure_transient_key( $ip, $username, $options );
    $failed_attempts = get_transient( $transient_key );
    if ( false === $failed_attempts ) {
        $failed_attempts = 0;
    }

    $failed_attempts++;
    set_transient( $transient_key, $failed_attempts, HOUR_IN_SECONDS );
    if ( ! wldelay_register_transient_key( $transient_key, time() + HOUR_IN_SECONDS ) ) {
        // Same as the login counter: an unregistered, durable-less counter
        // transient is undiscoverable by recovery, so fail open and drop it
        // (Codex round-3 review).
        delete_transient( $transient_key );
    }

    if ( $lockout_enabled ) {
        $lockout_threshold = isset( $options['wldelay_lockout_threshold'] )
            ? (int) $options['wldelay_lockout_threshold']
            : LDS_Settings::_DEFAULT_LOCKOUT_THRESHOLD;

        if ( $failed_attempts >= $lockout_threshold ) {
            wldelay_lock_password_reset( $ip, $username );
        }
    }

    return $failed_attempts;
}

/**
 * Apply delay and telemetry to password reset submissions.
 *
 * @param WP_Error $errors Password reset validation errors.
 */
function wldelay_handle_password_reset_request( $errors ) {
    $options = wldelay_get_options();
    if ( empty( $options['wldelay_password_reset_enabled'] ) ) {
        return;
    }

    if ( wldelay_is_safe_mode() || wldelay_is_ip_whitelisted() ) {
        return;
    }

    $ip = wldelay_get_client_ip();
    if ( empty( $ip ) ) {
        return;
    }

    $username      = wldelay_get_password_reset_username();
    if ( ! empty( $options['wldelay_lockout_enabled'] ) && wldelay_is_password_reset_locked( null, $username ) ) {
        if ( is_wp_error( $errors ) ) {
            $errors->add(
                'wldelay_password_reset_locked',
                wldelay_get_password_reset_lockout_error_message( null, $username )
            );
        }
        return;
    }

    $failure_count = wldelay_get_password_reset_failure_count( null, $username );
    $delay         = wldelay_get_delay_value( $failure_count );

    $failed_attempts = wldelay_track_password_reset_attempt( $username );
    // Reset attempts use their own counter/lockout; the pipeline only handles the log + event here.
    wldelay_process_failed_attempt( $username, 'password-reset', array( 'track' => false, 'delay' => false, 'lockout' => false ) );

    if ( $delay > 0 ) {
        sleep( $delay );
    }

    $locked_after_attempt = ! empty( $options['wldelay_lockout_enabled'] )
        && $failed_attempts > 0
        && wldelay_is_password_reset_locked( null, $username );

    if ( $locked_after_attempt && is_wp_error( $errors ) ) {
        $errors->add(
            'wldelay_password_reset_locked',
            wldelay_get_password_reset_lockout_error_message( null, $username )
        );
    }
}
add_action( 'lostpassword_post', 'wldelay_handle_password_reset_request' );

/**
 * Track a failed login attempt for counters, notifications, and lockout.
 *
 * @param string $username Username attempted.
 * @param string|null $source Optional login source for lockout logging.
 * @return int Updated failure count for the current tracking key. 0 if tracking is skipped.
 */
function wldelay_track_failed_attempt( $username, $source = null ) {
    $ip = wldelay_get_client_ip();
    if ( empty( $ip ) ) {
        return 0;
    }
    $options = wldelay_get_options();
    $email_enabled = ! empty( $options['wldelay_email_enabled'] );
    $lockout_enabled = ! empty( $options['wldelay_lockout_enabled'] );
    $progressive_enabled = ! empty( $options['wldelay_progressive_enabled'] );

    // Skip tracking if no feature needs failure counters.
    if ( ! $email_enabled && ! $lockout_enabled && ! $progressive_enabled ) {
        return 0;
    }

    $transient_key = wldelay_get_failure_transient_key( $ip, $username, $options );
    $failed_attempts = get_transient( $transient_key );

    if ( false === $failed_attempts ) {
        $failed_attempts = 0;
    }

    $failed_attempts++;
    set_transient( $transient_key, $failed_attempts, HOUR_IN_SECONDS );
    if ( ! wldelay_register_transient_key( $transient_key, time() + HOUR_IN_SECONDS ) ) {
        // The counter has no durable backing, so an unregistered counter
        // transient (registry write failed during a DB outage while an external
        // object cache still accepted the set_transient) is undiscoverable by
        // recovery — flush would report success while it lingered. Fail open:
        // drop it. Worst case the count restarts next request (Codex round-3 review).
        delete_transient( $transient_key );
    }

    // Check email notification threshold
    if ( $email_enabled ) {
        $email_threshold = isset( $options['wldelay_email_threshold'] ) ? (int) $options['wldelay_email_threshold'] : LDS_Settings::_DEFAULT_EMAIL_THRESHOLD;

        if ( $failed_attempts === $email_threshold ) {
            wldelay_send_notification_email( $ip, $username, $failed_attempts );
        }
    }

    // Check lockout threshold
    if ( $lockout_enabled ) {
        $lockout_threshold = isset( $options['wldelay_lockout_threshold'] )
            ? (int) $options['wldelay_lockout_threshold']
            : LDS_Settings::_DEFAULT_LOCKOUT_THRESHOLD;

        if ( $failed_attempts >= $lockout_threshold ) {
            wldelay_lock_ip( $ip, $username, $source );
        }
    }

    return $failed_attempts;
}

function wldelay_send_notification_email( $ip, $username, $attempts ) {
    $options = wldelay_get_options();

    // Check site-wide email cooldown
    $cooldown_minutes = isset( $options['wldelay_email_cooldown'] )
        ? (int) $options['wldelay_email_cooldown']
        : LDS_Settings::_DEFAULT_EMAIL_COOLDOWN;

    if ( $cooldown_minutes > 0 ) {
        $cooldown_key = 'wldelay_email_cooldown';
        $last_sent = get_transient( $cooldown_key );

        if ( false !== $last_sent ) {
            // Still in cooldown period, skip sending
            return;
        }

        // Set cooldown transient
        set_transient( $cooldown_key, time(), $cooldown_minutes * MINUTE_IN_SECONDS );
    }

    $to = ! empty( $options['wldelay_email_address'] ) ? $options['wldelay_email_address'] : get_option( 'admin_email' );
    $site_name = get_bloginfo( 'name' );
    /* translators: %s: site name */
    $subject = sprintf( __( '[%s] Failed login attempts alert', 'login-delay-shield' ), $site_name );

    /* translators: 1: site name, 2: IP address, 3: attempted username, 4: failed attempt count, 5: timestamp */
    $message = sprintf(
        __( "Multiple failed login attempts detected on %1\$s.\n\nIP Address: %2\$s\nUsername attempted: %3\$s\nFailed attempts: %4\$d\nTime: %5\$s\n\nThis is an automated alert from Login Delay Shield.", 'login-delay-shield' ),
        $site_name,
        $ip,
        $username,
        $attempts,
        current_time( 'mysql' )
    );

    wp_mail( $to, $subject, $message );
}

function wldelay_auth_login ($user, $password) {
    // Check if IP is whitelisted - bypass all security measures
    if ( wldelay_is_safe_mode() || wldelay_is_ip_whitelisted() ) {
        return $user;
    }

    $username = wldelay_get_requested_login_username();

    // Check lockout first (before any processing)
    $options = wldelay_get_options();
    if ( ! empty( $options['wldelay_lockout_enabled'] ) && wldelay_is_ip_locked( null, $username ) ) {
        return new WP_Error(
            'wldelay_ip_locked',
            wldelay_get_lockout_error_message( null, $username )
        );
    }

    if( is_wp_error( $user ) ) {
        $pipeline        = wldelay_process_failed_attempt(
            $username,
            wldelay_get_login_source(),
            array(
                'log'     => false, // wp_login_failed handles DB logging for this path.
                'lockout' => false, // The lockout shaping below performs its own locked check.
            )
        );
        $failed_attempts = $pipeline['failed_attempts'];

        sleep( $pipeline['delay'] );

        if ( ! empty( $options['wldelay_lockout_enabled'] ) && $failed_attempts > 0 ) {
            $lockout_threshold = isset( $options['wldelay_lockout_threshold'] )
                ? (int) $options['wldelay_lockout_threshold']
                : LDS_Settings::_DEFAULT_LOCKOUT_THRESHOLD;
            $remaining_attempts = $lockout_threshold - $failed_attempts;

            if ( $remaining_attempts > 0 ) {
                $user->add(
                    'wldelay_attempts_remaining',
                    sprintf(
                        /* translators: %d: number of failed login attempts remaining before lockout */
                        _n(
                            'Login failed. %d attempt remaining before temporary lockout.',
                            'Login failed. %d attempts remaining before temporary lockout.',
                            $remaining_attempts,
                            'login-delay-shield'
                        ),
                        $remaining_attempts
                    )
                );
            } elseif ( wldelay_is_ip_locked( null, $username ) ) {
                return new WP_Error(
                    'wldelay_ip_locked',
                    wldelay_get_lockout_error_message( null, $username )
                );
            }
        }
    }

    return $user;
}
add_filter('wp_authenticate_user', 'wldelay_auth_login',1, 2);

// ==========================================================================
// Custom Login URL
// ==========================================================================

/**
 * Check whether the custom login URL feature is active.
 *
 * @return bool
 */
function wldelay_custom_login_is_active() {
    if ( defined( 'WLDELAY_DISABLE_CUSTOM_LOGIN' ) && WLDELAY_DISABLE_CUSTOM_LOGIN ) {
        return false;
    }

    $options = wldelay_get_options();

    if ( empty( $options['wldelay_custom_login_enabled'] ) ) {
        return false;
    }

    $slug = isset( $options['wldelay_custom_login_slug'] ) ? trim( $options['wldelay_custom_login_slug'] ) : '';

    return $slug !== '';
}

/**
 * Get the configured custom login slug.
 *
 * @return string
 */
function wldelay_get_custom_login_slug() {
    $options = wldelay_get_options();
    return isset( $options['wldelay_custom_login_slug'] ) ? trim( $options['wldelay_custom_login_slug'] ) : 'my-login';
}

/**
 * Loopback self-check for the custom login URL.
 *
 * Requests the custom slug from the outside, the way a logged-out admin
 * would. Competing login-URL plugins are notorious for stranding admins
 * behind a 404 — this check catches that before it can happen.
 *
 * @param string $slug Custom login slug to probe.
 * @return string 'ok' when the URL responds, 'unreachable' on a definitive
 *                404, 'unverified' when the loopback request itself failed
 *                (some hosts block loopback connections entirely).
 */
function wldelay_custom_login_self_check( $slug ) {
    $url = home_url( '/' . rawurlencode( $slug ) . '/' );

    $response = wp_remote_get(
        $url,
        array(
            'timeout'   => 10,
            // Self-signed certificates are common on staging/local hosts and
            // irrelevant here — we only care whether the route resolves.
            'sslverify' => false,
        )
    );

    if ( is_wp_error( $response ) ) {
        return 'unverified';
    }

    return ( 404 === (int) wp_remote_retrieve_response_code( $response ) ) ? 'unreachable' : 'ok';
}

/**
 * React to custom-login settings changes: verify the new URL actually works
 * and email it to the site admin as a recovery aid.
 *
 * Runs on update_option_wldelay_options whenever the feature is newly enabled
 * or the slug changes while enabled. If the loopback self-check gets a
 * definitive 404 the feature is auto-disabled — wp-login.php keeps working
 * and the admin is told why — instead of stranding everyone behind a dead
 * URL. An inconclusive check (blocked loopback) leaves the feature enabled
 * but surfaces a warning.
 *
 * @param mixed $old_value Previous option value.
 * @param mixed $value     New option value.
 */
function wldelay_custom_login_handle_settings_change( $old_value, $value ) {
    // The auto-disable path below calls update_option on the same option,
    // which re-fires this hook; the guard breaks the recursion.
    static $running = false;
    if ( $running ) {
        return;
    }

    if ( defined( 'WP_TESTS_DOMAIN' ) && ! apply_filters( 'wldelay_test_enable_custom_login_self_check', false ) ) {
        // Inside the integration suite every update_option('wldelay_options')
        // would otherwise fire a real loopback request and an email. Tests
        // that exercise this handler opt in through the filter; production
        // ignores it (same pattern as the WP_TESTS_DOMAIN exit guards).
        return;
    }

    $old_enabled = is_array( $old_value ) && ! empty( $old_value['wldelay_custom_login_enabled'] );
    $new_enabled = is_array( $value ) && ! empty( $value['wldelay_custom_login_enabled'] );
    $old_slug    = ( is_array( $old_value ) && isset( $old_value['wldelay_custom_login_slug'] ) ) ? trim( $old_value['wldelay_custom_login_slug'] ) : '';
    $new_slug    = ( is_array( $value ) && isset( $value['wldelay_custom_login_slug'] ) ) ? trim( $value['wldelay_custom_login_slug'] ) : '';

    $newly_active = $new_enabled && '' !== $new_slug && ( ! $old_enabled || $old_slug !== $new_slug );
    if ( ! $newly_active ) {
        return;
    }

    $check = wldelay_custom_login_self_check( $new_slug );

    if ( 'unreachable' === $check ) {
        $running = true;
        $value['wldelay_custom_login_enabled'] = false;
        update_option( 'wldelay_options', $value );
        $running = false;
        wldelay_clear_options_cache();

        add_settings_error(
            'wldelay_options',
            'wldelay_custom_login_unreachable',
            sprintf(
                /* translators: %s: the custom login URL that failed the self-check. */
                __( 'Custom Login URL was disabled automatically: %s returned a 404 in a self-check, which would have locked you out. The standard wp-login.php still works.', 'login-delay-shield' ),
                esc_url( home_url( '/' . $new_slug . '/' ) )
            ),
            'error'
        );
        return;
    }

    if ( 'unverified' === $check ) {
        add_settings_error(
            'wldelay_options',
            'wldelay_custom_login_unverified',
            sprintf(
                /* translators: 1: the custom login URL, 2: WLDELAY_DISABLE_CUSTOM_LOGIN constant name. */
                __( 'Custom Login URL is enabled, but the self-check could not reach %1$s (the host may block loopback requests). Verify the URL in a private browser window before logging out. Emergency bypass: define %2$s in wp-config.php.', 'login-delay-shield' ),
                esc_url( home_url( '/' . $new_slug . '/' ) ),
                'WLDELAY_DISABLE_CUSTOM_LOGIN'
            ),
            'warning'
        );
    } else {
        add_settings_error(
            'wldelay_options',
            'wldelay_custom_login_active',
            sprintf(
                /* translators: %s: the new custom login URL. */
                __( 'Custom Login URL is active and verified. Bookmark your new login URL now: %s — wp-login.php returns a 404 from this point on.', 'login-delay-shield' ),
                esc_url( home_url( '/' . $new_slug . '/' ) )
            ),
            'success'
        );
    }

    wldelay_send_custom_login_url_email( $new_slug );
}
add_action( 'update_option_wldelay_options', 'wldelay_custom_login_handle_settings_change', 20, 2 );

/**
 * First-ever save of the option goes through add_option, which fires
 * add_option_{option} instead of update_option_{option} — without this
 * bridge the self-check would silently skip on a fresh install.
 *
 * @param string $option Option name (unused).
 * @param mixed  $value  Saved option value.
 */
function wldelay_custom_login_handle_option_added( $option, $value ) {
    wldelay_custom_login_handle_settings_change( array(), $value );
}
add_action( 'add_option_wldelay_options', 'wldelay_custom_login_handle_option_added', 20, 2 );

/**
 * Email the new custom login URL to the site admin.
 *
 * A recovery aid for the "browser history cleared, URL forgotten" scenario.
 * Disable with: add_filter( 'wldelay_send_custom_login_email', '__return_false' );
 *
 * @param string $slug The active custom login slug.
 */
function wldelay_send_custom_login_url_email( $slug ) {
    /**
     * Filters whether the new-login-URL notification email is sent.
     *
     * @param bool $send Default true.
     */
    if ( ! apply_filters( 'wldelay_send_custom_login_email', true ) ) {
        return;
    }

    $login_url = home_url( '/' . $slug . '/' );

    $subject = sprintf(
        /* translators: %s: site name. */
        __( '[%s] Your login URL has changed', 'login-delay-shield' ),
        wp_specialchars_decode( get_option( 'blogname' ), ENT_QUOTES )
    );

    $message = sprintf(
        /* translators: 1: new login URL, 2: WLDELAY_DISABLE_CUSTOM_LOGIN constant name. */
        __(
            'Login Delay Shield moved the login page of your site to:

%1$s

Bookmark this URL — the standard wp-login.php now returns a 404.

If you ever lose access, add this line to wp-config.php to restore wp-login.php:

define( \'%2$s\', true );',
            'login-delay-shield'
        ),
        $login_url,
        'WLDELAY_DISABLE_CUSTOM_LOGIN'
    );

    wp_mail( get_option( 'admin_email' ), $subject, $message );
}

/**
 * Register the custom login slug rewrite rule and prevent canonical redirect
 * from leaking the custom slug when someone visits /wp-login.php.
 */
function wldelay_custom_login_init() {
    if ( ! wldelay_custom_login_is_active() ) {
        return;
    }

    $slug = wldelay_get_custom_login_slug();
    add_rewrite_rule( '^' . preg_quote( $slug, '/' ) . '/?$', 'index.php?wldelay_custom_login=1', 'top' );

    // Intercept any redirect that would expose the custom slug when someone
    // visits /wp-login.php. Covers canonical redirect and any other source.
    add_filter( 'wp_redirect', 'wldelay_block_login_slug_leak', 1, 2 );
}
add_action( 'init', 'wldelay_custom_login_init' );

/**
 * Block any redirect that would expose the custom login slug.
 *
 * Hooked on wp_redirect with priority 1 so it fires before the redirect is
 * sent. If the original request was for /wp-login.php and WordPress tries to
 * redirect to the custom slug URL, we serve a 404 instead.
 *
 * @param string $location The redirect destination URL.
 * @param int    $status   HTTP status code.
 * @return string|false The redirect URL, or false to cancel.
 */
function wldelay_block_login_slug_leak( $location, $status = 302 ) {
    $request_path = trim( parse_url( $_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH ), '/' );

    // Only act when the original request targets wp-login.php.
    if ( $request_path !== 'wp-login.php' && $request_path !== 'wp-loginphp' ) {
        return $location;
    }

    $slug = wldelay_get_custom_login_slug();

    // Only block if the redirect destination contains our custom slug.
    if ( strpos( $location, $slug ) === false ) {
        return $location;
    }

    status_header( 404 );
    nocache_headers();

    $template = function_exists( 'get_404_template' ) ? get_404_template() : '';
    if ( $template && file_exists( $template ) ) {
        include $template;
    } else {
        echo '<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><h1>Not Found</h1></body></html>';
    }

    if ( defined( 'WP_TESTS_DOMAIN' ) ) {
        return false;
    }
    exit;
}

/**
 * Register custom query var so WordPress recognises the slug.
 *
 * @param array $vars Existing query vars.
 * @return array
 */
function wldelay_custom_login_query_vars( $vars ) {
    $vars[] = 'wldelay_custom_login';
    return $vars;
}
add_filter( 'query_vars', 'wldelay_custom_login_query_vars' );

/**
 * On template_redirect, load wp-login.php when the custom slug is requested.
 */
function wldelay_custom_login_template_redirect() {
    if ( ! wldelay_custom_login_is_active() ) {
        return;
    }

    // Check both the URL path and the query var set by the rewrite rule.
    $slug = wldelay_get_custom_login_slug();
    $request = trim( parse_url( $_SERVER['REQUEST_URI'], PHP_URL_PATH ), '/' );

    if ( $request === $slug || get_query_var( 'wldelay_custom_login' ) ) {
        require_once ABSPATH . 'wp-login.php';
        exit;
    }
}
add_action( 'template_redirect', 'wldelay_custom_login_template_redirect' );

/**
 * Secondary guard on login_init — blocks any direct wp-login.php access that
 * somehow bypassed the earlier init-level check (e.g. non-GET methods that
 * should not reach the login form).
 *
 * The primary block runs on init in wldelay_custom_login_init().
 */
function wldelay_custom_login_block_direct_access() {
    if ( ! wldelay_custom_login_is_active() ) {
        return;
    }

    // POST requests must pass through (form submissions).
    if ( 'POST' === ( $_SERVER['REQUEST_METHOD'] ?? '' ) ) {
        return;
    }

    $slug = wldelay_get_custom_login_slug();
    $request_uri = isset( $_SERVER['REQUEST_URI'] ) ? $_SERVER['REQUEST_URI'] : '';
    $path = trim( parse_url( $request_uri, PHP_URL_PATH ), '/' );

    // Allow requests via the custom slug.
    if ( strpos( $path, $slug ) !== false ) {
        return;
    }

    // Only block if the user-facing URL is exactly "wp-login.php" at the site
    // root. Internal paths like /wp/wp-login.php are legitimate WordPress
    // redirects (e.g. unauthenticated wp-admin access) and must pass through.
    if ( $path !== 'wp-login.php' ) {
        return;
    }

    status_header( 404 );
    nocache_headers();

    if ( defined( 'WP_TESTS_DOMAIN' ) ) {
        return;
    }
    exit;
}
add_action( 'login_init', 'wldelay_custom_login_block_direct_access' );

/**
 * Filter wp_login_url() to use the custom slug.
 *
 * @param string $login_url    The login URL.
 * @param string $redirect     The path to redirect to on login.
 * @param bool   $force_reauth Whether to force reauth.
 * @return string
 */
function wldelay_filter_login_url( $login_url, $redirect = '', $force_reauth = false ) {
    if ( ! wldelay_custom_login_is_active() ) {
        return $login_url;
    }

    $slug = wldelay_get_custom_login_slug();
    $custom_url = home_url( $slug );

    if ( ! empty( $redirect ) ) {
        $custom_url = add_query_arg( 'redirect_to', urlencode( $redirect ), $custom_url );
    }

    if ( $force_reauth ) {
        $custom_url = add_query_arg( 'reauth', '1', $custom_url );
    }

    return $custom_url;
}
add_filter( 'login_url', 'wldelay_filter_login_url', 10, 3 );

/**
 * Filter logout_url() to use the custom slug.
 *
 * @param string $logout_url The logout URL.
 * @param string $redirect   Redirect destination.
 * @return string
 */
function wldelay_filter_logout_url( $logout_url, $redirect = '' ) {
    if ( ! wldelay_custom_login_is_active() ) {
        return $logout_url;
    }

    // Extract query string from the original logout URL (contains _wpnonce, action=logout).
    $parsed = wp_parse_url( $logout_url );
    $slug = wldelay_get_custom_login_slug();
    $custom_url = home_url( $slug );

    if ( ! empty( $parsed['query'] ) ) {
        $custom_url .= '?' . $parsed['query'];
    }

    return $custom_url;
}
add_filter( 'logout_url', 'wldelay_filter_logout_url', 10, 2 );

/**
 * Filter lostpassword_url() to use the custom slug.
 *
 * @param string $lostpassword_url The lost password URL.
 * @param string $redirect         Redirect destination.
 * @return string
 */
function wldelay_filter_lostpassword_url( $lostpassword_url, $redirect = '' ) {
    if ( ! wldelay_custom_login_is_active() ) {
        return $lostpassword_url;
    }

    $slug = wldelay_get_custom_login_slug();
    $custom_url = add_query_arg( 'action', 'lostpassword', home_url( $slug ) );

    if ( ! empty( $redirect ) ) {
        $custom_url = add_query_arg( 'redirect_to', urlencode( $redirect ), $custom_url );
    }

    return $custom_url;
}
add_filter( 'lostpassword_url', 'wldelay_filter_lostpassword_url', 10, 2 );

/**
 * Replace wp-login.php references in the password reset email with the custom slug.
 *
 * @param string $message    Email message body.
 * @param string $key        Password reset key.
 * @param string $user_login Username.
 * @param object $user_data  WP_User object.
 * @return string
 */
function wldelay_filter_retrieve_password_message( $message, $key, $user_login, $user_data ) {
    if ( ! wldelay_custom_login_is_active() ) {
        return $message;
    }

    $slug = wldelay_get_custom_login_slug();
    $old_url = network_site_url( 'wp-login.php', 'login' );
    $new_url = home_url( $slug );

    return str_replace( $old_url, $new_url, $message );
}
add_filter( 'retrieve_password_message', 'wldelay_filter_retrieve_password_message', 10, 4 );

// ==========================================================================
// Login page lockout feedback (F-1-4)
//
// Pure frontend presentation over the existing auth/lockout data. Surfaces a
// distinct, accessible status block on wp-login.php when the current IP is
// locked, with a live countdown and a help link. No backend/auth behaviour
// change and no new option keys — every value is derived from the existing
// lockout helpers.
// ==========================================================================

/**
 * Resolve the "Need help getting in?" link target for the login feedback block.
 *
 * Defaults to the site's lost-password URL (respecting any custom-login-slug
 * filter already applied to lostpassword_url) and is filterable so site owners
 * can point it at a support/docs page instead.
 *
 * @return string Help URL (unescaped; escape at output).
 */
function wldelay_login_help_url() {
    /**
     * Filter the help link shown in the login lockout feedback block.
     *
     * @param string $url Default help URL (the site's lost-password URL).
     */
    return apply_filters( 'wldelay_login_help_url', wp_lostpassword_url() );
}

/**
 * Format a remaining-seconds value as a compact M:SS countdown string.
 *
 * Used for the static (no-JS) seed text; the inline JS reproduces the same
 * format as it ticks down so the displayed value is consistent.
 *
 * @param int $seconds Remaining seconds (>= 0).
 * @return string e.g. "1:59" or "0:08".
 */
function wldelay_format_countdown( $seconds ) {
    $seconds = max( 0, (int) $seconds );
    $minutes = (int) floor( $seconds / 60 );
    $rest    = $seconds % 60;

    return sprintf( '%d:%02d', $minutes, $rest );
}

/**
 * Whether the login feedback block should render for the current request.
 *
 * True only when the lockout feature is enabled AND the current IP (optionally
 * scoped to the submitted username) is locked. Cheap enough to gate the styles
 * and footer-script hooks on without rebuilding the block markup.
 *
 * NOTE on the `ip_username` lockout strategy: the lockout transient is keyed on
 * ip|username, but the submitted username is only available on the failed-login
 * POST (via $_POST['log']). On a *fresh GET* of wp-login.php there is no
 * username, so an ip_username lockout cannot be detected and the block does not
 * render on that GET — it does render on the failed-POST re-render, which is the
 * path a locked-out user actually takes. Under the default `ip` strategy the
 * username is irrelevant and the block renders on GET and POST alike. The
 * server-side gate in wldelay_auth_login() enforces the lockout regardless.
 *
 * @return bool
 */
function wldelay_login_feedback_active() {
    if ( wldelay_is_safe_mode() ) {
        return false;
    }

    $options = wldelay_get_options();

    if ( empty( $options['wldelay_lockout_enabled'] ) ) {
        return false;
    }

    $username = wldelay_get_requested_login_username();

    return (bool) wldelay_is_ip_locked( null, $username );
}

/**
 * Build the distinct, accessible lockout feedback block markup.
 *
 * Returns an empty string when the lockout feature is disabled or the current
 * IP is not locked, so callers can safely concatenate the result. All dynamic
 * values (remaining seconds, countdown text, help URL) are escaped here.
 *
 * @return string HTML for the block, or '' when nothing should render.
 */
function wldelay_render_login_lockout_block() {
    if ( ! wldelay_login_feedback_active() ) {
        return '';
    }

    $username  = wldelay_get_requested_login_username();
    $remaining = wldelay_get_lockout_remaining_seconds( null, $username );

    // Human-readable static fallback (shown when JS is off). human_time_diff
    // gives a friendly "2 minutes" phrasing matching the WP error line.
    $human_remaining = ( $remaining > 0 )
        ? human_time_diff( time(), time() + $remaining )
        : '';

    $countdown_seed = wldelay_format_countdown( $remaining );

    if ( $remaining > 0 ) {
        $intro = sprintf(
            /* translators: %s: human-readable remaining lockout time, e.g. "2 minutes". */
            __( 'Too many failed login attempts. You can try again in %s.', 'login-delay-shield' ),
            $human_remaining
        );
    } else {
        $intro = __( 'You can try again now.', 'login-delay-shield' );
    }

    $help_url   = wldelay_login_help_url();
    $help_label = __( 'Need help getting in?', 'login-delay-shield' );
    $ready_text = __( 'You can try again now.', 'login-delay-shield' );
    $prefix     = __( 'Try again in', 'login-delay-shield' );

    $html  = '<div class="wldelay-login-status wldelay-login-status--locked" role="alert" aria-live="assertive">';
    $html .= '<p class="wldelay-login-status__intro">' . esc_html( $intro ) . '</p>';
    // The countdown line carries the seed seconds + ready text for the JS.
    $html .= '<p class="wldelay-login-status__countdown"'
        . ' data-wldelay-remaining="' . esc_attr( (string) max( 0, (int) $remaining ) ) . '"'
        . ' data-wldelay-prefix="' . esc_attr( $prefix ) . '"'
        . ' data-wldelay-ready="' . esc_attr( $ready_text ) . '">'
        . esc_html( $prefix ) . ' <span class="wldelay-login-status__time">' . esc_html( $countdown_seed ) . '</span>'
        . '</p>';
    $html .= '<p class="wldelay-login-status__help">'
        . '<a href="' . esc_url( $help_url ) . '">' . esc_html( $help_label ) . '</a>'
        . '</p>';
    $html .= '</div>';

    return $html;
}

/**
 * login_message filter: prepend the rich lockout block above the login form.
 *
 * Augments (does not replace) WordPress's own messaging. Returns the input
 * unchanged when nothing should render, so a normal login page is untouched.
 *
 * @param string $message Existing login message markup.
 * @return string
 */
function wldelay_login_message_lockout( $message ) {
    $block = wldelay_render_login_lockout_block();

    if ( '' === $block ) {
        return $message;
    }

    return $block . $message;
}
add_filter( 'login_message', 'wldelay_login_message_lockout' );

/**
 * wp_login_errors filter: present the attempts-remaining warning in the same
 * distinct styling so the user notices it.
 *
 * The auth code adds the 'wldelay_attempts_remaining' code to the WP_Error; we
 * only wrap a marker class around the existing (unchanged) message so the login
 * page CSS can style it as a warning variant. The message text is not altered.
 *
 * @param WP_Error $errors      Login errors.
 * @param string   $redirect_to Redirect target (unused).
 * @return WP_Error
 */
function wldelay_login_errors_warning( $errors, $redirect_to = '' ) {
    if ( ! is_wp_error( $errors ) ) {
        return $errors;
    }

    $messages = $errors->get_error_messages( 'wldelay_attempts_remaining' );
    if ( empty( $messages ) ) {
        return $errors;
    }

    // Re-wrap each attempts-remaining message with a warning marker. The text
    // is escaped because WordPress prints login error messages without
    // additional escaping.
    $errors->remove( 'wldelay_attempts_remaining' );
    foreach ( $messages as $msg ) {
        $errors->add(
            'wldelay_attempts_remaining',
            '<span class="wldelay-login-warning">' . esc_html( $msg ) . '</span>'
        );
    }

    return $errors;
}
add_filter( 'wp_login_errors', 'wldelay_login_errors_warning', 10, 2 );

/**
 * Inline login-page CSS for the feedback block.
 *
 * Scoped to login hooks only — admin.css is NOT loaded here. Kept small and
 * CSP-friendly (no external assets).
 */
function wldelay_login_feedback_styles() {
    if ( ! wldelay_login_feedback_active() ) {
        return;
    }

    $css = '
.wldelay-login-status{margin:0 0 16px;padding:14px 16px;border-left:4px solid #d63638;background:#fcf0f1;border-radius:3px;color:#1d2327;}
.wldelay-login-status__intro{margin:0 0 6px;font-weight:600;}
.wldelay-login-status__countdown{margin:0 0 6px;font-size:13px;}
.wldelay-login-status__time{font-variant-numeric:tabular-nums;font-weight:600;}
.wldelay-login-status__help{margin:0;font-size:13px;}
.wldelay-login-status.is-ready{border-left-color:#00a32a;background:#edfaef;}
.wldelay-login-warning{display:inline-block;border-left:4px solid #dba617;padding-left:8px;}
';

    wp_register_style( 'wldelay-login-feedback', false );
    wp_enqueue_style( 'wldelay-login-feedback' );
    wp_add_inline_style( 'wldelay-login-feedback', $css );
}
add_action( 'login_enqueue_scripts', 'wldelay_login_feedback_styles' );

/**
 * Inline, unobtrusive countdown JS printed in the login footer.
 *
 * Reads the seed seconds from the block's data attribute and ticks the time
 * down each second, updating the visible M:SS text. On reaching zero it swaps
 * in the "ready" message and re-enables the submit button. No external assets,
 * no eval — CSP friendly. With JS off, the static seeded text remains visible.
 */
function wldelay_login_feedback_script() {
    // Only emit the script when a block is actually rendered, to avoid adding
    // inert script to every login page view. Gate on the cheap predicate rather
    // than rebuilding the full block markup + re-reading the store.
    if ( ! wldelay_login_feedback_active() ) {
        return;
    }

    ?>
<script>
(function(){
    var el = document.querySelector('.wldelay-login-status__countdown');
    if(!el){return;}
    var remaining = parseInt(el.getAttribute('data-wldelay-remaining'), 10);
    if(isNaN(remaining)){return;}
    var prefix = el.getAttribute('data-wldelay-prefix') || '';
    var ready = el.getAttribute('data-wldelay-ready') || '';
    var timeEl = el.querySelector('.wldelay-login-status__time');
    var box = el.closest('.wldelay-login-status');
    function fmt(s){var m=Math.floor(s/60);var r=s%60;return m + ':' + (r<10?'0':'') + r;}
    function finish(){
        el.textContent = ready;
        if(box){box.classList.add('is-ready');}
        // Re-enable only the submit button (this feature never disables other
        // fields, so leave any third party's disabled fields untouched).
        var btn = document.getElementById('wp-submit');
        if(btn){btn.disabled = false;}
    }
    if(remaining <= 0){finish();return;}
    var timer = setInterval(function(){
        remaining -= 1;
        if(remaining <= 0){clearInterval(timer);finish();return;}
        if(timeEl){timeEl.textContent = fmt(remaining);}
    }, 1000);
})();
</script>
    <?php
}
add_action( 'login_footer', 'wldelay_login_feedback_script' );
