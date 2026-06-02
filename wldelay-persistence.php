<?php
/**
 * Persistent, DB-backed lockout store (F-2-1).
 *
 * Lockouts move to a durable custom table so they survive object-cache /
 * transient eviction, can be enumerated for the Active Lockout Manager (F-1-1),
 * and provide a forensic record. Per-attempt failure counters intentionally
 * stay on the transient fast-path (see wldelay_track_failed_attempt) — only
 * lockouts are persisted here.
 *
 * The read path keeps a same-request static cache in front of the DB, and the
 * public lockout API additionally keeps a transient in front of this store, so
 * the hot path stays fast (the DB is only consulted on a transient miss).
 *
 * @package login-delay-shield
 */

defined( 'ABSPATH' ) || exit;

/**
 * Contract for the lockout persistence backend.
 *
 * Implementations store and enumerate active lockouts. All durations are in
 * seconds; expiries are absolute UNIX timestamps internally.
 */
interface WLDelay_Persistence {

    /**
     * Add or refresh a lockout.
     *
     * @param string $ip          IP address.
     * @param string $username    Username (may be empty for IP-only strategy).
     * @param int    $duration    Lockout duration in seconds.
     * @param string $type        Lockout type ('login' or 'password-reset').
     * @param string|null $source Optional originating source (wp-login, rest, …).
     * @param string $transient_key Exact transient name the caller set for this
     *                    lockout, recorded verbatim so IP-level recovery can
     *                    delete it directly without reconstructing it from the
     *                    (possibly truncated) forensic username column (F-2-1).
     * @return bool True on success.
     */
    public function add_lockout( $ip, $username, $duration, $type = 'login', $source = null, $transient_key = '' );

    /**
     * Get a single active lockout record.
     *
     * @param string $ip       IP address.
     * @param string $username Username.
     * @param string $type     Lockout type.
     * @return array|null Associative record (ip_address, username, lockout_type,
     *                    source, created_at, expires_at) or null if not locked.
     */
    public function get_lockout( $ip, $username, $type = 'login' );

    /**
     * Whether the IP/username/type is currently locked.
     *
     * @param string $ip       IP address.
     * @param string $username Username.
     * @param string $type     Lockout type.
     * @return bool
     */
    public function is_locked( $ip, $username, $type = 'login' );

    /**
     * Remaining lockout time in seconds, or 0 if not locked.
     *
     * @param string $ip       IP address.
     * @param string $username Username.
     * @param string $type     Lockout type.
     * @return int
     */
    public function get_remaining_seconds( $ip, $username, $type = 'login' );

    /**
     * Remove lockouts for an IP/username. When $type is null, removes every
     * lockout type for the pair.
     *
     * @param string      $ip       IP address.
     * @param string      $username Username.
     * @param string|null $type     Lockout type, or null for all types.
     * @return int Number of rows removed.
     */
    public function remove_lockout( $ip, $username, $type = null );

    /**
     * Remove every lockout row for an IP, regardless of username or type.
     *
     * IP-level recovery (admin unlock / WP-CLI `unlock-ip`) only knows the IP.
     * Under the ip_username strategy the durable row is keyed on the full
     * (ip, username) hash, so a username-agnostic key cannot match it — this
     * deletes by the indexed ip_address column instead so the IP is reliably
     * cleared (F-2-1).
     *
     * @param string $ip IP address.
     * @return int Number of rows removed.
     */
    public function remove_lockouts_for_ip( $ip );

    /**
     * Conditionally delete the durable rows captured in a recovery snapshot.
     *
     * IP-level and bulk recovery snapshot the target rows (capturing each row's
     * lockout_key + generation) BEFORE clearing the transient fast-path, then
     * call this with that snapshot. A row is only deleted when its generation
     * STILL matches the snapshot, so a concurrent failed login that refreshed
     * the row (writing a new generation via add_lockout) during the recovery
     * window survives — closing the race where unconditional deletion orphaned
     * an external-object-cache lockout and left a user locked after recovery
     * reported success (F-2-1 hardening).
     *
     * A snapshot entry whose generation is the empty string (a legacy row
     * predating the generation column) matches a current empty generation, so
     * legacy rows are still cleanable and never stranded.
     *
     * @param array[] $snapshot List of entries each with 'lockout_key' and
     *                          'generation' keys (extra keys are ignored).
     * @return int Number of rows removed.
     */
    public function remove_lockouts_matching_generation( array $snapshot );

    /**
     * List the stored lockouts for an IP (active or expired).
     *
     * IP-level recovery needs to clear the transient fast-path keys too, but a
     * username-scoped lockout transient (ip_username strategy) is keyed on
     * md5("ip|username") and cannot be derived from the IP alone. The durable
     * rows are the IP→username index the transient registry lacks: each row
     * records the effective username and type the transient was keyed under, so
     * recovery can reconstruct and clear those transients (F-2-1).
     *
     * @param string $ip IP address.
     * @return array[] List of records with at least 'lockout_key', 'username',
     *                 'lockout_type', 'transient_key' and 'generation' keys
     *                 (empty array when none / no table). 'transient_key' is the
     *                 exact transient name set at lock time, or '' for legacy
     *                 rows predating it; 'generation' is the per-write random
     *                 token used for the recovery compare-and-delete, or '' for
     *                 rows predating it (F-2-1).
     */
    public function get_lockouts_for_ip( $ip );

    /**
     * Enumerate all currently active lockouts.
     *
     * @param int $limit Maximum rows to return.
     * @return array[] List of lockout records.
     */
    public function get_active_lockouts( $limit = 200 );

    /**
     * Remove every lockout, active or expired.
     *
     * @return int Number of rows removed.
     */
    public function clear_all();

    /**
     * Delete expired lockout rows.
     *
     * @return int Number of rows removed.
     */
    public function purge_expired();
}

/**
 * Derive the stable storage key for a lockout.
 *
 * Pure logic (no WordPress dependency) so it is unit-testable. The key is a
 * fixed-length hash that fits the indexed varchar(64) column and isolates IP,
 * username, and lockout type.
 *
 * @param string $ip       IP address.
 * @param string $username Username.
 * @param string $type     Lockout type.
 * @return string 40-char sha1 hash.
 */
function wldelay_get_lockout_storage_key( $ip, $username = '', $type = 'login' ) {
    return sha1( $type . '|' . $ip . '|' . $username );
}

/**
 * Generate a fresh, unique generation token for a lockout write / registry record.
 *
 * Every lockout INSERT/refresh and every transient-registry write stamps a new
 * token so the recovery compare-and-delete can distinguish a snapshot row from a
 * row that a concurrent same-second relock refreshed during the recovery window.
 * The token only needs to be unique per write, not cryptographically secret, so
 * a short random hex is enough — and cheap enough for the auth hot path. Prefers
 * random_bytes() and degrades to wp_generate_password()/mt_rand() so it never
 * fatals on a platform without the CSPRNG (F-2-1 hardening).
 *
 * @return string 24-char hex token (fits the varchar(32) generation column).
 */
function wldelay_generate_lockout_generation() {
    if ( function_exists( 'random_bytes' ) ) {
        try {
            return bin2hex( random_bytes( 12 ) );
        } catch ( Exception $e ) {
            // Fall through to the non-CSPRNG paths below.
        }
    }

    if ( function_exists( 'wp_generate_password' ) ) {
        return wp_generate_password( 24, false );
    }

    // Last-resort fallback for a context without random_bytes or
    // wp_generate_password. wp_rand() is preferred over mt_rand() (far less
    // predictable, and the plugin-check standard requires it).
    $seed = function_exists( 'wp_rand' ) ? wp_rand() : 0;

    return substr( md5( uniqid( (string) $seed, true ) ), 0, 24 );
}

/**
 * Get the persistent lockout table name.
 *
 * @return string
 */
function wldelay_get_lockout_table_name() {
    global $wpdb;

    // Cache per active prefix, not once globally: under multisite a request
    // may switch_to_blog() between calls, changing $wpdb->prefix. A single
    // static would pin the first site's table and leak lockouts across sites
    // (F-2-1).
    static $table_names = array();

    $prefix = $wpdb->prefix;
    if ( ! isset( $table_names[ $prefix ] ) ) {
        $table_names[ $prefix ] = $prefix . 'wldelay_lockouts';
    }

    return $table_names[ $prefix ];
}

/**
 * Create (or upgrade) the persistent lockout table.
 *
 * Idempotent — safe to call on every activation and on the dbDelta upgrade
 * path. Mirrors the log-table approach so dbDelta can evolve the schema.
 */
function wldelay_create_lockout_table() {
    global $wpdb;

    $table_name      = wldelay_get_lockout_table_name();
    $charset_collate = $wpdb->get_charset_collate();

    // Drop the legacy gen-2 composite index before dbDelta runs. dbDelta never
    // drops an index that is absent from the CREATE TABLE statement, so the old
    // KEY ip_username (ip_address, username) would otherwise survive the upgrade.
    // While username is part of that composite, widening it to varchar(255)
    // breaches the 767-byte index limit on older MySQL/InnoDB and the ALTER
    // fails — leaving the column permanently at varchar(60). Dropping the index
    // first frees the widening ALTER (F-2-1). Idempotent: only drops if present.
    if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table_name ) ) === $table_name ) {
        $has_legacy_index = $wpdb->get_var(
            // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
            "SHOW INDEX FROM $table_name WHERE Key_name = 'ip_username'"
        );
        if ( $has_legacy_index ) {
            // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.SchemaChange, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $wpdb->query( "ALTER TABLE $table_name DROP INDEX ip_username" );
        }
    }

    $sql = "CREATE TABLE $table_name (
        id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
        lockout_key varchar(64) NOT NULL,
        ip_address varchar(45) NOT NULL,
        username varchar(255) NOT NULL DEFAULT '',
        lockout_type varchar(20) NOT NULL DEFAULT 'login',
        source varchar(20) DEFAULT NULL,
        transient_key varchar(191) NOT NULL DEFAULT '',
        generation varchar(32) NOT NULL DEFAULT '',
        created_at datetime NOT NULL,
        expires_at datetime NOT NULL,
        PRIMARY KEY  (id),
        UNIQUE KEY lockout_key (lockout_key),
        KEY ip_address (ip_address),
        KEY expires_at (expires_at)
    ) $charset_collate;";

    require_once( ABSPATH . 'wp-admin/includes/upgrade.php' );
    dbDelta( $sql );
}

/**
 * Whether the lockout table's username column has been widened to the gen-3
 * width (varchar(255)+). Used to gate the schema-version write so a failed or
 * partial widening ALTER (e.g. a 767-byte index-limit failure on old MySQL)
 * does not record the new DB version and skip the retry on the next request
 * (F-2-1).
 *
 * @return bool True when the column is at least 255 chars wide.
 */
function wldelay_lockout_username_is_widened() {
    global $wpdb;

    $table = wldelay_get_lockout_table_name();

    // Read the live column definition via SHOW COLUMNS. information_schema is
    // NOT used here: it can return a stale CHARACTER_MAXIMUM_LENGTH immediately
    // after a DDL ALTER (its metadata is cached), which would either pass this
    // gate falsely or wedge the upgrade in a permanent retry. SHOW COLUMNS
    // reflects the table definition directly.
    $column = $wpdb->get_row(
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        "SHOW COLUMNS FROM $table LIKE 'username'"
    );

    if ( ! $column || empty( $column->Type ) ) {
        return false;
    }

    // $column->Type looks like "varchar(255)"; extract the declared length.
    if ( preg_match( '/varchar\((\d+)\)/i', $column->Type, $matches ) ) {
        return (int) $matches[1] >= 255;
    }

    // A non-varchar type (e.g. a future widening to text) counts as widened.
    return true;
}

/**
 * Whether the lockout table carries the gen-4 transient_key column. Gates the
 * schema-version write so a dbDelta run that failed to add the column does not
 * record the new DB version and skip the retry — which would leave IP-level
 * recovery reconstructing transient keys from the truncated username column and
 * missing lockouts whose canonical identifier exceeds the column width (F-2-1).
 *
 * @return bool True when the transient_key column exists.
 */
function wldelay_lockout_has_transient_key_column() {
    global $wpdb;

    $table = wldelay_get_lockout_table_name();

    // SHOW COLUMNS reflects the live table definition directly (information_schema
    // can lag immediately after a DDL ALTER — same rationale as the widening gate).
    $column = $wpdb->get_row(
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        "SHOW COLUMNS FROM $table LIKE 'transient_key'"
    );

    return ! empty( $column );
}

/**
 * Whether the lockout table carries the gen-6 generation column. Gates the
 * schema-version write so a dbDelta run that failed to add the column does not
 * record the new DB version and skip the retry — which would leave recovery's
 * snapshot-then-conditional-delete with no generation to compare on, falling
 * back to deleting rows refreshed by a concurrent relock and re-opening the
 * orphaning race the column closes (F-2-1 hardening).
 *
 * @return bool True when the generation column exists.
 */
function wldelay_lockout_has_generation_column() {
    global $wpdb;

    $table = wldelay_get_lockout_table_name();

    // SHOW COLUMNS reflects the live table definition directly (information_schema
    // can lag immediately after a DDL ALTER — same rationale as the gates above).
    $column = $wpdb->get_row(
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        "SHOW COLUMNS FROM $table LIKE 'generation'"
    );

    return ! empty( $column );
}

/**
 * DB-backed implementation of the lockout persistence contract.
 *
 * The durable store sits behind the transient fast-path: the public lockout
 * API (wldelay_is_ip_locked) reads the transient first and only consults this
 * store on a transient miss, so the per-request hot path stays fast while the
 * DB remains authoritative across cache eviction.
 */
class WLDelay_DB_Persistence implements WLDelay_Persistence {

    /**
     * Reset any same-request state.
     *
     * The store reads straight from the DB so there is no static cache to
     * clear, but the hook is kept so callers (and tests simulating eviction)
     * have a stable contract.
     */
    public function reset_runtime_cache() {
        $this->table_exists = array();
    }

    /**
     * Cached table-existence flags for the current request, keyed by table
     * name so the cache is scoped per blog prefix. A single bool would carry
     * site A's result into site B after switch_to_blog() (F-2-1).
     *
     * @var array<string,bool>
     */
    private $table_exists = array();

    /**
     * Whether the lockout table exists.
     *
     * Read methods are on the authentication hot path; if the table is missing
     * (e.g. mid-upgrade, or before activation provisioned it) they must degrade
     * gracefully to "not locked" rather than raising a DB error. Cached per
     * request so the SHOW TABLES check runs at most once.
     *
     * @return bool
     */
    private function table_exists() {
        global $wpdb;
        $table = wldelay_get_lockout_table_name();

        if ( isset( $this->table_exists[ $table ] ) ) {
            return $this->table_exists[ $table ];
        }

        $suppress = $wpdb->suppress_errors( true );
        $found    = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) );
        $wpdb->suppress_errors( $suppress );

        $this->table_exists[ $table ] = ( $found === $table );

        return $this->table_exists[ $table ];
    }

    /**
     * {@inheritDoc}
     */
    public function add_lockout( $ip, $username, $duration, $type = 'login', $source = null, $transient_key = '' ) {
        global $wpdb;

        if ( empty( $ip ) ) {
            return false;
        }

        if ( ! $this->table_exists() ) {
            return false;
        }

        $username   = (string) $username;
        $type       = (string) $type;
        $now        = time();
        $expires    = $now + (int) $duration;
        // The lockout key hashes the FULL canonical identifier, so lockout
        // matching is exact at any username length. The username column is a
        // forensic/display copy; clamp it to the column width so a custom-auth
        // identifier (LDAP/SSO/email via wldelay_normalize_username) longer than
        // the column cannot fail the INSERT under strict SQL mode and silently
        // drop the durable record (F-2-1).
        $key          = wldelay_get_lockout_storage_key( $ip, $username, $type );
        $username_col = function_exists( 'mb_substr' ) ? mb_substr( $username, 0, 255 ) : substr( $username, 0, 255 );
        $created_at   = gmdate( 'Y-m-d H:i:s', $now );
        $expires_at   = gmdate( 'Y-m-d H:i:s', $expires );

        // Clamp the forensic source label to the column width (varchar(20)) for
        // the same reason as the username column above: a caller-supplied source
        // longer than the column (wldelay_lock_ip / wldelay_track_failed_attempt
        // accept an unconstrained source) must not fail the INSERT under strict
        // SQL mode and silently drop the durable record (F-2-1).
        if ( null !== $source ) {
            $source = (string) $source;
            $source = function_exists( 'mb_substr' ) ? mb_substr( $source, 0, 20 ) : substr( $source, 0, 20 );
        }

        // Record the exact transient name the caller set so IP-level recovery can
        // delete it directly. Clamp to the column width (varchar(191)); transient
        // names are short hashes, so this never truncates a real key — the clamp
        // only guards a misbehaving caller from failing the INSERT (F-2-1).
        $transient_key = (string) $transient_key;
        $transient_key = function_exists( 'mb_substr' ) ? mb_substr( $transient_key, 0, 191 ) : substr( $transient_key, 0, 191 );

        // Stamp a fresh generation on every insert AND every refresh. Recovery
        // snapshots the generation it intends to remove, then deletes only rows
        // whose generation still matches — so a concurrent same-second relock
        // (which lands here and writes a NEW generation through the ON DUPLICATE
        // KEY UPDATE branch) survives the recovery sweep instead of being
        // orphaned (F-2-1 hardening).
        $generation = wldelay_generate_lockout_generation();

        $table = wldelay_get_lockout_table_name();

        // Atomic upsert keyed on the unique lockout_key. A single statement
        // avoids the read-then-write race where two concurrent first-time locks
        // for the same identity both see no row and the loser fails on the
        // unique key, silently dropping the durable record. On a re-lock the
        // existing row is refreshed in place.
        //
        // The source column is nullable, so emit a literal NULL (rather than
        // the empty string $wpdb->prepare would substitute for a null %s) when
        // no source is supplied. prepare() is inlined into query() so the
        // parameters are escaped at the call site.
        if ( null === $source ) {
            $result = $wpdb->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                $wpdb->prepare(
                    "INSERT INTO $table
                        (lockout_key, ip_address, username, lockout_type, source, transient_key, generation, created_at, expires_at)
                     VALUES (%s, %s, %s, %s, NULL, %s, %s, %s, %s)
                     ON DUPLICATE KEY UPDATE
                        ip_address = VALUES(ip_address),
                        username = VALUES(username),
                        lockout_type = VALUES(lockout_type),
                        source = VALUES(source),
                        transient_key = VALUES(transient_key),
                        generation = VALUES(generation),
                        created_at = VALUES(created_at),
                        expires_at = VALUES(expires_at)", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
                    $key,
                    $ip,
                    $username_col,
                    $type,
                    $transient_key,
                    $generation,
                    $created_at,
                    $expires_at
                )
            );
        } else {
            $result = $wpdb->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                $wpdb->prepare(
                    "INSERT INTO $table
                        (lockout_key, ip_address, username, lockout_type, source, transient_key, generation, created_at, expires_at)
                     VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                     ON DUPLICATE KEY UPDATE
                        ip_address = VALUES(ip_address),
                        username = VALUES(username),
                        lockout_type = VALUES(lockout_type),
                        source = VALUES(source),
                        transient_key = VALUES(transient_key),
                        generation = VALUES(generation),
                        created_at = VALUES(created_at),
                        expires_at = VALUES(expires_at)", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
                    $key,
                    $ip,
                    $username_col,
                    $type,
                    (string) $source,
                    $transient_key,
                    $generation,
                    $created_at,
                    $expires_at
                )
            );
        }

        return false !== $result;
    }

    /**
     * {@inheritDoc}
     */
    public function get_lockout( $ip, $username, $type = 'login' ) {
        global $wpdb;

        if ( empty( $ip ) || ! $this->table_exists() ) {
            return null;
        }

        $key   = wldelay_get_lockout_storage_key( $ip, $username, $type );
        $table = wldelay_get_lockout_table_name();

        $row = $wpdb->get_row(
            $wpdb->prepare( "SELECT * FROM $table WHERE lockout_key = %s", $key ),
            ARRAY_A
        );

        if ( null === $row ) {
            return null;
        }

        $expires = strtotime( $row['expires_at'] . ' UTC' );

        if ( $expires <= time() ) {
            return null;
        }

        $row['expires_at'] = $expires;
        $row['created_at'] = strtotime( $row['created_at'] . ' UTC' );

        return $row;
    }

    /**
     * {@inheritDoc}
     */
    public function is_locked( $ip, $username, $type = 'login' ) {
        if ( empty( $ip ) ) {
            return false;
        }

        return null !== $this->get_lockout( $ip, $username, $type );
    }

    /**
     * Remaining lockout time in seconds, or 0 if not locked.
     *
     * @param string $ip       IP address.
     * @param string $username Username.
     * @param string $type     Lockout type.
     * @return int
     */
    public function get_remaining_seconds( $ip, $username, $type = 'login' ) {
        $record = $this->get_lockout( $ip, $username, $type );
        if ( null === $record ) {
            return 0;
        }

        return max( 0, (int) $record['expires_at'] - time() );
    }

    /**
     * {@inheritDoc}
     */
    public function remove_lockout( $ip, $username, $type = null ) {
        global $wpdb;

        if ( empty( $ip ) || ! $this->table_exists() ) {
            return 0;
        }

        $table = wldelay_get_lockout_table_name();

        if ( null === $type ) {
            $types = array( 'login', 'password-reset' );
        } else {
            $types = array( (string) $type );
        }

        $removed = 0;
        foreach ( $types as $one_type ) {
            $key     = wldelay_get_lockout_storage_key( $ip, $username, $one_type );
            $deleted = $wpdb->delete( $table, array( 'lockout_key' => $key ), array( '%s' ) );
            if ( $deleted ) {
                $removed += (int) $deleted;
            }
        }

        return $removed;
    }

    /**
     * {@inheritDoc}
     */
    public function remove_lockouts_for_ip( $ip ) {
        global $wpdb;

        if ( empty( $ip ) || ! $this->table_exists() ) {
            return 0;
        }

        $table   = wldelay_get_lockout_table_name();
        $deleted = $wpdb->delete( $table, array( 'ip_address' => (string) $ip ), array( '%s' ) );

        return false === $deleted ? 0 : (int) $deleted;
    }

    /**
     * {@inheritDoc}
     */
    public function remove_lockouts_matching_generation( array $snapshot ) {
        global $wpdb;

        if ( empty( $snapshot ) || ! $this->table_exists() ) {
            return 0;
        }

        $table   = wldelay_get_lockout_table_name();
        $removed = 0;

        // Compare-and-delete per snapshot row: WHERE lockout_key = %s AND
        // generation = %s. A row a concurrent relock refreshed during the
        // recovery window now carries a NEW generation, so it fails the match
        // and survives — exactly the orphaning race this closes. A legacy row's
        // empty-string generation matches a still-empty current generation, so
        // legacy rows remain cleanable.
        foreach ( $snapshot as $entry ) {
            if ( ! is_array( $entry ) || ! isset( $entry['lockout_key'] ) ) {
                continue;
            }

            $deleted = $wpdb->delete(
                $table,
                array(
                    'lockout_key' => (string) $entry['lockout_key'],
                    'generation'  => isset( $entry['generation'] ) ? (string) $entry['generation'] : '',
                ),
                array( '%s', '%s' )
            );

            if ( $deleted ) {
                $removed += (int) $deleted;
            }
        }

        return $removed;
    }

    /**
     * {@inheritDoc}
     */
    public function get_lockouts_for_ip( $ip ) {
        global $wpdb;

        if ( empty( $ip ) || ! $this->table_exists() ) {
            return array();
        }

        $table = wldelay_get_lockout_table_name();

        // No expiry filter: recovery clears the transient for every row keyed
        // to this IP, and deleting an already-expired transient is harmless.
        // lockout_key + generation are selected so IP-level recovery can snapshot
        // the rows and conditionally delete only those a concurrent relock did
        // not refresh (F-2-1 hardening).
        $rows = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT lockout_key, username, lockout_type, transient_key, generation FROM $table WHERE ip_address = %s",
                (string) $ip
            ),
            ARRAY_A
        );

        return is_array( $rows ) ? $rows : array();
    }

    /**
     * {@inheritDoc}
     */
    public function get_active_lockouts( $limit = 200 ) {
        global $wpdb;

        if ( ! $this->table_exists() ) {
            return array();
        }

        $limit = max( 1, (int) $limit );
        $table = wldelay_get_lockout_table_name();
        $now   = gmdate( 'Y-m-d H:i:s', time() );

        $rows = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT * FROM $table WHERE expires_at > %s ORDER BY expires_at DESC LIMIT %d",
                $now,
                $limit
            ),
            ARRAY_A
        );

        if ( empty( $rows ) ) {
            return array();
        }

        foreach ( $rows as &$row ) {
            $row['expires_at'] = strtotime( $row['expires_at'] . ' UTC' );
            $row['created_at'] = strtotime( $row['created_at'] . ' UTC' );
        }
        unset( $row );

        return $rows;
    }

    /**
     * {@inheritDoc}
     */
    public function clear_all() {
        global $wpdb;

        if ( ! $this->table_exists() ) {
            return 0;
        }

        $table = wldelay_get_lockout_table_name();

        // DELETE (not TRUNCATE) so the operation participates in any
        // surrounding transaction — keeps test isolation intact and is still
        // fast for the small lockout table.
        $deleted = $wpdb->query( "DELETE FROM $table" );

        return (int) $deleted;
    }

    /**
     * {@inheritDoc}
     */
    public function purge_expired() {
        global $wpdb;

        if ( ! $this->table_exists() ) {
            return 0;
        }

        $table = wldelay_get_lockout_table_name();
        $now   = gmdate( 'Y-m-d H:i:s', time() );

        $deleted = $wpdb->query(
            $wpdb->prepare( "DELETE FROM $table WHERE expires_at <= %s", $now )
        );

        return (int) $deleted;
    }
}

/**
 * Get the shared persistence store instance.
 *
 * The backend is filterable so a future implementation (Redis, external store)
 * can replace the DB-backed default without touching call sites.
 *
 * @return WLDelay_Persistence
 */
function wldelay_get_persistence_store() {
    static $store = null;

    if ( null === $store ) {
        /**
         * Filter the lockout persistence backend.
         *
         * @param WLDelay_Persistence|null $store Existing store, or null to use the default.
         */
        $store = apply_filters( 'wldelay_persistence_store', null );

        if ( ! $store instanceof WLDelay_Persistence ) {
            $store = new WLDelay_DB_Persistence();
        }
    }

    return $store;
}

/**
 * Reset the persistence store's same-request cache.
 *
 * Used by tests (object-cache eviction simulation) and after bulk recovery
 * operations so subsequent reads consult the DB.
 */
function wldelay_reset_persistence_runtime_cache() {
    $store = wldelay_get_persistence_store();
    if ( $store instanceof WLDelay_DB_Persistence ) {
        $store->reset_runtime_cache();
    }
}
