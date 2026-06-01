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
     * @return bool True on success.
     */
    public function add_lockout( $ip, $username, $duration, $type = 'login', $source = null );

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
 * Get the persistent lockout table name.
 *
 * @return string
 */
function wldelay_get_lockout_table_name() {
    static $table_name = null;

    if ( $table_name === null ) {
        global $wpdb;
        $table_name = $wpdb->prefix . 'wldelay_lockouts';
    }

    return $table_name;
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

    $sql = "CREATE TABLE $table_name (
        id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
        lockout_key varchar(64) NOT NULL,
        ip_address varchar(45) NOT NULL,
        username varchar(60) NOT NULL DEFAULT '',
        lockout_type varchar(20) NOT NULL DEFAULT 'login',
        source varchar(20) DEFAULT NULL,
        created_at datetime NOT NULL,
        expires_at datetime NOT NULL,
        PRIMARY KEY  (id),
        UNIQUE KEY lockout_key (lockout_key),
        KEY ip_username (ip_address, username),
        KEY expires_at (expires_at)
    ) $charset_collate;";

    require_once( ABSPATH . 'wp-admin/includes/upgrade.php' );
    dbDelta( $sql );
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
        $this->table_exists = null;
    }

    /**
     * Cached table-existence flag for the current request.
     *
     * @var bool|null
     */
    private $table_exists = null;

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
        if ( null !== $this->table_exists ) {
            return $this->table_exists;
        }

        global $wpdb;
        $table = wldelay_get_lockout_table_name();

        $suppress = $wpdb->suppress_errors( true );
        $found    = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) );
        $wpdb->suppress_errors( $suppress );

        $this->table_exists = ( $found === $table );

        return $this->table_exists;
    }

    /**
     * {@inheritDoc}
     */
    public function add_lockout( $ip, $username, $duration, $type = 'login', $source = null ) {
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
        $key        = wldelay_get_lockout_storage_key( $ip, $username, $type );
        $created_at = gmdate( 'Y-m-d H:i:s', $now );
        $expires_at = gmdate( 'Y-m-d H:i:s', $expires );

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
                        (lockout_key, ip_address, username, lockout_type, source, created_at, expires_at)
                     VALUES (%s, %s, %s, %s, NULL, %s, %s)
                     ON DUPLICATE KEY UPDATE
                        ip_address = VALUES(ip_address),
                        username = VALUES(username),
                        lockout_type = VALUES(lockout_type),
                        source = VALUES(source),
                        created_at = VALUES(created_at),
                        expires_at = VALUES(expires_at)", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
                    $key,
                    $ip,
                    $username,
                    $type,
                    $created_at,
                    $expires_at
                )
            );
        } else {
            $result = $wpdb->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                $wpdb->prepare(
                    "INSERT INTO $table
                        (lockout_key, ip_address, username, lockout_type, source, created_at, expires_at)
                     VALUES (%s, %s, %s, %s, %s, %s, %s)
                     ON DUPLICATE KEY UPDATE
                        ip_address = VALUES(ip_address),
                        username = VALUES(username),
                        lockout_type = VALUES(lockout_type),
                        source = VALUES(source),
                        created_at = VALUES(created_at),
                        expires_at = VALUES(expires_at)", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
                    $key,
                    $ip,
                    $username,
                    $type,
                    (string) $source,
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
