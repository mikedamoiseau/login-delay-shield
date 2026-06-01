<?php
/**
 * Integration tests wiring the persistent lockout store into the public
 * lockout API (F-2-1).
 *
 * Verifies wldelay_lock_ip / wldelay_is_ip_locked persist to the DB store and
 * survive transient eviction, that the upgrade hook creates the lockout table,
 * and that the recovery tools clear the persistent store too.
 */

class PersistentLockoutIntegrationTest extends WP_UnitTestCase {

    const TEST_IP = '203.0.113.200';

    public function setUp(): void {
        parent::setUp();

        wldelay_create_lockout_table();
        $this->truncate_lockout_table();

        $_SERVER['REMOTE_ADDR'] = self::TEST_IP;
        unset( $_POST['log'], $_SERVER['HTTP_CLIENT_IP'], $_SERVER['HTTP_X_FORWARDED_FOR'] );

        delete_option( 'wldelay_options' );
        wldelay_clear_options_cache();
        wldelay_reset_persistence_runtime_cache();

        // Clear transients for the test IP.
        delete_transient( wldelay_get_lockout_transient_key( self::TEST_IP ) );
    }

    public function tearDown(): void {
        unset( $_SERVER['REMOTE_ADDR'], $_POST['log'] );
        $this->truncate_lockout_table();
        delete_transient( wldelay_get_lockout_transient_key( self::TEST_IP ) );
        delete_option( 'wldelay_options' );
        wldelay_clear_options_cache();
        wldelay_reset_persistence_runtime_cache();
        parent::tearDown();
    }

    private function truncate_lockout_table() {
        global $wpdb;
        $table = wldelay_get_lockout_table_name();
        $wpdb->query( "TRUNCATE TABLE $table" ); // phpcs:ignore WordPress.DB
    }

    /**
     * wldelay_lock_ip writes a row into the persistent store.
     */
    public function test_lock_ip_writes_to_persistent_store() {
        update_option( 'wldelay_options', [
            'wldelay_lockout_enabled'  => true,
            'wldelay_lockout_duration' => 30,
        ] );
        wldelay_clear_options_cache();

        wldelay_lock_ip( self::TEST_IP );

        $store = wldelay_get_persistence_store();
        $this->assertTrue( $store->is_locked( self::TEST_IP, '' ) );
    }

    /**
     * A lockout set via wldelay_lock_ip is still detected by
     * wldelay_is_ip_locked after the transient fast-path is evicted — proving
     * the durable store backs the read path.
     */
    public function test_lockout_survives_transient_eviction() {
        update_option( 'wldelay_options', [
            'wldelay_lockout_enabled'  => true,
            'wldelay_lockout_duration' => 30,
        ] );
        wldelay_clear_options_cache();

        wldelay_lock_ip( self::TEST_IP );
        $this->assertTrue( wldelay_is_ip_locked( self::TEST_IP ) );

        // Evict the transient fast-path + same-request cache.
        delete_transient( wldelay_get_lockout_transient_key( self::TEST_IP ) );
        wldelay_reset_persistence_runtime_cache();

        $this->assertTrue(
            wldelay_is_ip_locked( self::TEST_IP ),
            'Lockout must persist after the transient is evicted'
        );
    }

    /**
     * The remaining-seconds helper still returns a positive countdown when the
     * lockout only exists in the persistent store.
     */
    public function test_remaining_seconds_from_persistent_store() {
        update_option( 'wldelay_options', [
            'wldelay_lockout_enabled'  => true,
            'wldelay_lockout_duration' => 5, // minutes
        ] );
        wldelay_clear_options_cache();

        wldelay_lock_ip( self::TEST_IP );

        delete_transient( wldelay_get_lockout_transient_key( self::TEST_IP ) );
        wldelay_reset_persistence_runtime_cache();

        $remaining = wldelay_get_lockout_remaining_seconds( self::TEST_IP );
        $this->assertGreaterThan( 0, $remaining );
        $this->assertLessThanOrEqual( 300, $remaining );
    }

    /**
     * Clearing a lockout via the recovery helper removes it from the
     * persistent store as well.
     */
    public function test_delete_lockout_for_ip_clears_persistent_store() {
        update_option( 'wldelay_options', [
            'wldelay_lockout_enabled'  => true,
            'wldelay_lockout_duration' => 30,
        ] );
        wldelay_clear_options_cache();

        wldelay_lock_ip( self::TEST_IP );
        $this->assertTrue( wldelay_is_ip_locked( self::TEST_IP ) );

        wldelay_delete_lockout_for_ip( self::TEST_IP );
        wldelay_reset_persistence_runtime_cache();

        $store = wldelay_get_persistence_store();
        $this->assertFalse( $store->is_locked( self::TEST_IP, '' ) );
        $this->assertFalse( wldelay_is_ip_locked( self::TEST_IP ) );
    }

    /**
     * IP-level recovery clears a durable lockout that was stored with a
     * username under the ip_username strategy. The CLI/admin unlock path knows
     * only the IP, so a username-agnostic key cannot match the stored row — the
     * recovery must delete by IP (F-2-1).
     */
    public function test_ip_only_recovery_clears_ip_username_durable_lockout() {
        update_option( 'wldelay_options', [
            'wldelay_lockout_enabled'          => true,
            'wldelay_lockout_duration'         => 30,
            'wldelay_lockout_attempt_strategy' => 'ip_username',
        ] );
        wldelay_clear_options_cache();

        $store = wldelay_get_persistence_store();

        // Durable row keyed on (ip, username), as ip_username mode would store it.
        $store->add_lockout( self::TEST_IP, 'victim', 600, 'login' );
        $this->assertTrue( $store->is_locked( self::TEST_IP, 'victim' ) );

        // IP-only recovery — the unlock-ip CLI command passes no username.
        $removed = wldelay_delete_lockout_for_ip( self::TEST_IP );
        wldelay_reset_persistence_runtime_cache();

        $this->assertGreaterThanOrEqual( 1, $removed );
        $this->assertFalse(
            wldelay_get_persistence_store()->is_locked( self::TEST_IP, 'victim' ),
            'IP-only recovery must clear durable lockouts stored with a username'
        );
    }

    /**
     * IP-only recovery clears the username-scoped transient lockout, not just
     * the durable row. Under the ip_username strategy wldelay_lock_ip() sets a
     * transient keyed on md5("ip|username") AND a durable row; the IP-only
     * unlock (admin button / WP-CLI unlock-ip) supplies no username, so without
     * the row-driven transient cleanup the user would stay locked on the
     * transient fast-path until it expired. Asserted WITHOUT evicting the
     * transient first — recovery itself must clear it (F-2-1).
     */
    public function test_ip_only_recovery_clears_username_scoped_transient() {
        update_option( 'wldelay_options', [
            'wldelay_lockout_enabled'          => true,
            'wldelay_lockout_duration'         => 30,
            'wldelay_lockout_attempt_strategy' => 'ip_username',
        ] );
        wldelay_clear_options_cache();

        // Lock under a username — sets both the username-scoped transient and
        // the durable row.
        wldelay_lock_ip( self::TEST_IP, 'victim' );
        $this->assertTrue( wldelay_is_ip_locked( self::TEST_IP, 'victim' ) );

        // IP-only recovery — the unlock-ip CLI command / admin button pass no
        // username.
        $removed = wldelay_delete_lockout_for_ip( self::TEST_IP );

        // No transient eviction and no runtime-cache reset: recovery itself
        // must have removed the transient fast-path entry.
        $this->assertGreaterThanOrEqual( 1, $removed );
        $this->assertFalse(
            wldelay_is_ip_locked( self::TEST_IP, 'victim' ),
            'IP-only recovery must clear the username-scoped transient lockout, not just the durable row'
        );
    }

    /**
     * Flushing all lockouts empties the persistent store too.
     */
    public function test_flush_lockouts_clears_persistent_store() {
        update_option( 'wldelay_options', [
            'wldelay_lockout_enabled'  => true,
            'wldelay_lockout_duration' => 30,
        ] );
        wldelay_clear_options_cache();

        wldelay_lock_ip( '203.0.113.201' );
        wldelay_lock_ip( '203.0.113.202' );

        wldelay_flush_lockout_transients();
        wldelay_reset_persistence_runtime_cache();

        $store = wldelay_get_persistence_store();
        $this->assertEmpty( $store->get_active_lockouts() );
    }

    /**
     * Expired lockout rows are purged by the cleanup job even when log
     * retention is set to keep-forever (0), so the lockout table cannot grow
     * without bound on sites that retain logs indefinitely (F-2-1).
     */
    public function test_cleanup_purges_expired_lockouts_when_retention_zero() {
        update_option( 'wldelay_options', [ 'wldelay_log_retention_days' => 0 ] );
        wldelay_clear_options_cache();

        $store = wldelay_get_persistence_store();
        $store->add_lockout( '198.51.100.41', '', 600 );   // active
        $store->add_lockout( '198.51.100.42', '', -10 );    // expired

        wldelay_cleanup_old_logs();
        wldelay_reset_persistence_runtime_cache();

        $active = wldelay_get_persistence_store()->get_active_lockouts();
        $ips = array_column( $active, 'ip_address' );
        $this->assertContains( '198.51.100.41', $ips );

        // The expired row is gone from the table entirely, not just inactive.
        global $wpdb;
        $table = wldelay_get_lockout_table_name();
        $count = (int) $wpdb->get_var( "SELECT COUNT(*) FROM $table" );
        $this->assertSame( 1, $count );
    }

    /**
     * The DB upgrade hook creates the lockout table on a version bump.
     */
    public function test_upgrade_creates_lockout_table() {
        global $wpdb;

        $table = wldelay_get_lockout_table_name();
        $wpdb->query( "DROP TABLE IF EXISTS $table" );

        update_option( 'wldelay_db_version', '1.0.0' );
        wldelay_maybe_upgrade_db();

        $exists = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) );
        $this->assertEquals( $table, $exists );
    }

    /**
     * An existing install whose stored version is the previous plugin version
     * string (2.3.4 — the F-2-1 parent) still provisions the lockout table on
     * upgrade, because the schema gate compares against WLDELAY_DB_VERSION
     * rather than the user-facing plugin version (F-2-1).
     */
    public function test_upgrade_from_previous_plugin_version_creates_lockout_table() {
        global $wpdb;

        $table = wldelay_get_lockout_table_name();
        $wpdb->query( "DROP TABLE IF EXISTS $table" );

        update_option( 'wldelay_db_version', '2.3.4' );
        wldelay_maybe_upgrade_db();

        $exists = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) );
        $this->assertEquals( $table, $exists );
        $this->assertEquals( WLDELAY_DB_VERSION, get_option( 'wldelay_db_version' ) );
    }

    /**
     * The lockout table is created on activation alongside the log table.
     */
    public function test_activation_creates_lockout_table() {
        global $wpdb;

        $table = wldelay_get_lockout_table_name();
        $wpdb->query( "DROP TABLE IF EXISTS $table" );

        wldelay_create_tables();

        $exists = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) );
        $this->assertEquals( $table, $exists );
    }

    /**
     * Upgrading a gen-2 lockout table (username varchar(60) + the legacy
     * composite KEY ip_username) widens the column to varchar(255), drops the
     * legacy index, and only then records the gen-3 DB version. Proves the
     * migration does not leave the column at the old width while still marking
     * the schema as current (F-2-1).
     */
    public function test_upgrade_widens_gen2_username_column_and_drops_legacy_index() {
        global $wpdb;

        $table = wldelay_get_lockout_table_name();
        $wpdb->query( "DROP TABLE IF EXISTS $table" );

        // Recreate the gen-2 shape: narrow username + the legacy composite index.
        $charset_collate = $wpdb->get_charset_collate();
        $wpdb->query(
            "CREATE TABLE $table (
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
            ) $charset_collate;"
        );

        // Pre-condition: column is narrow and the legacy index is present.
        $this->assertFalse( wldelay_lockout_username_is_widened() );
        $legacy = $wpdb->get_var( "SHOW INDEX FROM $table WHERE Key_name = 'ip_username'" );
        $this->assertNotNull( $legacy );

        update_option( 'wldelay_db_version', '2' );
        wldelay_maybe_upgrade_db();

        // Column widened, legacy composite index gone, version recorded.
        $this->assertTrue( wldelay_lockout_username_is_widened() );
        $legacy_after = $wpdb->get_var( "SHOW INDEX FROM $table WHERE Key_name = 'ip_username'" );
        $this->assertNull( $legacy_after );
        $this->assertEquals( WLDELAY_DB_VERSION, get_option( 'wldelay_db_version' ) );
    }
}
