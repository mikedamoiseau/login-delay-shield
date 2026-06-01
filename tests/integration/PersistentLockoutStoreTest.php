<?php
/**
 * Integration tests for the DB-backed persistent lockout store (F-2-1).
 *
 * Covers table creation, the WLDelay_Persistence contract (add/get/is_locked/
 * remove/get_active/purge_expired/clear_all), and that a lockout survives a
 * simulated object-cache flush (the whole point of the durable store).
 */

class PersistentLockoutStoreTest extends WP_UnitTestCase {

    /**
     * @var WLDelay_DB_Persistence
     */
    private $store;

    public function setUp(): void {
        parent::setUp();

        wldelay_create_lockout_table();
        $this->truncate_lockout_table();

        delete_option( 'wldelay_options' );
        wldelay_clear_options_cache();

        // The store is a singleton across tests; reset its per-request
        // table-existence cache now that the table is provisioned.
        wldelay_reset_persistence_runtime_cache();

        $this->store = wldelay_get_persistence_store();
    }

    public function tearDown(): void {
        $this->truncate_lockout_table();
        delete_option( 'wldelay_options' );
        wldelay_clear_options_cache();
        parent::tearDown();
    }

    private function truncate_lockout_table() {
        global $wpdb;
        $table = wldelay_get_lockout_table_name();
        $wpdb->query( "TRUNCATE TABLE $table" ); // phpcs:ignore WordPress.DB
    }

    /**
     * The lockout table is created with the expected columns.
     */
    public function test_lockout_table_created_with_expected_columns() {
        global $wpdb;

        $table = wldelay_get_lockout_table_name();
        $columns = $wpdb->get_results( "DESCRIBE $table" );
        $names = array_column( $columns, 'Field' );

        $this->assertContains( 'id', $names );
        $this->assertContains( 'lockout_key', $names );
        $this->assertContains( 'ip_address', $names );
        $this->assertContains( 'username', $names );
        $this->assertContains( 'lockout_type', $names );
        $this->assertContains( 'source', $names );
        $this->assertContains( 'created_at', $names );
        $this->assertContains( 'expires_at', $names );
    }

    /**
     * The lockout table carries a unique lockout_key index (the hot-path
     * lookup), an IP index, and an expires_at index. The username is part of
     * the hashed lockout_key, so it is intentionally not a standalone indexed
     * column (F-2-1).
     */
    public function test_lockout_table_has_indexes() {
        global $wpdb;

        $table = wldelay_get_lockout_table_name();
        $indexes = $wpdb->get_results( "SHOW INDEX FROM $table" );
        $names = array_unique( array_column( $indexes, 'Key_name' ) );

        $this->assertContains( 'PRIMARY', $names );
        $this->assertContains( 'lockout_key', $names );
        $this->assertContains( 'ip_address', $names );
        $this->assertContains( 'expires_at', $names );
    }

    /**
     * add_lockout + get_lockout round-trips a record.
     */
    public function test_add_and_get_lockout() {
        $this->store->add_lockout( '203.0.113.5', 'alice', 600, 'login', 'wp-login' );

        $record = $this->store->get_lockout( '203.0.113.5', 'alice' );

        $this->assertNotNull( $record );
        $this->assertSame( '203.0.113.5', $record['ip_address'] );
        $this->assertSame( 'alice', $record['username'] );
        $this->assertSame( 'login', $record['lockout_type'] );
        $this->assertSame( 'wp-login', $record['source'] );
        $this->assertGreaterThan( time(), $record['expires_at'] );
    }

    /**
     * is_locked returns true for an active lockout and false otherwise.
     */
    public function test_is_locked_true_for_active_lockout() {
        $this->assertFalse( $this->store->is_locked( '203.0.113.6', 'bob' ) );

        $this->store->add_lockout( '203.0.113.6', 'bob', 600 );

        $this->assertTrue( $this->store->is_locked( '203.0.113.6', 'bob' ) );
    }

    /**
     * An expired lockout is not considered active.
     */
    public function test_is_locked_false_for_expired_lockout() {
        // Insert directly with an already-passed expiry.
        $this->store->add_lockout( '203.0.113.7', 'carol', -10 );

        $this->assertFalse( $this->store->is_locked( '203.0.113.7', 'carol' ) );
    }

    /**
     * remove_lockout deletes the record.
     */
    public function test_remove_lockout() {
        $this->store->add_lockout( '203.0.113.8', 'dave', 600 );
        $this->assertTrue( $this->store->is_locked( '203.0.113.8', 'dave' ) );

        $removed = $this->store->remove_lockout( '203.0.113.8', 'dave' );

        $this->assertGreaterThanOrEqual( 1, $removed );
        $this->assertFalse( $this->store->is_locked( '203.0.113.8', 'dave' ) );
    }

    /**
     * add_lockout for an existing key updates rather than duplicates.
     */
    public function test_add_lockout_is_idempotent_per_key() {
        global $wpdb;
        $table = wldelay_get_lockout_table_name();

        $this->store->add_lockout( '203.0.113.9', 'erin', 600 );
        $this->store->add_lockout( '203.0.113.9', 'erin', 900 );

        $count = (int) $wpdb->get_var( "SELECT COUNT(*) FROM $table" );
        $this->assertSame( 1, $count );

        $record = $this->store->get_lockout( '203.0.113.9', 'erin' );
        $this->assertGreaterThan( time() + 700, $record['expires_at'] );
    }

    /**
     * get_active_lockouts enumerates only the non-expired entries.
     */
    public function test_get_active_lockouts_lists_only_active() {
        $this->store->add_lockout( '198.51.100.1', '', 600 );
        $this->store->add_lockout( '198.51.100.2', '', 600 );
        $this->store->add_lockout( '198.51.100.3', '', -10 ); // expired

        $active = $this->store->get_active_lockouts();

        $ips = array_column( $active, 'ip_address' );
        $this->assertContains( '198.51.100.1', $ips );
        $this->assertContains( '198.51.100.2', $ips );
        $this->assertNotContains( '198.51.100.3', $ips );
    }

    /**
     * purge_expired deletes expired rows and keeps active ones.
     */
    public function test_purge_expired() {
        global $wpdb;
        $table = wldelay_get_lockout_table_name();

        $this->store->add_lockout( '198.51.100.10', '', 600 );  // active
        $this->store->add_lockout( '198.51.100.11', '', -10 );  // expired
        $this->store->add_lockout( '198.51.100.12', '', -20 );  // expired

        $purged = $this->store->purge_expired();

        $this->assertSame( 2, $purged );
        $count = (int) $wpdb->get_var( "SELECT COUNT(*) FROM $table" );
        $this->assertSame( 1, $count );
    }

    /**
     * clear_all empties the table.
     */
    public function test_clear_all() {
        global $wpdb;
        $table = wldelay_get_lockout_table_name();

        $this->store->add_lockout( '198.51.100.20', '', 600 );
        $this->store->add_lockout( '198.51.100.21', '', 600 );

        $cleared = $this->store->clear_all();

        $this->assertGreaterThanOrEqual( 2, $cleared );
        $count = (int) $wpdb->get_var( "SELECT COUNT(*) FROM $table" );
        $this->assertSame( 0, $count );
    }

    /**
     * A lockout survives an object-cache flush — the durability guarantee.
     *
     * We write a lockout, flush the in-memory transient/object cache (which is
     * what would happen on cache eviction), and assert the lockout is still
     * reported as active because it lives in the DB.
     */
    public function test_lockout_survives_object_cache_flush() {
        $this->store->add_lockout( '203.0.113.50', 'frank', 600 );
        $this->assertTrue( $this->store->is_locked( '203.0.113.50', 'frank' ) );

        // Simulate object-cache eviction: wipe the in-memory cache and any
        // same-request static cache the store may hold.
        wp_cache_flush();
        wldelay_reset_persistence_runtime_cache();

        $this->assertTrue(
            $this->store->is_locked( '203.0.113.50', 'frank' ),
            'DB-backed lockout must survive an object-cache flush'
        );
    }

    /**
     * lockout_type isolates login lockouts from password-reset lockouts.
     */
    public function test_lockout_type_isolated() {
        $this->store->add_lockout( '203.0.113.60', 'gina', 600, 'login' );

        $this->assertTrue( $this->store->is_locked( '203.0.113.60', 'gina', 'login' ) );
        $this->assertFalse( $this->store->is_locked( '203.0.113.60', 'gina', 'password-reset' ) );
    }

    /**
     * A canonical identifier longer than the old 60-char column (LDAP/SSO/email
     * via the wldelay_normalize_username filter) is persisted durably and
     * matched exactly, instead of failing the INSERT under strict SQL mode and
     * degrading to a transient-only lockout (F-2-1).
     */
    public function test_long_username_persists_and_matches() {
        $long = str_repeat( 'a', 80 ) . '@sso.example.com'; // 96 chars, > old varchar(60)

        $this->assertTrue( $this->store->add_lockout( '203.0.113.70', $long, 600 ) );

        // Eviction-proof: clear the per-request cache and confirm the DB row
        // still answers, keyed on the full (untruncated) identifier.
        wldelay_reset_persistence_runtime_cache();
        $this->assertTrue( $this->store->is_locked( '203.0.113.70', $long ) );

        $record = $this->store->get_lockout( '203.0.113.70', $long );
        $this->assertNotNull( $record );
        $this->assertSame( '203.0.113.70', $record['ip_address'] );
    }

    /**
     * Two distinct identifiers that share the first 60 characters do not
     * collide, proving the lockout key hashes the full identifier rather than
     * the truncated column value (F-2-1).
     */
    public function test_long_usernames_sharing_prefix_do_not_collide() {
        $prefix = str_repeat( 'b', 60 );
        $one    = $prefix . '-one@example.com';
        $two    = $prefix . '-two@example.com';

        $this->store->add_lockout( '203.0.113.71', $one, 600 );

        $this->assertTrue( $this->store->is_locked( '203.0.113.71', $one ) );
        $this->assertFalse( $this->store->is_locked( '203.0.113.71', $two ) );
    }

    /**
     * A caller-supplied source longer than the source column (varchar(20)) is
     * clamped so the INSERT cannot fail under strict SQL mode and degrade the
     * lockout to transient-only. The durable row is still written and matched
     * (F-2-1).
     */
    public function test_long_source_persists_and_does_not_drop_lockout() {
        $long_source = str_repeat( 'x', 64 ); // 64 chars, > source varchar(20)

        $this->assertTrue(
            $this->store->add_lockout( '203.0.113.72', 'hank', 600, 'login', $long_source ),
            'An oversized source must not fail the durable INSERT'
        );

        wldelay_reset_persistence_runtime_cache();
        $this->assertTrue( $this->store->is_locked( '203.0.113.72', 'hank' ) );

        // The stored source is clamped to the column width, not dropped.
        $record = $this->store->get_lockout( '203.0.113.72', 'hank' );
        $this->assertNotNull( $record );
        $this->assertSame( 20, strlen( $record['source'] ) );
    }

    /**
     * remove_lockouts_for_ip deletes every row for an IP regardless of the
     * username or type the row was keyed under — the IP-level recovery path
     * (F-2-1).
     */
    public function test_remove_lockouts_for_ip_clears_all_keys() {
        $this->store->add_lockout( '203.0.113.80', 'alice', 600, 'login' );
        $this->store->add_lockout( '203.0.113.80', 'alice', 600, 'password-reset' );
        $this->store->add_lockout( '203.0.113.80', 'bob', 600, 'login' );
        $this->store->add_lockout( '203.0.113.81', 'carol', 600, 'login' ); // other IP, untouched

        $removed = $this->store->remove_lockouts_for_ip( '203.0.113.80' );

        $this->assertSame( 3, $removed );
        $this->assertFalse( $this->store->is_locked( '203.0.113.80', 'alice', 'login' ) );
        $this->assertFalse( $this->store->is_locked( '203.0.113.80', 'alice', 'password-reset' ) );
        $this->assertFalse( $this->store->is_locked( '203.0.113.80', 'bob', 'login' ) );
        $this->assertTrue( $this->store->is_locked( '203.0.113.81', 'carol', 'login' ) );
    }

    /**
     * The lockout table name follows the active $wpdb->prefix rather than
     * pinning the first prefix seen. Under multisite a request can
     * switch_to_blog() between calls; a globally-cached name would resolve the
     * wrong site's table and leak lockouts across sites (F-2-1).
     */
    public function test_table_name_follows_active_wpdb_prefix() {
        global $wpdb;

        $original = $wpdb->prefix;

        // Prime the cache with the current prefix.
        $this->assertSame( $original . 'wldelay_lockouts', wldelay_get_lockout_table_name() );

        // Simulate switch_to_blog() pointing $wpdb at another site's prefix.
        $wpdb->set_prefix( 'wptest7_' );
        $switched = wldelay_get_lockout_table_name();

        // Restore before asserting so a failure cannot poison later tests.
        $wpdb->set_prefix( $original );

        $this->assertSame( 'wptest7_wldelay_lockouts', $switched );
        $this->assertSame( $original . 'wldelay_lockouts', wldelay_get_lockout_table_name() );
    }
}
