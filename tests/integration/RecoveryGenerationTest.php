<?php
/**
 * Integration tests for the recovery-flush race hardening (F-2-1).
 *
 * Recovery (admin/CLI unlock-ip + bulk flush-lockouts) used to clear lockouts
 * unconditionally. When transients live in an EXTERNAL object cache a concurrent
 * same-second relock could be created/refreshed DURING the recovery window and
 * then be deleted as if it were a snapshot row, orphaning the live lockout and
 * leaving a user locked after recovery reported success.
 *
 * The fix stamps a unique GENERATION token on every transient-registry write and
 * on every durable lockout INSERT/refresh, snapshots the rows/records before
 * cleanup, and conditionally deletes only those whose generation still matches
 * the snapshot. These tests prove the refreshed row/record survives while the
 * snapshot one is removed — and that legacy (no-gen) records still clean up.
 */

class RecoveryGenerationTest extends WP_UnitTestCase {

    /**
     * @var WLDelay_DB_Persistence
     */
    private $store;

    public function setUp(): void {
        parent::setUp();

        wldelay_create_lockout_table();
        $this->truncate_lockout_table();

        delete_option( 'wldelay_options' );
        delete_option( wldelay_get_transient_registry_option_name() );
        wldelay_clear_options_cache();
        wldelay_reset_persistence_runtime_cache();

        $this->store = wldelay_get_persistence_store();
    }

    public function tearDown(): void {
        $this->truncate_lockout_table();
        delete_option( 'wldelay_options' );
        delete_option( wldelay_get_transient_registry_option_name() );
        wldelay_clear_options_cache();
        parent::tearDown();
    }

    private function truncate_lockout_table() {
        global $wpdb;
        $table = wldelay_get_lockout_table_name();
        $wpdb->query( "TRUNCATE TABLE $table" ); // phpcs:ignore WordPress.DB
    }

    /**
     * Read the current generation stored for a durable lockout row.
     */
    private function row_generation( $ip, $username = '', $type = 'login' ) {
        global $wpdb;
        $table = wldelay_get_lockout_table_name();
        $key   = wldelay_get_lockout_storage_key( $ip, $username, $type );

        return $wpdb->get_var(
            $wpdb->prepare( "SELECT generation FROM $table WHERE lockout_key = %s", $key )
        );
    }

    /* ---------------------------------------------------------------------
     * Schema
     * ------------------------------------------------------------------ */

    public function test_lockout_table_has_generation_column() {
        $this->assertTrue(
            wldelay_lockout_has_generation_column(),
            'The lockout table must carry the gen-6 generation column'
        );
    }

    public function test_add_lockout_writes_a_nonempty_generation() {
        $ip = '198.51.100.10';
        $this->store->add_lockout( $ip, '', 900, 'login', 'wp-login', 'wldelay_lockout_x' );

        $gen = $this->row_generation( $ip );
        $this->assertNotEmpty( $gen, 'Every lockout write must stamp a generation token' );
    }

    public function test_add_lockout_refresh_rotates_the_generation() {
        $ip = '198.51.100.11';

        $this->store->add_lockout( $ip, '', 900, 'login', 'wp-login', 'wldelay_lockout_x' );
        $gen_a = $this->row_generation( $ip );

        // A re-lock (refresh) of the same identity must write a NEW generation
        // through the ON DUPLICATE KEY UPDATE path.
        $this->store->add_lockout( $ip, '', 900, 'login', 'wp-login', 'wldelay_lockout_x' );
        $gen_b = $this->row_generation( $ip );

        $this->assertNotEmpty( $gen_a );
        $this->assertNotEmpty( $gen_b );
        $this->assertNotEquals(
            $gen_a,
            $gen_b,
            'A refresh must rotate the generation so recovery can tell a relock apart'
        );
    }

    /* ---------------------------------------------------------------------
     * Finding 1 — transient registry generation
     * ------------------------------------------------------------------ */

    /**
     * A concurrent same-second relock rewrites the registry record with a NEW
     * generation. The conditional unregister, run against the OLD snapshot, must
     * NOT delete it — and the live transient stays discoverable.
     */
    public function test_registry_conditional_unregister_skips_refreshed_record() {
        $key = wldelay_get_lockout_transient_key( '198.51.100.20' );

        // Original registration + snapshot (what recovery captures).
        wldelay_register_transient_key( $key, time() + HOUR_IN_SECONDS );
        $snapshot = wldelay_get_transient_registry_record( $key );
        $this->assertIsArray( $snapshot );
        $this->assertArrayHasKey( 'gen', $snapshot );

        // Concurrent relock during the recovery window: re-register the SAME key,
        // producing a new generation.
        wldelay_register_transient_key( $key, time() + HOUR_IN_SECONDS );
        $refreshed = wldelay_get_transient_registry_record( $key );
        $this->assertNotEquals(
            $snapshot['gen'],
            $refreshed['gen'],
            'Re-registration must rotate the registry generation'
        );

        // Recovery attempts to remove the record it snapshotted — must be a no-op.
        $removed = wldelay_unregister_transient_record_if_unchanged( $key, $snapshot );

        $this->assertFalse( $removed, 'A refreshed record must NOT be unregistered' );
        $this->assertContains(
            $key,
            wldelay_get_registered_transient_keys(),
            'The refreshed (live) transient must remain discoverable by later flushes'
        );
    }

    /**
     * With no concurrent activity the conditional unregister removes the record.
     */
    public function test_registry_conditional_unregister_removes_unchanged_record() {
        $key = wldelay_get_lockout_transient_key( '198.51.100.21' );
        wldelay_register_transient_key( $key, time() + HOUR_IN_SECONDS );
        $snapshot = wldelay_get_transient_registry_record( $key );

        $removed = wldelay_unregister_transient_record_if_unchanged( $key, $snapshot );

        $this->assertTrue( $removed );
        $this->assertNotContains( $key, wldelay_get_registered_transient_keys() );
    }

    /**
     * Backward compatibility: a legacy registry record without a 'gen' is still
     * enumerated and is still removable by the conditional unregister. The
     * atomic compare-and-delete matches the exact serialized legacy (key,exp)
     * value, so an unchanged legacy record is cleaned and never stranded.
     */
    public function test_legacy_record_without_generation_is_enumerated_and_flushable() {
        $key    = wldelay_get_lockout_transient_key( '198.51.100.22' );
        $record = wldelay_get_transient_registry_key_prefix() . md5( $key );

        // Write a legacy key+exp record (the pre-hardening format, no gen).
        update_option(
            $record,
            array( 'key' => $key, 'exp' => time() + HOUR_IN_SECONDS ),
            false
        );

        $this->assertContains(
            $key,
            wldelay_get_registered_transient_keys(),
            'A legacy no-gen record must still be enumerated'
        );

        $snapshot = wldelay_get_transient_registry_record( $key );
        $removed  = wldelay_unregister_transient_record_if_unchanged( $key, $snapshot );

        $this->assertTrue( $removed, 'A legacy no-gen record must still be flushable' );
        $this->assertNotContains( $key, wldelay_get_registered_transient_keys() );
    }

    /* ---------------------------------------------------------------------
     * Finding 2 — durable lockout generation (unlock-ip / single IP)
     * ------------------------------------------------------------------ */

    /**
     * A concurrent refresh during single-IP recovery (new generation) survives
     * the conditional delete, so the IP stays locked rather than being orphaned.
     */
    public function test_durable_unlock_ip_keeps_concurrently_refreshed_row() {
        $ip = '203.0.113.30';

        $this->store->add_lockout( $ip, '', 900, 'login', 'wp-login', 'wldelay_lockout_a' );

        // Recovery snapshots the rows for the IP (gen A).
        $snapshot = $this->store->get_lockouts_for_ip( $ip );
        $this->assertCount( 1, $snapshot );
        $this->assertArrayHasKey( 'generation', $snapshot[0] );
        $gen_a = $snapshot[0]['generation'];

        // Concurrent failed login refreshes the SAME row → generation B.
        $this->store->add_lockout( $ip, '', 900, 'login', 'wp-login', 'wldelay_lockout_a' );
        $this->assertNotEquals( $gen_a, $this->row_generation( $ip ) );

        // Recovery conditionally deletes only rows still at gen A — the refreshed
        // row (gen B) must survive.
        $removed = $this->store->remove_lockouts_matching_generation( $snapshot );

        $this->assertSame( 0, $removed, 'A row refreshed during recovery must NOT be deleted' );
        $this->assertTrue(
            $this->store->is_locked( $ip, '' ),
            'The IP must stay locked when its row was refreshed during recovery'
        );
    }

    /**
     * Happy path: with no concurrent activity the conditional delete removes the
     * snapshot row and the IP is cleared.
     */
    public function test_durable_unlock_ip_removes_unchanged_row() {
        $ip = '203.0.113.31';
        $this->store->add_lockout( $ip, '', 900, 'login', 'wp-login', 'wldelay_lockout_b' );

        $snapshot = $this->store->get_lockouts_for_ip( $ip );
        $removed  = $this->store->remove_lockouts_matching_generation( $snapshot );

        $this->assertSame( 1, $removed );
        $this->assertFalse( $this->store->is_locked( $ip, '' ) );
    }

    /**
     * End-to-end: wldelay_delete_lockout_for_ip() (the function both the admin
     * handler and the WP-CLI unlock-ip command call) clears a genuine lockout
     * with no concurrent activity, and a relock that lands AFTER recovery
     * completes (new generation) re-locks the IP — the durable row is not
     * resurrected from a stale generation and the conditional delete never
     * touched it. This guards the no-regression path for the live recovery
     * entry point.
     */
    public function test_delete_lockout_for_ip_clears_then_allows_fresh_relock() {
        $ip            = '203.0.113.32';
        $transient_key = wldelay_get_lockout_transient_key( $ip );

        set_transient( $transient_key, time(), 15 * MINUTE_IN_SECONDS );
        wldelay_register_transient_key( $transient_key, time() + 15 * MINUTE_IN_SECONDS );
        $this->store->add_lockout( $ip, '', 900, 'login', 'wp-login', $transient_key );

        $this->assertTrue( $this->store->is_locked( $ip, '' ) );

        wldelay_delete_lockout_for_ip( $ip );

        $this->assertFalse(
            $this->store->is_locked( $ip, '' ),
            'A normal unlock with no concurrent activity must fully clear the lockout'
        );

        // A relock after recovery completes re-locks the IP normally.
        $this->store->add_lockout( $ip, '', 900, 'login', 'wp-login', $transient_key );
        $this->assertTrue( $this->store->is_locked( $ip, '' ) );
    }

    /* ---------------------------------------------------------------------
     * Finding 2 — bulk flush across multiple IPs
     * ------------------------------------------------------------------ */

    /**
     * In a bulk flush, rows refreshed during the flush (new generation) survive
     * while snapshot rows are removed.
     */
    public function test_bulk_flush_keeps_refreshed_rows_and_removes_snapshot_rows() {
        $ip_keep   = '203.0.113.40';
        $ip_remove = '203.0.113.41';

        $this->store->add_lockout( $ip_keep, '', 900, 'login', 'wp-login', 'wldelay_lockout_keep' );
        $this->store->add_lockout( $ip_remove, '', 900, 'login', 'wp-login', 'wldelay_lockout_remove' );

        // Bulk recovery snapshots both active rows.
        $snapshot = $this->store->get_active_lockouts( PHP_INT_MAX );
        $this->assertCount( 2, $snapshot );

        // A concurrent failed login refreshes ip_keep during the flush window.
        $this->store->add_lockout( $ip_keep, '', 900, 'login', 'wp-login', 'wldelay_lockout_keep' );

        // Conditional delete against the snapshot: ip_remove (unchanged) goes,
        // ip_keep (new generation) survives.
        $removed = $this->store->remove_lockouts_matching_generation( $snapshot );

        $this->assertSame( 1, $removed, 'Only the unchanged snapshot row should be deleted' );
        $this->assertTrue(
            $this->store->is_locked( $ip_keep, '' ),
            'The row refreshed during the flush must survive'
        );
        $this->assertFalse(
            $this->store->is_locked( $ip_remove, '' ),
            'The untouched snapshot row must be removed'
        );
    }

    /**
     * Happy path: a normal bulk flush with no concurrent activity removes every
     * active row (no regression).
     */
    public function test_bulk_flush_removes_all_rows_without_concurrency() {
        $this->store->add_lockout( '203.0.113.50', '', 900, 'login', 'wp-login', 'wldelay_lockout_p' );
        $this->store->add_lockout( '203.0.113.51', '', 900, 'login', 'wp-login', 'wldelay_lockout_q' );

        $snapshot = $this->store->get_active_lockouts( PHP_INT_MAX );
        $removed  = $this->store->remove_lockouts_matching_generation( $snapshot );

        $this->assertSame( 2, $removed );
        $this->assertFalse( $this->store->is_locked( '203.0.113.50', '' ) );
        $this->assertFalse( $this->store->is_locked( '203.0.113.51', '' ) );
    }

    /**
     * Backward compatibility: a legacy durable row whose generation is the empty
     * string (predating the column default population) is still removable by the
     * conditional delete when the snapshot also carries the empty generation.
     */
    public function test_legacy_durable_row_with_empty_generation_is_removable() {
        global $wpdb;
        $ip    = '203.0.113.60';
        $table = wldelay_get_lockout_table_name();

        $this->store->add_lockout( $ip, '', 900, 'login', 'wp-login', 'wldelay_lockout_legacy' );

        // Simulate a legacy row: force the generation back to the column default.
        $key = wldelay_get_lockout_storage_key( $ip, '', 'login' );
        $wpdb->query(
            $wpdb->prepare( "UPDATE $table SET generation = '' WHERE lockout_key = %s", $key )
        );

        $snapshot = $this->store->get_lockouts_for_ip( $ip );
        $this->assertSame( '', (string) $snapshot[0]['generation'] );

        $removed = $this->store->remove_lockouts_matching_generation( $snapshot );

        $this->assertSame( 1, $removed, 'A legacy empty-generation row must still be removable' );
        $this->assertFalse( $this->store->is_locked( $ip, '' ) );
    }

    /* ---------------------------------------------------------------------
     * Atomic compare-and-delete (Codex F1/F2/F3, Codex-2 F1/F2)
     * ------------------------------------------------------------------ */

    /**
     * The registry cleanup is a single compare-and-delete keyed on the exact
     * serialized snapshot value, so there is no read-then-delete window. We
     * assert the post-condition directly: a record whose stored value differs
     * from the snapshot (the outcome of a concurrent relock landing in the
     * window) is NOT deleted. This is the interleaving the helper could not
     * survive before — a relock between read and unconditional delete.
     */
    public function test_atomic_unregister_does_not_delete_a_value_changed_after_snapshot() {
        $key = wldelay_get_lockout_transient_key( '198.51.100.30' );
        wldelay_register_transient_key( $key, time() + HOUR_IN_SECONDS );
        $snapshot = wldelay_get_transient_registry_record( $key );

        // Simulate the concurrent relock that lands AFTER the snapshot is taken
        // but BEFORE the delete: the live record now carries a new generation.
        wldelay_register_transient_key( $key, time() + HOUR_IN_SECONDS );

        $removed = wldelay_unregister_transient_record_if_unchanged( $key, $snapshot );

        $this->assertFalse(
            $removed,
            'A record whose value changed after the snapshot must not be deleted'
        );
        $this->assertContains(
            $key,
            wldelay_get_registered_transient_keys(),
            'The relocked record (and its live transient) must stay discoverable'
        );
    }

    /**
     * Upgrade window (Codex F2): a legacy no-gen record that a concurrent relock
     * upgraded to a gen-bearing value during recovery must NOT be deleted by a
     * legacy snapshot. The atomic delete matches the exact serialized legacy
     * value, never the upgraded one, so the race cannot reopen mid-rollout.
     */
    public function test_legacy_snapshot_does_not_delete_a_concurrently_upgraded_record() {
        $key    = wldelay_get_lockout_transient_key( '198.51.100.31' );
        $record = wldelay_get_transient_registry_key_prefix() . md5( $key );

        // Pre-hardening legacy record (no gen) — what recovery snapshots.
        update_option(
            $record,
            array( 'key' => $key, 'exp' => time() + HOUR_IN_SECONDS ),
            false
        );
        $snapshot = wldelay_get_transient_registry_record( $key );
        $this->assertArrayNotHasKey( 'gen', $snapshot );

        // Concurrent relock upgrades the record to the gen-bearing format.
        wldelay_register_transient_key( $key, time() + HOUR_IN_SECONDS );

        $removed = wldelay_unregister_transient_record_if_unchanged( $key, $snapshot );

        $this->assertFalse(
            $removed,
            'A legacy snapshot must not delete a record a relock upgraded to gen-bearing'
        );
        $this->assertContains( $key, wldelay_get_registered_transient_keys() );
    }

    /**
     * Null-snapshot path (Codex F2 / Codex-2 F2): when no per-key record existed
     * at snapshot time, the helper must NOT unconditionally delete a per-key
     * record — a concurrent relock that created one inside the recovery window
     * must survive. The legacy shared array is cleared wholesale by the flush
     * path, so the per-key slot is correctly left to the live writer.
     */
    public function test_null_snapshot_does_not_clobber_a_concurrently_created_record() {
        $key = wldelay_get_lockout_transient_key( '198.51.100.32' );

        // No per-key record exists when recovery snapshots.
        $this->assertNull( wldelay_get_transient_registry_record( $key ) );
        $snapshot = wldelay_get_transient_registry_record( $key );

        // Concurrent relock creates a fresh per-key record inside the window.
        wldelay_register_transient_key( $key, time() + HOUR_IN_SECONDS );

        $removed = wldelay_unregister_transient_record_if_unchanged( $key, $snapshot );

        $this->assertFalse( $removed, 'A null snapshot must be a no-op, not an unconditional delete' );
        $this->assertContains(
            $key,
            wldelay_get_registered_transient_keys(),
            'The concurrently created record must survive a null-snapshot cleanup'
        );
    }
}
