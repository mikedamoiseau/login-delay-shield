<?php
/**
 * Integration tests for admin-screen rate-limiting (F-3-2).
 *
 * Covers:
 * - wldelay_admin_throttled_log_count(): per-user transient cache for log-table
 *   COUNT aggregates; stale within the 60-second window, live for logged-out users
 *   and different filter sets.
 * - wldelay_check_export_throttle(): one-run-per-60-seconds gate for the CSV
 *   export endpoint.
 */

class AdminThrottleTest extends WP_UnitTestCase {

    /**
     * User IDs created during this test class run, for transient cleanup.
     *
     * @var int[]
     */
    private array $created_user_ids = array();

    public function setUp(): void {
        parent::setUp();
        wldelay_create_log_table();

        global $wpdb;
        $wpdb->query( 'TRUNCATE TABLE ' . wldelay_get_log_table_name() );
    }

    public function tearDown(): void {
        // Clean up per-user throttle transients created during tests.
        foreach ( $this->created_user_ids as $uid ) {
            delete_transient( 'wldelay_admin_qcache_' . $uid );
            delete_transient( 'wldelay_export_throttle_' . $uid );
        }
        $this->created_user_ids = array();

        wp_set_current_user( 0 );
        parent::tearDown();
    }

    // -------------------------------------------------------------------------
    // Helper
    // -------------------------------------------------------------------------

    private function make_admin(): int {
        $uid                      = self::factory()->user->create( array( 'role' => 'administrator' ) );
        $this->created_user_ids[] = $uid;
        return $uid;
    }

    // -------------------------------------------------------------------------
    // wldelay_admin_throttled_log_count()
    // -------------------------------------------------------------------------

    /**
     * The same filter set served from cache within the 60-second window.
     *
     * A new row inserted after the first call should NOT appear in the count
     * returned by the second call — the cached value is served stale.
     */
    public function test_identical_filtered_count_served_from_cache_within_60s() {
        $uid     = $this->make_admin();
        wp_set_current_user( $uid );
        $filters = array( 'username' => 'admin' );

        $first = wldelay_admin_throttled_log_count( $filters );

        // Insert a matching row AFTER the first call.
        wldelay_log_failed_attempt( '198.51.100.99', 'admin', 'wp-login' );

        $second = wldelay_admin_throttled_log_count( $filters );

        // Both calls must return the same (cached) value.
        $this->assertSame( $first, $second, 'Count should be served stale from cache within 60 s' );
    }

    /**
     * Different filter sets must bypass the cache and return a live count.
     *
     * The cache is keyed on the MD5 of the filter array. A different filter
     * set must hit the DB and return the real count.
     */
    public function test_different_filters_bypass_cache() {
        $uid = $this->make_admin();
        wp_set_current_user( $uid );

        wldelay_admin_throttled_log_count( array( 'username' => 'a' ) );
        $count_b = wldelay_admin_throttled_log_count( array( 'username' => 'b' ) );

        $this->assertSame(
            wldelay_count_login_log_attempts( array( 'username' => 'b' ) ),
            $count_b,
            'Different filters must produce a live (non-cached) count'
        );
    }

    /**
     * Logged-out (user_id === 0) requests must always return the live count.
     *
     * No per-user transient should be written for anonymous access.
     */
    public function test_no_cache_for_logged_out_user() {
        wp_set_current_user( 0 );

        // Insert a row, then call the throttled wrapper twice.
        wldelay_log_failed_attempt( '198.51.100.50', 'anon-user', 'wp-login' );
        $first = wldelay_admin_throttled_log_count( array() );

        // Insert another row — the second call must reflect it.
        wldelay_log_failed_attempt( '198.51.100.51', 'anon-user-2', 'wp-login' );
        $second = wldelay_admin_throttled_log_count( array() );

        $this->assertGreaterThan( $first, $second, 'Logged-out path must always return a fresh count' );

        // Confirm no transient was written for user 0.
        $this->assertFalse(
            get_transient( 'wldelay_admin_qcache_0' ),
            'No cache transient should be created for logged-out users'
        );
    }

    /**
     * Two different users must not share a cache — each has its own transient key.
     *
     * User B has no warm cache when User A has already called the function.
     * User B's first call must return the live (post-insert) count, not A's stale
     * cached value.
     */
    public function test_two_users_do_not_share_cache() {
        $uid_a = $this->make_admin();
        $uid_b = $this->make_admin();

        wp_set_current_user( $uid_a );
        wldelay_admin_throttled_log_count( array( 'username' => 'shared' ) );
        wldelay_log_failed_attempt( '198.51.100.5', 'shared', 'wp-login' );

        // User B has no cache yet → must see the live (post-insert) count, not A's cached value.
        wp_set_current_user( $uid_b );
        $b_count = wldelay_admin_throttled_log_count( array( 'username' => 'shared' ) );
        $this->assertSame( wldelay_count_login_log_attempts( array( 'username' => 'shared' ) ), $b_count );

        // Each user has its own transient key.
        $this->assertNotFalse( get_transient( 'wldelay_admin_qcache_' . $uid_a ) );
        $this->assertNotFalse( get_transient( 'wldelay_admin_qcache_' . $uid_b ) );
    }

    /**
     * Hammering with many DIFFERENT filter sets overwrites ONE transient per user —
     * no unbounded transient churn.
     */
    public function test_no_transient_churn_across_different_filter_sets() {
        $uid = $this->make_admin();
        wp_set_current_user( $uid );

        $usernames = array( 'alice', 'bob', 'carol', 'dave', 'eve' );
        foreach ( $usernames as $u ) {
            wldelay_admin_throttled_log_count( array( 'username' => $u ) );
        }

        // The transient for user $uid must exist (the last write overwrote the key).
        $cached = get_transient( 'wldelay_admin_qcache_' . $uid );
        $this->assertIsArray( $cached, 'A single transient per user should exist after multiple filter-set calls' );

        // The stored hash should correspond to the LAST filter set used.
        $last_hash = md5( wp_json_encode( array( 'username' => 'eve' ) ) );
        $this->assertSame( $last_hash, $cached['hash'] );
    }

    // -------------------------------------------------------------------------
    // wldelay_check_export_throttle()
    // -------------------------------------------------------------------------

    /**
     * When a throttle transient already exists for the current user, the gate
     * must return WP_Error.
     */
    public function test_export_refused_within_60s_of_previous_export() {
        $uid = $this->make_admin();
        wp_set_current_user( $uid );

        // Pre-set the throttle transient as if an export happened moments ago.
        set_transient( 'wldelay_export_throttle_' . $uid, time(), 60 );

        $result = wldelay_check_export_throttle();

        $this->assertWPError( $result, 'Export within 60 s of previous export must be refused with WP_Error' );
        $this->assertSame( 'wldelay_export_throttled', $result->get_error_code() );
    }

    /**
     * When no throttle transient exists the gate must:
     *   1. Return true (allowed).
     *   2. SET the throttle transient so the immediate next call is refused.
     */
    public function test_export_allowed_when_no_recent_export() {
        $uid = $this->make_admin();
        wp_set_current_user( $uid );

        delete_transient( 'wldelay_export_throttle_' . $uid );

        // First call — no prior export.
        $first = wldelay_check_export_throttle();
        $this->assertTrue( $first, 'First export call with no throttle transient must return true' );

        // Second immediate call — throttle must now be active.
        $second = wldelay_check_export_throttle();
        $this->assertWPError( $second, 'Second immediate call must be refused after the first set the throttle' );
    }
}
