<?php
/**
 * Integration tests for the split dashboard sub-caches (F-4-1).
 *
 * The dashboard widget data used to live in a single transient that was deleted
 * on every failed login, which thrashed the expensive 7-day trends aggregate
 * under a brute-force attack. The data is now split into two independent
 * transients: a cheap fast-moving "recent attempts" list (short TTL, invalidated
 * per failed attempt) and the expensive "trends" aggregate (longer TTL, NOT
 * invalidated per attempt). These tests pin that narrow-invalidation behaviour.
 */
class DashboardCacheTest extends WP_UnitTestCase {

    public function setUp(): void {
        parent::setUp();

        $admin_id = $this->factory->user->create( array( 'role' => 'administrator' ) );
        wp_set_current_user( $admin_id );
    }

    public function tearDown(): void {
        global $wpdb;

        $table_name = wldelay_get_log_table_name();
        $wpdb->query( "TRUNCATE TABLE $table_name" );

        delete_transient( WLDELAY_DASH_RECENT_CACHE );
        delete_transient( WLDELAY_DASH_TRENDS_CACHE );

        delete_option( WLDELAY_OPTION_NAME );

        parent::tearDown();
    }

    /**
     * Prime both sub-caches by rendering the widget once.
     */
    private function prime_caches() {
        ob_start();
        wldelay_dashboard_widget_content();
        ob_get_clean();
    }

    /**
     * A failed attempt invalidates ONLY the recent sub-cache and leaves the
     * expensive trends aggregate intact — the whole point of the split.
     */
    public function test_failed_attempt_clears_recent_but_keeps_trends() {
        wldelay_create_log_table();
        wldelay_log_failed_attempt( '192.0.2.10', 'attacker', 'wp-login' );

        $this->prime_caches();

        $this->assertNotFalse( get_transient( WLDELAY_DASH_RECENT_CACHE ), 'Recent cache should be primed' );
        $this->assertNotFalse( get_transient( WLDELAY_DASH_TRENDS_CACHE ), 'Trends cache should be primed' );

        // Capture the trends cache so we can prove it is untouched.
        $trends_before = get_transient( WLDELAY_DASH_TRENDS_CACHE );

        wldelay_log_failed_attempt( '192.0.2.11', 'attacker2', 'wp-login' );

        $this->assertFalse(
            get_transient( WLDELAY_DASH_RECENT_CACHE ),
            'A failed attempt must invalidate the recent sub-cache'
        );
        $this->assertNotFalse(
            get_transient( WLDELAY_DASH_TRENDS_CACHE ),
            'A failed attempt must NOT invalidate the expensive trends sub-cache'
        );
        $this->assertEquals(
            $trends_before,
            get_transient( WLDELAY_DASH_TRENDS_CACHE ),
            'Trends sub-cache content must be unchanged by a failed attempt'
        );
    }

    /**
     * A miss on the recent sub-cache rebuilds only that one (trends untouched).
     */
    public function test_recent_miss_rebuilds_only_recent() {
        wldelay_create_log_table();
        wldelay_log_failed_attempt( '192.0.2.20', 'user-a', 'wp-login' );

        $this->prime_caches();
        $trends_before = get_transient( WLDELAY_DASH_TRENDS_CACHE );

        delete_transient( WLDELAY_DASH_RECENT_CACHE );
        $this->prime_caches();

        $this->assertNotFalse( get_transient( WLDELAY_DASH_RECENT_CACHE ), 'Recent cache should be rebuilt' );
        $this->assertEquals(
            $trends_before,
            get_transient( WLDELAY_DASH_TRENDS_CACHE ),
            'Rebuilding recent must not touch the trends cache'
        );
    }

    /**
     * A miss on the trends sub-cache rebuilds only that one (recent untouched).
     */
    public function test_trends_miss_rebuilds_only_trends() {
        wldelay_create_log_table();
        wldelay_log_failed_attempt( '192.0.2.30', 'user-b', 'wp-login' );

        $this->prime_caches();
        $recent_before = get_transient( WLDELAY_DASH_RECENT_CACHE );

        delete_transient( WLDELAY_DASH_TRENDS_CACHE );
        $this->prime_caches();

        $this->assertNotFalse( get_transient( WLDELAY_DASH_TRENDS_CACHE ), 'Trends cache should be rebuilt' );
        $this->assertEquals(
            $recent_before,
            get_transient( WLDELAY_DASH_RECENT_CACHE ),
            'Rebuilding trends must not touch the recent cache'
        );
    }

    /**
     * A bulk log clear (retention cleanup) invalidates BOTH sub-caches, because
     * deleting old rows genuinely makes the aggregate stale.
     */
    public function test_bulk_log_clear_invalidates_both_caches() {
        global $wpdb;

        wldelay_create_log_table();
        $table_name = wldelay_get_log_table_name();

        // Insert an old row that retention cleanup will delete.
        $wpdb->insert(
            $table_name,
            array(
                'ip_address'   => '192.0.2.40',
                'username'     => 'old-user',
                'attempted_at' => gmdate( 'Y-m-d H:i:s', strtotime( '-30 days' ) ),
                'source'       => 'wp-login',
            )
        );

        // Configure a retention window so cleanup actually deletes rows.
        update_option( WLDELAY_OPTION_NAME, array( 'wldelay_log_retention_days' => 7 ) );

        $this->prime_caches();
        $this->assertNotFalse( get_transient( WLDELAY_DASH_RECENT_CACHE ) );
        $this->assertNotFalse( get_transient( WLDELAY_DASH_TRENDS_CACHE ) );

        wldelay_cleanup_old_logs();

        $this->assertFalse(
            get_transient( WLDELAY_DASH_RECENT_CACHE ),
            'Bulk log clear must invalidate the recent sub-cache'
        );
        $this->assertFalse(
            get_transient( WLDELAY_DASH_TRENDS_CACHE ),
            'Bulk log clear must invalidate the trends sub-cache (aggregates are stale)'
        );
    }

    /**
     * The widget renders the same data whether served from cache or freshly built.
     */
    public function test_widget_output_identical_cached_vs_fresh() {
        wldelay_create_log_table();
        wldelay_log_failed_attempt( '192.0.2.50', 'render-user', 'wp-login' );

        // Cold render (both caches miss, then get populated).
        delete_transient( WLDELAY_DASH_RECENT_CACHE );
        delete_transient( WLDELAY_DASH_TRENDS_CACHE );
        ob_start();
        wldelay_dashboard_widget_content();
        $fresh = ob_get_clean();

        // Warm render (both caches hit).
        ob_start();
        wldelay_dashboard_widget_content();
        $cached = ob_get_clean();

        $this->assertSame( $fresh, $cached, 'Cached and freshly-built widget output must be identical' );
        $this->assertStringContainsString( 'render-user', $cached );
        $this->assertStringContainsString( 'Failed login trends: last 7 days', $cached );
    }
}
