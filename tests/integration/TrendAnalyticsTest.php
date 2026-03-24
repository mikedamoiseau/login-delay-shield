<?php
/**
 * Integration tests for trend analytics query functions.
 */

class TrendAnalyticsTest extends WP_UnitTestCase {

    /**
     * Set up before each test.
     */
    public function setUp(): void {
        parent::setUp();

        wldelay_create_log_table();
    }

    /**
     * Clean up after each test.
     */
    public function tearDown(): void {
        global $wpdb;

        $table_name = wldelay_get_log_table_name();
        $wpdb->query( "TRUNCATE TABLE $table_name" );

        parent::tearDown();
    }

    /**
     * Insert a failed login attempt at a specific date.
     *
     * @param string $ip       IP address.
     * @param string $username Username.
     * @param string $date     Date string (Y-m-d H:i:s).
     * @param string $source   Source (default wp-login).
     */
    private function insert_attempt( $ip, $username, $date, $source = 'wp-login' ) {
        global $wpdb;

        $table_name = wldelay_get_log_table_name();
        $wpdb->insert(
            $table_name,
            array(
                'ip_address'   => $ip,
                'username'     => $username,
                'attempted_at' => $date,
                'source'       => $source,
            ),
            array( '%s', '%s', '%s', '%s' )
        );
    }

    /**
     * Test top IPs returns correct ranking.
     */
    public function test_top_ips_returns_ranked_results() {
        $now = gmdate( 'Y-m-d H:i:s' );

        // IP A: 5 attempts
        for ( $i = 0; $i < 5; $i++ ) {
            $this->insert_attempt( '10.0.0.1', 'admin', $now );
        }
        // IP B: 3 attempts
        for ( $i = 0; $i < 3; $i++ ) {
            $this->insert_attempt( '10.0.0.2', 'admin', $now );
        }
        // IP C: 1 attempt
        $this->insert_attempt( '10.0.0.3', 'admin', $now );

        $results = wldelay_get_top_ips( 7, 10 );

        $this->assertCount( 3, $results );
        $this->assertEquals( '10.0.0.1', $results[0]->ip_address );
        $this->assertEquals( 5, (int) $results[0]->attempt_count );
        $this->assertEquals( '10.0.0.2', $results[1]->ip_address );
        $this->assertEquals( 3, (int) $results[1]->attempt_count );
        $this->assertEquals( '10.0.0.3', $results[2]->ip_address );
        $this->assertEquals( 1, (int) $results[2]->attempt_count );
    }

    /**
     * Test top IPs respects the period filter.
     */
    public function test_top_ips_respects_period() {
        $now       = gmdate( 'Y-m-d H:i:s' );
        $old_date  = gmdate( 'Y-m-d H:i:s', time() - ( 10 * DAY_IN_SECONDS ) );

        $this->insert_attempt( '10.0.0.1', 'admin', $now );
        $this->insert_attempt( '10.0.0.2', 'admin', $old_date );

        $results_7 = wldelay_get_top_ips( 7, 10 );
        $this->assertCount( 1, $results_7 );
        $this->assertEquals( '10.0.0.1', $results_7[0]->ip_address );

        $results_14 = wldelay_get_top_ips( 14, 10 );
        $this->assertCount( 2, $results_14 );
    }

    /**
     * Test top IPs respects the limit parameter.
     */
    public function test_top_ips_respects_limit() {
        $now = gmdate( 'Y-m-d H:i:s' );

        for ( $i = 1; $i <= 5; $i++ ) {
            $this->insert_attempt( '10.0.0.' . $i, 'admin', $now );
        }

        $results = wldelay_get_top_ips( 7, 3 );
        $this->assertCount( 3, $results );
    }

    /**
     * Test top IPs returns empty when no data.
     */
    public function test_top_ips_empty_when_no_data() {
        $results = wldelay_get_top_ips( 7, 10 );
        $this->assertIsArray( $results );
        $this->assertEmpty( $results );
    }

    /**
     * Test top usernames returns correct ranking.
     */
    public function test_top_usernames_returns_ranked_results() {
        $now = gmdate( 'Y-m-d H:i:s' );

        for ( $i = 0; $i < 4; $i++ ) {
            $this->insert_attempt( '10.0.0.1', 'admin', $now );
        }
        for ( $i = 0; $i < 2; $i++ ) {
            $this->insert_attempt( '10.0.0.1', 'root', $now );
        }
        $this->insert_attempt( '10.0.0.1', 'test', $now );

        $results = wldelay_get_top_usernames( 7, 10 );

        $this->assertCount( 3, $results );
        $this->assertEquals( 'admin', $results[0]->username );
        $this->assertEquals( 4, (int) $results[0]->attempt_count );
        $this->assertEquals( 'root', $results[1]->username );
        $this->assertEquals( 2, (int) $results[1]->attempt_count );
    }

    /**
     * Test top usernames respects the period filter.
     */
    public function test_top_usernames_respects_period() {
        $now       = gmdate( 'Y-m-d H:i:s' );
        $old_date  = gmdate( 'Y-m-d H:i:s', time() - ( 20 * DAY_IN_SECONDS ) );

        $this->insert_attempt( '10.0.0.1', 'admin', $now );
        $this->insert_attempt( '10.0.0.1', 'old_user', $old_date );

        $results = wldelay_get_top_usernames( 7, 10 );
        $this->assertCount( 1, $results );
        $this->assertEquals( 'admin', $results[0]->username );

        $results_30 = wldelay_get_top_usernames( 30, 10 );
        $this->assertCount( 2, $results_30 );
    }

    /**
     * Test daily attempts returns data grouped by date.
     */
    public function test_daily_attempts_groups_by_date() {
        $today     = gmdate( 'Y-m-d' );
        $yesterday = gmdate( 'Y-m-d', time() - DAY_IN_SECONDS );

        // 3 attempts today
        for ( $i = 0; $i < 3; $i++ ) {
            $this->insert_attempt( '10.0.0.1', 'admin', $today . ' 10:00:0' . $i );
        }
        // 2 attempts yesterday
        for ( $i = 0; $i < 2; $i++ ) {
            $this->insert_attempt( '10.0.0.1', 'admin', $yesterday . ' 15:00:0' . $i );
        }

        $results = wldelay_get_daily_attempts( 7 );

        $this->assertCount( 2, $results );
        // Results ordered by date ASC
        $this->assertEquals( $yesterday, $results[0]->log_date );
        $this->assertEquals( 2, (int) $results[0]->attempt_count );
        $this->assertEquals( $today, $results[1]->log_date );
        $this->assertEquals( 3, (int) $results[1]->attempt_count );
    }

    /**
     * Test daily attempts respects the period filter.
     */
    public function test_daily_attempts_respects_period() {
        $today    = gmdate( 'Y-m-d' );
        $old_date = gmdate( 'Y-m-d', time() - ( 15 * DAY_IN_SECONDS ) );

        $this->insert_attempt( '10.0.0.1', 'admin', $today . ' 12:00:00' );
        $this->insert_attempt( '10.0.0.1', 'admin', $old_date . ' 12:00:00' );

        $results_7 = wldelay_get_daily_attempts( 7 );
        $this->assertCount( 1, $results_7 );

        $results_30 = wldelay_get_daily_attempts( 30 );
        $this->assertCount( 2, $results_30 );
    }

    /**
     * Test daily attempts returns empty when no data.
     */
    public function test_daily_attempts_empty_when_no_data() {
        $results = wldelay_get_daily_attempts( 7 );
        $this->assertIsArray( $results );
        $this->assertEmpty( $results );
    }

    /**
     * Test functions handle invalid parameters gracefully.
     */
    public function test_functions_handle_invalid_params() {
        // Days = 0 should default to 7
        $results = wldelay_get_top_ips( 0, 10 );
        $this->assertIsArray( $results );

        // Negative limit defaults to 10
        $results = wldelay_get_top_usernames( 7, -1 );
        $this->assertIsArray( $results );

        // Zero days for daily attempts defaults to 7
        $results = wldelay_get_daily_attempts( 0 );
        $this->assertIsArray( $results );
    }
}
