<?php
/**
 * Integration tests for cron job scheduling and cleanup functionality.
 */

class CronTest extends WP_UnitTestCase {

    /**
     * Clean up after each test.
     */
    public function tearDown(): void {
        // Clear the scheduled event
        $timestamp = wp_next_scheduled( 'wldelay_cleanup_logs' );
        if ( $timestamp ) {
            wp_unschedule_event( $timestamp, 'wldelay_cleanup_logs' );
        }

        delete_option( 'wldelay_options' );
        parent::tearDown();
    }

    /**
     * Test that cleanup action is registered.
     */
    public function test_cleanup_action_registered() {
        $this->assertNotFalse(
            has_action( 'wldelay_cleanup_logs', 'wldelay_cleanup_old_logs' ),
            'wldelay_cleanup_old_logs should be hooked to wldelay_cleanup_logs action'
        );
    }

    /**
     * Test that schedule cleanup function works.
     */
    public function test_schedule_cleanup_creates_event() {
        // Unschedule any existing event
        $timestamp = wp_next_scheduled( 'wldelay_cleanup_logs' );
        if ( $timestamp ) {
            wp_unschedule_event( $timestamp, 'wldelay_cleanup_logs' );
        }

        // Verify no event scheduled
        $this->assertFalse( wp_next_scheduled( 'wldelay_cleanup_logs' ) );

        // Schedule the cleanup
        wldelay_schedule_cleanup();

        // Verify event is now scheduled
        $this->assertNotFalse( wp_next_scheduled( 'wldelay_cleanup_logs' ) );
    }

    /**
     * Test that schedule cleanup doesn't duplicate events.
     */
    public function test_schedule_cleanup_no_duplicate() {
        // Schedule first time
        wldelay_schedule_cleanup();
        $first_timestamp = wp_next_scheduled( 'wldelay_cleanup_logs' );

        // Try to schedule again
        wldelay_schedule_cleanup();
        $second_timestamp = wp_next_scheduled( 'wldelay_cleanup_logs' );

        // Should be the same timestamp (not rescheduled)
        $this->assertEquals( $first_timestamp, $second_timestamp );
    }

    /**
     * Test that unschedule cleanup removes the event.
     */
    public function test_unschedule_cleanup_removes_event() {
        // Schedule first
        wldelay_schedule_cleanup();
        $this->assertNotFalse( wp_next_scheduled( 'wldelay_cleanup_logs' ) );

        // Unschedule
        wldelay_unschedule_cleanup();

        // Verify removed
        $this->assertFalse( wp_next_scheduled( 'wldelay_cleanup_logs' ) );
    }

    /**
     * Test that unschedule cleanup handles no existing event gracefully.
     */
    public function test_unschedule_cleanup_handles_no_event() {
        // Make sure no event is scheduled
        $timestamp = wp_next_scheduled( 'wldelay_cleanup_logs' );
        if ( $timestamp ) {
            wp_unschedule_event( $timestamp, 'wldelay_cleanup_logs' );
        }

        // This should not throw an error
        wldelay_unschedule_cleanup();

        // Should still be false
        $this->assertFalse( wp_next_scheduled( 'wldelay_cleanup_logs' ) );
    }

    /**
     * Test that cleanup deletes old logs.
     */
    public function test_cleanup_deletes_old_logs() {
        global $wpdb;

        wldelay_create_log_table();
        $table_name = wldelay_get_log_table_name();

        // Set retention to 7 days
        update_option( 'wldelay_options', [
            'wldelay_log_retention_days' => 7,
        ] );

        // Insert an old log entry (10 days ago)
        $old_date = gmdate( 'Y-m-d H:i:s', strtotime( '-10 days' ) );
        $wpdb->insert( $table_name, [
            'ip_address' => '192.168.1.1',
            'username' => 'old_user',
            'attempted_at' => $old_date,
            'source' => 'wp-login',
        ] );

        // Insert a recent log entry (1 day ago)
        $recent_date = gmdate( 'Y-m-d H:i:s', strtotime( '-1 day' ) );
        $wpdb->insert( $table_name, [
            'ip_address' => '192.168.1.2',
            'username' => 'recent_user',
            'attempted_at' => $recent_date,
            'source' => 'wp-login',
        ] );

        // Run cleanup
        wldelay_cleanup_old_logs();

        // Check results
        $remaining = $wpdb->get_results( "SELECT * FROM $table_name" );

        $this->assertCount( 1, $remaining );
        $this->assertEquals( 'recent_user', $remaining[0]->username );
    }

    /**
     * Test that cleanup respects retention setting of 0 (keep forever).
     */
    public function test_cleanup_respects_zero_retention() {
        global $wpdb;

        wldelay_create_log_table();
        $table_name = wldelay_get_log_table_name();

        // Set retention to 0 (keep forever)
        update_option( 'wldelay_options', [
            'wldelay_log_retention_days' => 0,
        ] );

        // Insert an old log entry (100 days ago)
        $old_date = gmdate( 'Y-m-d H:i:s', strtotime( '-100 days' ) );
        $wpdb->insert( $table_name, [
            'ip_address' => '192.168.1.1',
            'username' => 'old_user',
            'attempted_at' => $old_date,
            'source' => 'wp-login',
        ] );

        // Run cleanup
        wldelay_cleanup_old_logs();

        // Check results - should not delete anything
        $remaining = $wpdb->get_results( "SELECT * FROM $table_name" );

        $this->assertCount( 1, $remaining );
        $this->assertEquals( 'old_user', $remaining[0]->username );
    }

    /**
     * Test that cleanup uses default retention when option not set.
     */
    public function test_cleanup_uses_default_retention() {
        global $wpdb;

        wldelay_create_log_table();
        $table_name = wldelay_get_log_table_name();

        // Don't set any options (use defaults)
        delete_option( 'wldelay_options' );

        // Insert an old log entry (older than default 30 days)
        $old_date = gmdate( 'Y-m-d H:i:s', strtotime( '-35 days' ) );
        $wpdb->insert( $table_name, [
            'ip_address' => '192.168.1.1',
            'username' => 'old_user',
            'attempted_at' => $old_date,
            'source' => 'wp-login',
        ] );

        // Insert a recent log entry
        $recent_date = gmdate( 'Y-m-d H:i:s', strtotime( '-5 days' ) );
        $wpdb->insert( $table_name, [
            'ip_address' => '192.168.1.2',
            'username' => 'recent_user',
            'attempted_at' => $recent_date,
            'source' => 'wp-login',
        ] );

        // Run cleanup
        wldelay_cleanup_old_logs();

        // Check results - old entry should be deleted
        $remaining = $wpdb->get_results( "SELECT * FROM $table_name" );

        $this->assertCount( 1, $remaining );
        $this->assertEquals( 'recent_user', $remaining[0]->username );
    }

    /**
     * Test that cleanup handles empty table gracefully.
     */
    public function test_cleanup_handles_empty_table() {
        global $wpdb;

        wldelay_create_log_table();
        $table_name = wldelay_get_log_table_name();

        // Clear table
        $wpdb->query( "TRUNCATE TABLE $table_name" );

        update_option( 'wldelay_options', [
            'wldelay_log_retention_days' => 7,
        ] );

        // This should not throw an error
        wldelay_cleanup_old_logs();

        // Should still be empty
        $count = $wpdb->get_var( "SELECT COUNT(*) FROM $table_name" );
        $this->assertEquals( 0, $count );
    }

    /**
     * Test scheduled event recurrence is daily.
     */
    public function test_scheduled_event_is_daily() {
        wldelay_schedule_cleanup();

        $timestamp = wp_next_scheduled( 'wldelay_cleanup_logs' );
        $this->assertNotFalse( $timestamp );

        // Get all cron events
        $crons = _get_cron_array();

        // Find our event and check recurrence
        foreach ( $crons as $time => $events ) {
            if ( isset( $events['wldelay_cleanup_logs'] ) ) {
                foreach ( $events['wldelay_cleanup_logs'] as $hook_data ) {
                    $this->assertEquals( 'daily', $hook_data['schedule'] );
                    return;
                }
            }
        }

        $this->fail( 'Could not find wldelay_cleanup_logs in cron array' );
    }
}
