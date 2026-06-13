<?php
/**
 * Integration tests for the botnet / credential-stuffing detection module (F-1-9).
 *
 * Each test runs against the bundled MariaDB via WP_UnitTestCase. All transients
 * and options are reset per test so assertions are deterministic.
 */

class BotnetDetectionTest extends WP_UnitTestCase {

    /** @var string Original REMOTE_ADDR, restored on tearDown. */
    private $original_remote_addr;

    /** @var array Captured wp_mail calls. */
    private $sent_emails = array();

    public function setUp(): void {
        parent::setUp();

        global $wpdb;

        // Ensure the log table and audit table exist.
        wldelay_create_log_table();
        wldelay_create_audit_table();

        // Truncate both tables for test isolation.
        $log_table   = wldelay_get_log_table_name();
        $audit_table = wldelay_get_audit_table_name();
        $wpdb->query( "TRUNCATE TABLE $log_table" );
        $wpdb->query( "TRUNCATE TABLE $audit_table" );

        // Reset deferred task queue.
        wldelay_reset_deferred_tasks();

        // Clear botnet transients.
        delete_transient( WLDELAY_BOTNET_DETECTIONS_TRANSIENT );

        // Clear options cache.
        wldelay_clear_options_cache();
        delete_option( 'wldelay_options' );

        // Capture emails.
        $this->sent_emails = array();
        add_filter( 'wp_mail', array( $this, 'capture_email' ) );

        // Fix REMOTE_ADDR so the pipeline's IP detection is deterministic.
        $this->original_remote_addr = isset( $_SERVER['REMOTE_ADDR'] ) ? $_SERVER['REMOTE_ADDR'] : '';
        $_SERVER['REMOTE_ADDR'] = '192.0.2.1'; // TEST-NET-1, won't match attack IPs
        unset( $_SERVER['HTTP_CLIENT_IP'], $_SERVER['HTTP_X_FORWARDED_FOR'] );
    }

    public function tearDown(): void {
        remove_filter( 'wp_mail', array( $this, 'capture_email' ) );

        $_SERVER['REMOTE_ADDR'] = $this->original_remote_addr;
        unset( $_SERVER['HTTP_CLIENT_IP'], $_SERVER['HTTP_X_FORWARDED_FOR'] );

        // Clear per-test cooldown transients (safety net — delete_transient is
        // idempotent).
        delete_transient( wldelay_botnet_cooldown_key( 'admin' ) );
        delete_transient( wldelay_botnet_cooldown_key( 'bob' ) );
        delete_transient( wldelay_botnet_cooldown_key( 'carol' ) );
        delete_transient( wldelay_botnet_cooldown_key( 'dave' ) );
        delete_transient( wldelay_botnet_cooldown_key( 'erin' ) );
        delete_transient( WLDELAY_BOTNET_DETECTIONS_TRANSIENT );

        wldelay_clear_options_cache();
        wldelay_reset_deferred_tasks();

        parent::tearDown();
    }

    /**
     * Capture emails sent via wp_mail for assertion.
     */
    public function capture_email( $args ) {
        $this->sent_emails[] = $args;
        return $args;
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    /**
     * Seed $ip_count distinct-IP failed attempts for one username.
     *
     * @param string $username
     * @param int    $ip_count Each attempt comes from a unique 198.51.100.x IP.
     */
    private function seed_attempts( $username, $ip_count ) {
        for ( $i = 1; $i <= $ip_count; $i++ ) {
            wldelay_log_failed_attempt( '198.51.100.' . $i, $username, 'wp-login' );
        }
    }

    /**
     * Enable botnet detection with a given threshold and window.
     */
    private function enable_botnet( $threshold = 5, $window_minutes = 15 ) {
        update_option( 'wldelay_options', array(
            'wldelay_botnet_enabled'       => true,
            'wldelay_botnet_ip_threshold'  => $threshold,
            'wldelay_botnet_window_minutes' => $window_minutes,
        ) );
        wldelay_clear_options_cache();
    }

    /**
     * Count audit rows for a given action and username (object column).
     */
    private function count_audit_rows( $action, $object = '' ) {
        global $wpdb;
        $table = wldelay_get_audit_table_name();

        if ( '' !== $object ) {
            return (int) $wpdb->get_var(
                $wpdb->prepare(
                    "SELECT COUNT(*) FROM $table WHERE action = %s AND object = %s",
                    $action,
                    $object
                )
            );
        }
        return (int) $wpdb->get_var(
            $wpdb->prepare( "SELECT COUNT(*) FROM $table WHERE action = %s", $action )
        );
    }

    // =========================================================================
    // Core detection
    // =========================================================================

    /**
     * Running the task with exactly-threshold distinct IPs fires a detection:
     * the detections feed gets one entry, the cooldown is set, and the audit
     * trail records a botnet_detected row for the username.
     */
    public function test_detection_fires_at_threshold() {
        $this->enable_botnet( 5 );
        delete_transient( wldelay_botnet_cooldown_key( 'admin' ) );
        delete_transient( WLDELAY_BOTNET_DETECTIONS_TRANSIENT );

        $this->seed_attempts( 'admin', 5 );

        wldelay_botnet_task( array( 'username' => 'admin' ) );

        // Dashboard feed.
        $detections = wldelay_botnet_get_recent_detections();
        $this->assertCount( 1, $detections );
        $this->assertSame( 'admin', $detections[0]['username'] );
        $this->assertSame( 5, $detections[0]['distinct_ips'] );

        // Cooldown transient is set (truthy — prevents repeat alerts).
        $this->assertNotFalse( get_transient( wldelay_botnet_cooldown_key( 'admin' ) ) );

        // Audit trail.
        $this->assertSame( 1, $this->count_audit_rows( 'botnet_detected', 'admin' ) );
    }

    /**
     * Below-threshold distinct IPs do not trigger a detection.
     */
    public function test_below_threshold_no_detection() {
        $this->enable_botnet( 5 );
        delete_transient( wldelay_botnet_cooldown_key( 'bob' ) );

        $this->seed_attempts( 'bob', 4 ); // one below threshold

        wldelay_botnet_task( array( 'username' => 'bob' ) );

        $detections = wldelay_botnet_get_recent_detections();
        $this->assertCount( 0, $detections );
        $this->assertFalse( get_transient( wldelay_botnet_cooldown_key( 'bob' ) ) );
        $this->assertSame( 0, $this->count_audit_rows( 'botnet_detected', 'bob' ) );
    }

    /**
     * Many attempts from a SINGLE IP for the same username do NOT count as a
     * botnet — distinct_ips = 1, which is always below the minimum threshold of 2.
     */
    public function test_same_ip_many_attempts_is_not_a_botnet() {
        $this->enable_botnet( 2 );
        delete_transient( wldelay_botnet_cooldown_key( 'carol' ) );

        for ( $i = 0; $i < 10; $i++ ) {
            wldelay_log_failed_attempt( '198.51.100.1', 'carol', 'wp-login' );
        }

        wldelay_botnet_task( array( 'username' => 'carol' ) );

        $detections = wldelay_botnet_get_recent_detections();
        $this->assertCount( 0, $detections );
        $this->assertSame( 0, $this->count_audit_rows( 'botnet_detected', 'carol' ) );
    }

    // =========================================================================
    // Cooldown / deduplication
    // =========================================================================

    /**
     * Running the task twice for the same username only produces one detection
     * alert — the cooldown set by the first run prevents the second.
     */
    public function test_cooldown_suppresses_repeat_alert() {
        $this->enable_botnet( 5 );
        delete_transient( wldelay_botnet_cooldown_key( 'dave' ) );
        delete_transient( WLDELAY_BOTNET_DETECTIONS_TRANSIENT );

        $this->seed_attempts( 'dave', 6 );

        // First run fires.
        wldelay_botnet_task( array( 'username' => 'dave' ) );
        $detections_after_first = wldelay_botnet_get_recent_detections();
        $this->assertCount( 1, $detections_after_first );

        // Second run is blocked by cooldown.
        wldelay_botnet_task( array( 'username' => 'dave' ) );
        $detections_after_second = wldelay_botnet_get_recent_detections();
        $this->assertCount( 1, $detections_after_second ); // still 1
        $this->assertSame( 1, $this->count_audit_rows( 'botnet_detected', 'dave' ) );
    }

    // =========================================================================
    // Email
    // =========================================================================

    /**
     * Email is sent when email alerts are enabled and detection fires.
     * Email is NOT sent when email alerts are disabled, but the detection feed
     * still records the detection.
     */
    public function test_email_sent_only_when_email_alerts_enabled() {
        global $wpdb;
        $log_table   = wldelay_get_log_table_name();
        $audit_table = wldelay_get_audit_table_name();

        // --- Case A: email enabled ---
        update_option( 'wldelay_options', array(
            'wldelay_botnet_enabled'        => true,
            'wldelay_botnet_ip_threshold'   => 3,
            'wldelay_botnet_window_minutes' => 15,
            'wldelay_email_enabled'         => true,
            'wldelay_email_address'         => 'security@example.com',
        ) );
        wldelay_clear_options_cache();

        for ( $i = 1; $i <= 3; $i++ ) {
            wldelay_log_failed_attempt( '198.51.100.' . $i, 'admin', 'wp-login' );
        }
        wldelay_botnet_task( array( 'username' => 'admin' ) );

        $this->assertCount( 1, $this->sent_emails, 'Case A: one email expected when alerts enabled' );
        $this->assertStringContainsString( 'Distributed login attack', $this->sent_emails[0]['subject'] );

        // --- Reset for Case B ---
        delete_transient( wldelay_botnet_cooldown_key( 'admin' ) );
        delete_transient( WLDELAY_BOTNET_DETECTIONS_TRANSIENT );
        $wpdb->query( "TRUNCATE TABLE $log_table" );
        $wpdb->query( "TRUNCATE TABLE $audit_table" );
        $this->sent_emails = array();

        // --- Case B: email disabled ---
        update_option( 'wldelay_options', array(
            'wldelay_botnet_enabled'        => true,
            'wldelay_botnet_ip_threshold'   => 3,
            'wldelay_botnet_window_minutes' => 15,
            'wldelay_email_enabled'         => false,
        ) );
        wldelay_clear_options_cache();

        for ( $i = 1; $i <= 3; $i++ ) {
            wldelay_log_failed_attempt( '198.51.100.' . $i, 'admin', 'wp-login' );
        }
        wldelay_botnet_task( array( 'username' => 'admin' ) );

        // No email, but detection is still recorded.
        $this->assertCount( 0, $this->sent_emails, 'Case B: no email when alerts disabled' );
        $detections = wldelay_botnet_get_recent_detections();
        $this->assertCount( 1, $detections, 'Case B: detection feed still records the event' );
    }

    // =========================================================================
    // End-to-end: pipeline → event → deferred task → flush
    // =========================================================================

    /**
     * Full end-to-end path: five failures for 'erin' (from five distinct IPs)
     * routed through wldelay_process_failed_attempt() (with delay/track/lockout
     * disabled for test speed) fire the pipeline event, which enqueues a
     * botnet_check deferred task; flushing the queue runs the detection.
     */
    public function test_end_to_end_via_pipeline_and_shutdown_flush() {
        $this->enable_botnet( 5 );
        delete_transient( wldelay_botnet_cooldown_key( 'erin' ) );
        delete_transient( WLDELAY_BOTNET_DETECTIONS_TRANSIENT );
        wldelay_reset_deferred_tasks();

        // Five attempts from five different IPs routed through the pipeline.
        $ips = array( '10.0.1.1', '10.0.1.2', '10.0.1.3', '10.0.1.4', '10.0.1.5' );
        foreach ( $ips as $ip ) {
            $_SERVER['REMOTE_ADDR'] = $ip;
            wldelay_process_failed_attempt(
                'erin',
                'wp-login',
                array( 'track' => false, 'delay' => false, 'lockout' => false )
            );
        }

        // Exactly one botnet_check task should be queued (coalesced by the queue
        // dedupe: same id + same args = one entry).
        $this->assertSame( 1, wldelay_count_deferred_tasks() );

        // Simulate the shutdown flush.
        wldelay_flush_deferred_tasks();

        $detections = wldelay_botnet_get_recent_detections();
        $this->assertCount( 1, $detections, 'Exactly one detection should be recorded after flush' );
        $this->assertSame( 'erin', $detections[0]['username'] );
        $this->assertSame( 5, $detections[0]['distinct_ips'] );
    }

    // =========================================================================
    // Site-local-clock correctness
    // =========================================================================

    /**
     * Attempts outside the detection window are NOT counted, even if there are
     * more than enough IPs total. This test directly seeds old rows using
     * attempted_at built from current_time('timestamp') minus an excess so the
     * cutoff correctness (site-local vs UTC) is exercised.
     */
    public function test_old_attempts_outside_window_not_counted() {
        global $wpdb;

        $this->enable_botnet( 5, 15 ); // threshold 5, window 15 minutes
        delete_transient( wldelay_botnet_cooldown_key( 'admin' ) );

        $table = wldelay_get_log_table_name();

        // Seed 5 OLD attempts (20 min ago — outside the 15-min window).
        $old_cutoff = gmdate( 'Y-m-d H:i:s', current_time( 'timestamp' ) - 20 * MINUTE_IN_SECONDS );
        for ( $i = 1; $i <= 5; $i++ ) {
            $wpdb->insert(
                $table,
                array(
                    'ip_address'   => '198.51.100.' . $i,
                    'username'     => 'admin',
                    'source'       => 'wp-login',
                    'attempted_at' => $old_cutoff,
                ),
                array( '%s', '%s', '%s', '%s' )
            );
        }

        // Seed 2 RECENT attempts (inside the window) — below threshold of 5.
        wldelay_log_failed_attempt( '198.51.101.1', 'admin', 'wp-login' );
        wldelay_log_failed_attempt( '198.51.101.2', 'admin', 'wp-login' );

        wldelay_botnet_task( array( 'username' => 'admin' ) );

        // Total distinct IPs: 7, but only 2 are within the window → no detection.
        $detections = wldelay_botnet_get_recent_detections();
        $this->assertCount( 0, $detections, 'Old attempts outside the window must not count' );
        $this->assertFalse( get_transient( wldelay_botnet_cooldown_key( 'admin' ) ) );
    }
}
