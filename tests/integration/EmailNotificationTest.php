<?php
/**
 * Integration tests for email notification functionality.
 */

class EmailNotificationTest extends WP_UnitTestCase {

    /**
     * @var array Captured emails.
     */
    private $sent_emails = [];

    /**
     * Set up before each test.
     */
    public function setUp(): void {
        parent::setUp();

        // Clear sent emails
        $this->sent_emails = [];

        // Hook into wp_mail to capture sent emails
        add_filter( 'wp_mail', [ $this, 'capture_email' ] );

        // Clear any existing options to ensure clean slate
        delete_option( 'wldelay_options' );

        // Clear all IP-related SERVER variables to ensure consistent IP detection
        unset( $_SERVER['HTTP_CLIENT_IP'], $_SERVER['HTTP_X_FORWARDED_FOR'] );

        // Set up a test IP
        $_SERVER['REMOTE_ADDR'] = '192.168.1.100';

        // Clear any existing transients for this IP
        delete_transient( 'wldelay_fails_' . md5( '192.168.1.100' ) );
        delete_transient( 'wldelay_lockout_' . md5( '192.168.1.100' ) );
        delete_transient( 'wldelay_email_cooldown' );

        // Clear options cache
        wldelay_clear_options_cache();
    }

    /**
     * Tear down after each test.
     */
    public function tearDown(): void {
        remove_filter( 'wp_mail', [ $this, 'capture_email' ] );
        unset( $_SERVER['REMOTE_ADDR'] );
        parent::tearDown();
    }

    /**
     * Capture emails sent via wp_mail.
     *
     * @param array $args Email arguments.
     * @return array
     */
    public function capture_email( $args ) {
        $this->sent_emails[] = $args;
        return $args;
    }

    /**
     * Test that failed attempts are tracked via transients.
     */
    public function test_failed_attempts_tracked() {
        update_option( 'wldelay_options', [
            'wldelay_email_enabled' => true,
            'wldelay_email_threshold' => 5,
            'wldelay_lockout_enabled' => false,
        ] );
        wldelay_clear_options_cache();

        // Simulate a failed attempt
        wldelay_track_failed_attempt( 'testuser' );

        $transient_key = 'wldelay_fails_' . md5( '192.168.1.100' );
        $count = get_transient( $transient_key );

        $this->assertEquals( 1, $count );
    }

    /**
     * Test that attempts increment correctly.
     */
    public function test_failed_attempts_increment() {
        update_option( 'wldelay_options', [
            'wldelay_email_enabled' => true,
            'wldelay_email_threshold' => 10,
            'wldelay_lockout_enabled' => false,
        ] );
        wldelay_clear_options_cache();

        // Simulate multiple failed attempts
        for ( $i = 1; $i <= 3; $i++ ) {
            wldelay_track_failed_attempt( 'testuser' );
        }

        $transient_key = 'wldelay_fails_' . md5( '192.168.1.100' );
        $count = get_transient( $transient_key );

        $this->assertEquals( 3, $count );
    }

    /**
     * Test that email is sent when threshold is reached.
     */
    public function test_email_sent_at_threshold() {
        update_option( 'wldelay_options', [
            'wldelay_email_enabled' => true,
            'wldelay_email_threshold' => 3,
            'wldelay_lockout_enabled' => false,
        ] );
        wldelay_clear_options_cache();

        // Should not send email before threshold
        wldelay_track_failed_attempt( 'testuser' );
        $this->assertCount( 0, $this->sent_emails );

        wldelay_track_failed_attempt( 'testuser' );
        $this->assertCount( 0, $this->sent_emails );

        // Should send email at threshold
        wldelay_track_failed_attempt( 'testuser' );
        $this->assertCount( 1, $this->sent_emails );
    }

    /**
     * Test that email is not sent below threshold.
     */
    public function test_email_not_sent_below_threshold() {
        update_option( 'wldelay_options', [
            'wldelay_email_enabled' => true,
            'wldelay_email_threshold' => 10,
            'wldelay_lockout_enabled' => false,
        ] );
        wldelay_clear_options_cache();

        // Simulate 5 attempts (below threshold of 10)
        for ( $i = 0; $i < 5; $i++ ) {
            wldelay_track_failed_attempt( 'testuser' );
        }

        $this->assertCount( 0, $this->sent_emails );
    }

    /**
     * Test that email is only sent once at threshold (not after).
     */
    public function test_email_sent_only_at_threshold() {
        update_option( 'wldelay_options', [
            'wldelay_email_enabled' => true,
            'wldelay_email_threshold' => 2,
            'wldelay_lockout_enabled' => false,
        ] );
        wldelay_clear_options_cache();

        // First attempt
        wldelay_track_failed_attempt( 'testuser' );
        $this->assertCount( 0, $this->sent_emails );

        // Second attempt - threshold reached, email should be sent
        wldelay_track_failed_attempt( 'testuser' );
        $this->assertCount( 1, $this->sent_emails );

        // Third attempt - no additional email
        wldelay_track_failed_attempt( 'testuser' );
        $this->assertCount( 1, $this->sent_emails );

        // Fourth attempt - still no additional email
        wldelay_track_failed_attempt( 'testuser' );
        $this->assertCount( 1, $this->sent_emails );
    }

    /**
     * Test that custom email address is used.
     */
    public function test_custom_email_address_used() {
        update_option( 'wldelay_options', [
            'wldelay_email_enabled' => true,
            'wldelay_email_threshold' => 1,
            'wldelay_email_address' => 'custom@example.com',
            'wldelay_lockout_enabled' => false,
        ] );
        wldelay_clear_options_cache();

        wldelay_track_failed_attempt( 'testuser' );

        $this->assertCount( 1, $this->sent_emails );
        $this->assertEquals( 'custom@example.com', $this->sent_emails[0]['to'] );
    }

    /**
     * Test that admin email is used when custom email is empty.
     */
    public function test_admin_email_fallback() {
        update_option( 'admin_email', 'admin@example.com' );
        update_option( 'wldelay_options', [
            'wldelay_email_enabled' => true,
            'wldelay_email_threshold' => 1,
            'wldelay_email_address' => '',
            'wldelay_lockout_enabled' => false, // Explicitly disable lockout
        ] );
        wldelay_clear_options_cache();

        // Clear emails captured during option setup (WordPress sends admin email change notification)
        $this->sent_emails = [];

        wldelay_track_failed_attempt( 'testuser' );

        $this->assertCount( 1, $this->sent_emails );
        $this->assertEquals( 'admin@example.com', $this->sent_emails[0]['to'] );
    }

    /**
     * Test that email contains expected information.
     */
    public function test_email_contains_expected_info() {
        update_option( 'blogname', 'Test Site' );
        update_option( 'wldelay_options', [
            'wldelay_email_enabled' => true,
            'wldelay_email_threshold' => 1,
            'wldelay_lockout_enabled' => false,
        ] );
        wldelay_clear_options_cache();

        wldelay_track_failed_attempt( 'hackeruser' );

        $this->assertCount( 1, $this->sent_emails );

        $email = $this->sent_emails[0];

        // Check subject contains site name
        $this->assertStringContainsString( 'Test Site', $email['subject'] );
        $this->assertStringContainsString( 'Failed login', $email['subject'] );

        // Check body contains expected info
        $this->assertStringContainsString( '192.168.1.100', $email['message'] );
        $this->assertStringContainsString( 'hackeruser', $email['message'] );
        $this->assertStringContainsString( 'Login Delay Shield', $email['message'] );
    }

    /**
     * Test that tracking does nothing when email notifications are disabled.
     */
    public function test_tracking_disabled_when_email_disabled() {
        update_option( 'wldelay_options', [
            'wldelay_email_enabled' => false,
            'wldelay_email_threshold' => 1,
            'wldelay_lockout_enabled' => false,
        ] );
        wldelay_clear_options_cache();

        wldelay_track_failed_attempt( 'testuser' );

        // No transient should be set
        $transient_key = 'wldelay_fails_' . md5( '192.168.1.100' );
        $count = get_transient( $transient_key );

        $this->assertFalse( $count );
        $this->assertCount( 0, $this->sent_emails );
    }

    /**
     * Test client IP detection from REMOTE_ADDR.
     */
    public function test_client_ip_from_remote_addr() {
        $_SERVER['REMOTE_ADDR'] = '10.0.0.1';
        unset( $_SERVER['HTTP_CLIENT_IP'], $_SERVER['HTTP_X_FORWARDED_FOR'] );

        $ip = wldelay_get_client_ip();

        $this->assertEquals( '10.0.0.1', $ip );
    }

    /**
     * Test client IP detection from HTTP_CLIENT_IP.
     */
    public function test_client_ip_from_http_client_ip() {
        update_option( 'wldelay_options', array(
            'wldelay_trust_proxy_headers' => true,
        ) );
        wldelay_clear_options_cache();

        $_SERVER['HTTP_CLIENT_IP'] = '172.16.0.1';
        $_SERVER['REMOTE_ADDR'] = '10.0.0.1';

        $ip = wldelay_get_client_ip();

        $this->assertEquals( '172.16.0.1', $ip );
    }

    /**
     * Test client IP detection from X-Forwarded-For.
     */
    public function test_client_ip_from_x_forwarded_for() {
        update_option( 'wldelay_options', array(
            'wldelay_trust_proxy_headers' => true,
        ) );
        wldelay_clear_options_cache();

        unset( $_SERVER['HTTP_CLIENT_IP'] );
        $_SERVER['HTTP_X_FORWARDED_FOR'] = '203.0.113.50, 70.41.3.18, 150.172.238.178';
        $_SERVER['REMOTE_ADDR'] = '10.0.0.1';

        $ip = wldelay_get_client_ip();

        // Should return first IP in the list
        $this->assertEquals( '203.0.113.50', $ip );
    }

    /**
     * Test that email cooldown prevents rapid emails.
     */
    public function test_email_cooldown_prevents_rapid_emails() {
        // Enable email with cooldown of 5 minutes
        update_option( 'wldelay_options', [
            'wldelay_email_enabled' => true,
            'wldelay_email_threshold' => 1,
            'wldelay_email_cooldown' => 5,
        ] );
        wldelay_clear_options_cache();

        // First email should be sent
        wldelay_send_notification_email( '192.168.1.100', 'testuser', 5 );
        $this->assertCount( 1, $this->sent_emails );

        // Second email should be blocked by cooldown
        wldelay_send_notification_email( '192.168.1.101', 'testuser2', 5 );
        $this->assertCount( 1, $this->sent_emails ); // Still 1

        // Clear the cooldown transient
        delete_transient( 'wldelay_email_cooldown' );

        // Now email should be sent
        wldelay_send_notification_email( '192.168.1.102', 'testuser3', 5 );
        $this->assertCount( 2, $this->sent_emails );
    }

    /**
     * Test that simultaneous failures from multiple distinct IPs are suppressed after the first alert.
     *
     * Documents intentional behavior: when multiple IPs each hit the failure threshold within the
     * email cooldown window, only the first IP triggers an alert. Subsequent IPs are silently
     * suppressed until the cooldown expires. This is by design — the cooldown is site-wide.
     */
    public function test_multi_ip_simultaneous_threshold_only_first_triggers_alert() {
        update_option( 'wldelay_options', [
            'wldelay_email_enabled'   => true,
            'wldelay_email_threshold' => 1,
            'wldelay_email_cooldown'  => 5,
            'wldelay_lockout_enabled' => false,
        ] );
        wldelay_clear_options_cache();

        // IP 1 hits threshold — email should fire
        $_SERVER['REMOTE_ADDR'] = '10.0.1.1';
        delete_transient( 'wldelay_fails_' . md5( '10.0.1.1' ) );
        wldelay_track_failed_attempt( 'attacker1' );
        $this->assertCount( 1, $this->sent_emails, 'First IP reaching threshold should trigger an alert' );

        // IP 2 hits its own threshold within cooldown window — suppressed
        $_SERVER['REMOTE_ADDR'] = '10.0.1.2';
        delete_transient( 'wldelay_fails_' . md5( '10.0.1.2' ) );
        wldelay_track_failed_attempt( 'attacker2' );
        $this->assertCount( 1, $this->sent_emails, 'Second IP should be suppressed by site-wide cooldown' );

        // IP 3 also suppressed — all subsequent IPs silenced during cooldown
        $_SERVER['REMOTE_ADDR'] = '10.0.1.3';
        delete_transient( 'wldelay_fails_' . md5( '10.0.1.3' ) );
        wldelay_track_failed_attempt( 'attacker3' );
        $this->assertCount( 1, $this->sent_emails, 'Third IP also suppressed during cooldown' );

        // After cooldown expires, the next IP at threshold fires again
        delete_transient( 'wldelay_email_cooldown' );
        $_SERVER['REMOTE_ADDR'] = '10.0.1.4';
        delete_transient( 'wldelay_fails_' . md5( '10.0.1.4' ) );
        wldelay_track_failed_attempt( 'attacker4' );
        $this->assertCount( 2, $this->sent_emails, 'After cooldown expires, next IP at threshold triggers a new alert' );
    }

    /**
     * Test that email cooldown of 0 disables rate limiting.
     */
    public function test_email_cooldown_zero_disables_rate_limiting() {
        // Enable email with cooldown disabled
        update_option( 'wldelay_options', [
            'wldelay_email_enabled' => true,
            'wldelay_email_threshold' => 1,
            'wldelay_email_cooldown' => 0,
        ] );
        wldelay_clear_options_cache();

        // Multiple emails should be sent
        wldelay_send_notification_email( '192.168.1.100', 'testuser', 5 );
        wldelay_send_notification_email( '192.168.1.101', 'testuser2', 5 );
        wldelay_send_notification_email( '192.168.1.102', 'testuser3', 5 );

        $this->assertCount( 3, $this->sent_emails );
    }
}
