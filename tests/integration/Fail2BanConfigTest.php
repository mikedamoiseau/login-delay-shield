<?php
/**
 * Sync-guard tests for the downloadable fail2ban filter/jail config (F-5-8).
 *
 * The central contract: wldelay_fail2ban_failregex_as_pcre() must match every
 * line that wldelay_format_fail2ban_line() can produce.  Change the line format
 * without updating the regex and these tests will fail, preventing a silent
 * mismatch from shipping.
 */

class Fail2BanConfigTest extends WP_UnitTestCase {

    public function test_failregex_matches_real_failed_login_line() {
        $line  = wldelay_format_fail2ban_line( 'failed login', '203.0.113.9', 'admin', 'wp-login' );
        $regex = wldelay_fail2ban_failregex_as_pcre();
        $this->assertSame( 1, preg_match( $regex, $line, $m ) );
        $this->assertSame( '203.0.113.9', $m['host'] );
    }

    public function test_failregex_matches_lockout_line_and_ipv6() {
        $line = wldelay_format_fail2ban_line( 'lockout', '2001:db8::1', 'admin', 'xmlrpc' );
        $this->assertSame( 1, preg_match( wldelay_fail2ban_failregex_as_pcre(), $line, $m ) );
        $this->assertSame( '2001:db8::1', $m['host'] );
    }

    public function test_failregex_handles_username_with_spaces() {
        // sanitize_field replaces spaces with underscores — regex must match that output.
        $line = wldelay_format_fail2ban_line( 'failed login', '203.0.113.9', 'john doe', 'wp-login' );
        $this->assertSame( 1, preg_match( wldelay_fail2ban_failregex_as_pcre(), $line ) );
    }

    public function test_jail_config_contains_configured_log_path() {
        $jail = wldelay_fail2ban_generate_jail_config();
        $this->assertStringContainsString( wldelay_fail2ban_resolve_log_path(), $jail );
        $this->assertStringContainsString( '[wldelay]', $jail );
    }

    /** Additional sync-guard coverage: all five documented sources. */
    public function test_failregex_matches_all_sources() {
        $sources = array( 'wp-login', 'xmlrpc', 'rest', 'application-password', 'password-reset' );
        $regex   = wldelay_fail2ban_failregex_as_pcre();

        foreach ( $sources as $source ) {
            $line = wldelay_format_fail2ban_line( 'failed login', '198.51.100.1', 'tester', $source );
            $this->assertSame(
                1,
                preg_match( $regex, $line ),
                "failregex did not match source={$source} line: {$line}"
            );
        }
    }

    /** Empty username is sanitized to the '-' sentinel; \S+ must still match. */
    public function test_failregex_matches_empty_username_sentinel() {
        $line = wldelay_format_fail2ban_line( 'failed login', '203.0.113.9', '', 'rest' );
        $this->assertSame( 1, preg_match( wldelay_fail2ban_failregex_as_pcre(), $line, $m ) );
        $this->assertSame( '203.0.113.9', $m['host'] );
    }

    /** Both event types must match. */
    public function test_failregex_matches_both_events() {
        $regex = wldelay_fail2ban_failregex_as_pcre();

        foreach ( array( 'failed login', 'lockout' ) as $event ) {
            $line = wldelay_format_fail2ban_line( $event, '192.0.2.1', 'user', 'wp-login' );
            $this->assertSame(
                1,
                preg_match( $regex, $line ),
                "failregex did not match event={$event} line: {$line}"
            );
        }
    }

    /** Filter config must include the failregex keyword. */
    public function test_filter_config_contains_failregex() {
        $filter = wldelay_fail2ban_generate_filter_config();
        $this->assertStringContainsString( 'failregex', $filter );
        $this->assertStringContainsString( wldelay_fail2ban_get_failregex(), $filter );
    }

    /** Jail config must include required jail keys. */
    public function test_jail_config_structure() {
        $jail = wldelay_fail2ban_generate_jail_config();
        $this->assertStringContainsString( '[wldelay]', $jail );
        $this->assertStringContainsString( 'logpath', $jail );
        $this->assertStringContainsString( 'maxretry', $jail );
        $this->assertStringContainsString( 'bantime', $jail );
    }
}
