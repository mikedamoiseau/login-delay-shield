<?php
/**
 * Unit tests for fail2ban-compatible logging helpers.
 */

use Brain\Monkey\Functions;

class Fail2BanTest extends LDS_Unit_Test_Case {

    protected function setUp(): void {
        parent::setUp();

        Functions\when( 'sanitize_text_field' )->alias( function( $value ) {
            return trim( strip_tags( (string) $value ) );
        } );
    }

    public function test_formats_failed_login_line_with_stable_prefix_and_fields() {
        $line = wldelay_format_fail2ban_line(
            'failed login',
            '203.0.113.10',
            'Admin User',
            'wp-login',
            1714564800
        );

        $this->assertStringStartsWith( '2024-05-01T12:00:00+00:00 Login Delay Shield: failed login', $line );
        $this->assertStringContainsString( 'source=wp-login', $line );
        $this->assertStringContainsString( 'ip=203.0.113.10', $line );
        $this->assertStringContainsString( 'username=Admin_User', $line );
    }

    public function test_formats_lockout_line() {
        $line = wldelay_format_fail2ban_line(
            'lockout',
            '2001:db8::10',
            'alice',
            'application-password',
            1714564800
        );

        $this->assertStringContainsString( 'Login Delay Shield: lockout', $line );
        $this->assertStringContainsString( 'source=application-password', $line );
        $this->assertStringContainsString( 'ip=2001:db8::10', $line );
        $this->assertStringContainsString( 'username=alice', $line );
    }

    public function test_format_rejects_invalid_ip() {
        $line = wldelay_format_fail2ban_line(
            'failed login',
            'not-an-ip',
            'admin',
            'wp-login',
            1714564800
        );

        $this->assertSame( '', $line );
    }

    public function test_sanitizes_relative_log_path_under_default_directory() {
        $path = wldelay_sanitize_fail2ban_log_path( 'security/fail2ban.log' );

        $this->assertSame( dirname( wldelay_fail2ban_get_default_log_path() ) . '/security/fail2ban.log', $path );
    }

    public function test_sanitizes_empty_path_as_empty_for_runtime_default() {
        $this->assertSame( '', wldelay_sanitize_fail2ban_log_path( '' ) );
        $this->assertSame( wldelay_fail2ban_get_default_log_path(), wldelay_fail2ban_resolve_log_path( '' ) );
    }

    public function test_rejects_path_traversal_uploads_root_and_disallowed_absolute_paths() {
        $this->assertSame( '', wldelay_sanitize_fail2ban_log_path( '../fail2ban.log' ) );
        $this->assertSame( '', wldelay_sanitize_fail2ban_log_path( 'php://temp.log' ) );
        $this->assertSame( dirname( wldelay_fail2ban_get_default_log_path() ) . '/fail2ban.log', wldelay_sanitize_fail2ban_log_path( 'fail2ban.log' ) );
        $this->assertSame( '', wldelay_sanitize_fail2ban_log_path( wldelay_fail2ban_get_uploads_basedir() . '/fail2ban.log' ) );
        $this->assertSame( '', wldelay_sanitize_fail2ban_log_path( wldelay_fail2ban_get_uploads_basedir() . '/security/fail2ban.log' ) );
        $this->assertSame( '', wldelay_sanitize_fail2ban_log_path( wldelay_fail2ban_get_default_base_dir() . '/other.log' ) );
        $this->assertSame( '', wldelay_sanitize_fail2ban_log_path( '/var/log/auth.log' ) );
    }

    public function test_rejects_non_log_paths() {
        $this->assertSame( '', wldelay_sanitize_fail2ban_log_path( 'fail2ban.txt' ) );
    }

    public function test_disabled_options_do_not_log_events() {
        $options = array(
            'wldelay_fail2ban_enabled'          => false,
            'wldelay_fail2ban_include_lockouts' => true,
        );

        $this->assertFalse( wldelay_fail2ban_should_log_event( 'failed login', $options ) );
        $this->assertFalse( wldelay_fail2ban_should_log_event( 'lockout', $options ) );
    }

    public function test_lockout_toggle_controls_lockout_events_only() {
        $options = array(
            'wldelay_fail2ban_enabled'          => true,
            'wldelay_fail2ban_include_lockouts' => false,
        );

        $this->assertTrue( wldelay_fail2ban_should_log_event( 'failed login', $options ) );
        $this->assertFalse( wldelay_fail2ban_should_log_event( 'lockout', $options ) );
    }
}
