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

        Functions\when( 'get_option' )->justReturn( false );
        Functions\when( 'update_option' )->justReturn( true );
        Functions\when( 'wp_generate_password' )->alias( function( $length = 12 ) {
            return substr( str_repeat( 'abcdefghijklmnop', 2 ), 0, $length );
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

    public function test_default_log_directory_uses_random_token_and_stays_under_wp_content() {
        $base = wldelay_fail2ban_get_default_base_dir();
        $path = wldelay_fail2ban_get_default_log_path();

        // Base directory must stay inside wp-content, never collapse to the document root.
        $this->assertStringEndsWith( '/wp-content', $base );

        // Default log directory carries an unguessable per-install token so it
        // cannot be downloaded by URL guessing on servers that ignore .htaccess.
        $this->assertMatchesRegularExpression(
            '#/login-delay-shield-fail2ban-[A-Za-z0-9]{16}/login-delay-shield-fail2ban\.log$#',
            $path
        );

        // Token must be stable across calls within a request.
        $this->assertSame( $path, wldelay_fail2ban_get_default_log_path() );
    }

    public function test_lockout_toggle_controls_lockout_events_only() {
        $options = array(
            'wldelay_fail2ban_enabled'          => true,
            'wldelay_fail2ban_include_lockouts' => false,
        );

        $this->assertTrue( wldelay_fail2ban_should_log_event( 'failed login', $options ) );
        $this->assertFalse( wldelay_fail2ban_should_log_event( 'lockout', $options ) );
    }

    public function test_default_max_log_bytes_is_positive() {
        $this->assertGreaterThan( 0, wldelay_fail2ban_get_max_log_bytes() );
    }

    public function test_rotates_when_log_meets_or_exceeds_max() {
        $path = $this->temp_log_path();
        file_put_contents( $path, str_repeat( 'x', 100 ) );

        $rotated = wldelay_fail2ban_maybe_rotate_log( $path, 100 );

        $this->assertTrue( $rotated );
        $this->assertFileDoesNotExist( $path );
        $this->assertFileExists( $path . '.1' );
    }

    public function test_does_not_rotate_when_under_max() {
        $path = $this->temp_log_path();
        file_put_contents( $path, str_repeat( 'x', 50 ) );

        $rotated = wldelay_fail2ban_maybe_rotate_log( $path, 100 );

        $this->assertFalse( $rotated );
        $this->assertFileExists( $path );
        $this->assertFileDoesNotExist( $path . '.1' );
    }

    public function test_rotation_overwrites_previous_backup() {
        $path = $this->temp_log_path();
        file_put_contents( $path . '.1', 'old-backup' );
        file_put_contents( $path, str_repeat( 'x', 100 ) );

        wldelay_fail2ban_maybe_rotate_log( $path, 100 );

        $this->assertSame( str_repeat( 'x', 100 ), file_get_contents( $path . '.1' ) );
    }

    public function test_rotation_disabled_when_max_zero() {
        $path = $this->temp_log_path();
        file_put_contents( $path, str_repeat( 'x', 100 ) );

        $rotated = wldelay_fail2ban_maybe_rotate_log( $path, 0 );

        $this->assertFalse( $rotated );
        $this->assertFileExists( $path );
        $this->assertFileDoesNotExist( $path . '.1' );
    }

    public function test_protect_log_dir_writes_guards_in_any_existing_dir() {
        $dir = sys_get_temp_dir() . '/wldelay-protect-' . substr( md5( uniqid( '', true ) ), 0, 8 );
        mkdir( $dir, 0755, true );

        wldelay_fail2ban_protect_log_dir( $dir );

        $this->assertFileExists( $dir . '/.htaccess' );
        $this->assertFileExists( $dir . '/index.html' );
        $this->assertFileExists( $dir . '/index.php' );
        $this->assertStringContainsString( 'Require all denied', file_get_contents( $dir . '/.htaccess' ) );

        foreach ( array( '.htaccess', 'index.html', 'index.php' ) as $f ) {
            unlink( $dir . '/' . $f );
        }
        rmdir( $dir );
    }

    private function temp_log_path() {
        $path = sys_get_temp_dir() . '/wldelay-rotate-' . substr( md5( uniqid( '', true ) ), 0, 8 ) . '.log';
        $this->temp_paths[] = $path;
        return $path;
    }

    protected $temp_paths = array();

    protected function tearDown(): void {
        foreach ( $this->temp_paths as $path ) {
            foreach ( array( $path, $path . '.1' ) as $f ) {
                if ( file_exists( $f ) ) {
                    unlink( $f );
                }
            }
        }
        $this->temp_paths = array();

        parent::tearDown();
    }
}
