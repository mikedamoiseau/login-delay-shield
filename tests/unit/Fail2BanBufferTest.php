<?php
/**
 * Unit tests for the buffered fail2ban writer (F-4-5).
 *
 * Lines are formatted and buffered at call time; a single locked append on
 * the shutdown hook writes them out. These tests cover the buffer gating
 * (enabled/disabled, IP validation), the flush write, and the lazy one-time
 * shutdown hook registration.
 */

use Brain\Monkey\Actions;
use Brain\Monkey\Filters;
use Brain\Monkey\Functions;

class Fail2BanBufferTest extends LDS_Unit_Test_Case {

    /**
     * Temp dirs created by flush tests, removed in tearDown.
     *
     * @var array<int,string>
     */
    protected $temp_dirs = array();

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

        wldelay_reset_fail2ban_buffer();
    }

    protected function tearDown(): void {
        wldelay_reset_fail2ban_buffer();

        foreach ( $this->temp_dirs as $dir ) {
            if ( is_dir( $dir ) ) {
                foreach ( scandir( $dir ) as $entry ) {
                    if ( $entry !== '.' && $entry !== '..' ) {
                        @unlink( $dir . '/' . $entry );
                    }
                }
                @rmdir( $dir );
            }
        }
        $this->temp_dirs = array();

        parent::tearDown();
    }

    /**
     * Stub wldelay_get_options (not loaded in the unit bootstrap) so the
     * buffer's enable gating sees the given options.
     *
     * NOTE: uses Functions\when(), so tests must never Functions\expect()
     * wldelay_get_options afterwards (the when() stub silently swallows it).
     *
     * @param array $options Plugin options.
     */
    private function stub_options( array $options ) {
        Functions\when( 'wldelay_get_options' )->justReturn( $options );
    }

    /**
     * Create a unique writable temp log target and allow it via the
     * wldelay_fail2ban_allowed_log_dirs filter so flush resolves to it.
     *
     * @return string Absolute log path inside a fresh temp directory.
     */
    private function allowed_temp_log_path() {
        $dir = sys_get_temp_dir() . '/wldelay-f2b-buffer-' . substr( md5( uniqid( '', true ) ), 0, 8 );
        $this->temp_dirs[] = $dir;

        Filters\expectApplied( 'wldelay_fail2ban_allowed_log_dirs' )
            ->zeroOrMoreTimes()
            ->andReturn( array( $dir ) );

        return $dir . '/buffer-test.log';
    }

    public function test_buffer_accumulates_without_writing() {
        $this->stub_options( array( 'wldelay_fail2ban_enabled' => true ) );

        $this->assertTrue( wldelay_buffer_fail2ban_line( 'failed login', '203.0.113.9', 'admin', 'wp-login' ) );
        $this->assertTrue( wldelay_buffer_fail2ban_line( 'failed login', '203.0.113.9', 'bob', 'rest' ) );

        $buffer = wldelay_get_fail2ban_buffer();
        $this->assertCount( 2, $buffer );
        $this->assertStringContainsString( 'username=admin', $buffer[0] );
        $this->assertStringContainsString( 'username=bob', $buffer[1] );
    }

    public function test_disabled_event_not_buffered() {
        $this->stub_options( array( 'wldelay_fail2ban_enabled' => false ) );

        $this->assertFalse( wldelay_buffer_fail2ban_line( 'failed login', '203.0.113.9', 'admin', 'wp-login' ) );
        $this->assertCount( 0, wldelay_get_fail2ban_buffer() );
    }

    public function test_invalid_ip_not_buffered() {
        $this->stub_options( array( 'wldelay_fail2ban_enabled' => true ) );

        $this->assertFalse( wldelay_buffer_fail2ban_line( 'failed login', 'not-an-ip', 'admin', 'wp-login' ) );
        $this->assertCount( 0, wldelay_get_fail2ban_buffer() );
    }

    public function test_flush_writes_lines_in_order_and_empties_buffer() {
        $path = $this->allowed_temp_log_path();
        $this->stub_options( array(
            'wldelay_fail2ban_enabled'          => true,
            'wldelay_fail2ban_include_lockouts' => true,
            'wldelay_fail2ban_log_path'         => $path,
        ) );

        wldelay_buffer_fail2ban_line( 'failed login', '203.0.113.9', 'admin', 'wp-login' );
        wldelay_buffer_fail2ban_line( 'lockout', '203.0.113.9', 'admin', 'wp-login' );

        $written = wldelay_flush_fail2ban_buffer();

        $this->assertSame( 2, $written );
        $this->assertCount( 0, wldelay_get_fail2ban_buffer() );
        $this->assertFileExists( $path );

        $lines = array_values( array_filter( explode( PHP_EOL, file_get_contents( $path ) ) ) );
        $this->assertCount( 2, $lines );
        $this->assertStringContainsString( 'Login Delay Shield: failed login', $lines[0] );
        $this->assertStringContainsString( 'Login Delay Shield: lockout', $lines[1] );
    }

    public function test_flush_with_empty_buffer_writes_nothing() {
        $path = $this->allowed_temp_log_path();
        $this->stub_options( array(
            'wldelay_fail2ban_enabled'  => true,
            'wldelay_fail2ban_log_path' => $path,
        ) );

        $this->assertSame( 0, wldelay_flush_fail2ban_buffer() );
        $this->assertFileDoesNotExist( $path );
    }

    public function test_shutdown_hook_registered_on_first_buffered_line_only() {
        $this->stub_options( array( 'wldelay_fail2ban_enabled' => true ) );

        Actions\expectAdded( 'shutdown' )
            ->once()
            ->with( 'wldelay_flush_fail2ban_buffer', PHP_INT_MAX );

        wldelay_buffer_fail2ban_line( 'failed login', '203.0.113.9', 'admin', 'wp-login' );
        wldelay_buffer_fail2ban_line( 'failed login', '203.0.113.9', 'bob', 'wp-login' );

        $this->assertCount( 2, wldelay_get_fail2ban_buffer() );
    }
}
