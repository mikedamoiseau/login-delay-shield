<?php
/**
 * Integration tests for fail2ban-compatible logging.
 */

class Fail2BanTest extends WP_UnitTestCase {

    private $log_path;

    public function setUp(): void {
        parent::setUp();

        wldelay_create_log_table();
        delete_option( 'wldelay_options' );
        wldelay_clear_options_cache();

        $this->log_path = trailingslashit( dirname( wldelay_fail2ban_get_default_log_path() ) ) . 'test/login-delay-shield-fail2ban-test.log';
        $this->delete_log_file();

        // F-4-5: lines are buffered per request; start each test with an empty buffer.
        wldelay_reset_fail2ban_buffer();

        $_SERVER['REMOTE_ADDR'] = '203.0.113.10';
    }

    public function tearDown(): void {
        global $wpdb;

        // F-4-5: drop any unflushed lines so they cannot leak into other tests.
        wldelay_reset_fail2ban_buffer();

        $this->delete_log_file();
        if ( $wpdb ) {
            $wpdb->query( 'TRUNCATE TABLE ' . wldelay_get_log_table_name() );
        }
        unset( $_SERVER['REMOTE_ADDR'] );
        delete_option( 'wldelay_options' );
        wldelay_clear_options_cache();

        parent::tearDown();
    }

    private function delete_log_file() {
        if ( $this->log_path && is_dir( dirname( $this->log_path ) ) ) {
            $this->recursive_rmdir( dirname( $this->log_path ) );
        }

        $default_dir = dirname( wldelay_fail2ban_get_default_log_path() );
        if ( is_dir( $default_dir ) ) {
            $this->recursive_rmdir( $default_dir );
        }
    }

    private function recursive_rmdir( $dir ) {
        foreach ( scandir( $dir ) as $entry ) {
            if ( $entry === '.' || $entry === '..' ) {
                continue;
            }
            $path = $dir . '/' . $entry;
            if ( is_dir( $path ) && ! is_link( $path ) ) {
                $this->recursive_rmdir( $path );
            } else {
                @unlink( $path );
            }
        }
        @rmdir( $dir );
    }

    public function test_failed_attempt_does_not_write_when_disabled() {
        update_option( 'wldelay_options', array(
            'wldelay_fail2ban_enabled'  => false,
            'wldelay_fail2ban_log_path' => $this->log_path,
        ) );
        wldelay_clear_options_cache();

        wldelay_log_failed_attempt( '203.0.113.10', 'alice', 'wp-login' );
        wldelay_flush_fail2ban_buffer();

        $this->assertFileDoesNotExist( $this->log_path );
    }

    public function test_failed_attempt_writes_when_enabled() {
        update_option( 'wldelay_options', array(
            'wldelay_fail2ban_enabled'  => true,
            'wldelay_fail2ban_log_path' => $this->log_path,
        ) );
        wldelay_clear_options_cache();

        wldelay_log_failed_attempt( '203.0.113.10', 'alice', 'wp-login' );
        wldelay_flush_fail2ban_buffer();

        $this->assertFileExists( $this->log_path );
        $contents = file_get_contents( $this->log_path );
        $this->assertStringContainsString( 'Login Delay Shield: failed login', $contents );
        $this->assertStringContainsString( 'source=wp-login', $contents );
        $this->assertStringContainsString( 'ip=203.0.113.10', $contents );
        $this->assertStringContainsString( 'username=alice', $contents );
    }

    public function test_default_log_directory_gets_basic_web_protection() {
        update_option( 'wldelay_options', array(
            'wldelay_fail2ban_enabled'  => true,
            'wldelay_fail2ban_log_path' => '',
        ) );
        wldelay_clear_options_cache();

        wldelay_log_failed_attempt( '203.0.113.10', 'alice', 'wp-login' );
        wldelay_flush_fail2ban_buffer();

        $default_path = wldelay_fail2ban_get_default_log_path();
        $default_dir  = dirname( $default_path );
        $this->assertFileExists( $default_path );
        $this->assertFileExists( trailingslashit( $default_dir ) . '.htaccess' );
        $this->assertFileExists( trailingslashit( $default_dir ) . 'index.html' );
        $this->assertFileExists( trailingslashit( $default_dir ) . 'index.php' );
        $htaccess = file_get_contents( trailingslashit( $default_dir ) . '.htaccess' );
        $this->assertStringContainsString( 'Require all denied', $htaccess );
        $this->assertStringContainsString( 'Deny from all', $htaccess );
        $index_php = file_get_contents( trailingslashit( $default_dir ) . 'index.php' );
        $this->assertStringContainsString( 'Silence is golden', $index_php );
    }

    public function test_lockout_event_respects_toggle() {
        update_option( 'wldelay_options', array(
            'wldelay_fail2ban_enabled'          => true,
            'wldelay_fail2ban_log_path'         => $this->log_path,
            'wldelay_fail2ban_include_lockouts' => false,
        ) );
        wldelay_clear_options_cache();

        wldelay_lock_ip( '203.0.113.10', 'alice', 'wp-login' );
        wldelay_flush_fail2ban_buffer();

        $this->assertFileDoesNotExist( $this->log_path );
    }

    public function test_lockout_event_writes_when_enabled() {
        update_option( 'wldelay_options', array(
            'wldelay_fail2ban_enabled'          => true,
            'wldelay_fail2ban_log_path'         => $this->log_path,
            'wldelay_fail2ban_include_lockouts' => true,
        ) );
        wldelay_clear_options_cache();

        wldelay_lock_ip( '203.0.113.10', 'alice', 'wp-login' );
        wldelay_flush_fail2ban_buffer();

        $this->assertFileExists( $this->log_path );
        $contents = file_get_contents( $this->log_path );
        $this->assertStringContainsString( 'Login Delay Shield: lockout', $contents );
        $this->assertStringContainsString( 'source=wp-login', $contents );
        $this->assertStringContainsString( 'ip=203.0.113.10', $contents );
        $this->assertStringContainsString( 'username=alice', $contents );
    }

    public function test_two_attempts_in_one_request_flush_as_two_lines() {
        update_option( 'wldelay_options', array(
            'wldelay_fail2ban_enabled'  => true,
            'wldelay_fail2ban_log_path' => $this->log_path,
        ) );
        wldelay_clear_options_cache();

        wldelay_log_failed_attempt( '203.0.113.10', 'alice', 'wp-login' );
        wldelay_log_failed_attempt( '203.0.113.10', 'bob', 'rest' );

        // Nothing hits the filesystem until the single shutdown flush (F-4-5).
        $this->assertFileDoesNotExist( $this->log_path );

        $this->assertSame( 2, wldelay_flush_fail2ban_buffer() );

        $lines = array_values( array_filter( explode( PHP_EOL, file_get_contents( $this->log_path ) ) ) );
        $this->assertCount( 2, $lines );
        $this->assertStringContainsString( 'username=alice', $lines[0] );
        $this->assertStringContainsString( 'username=bob', $lines[1] );
    }
}
