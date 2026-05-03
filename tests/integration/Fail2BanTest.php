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

        $uploads = wp_upload_dir();
        $this->log_path = trailingslashit( $uploads['basedir'] ) . 'login-delay-shield-fail2ban-test.log';
        $this->delete_log_file();

        $_SERVER['REMOTE_ADDR'] = '203.0.113.10';
    }

    public function tearDown(): void {
        $this->delete_log_file();
        unset( $_SERVER['REMOTE_ADDR'] );
        delete_option( 'wldelay_options' );
        wldelay_clear_options_cache();

        parent::tearDown();
    }

    private function delete_log_file() {
        if ( $this->log_path && file_exists( $this->log_path ) ) {
            unlink( $this->log_path );
        }
    }

    public function test_failed_attempt_does_not_write_when_disabled() {
        update_option( 'wldelay_options', array(
            'wldelay_fail2ban_enabled'  => false,
            'wldelay_fail2ban_log_path' => $this->log_path,
        ) );
        wldelay_clear_options_cache();

        wldelay_log_failed_attempt( '203.0.113.10', 'alice', 'wp-login' );

        $this->assertFileDoesNotExist( $this->log_path );
    }

    public function test_failed_attempt_writes_when_enabled() {
        update_option( 'wldelay_options', array(
            'wldelay_fail2ban_enabled'  => true,
            'wldelay_fail2ban_log_path' => $this->log_path,
        ) );
        wldelay_clear_options_cache();

        wldelay_log_failed_attempt( '203.0.113.10', 'alice', 'wp-login' );

        $this->assertFileExists( $this->log_path );
        $contents = file_get_contents( $this->log_path );
        $this->assertStringContainsString( 'Login Delay Shield: failed login', $contents );
        $this->assertStringContainsString( 'source=wp-login', $contents );
        $this->assertStringContainsString( 'ip=203.0.113.10', $contents );
        $this->assertStringContainsString( 'username=alice', $contents );
    }

    public function test_lockout_event_respects_toggle() {
        update_option( 'wldelay_options', array(
            'wldelay_fail2ban_enabled'          => true,
            'wldelay_fail2ban_log_path'         => $this->log_path,
            'wldelay_fail2ban_include_lockouts' => false,
        ) );
        wldelay_clear_options_cache();

        wldelay_lock_ip( '203.0.113.10', 'alice', 'wp-login' );

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

        $this->assertFileExists( $this->log_path );
        $contents = file_get_contents( $this->log_path );
        $this->assertStringContainsString( 'Login Delay Shield: lockout', $contents );
        $this->assertStringContainsString( 'source=wp-login', $contents );
        $this->assertStringContainsString( 'ip=203.0.113.10', $contents );
        $this->assertStringContainsString( 'username=alice', $contents );
    }
}
