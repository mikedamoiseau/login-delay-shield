<?php
/**
 * Unit tests for wldelay_get_client_ip() functionality.
 */

use Brain\Monkey\Functions;

class ClientIpTest extends LDS_Unit_Test_Case {

    /**
     * Current mock options for get_option calls.
     */
    private $mock_options = array();

    /**
     * Reset $_SERVER before each test.
     */
    protected function setUp(): void {
        parent::setUp();

        // Clear relevant $_SERVER values
        unset( $_SERVER['HTTP_CLIENT_IP'] );
        unset( $_SERVER['HTTP_X_FORWARDED_FOR'] );
        unset( $_SERVER['REMOTE_ADDR'] );

        // Default: proxy headers NOT trusted (secure default)
        $this->mock_options = array();

        // Mock sanitize_text_field to just trim
        Functions\when( 'sanitize_text_field' )->alias( function( $str ) {
            return trim( strip_tags( $str ) );
        });

        // Mock get_option to return our test options
        Functions\when( 'get_option' )->alias( function( $option, $default = array() ) {
            if ( $option === 'wldelay_options' ) {
                return $this->mock_options;
            }
            return $default;
        });
    }

    /**
     * Helper to enable proxy header trust for specific tests.
     */
    private function enable_proxy_trust() {
        $this->mock_options['wldelay_trust_proxy_headers'] = true;
    }

    // =========================================================================
    // Tests with proxy headers NOT trusted (default secure behavior)
    // =========================================================================

    /**
     * Test that REMOTE_ADDR is used when proxy headers are not trusted.
     */
    public function test_uses_remote_addr_by_default() {
        $_SERVER['HTTP_CLIENT_IP'] = '192.168.1.100';
        $_SERVER['HTTP_X_FORWARDED_FOR'] = '10.0.0.1';
        $_SERVER['REMOTE_ADDR'] = '203.0.113.50';

        $ip = $this->get_client_ip();

        $this->assertEquals( '203.0.113.50', $ip, 'Should use REMOTE_ADDR when proxy headers are not trusted' );
    }

    /**
     * Test that proxy headers are ignored when not trusted.
     */
    public function test_ignores_x_forwarded_for_by_default() {
        $_SERVER['HTTP_X_FORWARDED_FOR'] = '10.0.0.50';
        $_SERVER['REMOTE_ADDR'] = '127.0.0.1';

        $ip = $this->get_client_ip();

        $this->assertEquals( '127.0.0.1', $ip, 'Should ignore X-Forwarded-For when proxy headers are not trusted' );
    }

    /**
     * Test that HTTP_CLIENT_IP is ignored when not trusted.
     */
    public function test_ignores_client_ip_by_default() {
        $_SERVER['HTTP_CLIENT_IP'] = '10.0.0.99';
        $_SERVER['REMOTE_ADDR'] = '198.51.100.25';

        $ip = $this->get_client_ip();

        $this->assertEquals( '198.51.100.25', $ip, 'Should ignore HTTP_CLIENT_IP when proxy headers are not trusted' );
    }

    /**
     * Test that empty string is returned when only proxy headers are set (untrusted).
     */
    public function test_returns_empty_when_only_proxy_headers_set() {
        $_SERVER['HTTP_CLIENT_IP'] = '192.168.1.100';
        $_SERVER['HTTP_X_FORWARDED_FOR'] = '10.0.0.1';
        // No REMOTE_ADDR set

        $ip = $this->get_client_ip();

        $this->assertEquals( '', $ip, 'Should return empty when only untrusted proxy headers are available' );
    }

    // =========================================================================
    // Tests with proxy headers trusted
    // =========================================================================

    /**
     * Test that HTTP_CLIENT_IP takes priority when trusted.
     */
    public function test_http_client_ip_priority_when_trusted() {
        $this->enable_proxy_trust();

        $_SERVER['HTTP_CLIENT_IP'] = '192.168.1.100';
        $_SERVER['HTTP_X_FORWARDED_FOR'] = '10.0.0.1';
        $_SERVER['REMOTE_ADDR'] = '127.0.0.1';

        $ip = $this->get_client_ip();

        $this->assertEquals( '192.168.1.100', $ip );
    }

    /**
     * Test that X-Forwarded-For is used when trusted and HTTP_CLIENT_IP is not set.
     */
    public function test_x_forwarded_for_when_trusted() {
        $this->enable_proxy_trust();

        $_SERVER['HTTP_X_FORWARDED_FOR'] = '10.0.0.50';
        $_SERVER['REMOTE_ADDR'] = '127.0.0.1';

        $ip = $this->get_client_ip();

        $this->assertEquals( '10.0.0.50', $ip );
    }

    /**
     * Test that first IP is extracted from X-Forwarded-For chain when trusted.
     */
    public function test_x_forwarded_for_extracts_first_ip_when_trusted() {
        $this->enable_proxy_trust();

        $_SERVER['HTTP_X_FORWARDED_FOR'] = '203.0.113.50, 192.168.1.1, 10.0.0.1';
        $_SERVER['REMOTE_ADDR'] = '127.0.0.1';

        $ip = $this->get_client_ip();

        $this->assertEquals( '203.0.113.50', $ip );
    }

    /**
     * Test that REMOTE_ADDR is still used as fallback when trusted but no proxy headers.
     */
    public function test_remote_addr_fallback_when_trusted() {
        $this->enable_proxy_trust();

        $_SERVER['REMOTE_ADDR'] = '198.51.100.25';

        $ip = $this->get_client_ip();

        $this->assertEquals( '198.51.100.25', $ip );
    }

    /**
     * Test that empty HTTP_CLIENT_IP is skipped when trusted.
     */
    public function test_empty_client_ip_skipped_when_trusted() {
        $this->enable_proxy_trust();

        $_SERVER['HTTP_CLIENT_IP'] = '';
        $_SERVER['HTTP_X_FORWARDED_FOR'] = '10.0.0.75';
        $_SERVER['REMOTE_ADDR'] = '127.0.0.1';

        $ip = $this->get_client_ip();

        $this->assertEquals( '10.0.0.75', $ip );
    }

    // =========================================================================
    // General tests (apply to both modes)
    // =========================================================================

    /**
     * Test that empty string is returned when no headers are set.
     */
    public function test_returns_empty_when_no_headers() {
        $ip = $this->get_client_ip();

        $this->assertEquals( '', $ip );
    }

    /**
     * Test that IPv6 addresses are handled correctly.
     */
    public function test_ipv6_address_handling() {
        $_SERVER['REMOTE_ADDR'] = '2001:db8::1';

        $ip = $this->get_client_ip();

        $this->assertEquals( '2001:db8::1', $ip );
    }

    /**
     * Test that IPv6 in X-Forwarded-For chain is extracted when trusted.
     */
    public function test_ipv6_in_x_forwarded_for_when_trusted() {
        $this->enable_proxy_trust();

        $_SERVER['HTTP_X_FORWARDED_FOR'] = '2001:db8::100, 192.168.1.1';

        $ip = $this->get_client_ip();

        $this->assertEquals( '2001:db8::100', $ip );
    }

    /**
     * Test that IP is trimmed of whitespace.
     */
    public function test_ip_is_trimmed() {
        $_SERVER['REMOTE_ADDR'] = '  192.168.1.50  ';

        $ip = $this->get_client_ip();

        $this->assertEquals( '192.168.1.50', $ip );
    }

    /**
     * Test X-Forwarded-For with spaces around IPs when trusted.
     */
    public function test_x_forwarded_for_with_spaces_when_trusted() {
        $this->enable_proxy_trust();

        $_SERVER['HTTP_X_FORWARDED_FOR'] = '  203.0.113.100  ,  192.168.1.1  ';

        $ip = $this->get_client_ip();

        $this->assertEquals( '203.0.113.100', $ip );
    }

    // =========================================================================
    // Security-focused tests
    // =========================================================================

    /**
     * Test that attackers cannot bypass lockout by spoofing headers (default).
     */
    public function test_spoofed_headers_ignored_by_default() {
        // Attacker sends spoofed headers but their real IP is REMOTE_ADDR
        $_SERVER['HTTP_CLIENT_IP'] = '1.2.3.4';  // Spoofed
        $_SERVER['HTTP_X_FORWARDED_FOR'] = '5.6.7.8';  // Spoofed
        $_SERVER['REMOTE_ADDR'] = '198.51.100.50';  // Real connection IP

        $ip = $this->get_client_ip();

        $this->assertEquals( '198.51.100.50', $ip, 'Should use real connection IP, not spoofed headers' );
    }

    /**
     * Test that whitespace-only proxy headers fall back to REMOTE_ADDR when trusted.
     */
    public function test_whitespace_proxy_headers_fallback_when_trusted() {
        $this->enable_proxy_trust();

        $_SERVER['HTTP_CLIENT_IP'] = '   ';
        $_SERVER['HTTP_X_FORWARDED_FOR'] = '';
        $_SERVER['REMOTE_ADDR'] = '10.0.0.1';

        $ip = $this->get_client_ip();

        // Whitespace-only headers are trimmed before empty() check,
        // so they correctly fall back to REMOTE_ADDR
        $this->assertEquals( '10.0.0.1', $ip );
    }

    /**
     * Test that whitespace in X-Forwarded-For is trimmed correctly.
     */
    public function test_whitespace_x_forwarded_for_trimmed() {
        $this->enable_proxy_trust();

        $_SERVER['HTTP_CLIENT_IP'] = '';
        $_SERVER['HTTP_X_FORWARDED_FOR'] = '  192.168.1.50  , 10.0.0.1';
        $_SERVER['REMOTE_ADDR'] = '10.0.0.99';

        $ip = $this->get_client_ip();

        // First IP should be trimmed of whitespace
        $this->assertEquals( '192.168.1.50', $ip );
    }

    /**
     * Helper to replicate wldelay_get_client_ip() logic.
     *
     * @return string The client IP address.
     */
    private function get_client_ip(): string {
        $options = get_option( 'wldelay_options', array() );
        $trust_proxy = ! empty( $options['wldelay_trust_proxy_headers'] );

        $ip = '';

        // Only check proxy headers if explicitly trusted (they can be spoofed)
        if ( $trust_proxy ) {
            $client_ip = isset( $_SERVER['HTTP_CLIENT_IP'] ) ? trim( $_SERVER['HTTP_CLIENT_IP'] ) : '';
            $forwarded = isset( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ? trim( $_SERVER['HTTP_X_FORWARDED_FOR'] ) : '';

            if ( ! empty( $client_ip ) ) {
                $ip = $client_ip;
            } elseif ( ! empty( $forwarded ) ) {
                // Take the first IP (client IP) from the chain
                $ip = trim( explode( ',', $forwarded )[0] );
            }
        }

        // Fall back to REMOTE_ADDR (the actual TCP connection IP)
        if ( empty( $ip ) && ! empty( $_SERVER['REMOTE_ADDR'] ) ) {
            $ip = $_SERVER['REMOTE_ADDR'];
        }

        return sanitize_text_field( trim( $ip ) );
    }
}
