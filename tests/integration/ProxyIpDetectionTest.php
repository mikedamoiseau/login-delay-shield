<?php
/**
 * Integration tests for proxy/CDN-aware client IP detection:
 * CF-Connecting-IP (validated against Cloudflare ranges), X-Sucuri-ClientIP,
 * X-Real-IP, header priority, garbage-value fallback, and the proxy
 * configuration health check.
 */

class ProxyIpDetectionTest extends WP_UnitTestCase {

    private const PROXY_KEYS = [
        'HTTP_CF_CONNECTING_IP',
        'HTTP_X_SUCURI_CLIENTIP',
        'HTTP_X_REAL_IP',
        'HTTP_X_FORWARDED_FOR',
        'HTTP_CLIENT_IP',
        'REMOTE_ADDR',
    ];

    public function setUp(): void {
        parent::setUp();
        foreach ( self::PROXY_KEYS as $key ) {
            unset( $_SERVER[ $key ] );
        }
        delete_option( 'wldelay_options' );
        wldelay_clear_options_cache();
    }

    public function tearDown(): void {
        foreach ( self::PROXY_KEYS as $key ) {
            unset( $_SERVER[ $key ] );
        }
        delete_option( 'wldelay_options' );
        wldelay_clear_options_cache();
        parent::tearDown();
    }

    private function trust_proxy() {
        update_option( 'wldelay_options', [ 'wldelay_trust_proxy_headers' => true ] );
        wldelay_clear_options_cache();
    }

    // =========================================================================
    // Cloudflare range validation
    // =========================================================================

    public function test_cloudflare_remote_addr_detection() {
        // 104.16.0.0/13 is a published Cloudflare range.
        $this->assertTrue( wldelay_is_cloudflare_remote_addr( '104.16.1.1' ) );
        // IPv6 edge: 2606:4700::/32.
        $this->assertTrue( wldelay_is_cloudflare_remote_addr( '2606:4700::1234' ) );
        // Non-Cloudflare addresses.
        $this->assertFalse( wldelay_is_cloudflare_remote_addr( '203.0.113.5' ) );
        $this->assertFalse( wldelay_is_cloudflare_remote_addr( '' ) );
        $this->assertFalse( wldelay_is_cloudflare_remote_addr( 'not-an-ip' ) );
    }

    public function test_cloudflare_ranges_filterable() {
        add_filter( 'wldelay_cloudflare_ip_ranges', function () {
            return [ '198.51.100.0/24' ];
        } );

        $this->assertTrue( wldelay_is_cloudflare_remote_addr( '198.51.100.7' ) );
        $this->assertFalse( wldelay_is_cloudflare_remote_addr( '104.16.1.1' ), 'Filter should replace the bundled list' );

        remove_all_filters( 'wldelay_cloudflare_ip_ranges' );
    }

    // =========================================================================
    // CF-Connecting-IP
    // =========================================================================

    public function test_cf_connecting_ip_honored_from_cloudflare_edge() {
        $this->trust_proxy();
        $_SERVER['REMOTE_ADDR'] = '104.16.1.1'; // Cloudflare edge.
        $_SERVER['HTTP_CF_CONNECTING_IP'] = '203.0.113.42';

        $this->assertSame( '203.0.113.42', wldelay_get_client_ip() );
    }

    public function test_cf_connecting_ip_ignored_when_not_from_cloudflare() {
        $this->trust_proxy();
        $_SERVER['REMOTE_ADDR'] = '203.0.113.5'; // NOT Cloudflare: spoof attempt.
        $_SERVER['HTTP_CF_CONNECTING_IP'] = '10.99.99.99';

        $this->assertSame( '203.0.113.5', wldelay_get_client_ip(), 'Spoofed CF header must be ignored' );
    }

    public function test_cf_connecting_ip_ignored_when_trust_disabled() {
        $_SERVER['REMOTE_ADDR'] = '104.16.1.1';
        $_SERVER['HTTP_CF_CONNECTING_IP'] = '203.0.113.42';

        $this->assertSame( '104.16.1.1', wldelay_get_client_ip() );
    }

    // =========================================================================
    // Other proxy headers
    // =========================================================================

    public function test_sucuri_header_honored_when_trusted() {
        $this->trust_proxy();
        $_SERVER['REMOTE_ADDR'] = '192.0.2.1';
        $_SERVER['HTTP_X_SUCURI_CLIENTIP'] = '203.0.113.77';

        $this->assertSame( '203.0.113.77', wldelay_get_client_ip() );
    }

    public function test_x_real_ip_honored_when_trusted() {
        $this->trust_proxy();
        $_SERVER['REMOTE_ADDR'] = '192.0.2.1';
        $_SERVER['HTTP_X_REAL_IP'] = '203.0.113.88';

        $this->assertSame( '203.0.113.88', wldelay_get_client_ip() );
    }

    public function test_header_priority_cf_wins_over_forwarded_for() {
        $this->trust_proxy();
        $_SERVER['REMOTE_ADDR'] = '104.16.1.1';
        $_SERVER['HTTP_CF_CONNECTING_IP'] = '203.0.113.42';
        $_SERVER['HTTP_X_FORWARDED_FOR'] = '198.51.100.9, 104.16.1.1';

        $this->assertSame( '203.0.113.42', wldelay_get_client_ip() );
    }

    public function test_client_ip_preserved_over_forwarded_for() {
        // Pre-existing priority must not change: Client-IP before X-Forwarded-For.
        $this->trust_proxy();
        $_SERVER['REMOTE_ADDR'] = '192.0.2.1';
        $_SERVER['HTTP_CLIENT_IP'] = '203.0.113.11';
        $_SERVER['HTTP_X_FORWARDED_FOR'] = '198.51.100.9';

        $this->assertSame( '203.0.113.11', wldelay_get_client_ip() );
    }

    public function test_forwarded_for_first_ip_used() {
        $this->trust_proxy();
        $_SERVER['REMOTE_ADDR'] = '192.0.2.1';
        $_SERVER['HTTP_X_FORWARDED_FOR'] = ' 203.0.113.33 , 198.51.100.9';

        $this->assertSame( '203.0.113.33', wldelay_get_client_ip() );
    }

    // =========================================================================
    // Garbage handling
    // =========================================================================

    public function test_garbage_header_falls_back_to_next_candidate() {
        $this->trust_proxy();
        $_SERVER['REMOTE_ADDR'] = '192.0.2.1';
        $_SERVER['HTTP_X_REAL_IP'] = '<script>alert(1)</script>';
        $_SERVER['HTTP_X_FORWARDED_FOR'] = '203.0.113.55';

        $this->assertSame( '203.0.113.55', wldelay_get_client_ip() );
    }

    public function test_all_garbage_headers_fall_back_to_remote_addr() {
        $this->trust_proxy();
        $_SERVER['REMOTE_ADDR'] = '192.0.2.1';
        $_SERVER['HTTP_CLIENT_IP'] = 'not-an-ip';
        $_SERVER['HTTP_X_FORWARDED_FOR'] = 'also-garbage';

        $this->assertSame( '192.0.2.1', wldelay_get_client_ip() );
    }

    // =========================================================================
    // Proxy health status
    // =========================================================================

    public function test_health_misconfigured_cdn_when_headers_present_but_trust_off() {
        $_SERVER['REMOTE_ADDR'] = '104.16.1.1';
        $_SERVER['HTTP_CF_CONNECTING_IP'] = '203.0.113.42';

        $health = wldelay_get_proxy_health_status();
        $this->assertSame( 'misconfigured-cdn', $health['status'] );
        $this->assertContains( 'CF-Connecting-IP', $health['headers'] );
    }

    public function test_health_spoofable_when_trust_on_but_no_headers() {
        $this->trust_proxy();
        $_SERVER['REMOTE_ADDR'] = '192.0.2.1';

        $health = wldelay_get_proxy_health_status();
        $this->assertSame( 'spoofable', $health['status'] );
        $this->assertSame( [], $health['headers'] );
    }

    public function test_health_ok_when_trust_on_and_headers_present() {
        $this->trust_proxy();
        $_SERVER['REMOTE_ADDR'] = '104.16.1.1';
        $_SERVER['HTTP_X_FORWARDED_FOR'] = '203.0.113.42';

        $this->assertSame( 'ok', wldelay_get_proxy_health_status()['status'] );
    }

    public function test_health_none_when_trust_off_and_no_headers() {
        $_SERVER['REMOTE_ADDR'] = '192.0.2.1';

        $this->assertSame( 'none', wldelay_get_proxy_health_status()['status'] );
    }
}
