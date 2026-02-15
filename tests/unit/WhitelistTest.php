<?php
/**
 * Unit tests for IP whitelist functionality.
 */

use Brain\Monkey\Functions;

class WhitelistTest extends LDS_Unit_Test_Case {

    /**
     * @var LDS_Settings
     */
    private $settings;

    protected function setUp(): void {
        parent::setUp();

        // Mock WordPress functions used by the settings class
        Functions\when( 'absint' )->alias( function( $value ) {
            return abs( (int) $value );
        });

        Functions\when( 'sanitize_email' )->alias( function( $email ) {
            return filter_var( $email, FILTER_SANITIZE_EMAIL );
        });

        // Create settings instance
        $this->settings = new LDS_Settings();
    }

    /**
     * Test that valid IPv4 addresses are accepted.
     */
    public function test_valid_ipv4_addresses_accepted() {
        $input = "192.168.1.1\n10.0.0.1\n172.16.0.1";

        $result = $this->settings->sanitize_whitelist_ips( $input );

        $this->assertStringContainsString( '192.168.1.1', $result );
        $this->assertStringContainsString( '10.0.0.1', $result );
        $this->assertStringContainsString( '172.16.0.1', $result );
    }

    /**
     * Test that valid IPv4 CIDR ranges are accepted.
     */
    public function test_valid_ipv4_cidr_accepted() {
        $input = "10.0.0.0/8\n192.168.1.0/24\n172.16.0.0/12";

        $result = $this->settings->sanitize_whitelist_ips( $input );

        $this->assertStringContainsString( '10.0.0.0/8', $result );
        $this->assertStringContainsString( '192.168.1.0/24', $result );
        $this->assertStringContainsString( '172.16.0.0/12', $result );
    }

    /**
     * Test that valid IPv6 addresses are accepted.
     */
    public function test_valid_ipv6_addresses_accepted() {
        $input = "::1\n2001:db8::1\nfe80::1";

        $result = $this->settings->sanitize_whitelist_ips( $input );

        $this->assertStringContainsString( '::1', $result );
        $this->assertStringContainsString( '2001:db8::1', $result );
        $this->assertStringContainsString( 'fe80::1', $result );
    }

    /**
     * Test that valid IPv6 CIDR ranges are accepted.
     */
    public function test_valid_ipv6_cidr_accepted() {
        $input = "2001:db8::/32\nfe80::/10";

        $result = $this->settings->sanitize_whitelist_ips( $input );

        $this->assertStringContainsString( '2001:db8::/32', $result );
        $this->assertStringContainsString( 'fe80::/10', $result );
    }

    /**
     * Test that invalid IP addresses are removed.
     */
    public function test_invalid_ips_removed() {
        $input = "invalid\n999.999.999.999\n192.168.1.1\nabc.def.ghi.jkl";

        $result = $this->settings->sanitize_whitelist_ips( $input );

        $this->assertStringNotContainsString( 'invalid', $result );
        $this->assertStringNotContainsString( '999.999.999.999', $result );
        $this->assertStringNotContainsString( 'abc.def.ghi.jkl', $result );
        $this->assertStringContainsString( '192.168.1.1', $result );
    }

    /**
     * Test that invalid CIDR masks are removed.
     */
    public function test_invalid_cidr_mask_removed() {
        $input = "192.168.1.0/33\n10.0.0.0/8\n192.168.1.0/-1";

        $result = $this->settings->sanitize_whitelist_ips( $input );

        $this->assertStringNotContainsString( '192.168.1.0/33', $result );
        $this->assertStringNotContainsString( '192.168.1.0/-1', $result );
        $this->assertStringContainsString( '10.0.0.0/8', $result );
    }

    /**
     * Test that empty lines are ignored.
     */
    public function test_empty_lines_ignored() {
        $input = "192.168.1.1\n\n\n10.0.0.1\n   \n";

        $result = $this->settings->sanitize_whitelist_ips( $input );
        $lines = array_filter( explode( "\n", $result ) );

        $this->assertCount( 2, $lines );
    }

    /**
     * Test that whitespace is trimmed.
     */
    public function test_whitespace_trimmed() {
        $input = "  192.168.1.1  \n   10.0.0.1   ";

        $result = $this->settings->sanitize_whitelist_ips( $input );

        $this->assertStringContainsString( '192.168.1.1', $result );
        $this->assertStringContainsString( '10.0.0.1', $result );
        // Verify no leading/trailing whitespace on lines
        $lines = explode( "\n", $result );
        foreach ( $lines as $line ) {
            $this->assertEquals( trim( $line ), $line );
        }
    }

    /**
     * Test that empty input returns empty string.
     */
    public function test_empty_input_returns_empty() {
        $this->assertEquals( '', $this->settings->sanitize_whitelist_ips( '' ) );
        $this->assertEquals( '', $this->settings->sanitize_whitelist_ips( '   ' ) );
        $this->assertEquals( '', $this->settings->sanitize_whitelist_ips( "\n\n" ) );
    }

    /**
     * Test IP in range - exact match.
     */
    public function test_ip_in_range_exact_match() {
        $this->assertTrue( $this->ip_in_range( '192.168.1.1', '192.168.1.1' ) );
        $this->assertFalse( $this->ip_in_range( '192.168.1.1', '192.168.1.2' ) );
    }

    /**
     * Test IP in range - IPv4 CIDR /24.
     */
    public function test_ip_in_range_ipv4_cidr_24() {
        // 192.168.1.0/24 covers 192.168.1.0 - 192.168.1.255
        $this->assertTrue( $this->ip_in_range( '192.168.1.1', '192.168.1.0/24' ) );
        $this->assertTrue( $this->ip_in_range( '192.168.1.255', '192.168.1.0/24' ) );
        $this->assertFalse( $this->ip_in_range( '192.168.2.1', '192.168.1.0/24' ) );
    }

    /**
     * Test IP in range - IPv4 CIDR /8.
     */
    public function test_ip_in_range_ipv4_cidr_8() {
        // 10.0.0.0/8 covers 10.0.0.0 - 10.255.255.255
        $this->assertTrue( $this->ip_in_range( '10.0.0.1', '10.0.0.0/8' ) );
        $this->assertTrue( $this->ip_in_range( '10.255.255.255', '10.0.0.0/8' ) );
        $this->assertFalse( $this->ip_in_range( '11.0.0.1', '10.0.0.0/8' ) );
    }

    /**
     * Test IP in range - IPv4 CIDR /32 (single IP).
     */
    public function test_ip_in_range_ipv4_cidr_32() {
        $this->assertTrue( $this->ip_in_range( '192.168.1.100', '192.168.1.100/32' ) );
        $this->assertFalse( $this->ip_in_range( '192.168.1.101', '192.168.1.100/32' ) );
    }

    /**
     * Test IP in range - IPv6 CIDR.
     */
    public function test_ip_in_range_ipv6_cidr() {
        // 2001:db8::/32 covers 2001:db8::* addresses
        $this->assertTrue( $this->ip_in_range( '2001:db8::1', '2001:db8::/32' ) );
        $this->assertTrue( $this->ip_in_range( '2001:db8:ffff:ffff:ffff:ffff:ffff:ffff', '2001:db8::/32' ) );
        $this->assertFalse( $this->ip_in_range( '2001:db9::1', '2001:db8::/32' ) );
    }

    /**
     * Test IP in range - invalid inputs.
     */
    public function test_ip_in_range_invalid_inputs() {
        // Invalid IP
        $this->assertFalse( $this->ip_in_range( 'invalid', '192.168.1.0/24' ) );
        // Invalid range
        $this->assertFalse( $this->ip_in_range( '192.168.1.1', 'invalid/24' ) );
        // Invalid mask
        $this->assertFalse( $this->ip_in_range( '192.168.1.1', '192.168.1.0/33' ) );
    }

    /**
     * Test IP in range - mixed IPv4/IPv6 returns false.
     */
    public function test_ip_in_range_mixed_versions() {
        $this->assertFalse( $this->ip_in_range( '192.168.1.1', '2001:db8::/32' ) );
        $this->assertFalse( $this->ip_in_range( '2001:db8::1', '192.168.1.0/24' ) );
    }

    /**
     * Helper to replicate wldelay_ip_in_range() logic.
     * This mirrors the function from wp-login-delay.php for unit testing.
     *
     * @param string $ip The IP address to check.
     * @param string $range The CIDR range.
     * @return bool
     */
    private function ip_in_range( $ip, $range ) {
        // Check for CIDR notation
        if ( strpos( $range, '/' ) === false ) {
            // Exact match
            return $ip === $range;
        }

        list( $range_ip, $netmask ) = explode( '/', $range, 2 );
        $netmask = (int) $netmask;

        // IPv4
        if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) &&
             filter_var( $range_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
            if ( $netmask < 0 || $netmask > 32 ) {
                return false;
            }
            $ip_long = ip2long( $ip );
            $range_long = ip2long( $range_ip );
            $mask = -1 << ( 32 - $netmask );
            return ( $ip_long & $mask ) === ( $range_long & $mask );
        }

        // IPv6
        if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) &&
             filter_var( $range_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
            if ( $netmask < 0 || $netmask > 128 ) {
                return false;
            }
            $ip_bin = inet_pton( $ip );
            $range_bin = inet_pton( $range_ip );

            // Create binary mask
            $mask = str_repeat( "\xff", (int) floor( $netmask / 8 ) );
            if ( $netmask % 8 ) {
                $mask .= chr( 0xff << ( 8 - ( $netmask % 8 ) ) );
            }
            $mask = str_pad( $mask, 16, "\x00" );

            return ( $ip_bin & $mask ) === ( $range_bin & $mask );
        }

        return false;
    }
}
