<?php
/**
 * Integration tests for the built-in country resolver.
 *
 * The plugin ships no GeoIP database, but a great many sites already sit behind
 * something that has already done the lookup — Cloudflare, or an Apache/nginx
 * GeoIP module. Reading what they report makes country blocking usable without
 * writing a line of PHP, provided the source can be trusted.
 */

class CountryResolverTest extends WP_UnitTestCase {

    public function setUp(): void {
        parent::setUp();
        $_SERVER['REMOTE_ADDR'] = '203.0.113.44';
        unset(
            $_SERVER['HTTP_CF_IPCOUNTRY'],
            $_SERVER['HTTP_X_COUNTRY_CODE'],
            $_SERVER['GEOIP_COUNTRY_CODE']
        );
        delete_option( WLDELAY_OPTION_NAME );
        wldelay_clear_options_cache();
    }

    public function tearDown(): void {
        unset(
            $_SERVER['REMOTE_ADDR'],
            $_SERVER['HTTP_CF_IPCOUNTRY'],
            $_SERVER['HTTP_X_COUNTRY_CODE'],
            $_SERVER['GEOIP_COUNTRY_CODE']
        );
        delete_option( WLDELAY_OPTION_NAME );
        wldelay_clear_options_cache();
        parent::tearDown();
    }

    private function trust_proxy_headers() {
        update_option( WLDELAY_OPTION_NAME, array( 'wldelay_trust_proxy_headers' => true ) );
        wldelay_clear_options_cache();
    }

    public function test_resolver_is_registered_below_the_default_priority() {
        // Must run BEFORE a site-supplied resolver (default priority 10) so that
        // a custom resolver, running later, still has the final say.
        $priority = has_filter( 'wldelay_resolve_country_code', 'wldelay_default_country_resolver' );
        $this->assertNotFalse( $priority );
        $this->assertLessThan( 10, $priority );
    }

    public function test_no_headers_resolves_to_empty() {
        $this->trust_proxy_headers();

        $this->assertSame( '', wldelay_default_country_resolver( '', '203.0.113.44', 'wp-login' ) );
    }

    public function test_cf_ipcountry_is_ignored_when_proxy_headers_are_not_trusted() {
        // Proxy trust off: the header is attacker-controllable, so it must not
        // be honoured — spoofing it would otherwise let a visitor pick a country.
        $_SERVER['HTTP_CF_IPCOUNTRY'] = 'RU';
        $_SERVER['REMOTE_ADDR']       = '173.245.48.1'; // a real Cloudflare edge IP

        $this->assertSame( '', wldelay_default_country_resolver( '', '203.0.113.44', 'wp-login' ) );
    }

    public function test_cf_ipcountry_is_ignored_when_the_peer_is_not_cloudflare() {
        $this->trust_proxy_headers();
        $_SERVER['HTTP_CF_IPCOUNTRY'] = 'RU';
        $_SERVER['REMOTE_ADDR']       = '203.0.113.44'; // not a Cloudflare range

        $this->assertSame( '', wldelay_default_country_resolver( '', '203.0.113.44', 'wp-login' ) );
    }

    public function test_cf_ipcountry_is_used_when_trusted_and_peer_is_cloudflare() {
        $this->trust_proxy_headers();
        $_SERVER['HTTP_CF_IPCOUNTRY'] = 'ru';
        $_SERVER['REMOTE_ADDR']       = '173.245.48.1';

        $this->assertSame( 'RU', wldelay_default_country_resolver( '', '203.0.113.44', 'wp-login' ) );
    }

    public function test_generic_country_header_requires_proxy_trust() {
        $_SERVER['HTTP_X_COUNTRY_CODE'] = 'DE';
        $this->assertSame( '', wldelay_default_country_resolver( '', '203.0.113.44', 'wp-login' ) );

        $this->trust_proxy_headers();
        $this->assertSame( 'DE', wldelay_default_country_resolver( '', '203.0.113.44', 'wp-login' ) );
    }

    public function test_server_geoip_variable_is_used_without_proxy_trust() {
        // Not a header: PHP exposes client headers as HTTP_*, so a bare
        // GEOIP_COUNTRY_CODE can only have been set by the web server itself
        // (mod_geoip / MaxMind). Trustworthy regardless of the proxy setting.
        $_SERVER['GEOIP_COUNTRY_CODE'] = 'fr';

        $this->assertSame( 'FR', wldelay_default_country_resolver( '', '203.0.113.44', 'wp-login' ) );
    }

    public function test_server_geoip_variable_can_be_distrusted_by_filter() {
        // Escape hatch for a deployment that maps client input into a bare CGI
        // parameter, where the variable is no longer server-authored.
        $_SERVER['GEOIP_COUNTRY_CODE'] = 'FR';
        add_filter( 'wldelay_trust_server_country_variable', '__return_false' );

        $this->assertSame( '', wldelay_default_country_resolver( '', '203.0.113.44', 'wp-login' ) );

        remove_all_filters( 'wldelay_trust_server_country_variable' );
        $this->assertSame( 'FR', wldelay_default_country_resolver( '', '203.0.113.44', 'wp-login' ) );
    }

    public function test_cloudflare_tor_marker_is_not_a_country() {
        // CF sends T1 for Tor exit nodes; the two-letter normaliser rejects it,
        // so Tor cannot be blocked through country blocking.
        $this->trust_proxy_headers();
        $_SERVER['REMOTE_ADDR']       = '173.245.48.1';
        $_SERVER['HTTP_CF_IPCOUNTRY'] = 'T1';

        $this->assertSame( '', wldelay_default_country_resolver( '', '203.0.113.44', 'wp-login' ) );
    }

    public function test_an_already_resolved_country_is_left_alone() {
        $this->trust_proxy_headers();
        $_SERVER['HTTP_X_COUNTRY_CODE'] = 'DE';

        $this->assertSame( 'US', wldelay_default_country_resolver( 'US', '203.0.113.44', 'wp-login' ) );
    }

    public function test_malformed_header_values_are_rejected() {
        $this->trust_proxy_headers();

        foreach ( array( 'XYZ', '1', '', 'D', 'de-DE', '<script>' ) as $value ) {
            $_SERVER['HTTP_X_COUNTRY_CODE'] = $value;
            $this->assertSame(
                '',
                wldelay_default_country_resolver( '', '203.0.113.44', 'wp-login' ),
                sprintf( 'Value %s must not resolve to a country.', var_export( $value, true ) )
            );
        }
    }

    public function test_detection_reports_which_source_supplied_the_country() {
        $this->trust_proxy_headers();

        $this->assertSame(
            array(
                'code'   => '',
                'source' => '',
            ),
            wldelay_detect_country_from_request()
        );

        $_SERVER['HTTP_X_COUNTRY_CODE'] = 'DE';
        $detected                       = wldelay_detect_country_from_request();
        $this->assertSame( 'DE', $detected['code'] );
        $this->assertSame( 'proxy-header', $detected['source'] );

        $_SERVER['REMOTE_ADDR']       = '173.245.48.1';
        $_SERVER['HTTP_CF_IPCOUNTRY'] = 'RU';
        $detected                     = wldelay_detect_country_from_request();
        $this->assertSame( 'RU', $detected['code'] );
        $this->assertSame( 'cloudflare', $detected['source'] );

        // The server variable outranks both headers.
        $_SERVER['GEOIP_COUNTRY_CODE'] = 'FR';
        $detected                      = wldelay_detect_country_from_request();
        $this->assertSame( 'FR', $detected['code'] );
        $this->assertSame( 'server-module', $detected['source'] );
    }

    public function test_detects_when_the_owners_own_country_is_on_the_block_list() {
        update_option(
            WLDELAY_OPTION_NAME,
            array(
                'wldelay_trust_proxy_headers'        => true,
                'wldelay_country_blocking_enabled'   => true,
                'wldelay_country_blocking_countries' => "RU\nDE",
            )
        );
        wldelay_clear_options_cache();

        $_SERVER['HTTP_X_COUNTRY_CODE'] = 'DE';
        $this->assertTrue( wldelay_is_own_country_blocked(), 'Blocking your own country risks locking yourself out.' );

        $_SERVER['HTTP_X_COUNTRY_CODE'] = 'FR';
        $this->assertFalse( wldelay_is_own_country_blocked() );
    }

    public function test_own_country_check_is_false_when_the_feature_is_off_or_undetected() {
        update_option(
            WLDELAY_OPTION_NAME,
            array(
                'wldelay_trust_proxy_headers'        => true,
                'wldelay_country_blocking_enabled'   => false,
                'wldelay_country_blocking_countries' => 'DE',
            )
        );
        wldelay_clear_options_cache();
        $_SERVER['HTTP_X_COUNTRY_CODE'] = 'DE';
        $this->assertFalse( wldelay_is_own_country_blocked() );

        update_option(
            WLDELAY_OPTION_NAME,
            array(
                'wldelay_trust_proxy_headers'        => true,
                'wldelay_country_blocking_enabled'   => true,
                'wldelay_country_blocking_countries' => 'DE',
            )
        );
        wldelay_clear_options_cache();
        unset( $_SERVER['HTTP_X_COUNTRY_CODE'] );
        $this->assertFalse( wldelay_is_own_country_blocked() );
    }

    public function test_a_site_supplied_resolver_still_wins() {
        $this->trust_proxy_headers();
        $_SERVER['HTTP_X_COUNTRY_CODE'] = 'DE';

        add_filter(
            'wldelay_resolve_country_code',
            function () {
                return 'JP';
            }
        );

        $this->assertSame( 'JP', wldelay_resolve_country_code( '203.0.113.44', 'wp-login' ) );

        remove_all_filters( 'wldelay_resolve_country_code' );
    }

    public function test_country_blocking_works_end_to_end_with_only_a_cloudflare_header() {
        update_option(
            WLDELAY_OPTION_NAME,
            array(
                'wldelay_trust_proxy_headers'        => true,
                'wldelay_country_blocking_enabled'   => true,
                'wldelay_country_blocking_countries' => 'RU',
                'wldelay_delay'                      => 0,
            )
        );
        wldelay_clear_options_cache();

        $_SERVER['REMOTE_ADDR']       = '173.245.48.1';
        $_SERVER['HTTP_CF_IPCOUNTRY'] = 'RU';

        $password = 'correct-horse-battery-staple';
        self::factory()->user->create(
            array(
                'user_login' => 'cf_country_user',
                'user_pass'  => $password,
            )
        );

        $result = wp_authenticate( 'cf_country_user', $password );

        $this->assertWPError( $result, 'No PHP required: the Cloudflare header alone must drive the block.' );
        $this->assertSame( 'wldelay_country_blocked', $result->get_error_code() );
    }
}
