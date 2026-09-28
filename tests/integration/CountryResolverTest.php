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

    public function test_site_resolver_always_receives_an_empty_value() {
        // A resolver written as `return $c ?: lookup()` must not be handed a
        // header value: with proxy trust on, X-Country-Code is whatever the
        // visitor sent, and deferring to it would let them pick a country.
        $this->trust_proxy_headers();
        $_SERVER['HTTP_X_COUNTRY_CODE'] = 'US';

        $received = null;
        add_filter(
            'wldelay_resolve_country_code',
            function ( $country ) use ( &$received ) {
                $received = $country;
                return '' !== $country ? $country : 'RU';
            }
        );

        $this->assertSame( 'RU', wldelay_resolve_country_code( '203.0.113.44', 'wp-login' ) );
        $this->assertSame( '', $received );
    }

    public function test_built_in_detection_fills_in_when_no_resolver_answers() {
        $this->trust_proxy_headers();
        $_SERVER['HTTP_X_COUNTRY_CODE'] = 'DE';

        add_filter( 'wldelay_resolve_country_code', '__return_empty_string' );

        $this->assertSame( 'DE', wldelay_resolve_country_code( '203.0.113.44', 'wp-login' ) );
    }

    public function test_no_headers_resolves_to_empty() {
        $this->trust_proxy_headers();

        $this->assertSame( '', wldelay_detect_country_from_request()['code'] );
    }

    public function test_cf_ipcountry_is_ignored_when_proxy_headers_are_not_trusted() {
        // Proxy trust off: the header is attacker-controllable, so it must not
        // be honoured — spoofing it would otherwise let a visitor pick a country.
        $_SERVER['HTTP_CF_IPCOUNTRY'] = 'RU';
        $_SERVER['REMOTE_ADDR']       = '173.245.48.1'; // a real Cloudflare edge IP

        $this->assertSame( '', wldelay_detect_country_from_request()['code'] );
    }

    public function test_cf_ipcountry_is_ignored_when_the_peer_is_not_cloudflare() {
        $this->trust_proxy_headers();
        $_SERVER['HTTP_CF_IPCOUNTRY'] = 'RU';
        $_SERVER['REMOTE_ADDR']       = '203.0.113.44'; // not a Cloudflare range

        $this->assertSame( '', wldelay_detect_country_from_request()['code'] );
    }

    public function test_cf_ipcountry_is_used_when_trusted_and_peer_is_cloudflare() {
        $this->trust_proxy_headers();
        $_SERVER['HTTP_CF_IPCOUNTRY'] = 'ru';
        $_SERVER['REMOTE_ADDR']       = '173.245.48.1';

        $this->assertSame( 'RU', wldelay_detect_country_from_request()['code'] );
    }

    public function test_generic_country_header_requires_proxy_trust() {
        $_SERVER['HTTP_X_COUNTRY_CODE'] = 'DE';
        $this->assertSame( '', wldelay_detect_country_from_request()['code'] );

        $this->trust_proxy_headers();
        $this->assertSame( 'DE', wldelay_detect_country_from_request()['code'] );
    }

    public function test_server_geoip_variable_is_used_without_proxy_trust() {
        // Not a header: PHP exposes client headers as HTTP_*, so a bare
        // GEOIP_COUNTRY_CODE can only have been set by the web server itself
        // (mod_geoip / MaxMind). Trustworthy regardless of the proxy setting.
        $_SERVER['GEOIP_COUNTRY_CODE'] = 'fr';

        $this->assertSame( 'FR', wldelay_detect_country_from_request()['code'] );
    }

    public function test_server_geoip_variable_can_be_distrusted_by_filter() {
        // Escape hatch for a deployment that maps client input into a bare CGI
        // parameter, where the variable is no longer server-authored.
        $_SERVER['GEOIP_COUNTRY_CODE'] = 'FR';
        add_filter( 'wldelay_trust_server_country_variable', '__return_false' );

        $this->assertSame( '', wldelay_detect_country_from_request()['code'] );

        remove_all_filters( 'wldelay_trust_server_country_variable' );
        $this->assertSame( 'FR', wldelay_detect_country_from_request()['code'] );
    }

    public function test_cloudflare_tor_marker_is_not_a_country() {
        // CF sends T1 for Tor exit nodes; the two-letter normaliser rejects it,
        // so Tor cannot be blocked through country blocking.
        $this->trust_proxy_headers();
        $_SERVER['REMOTE_ADDR']       = '173.245.48.1';
        $_SERVER['HTTP_CF_IPCOUNTRY'] = 'T1';

        $this->assertSame( '', wldelay_detect_country_from_request()['code'] );
    }

    public function test_malformed_header_values_are_rejected() {
        $this->trust_proxy_headers();

        foreach ( array( 'XYZ', '1', '', 'D', 'de-DE', '<script>' ) as $value ) {
            $_SERVER['HTTP_X_COUNTRY_CODE'] = $value;
            $this->assertSame(
                '',
                wldelay_detect_country_from_request()['code'],
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

        // A verified Cloudflare peer outranks the server variable: behind
        // Cloudflare an origin GeoIP module looks up the edge, not the visitor.
        $_SERVER['GEOIP_COUNTRY_CODE'] = 'US';
        $detected                      = wldelay_detect_country_from_request();
        $this->assertSame( 'RU', $detected['code'] );
        $this->assertSame( 'cloudflare', $detected['source'] );

        // Without a Cloudflare peer the server variable outranks the generic,
        // unverifiable proxy header.
        $_SERVER['REMOTE_ADDR'] = '203.0.113.44';
        $detected               = wldelay_detect_country_from_request();
        $this->assertSame( 'US', $detected['code'] );
        $this->assertSame( 'server-module', $detected['source'] );
    }

    public function test_ipv4_mapped_cloudflare_peer_is_recognised() {
        // A dual-stack listener reports an IPv4 peer as ::ffff:a.b.c.d.
        $this->assertTrue( wldelay_is_cloudflare_remote_addr( '::ffff:173.245.48.1' ) );
        $this->assertFalse( wldelay_is_cloudflare_remote_addr( '::ffff:203.0.113.44' ) );

        $this->trust_proxy_headers();
        $_SERVER['REMOTE_ADDR']       = '::ffff:173.245.48.1';
        $_SERVER['HTTP_CF_IPCOUNTRY'] = 'RU';
        $this->assertSame( 'RU', wldelay_detect_country_from_request()['code'] );
    }

    /**
     * Render the settings card's detection readout.
     */
    private function render_detection_status() {
        $view   = new LDS_Settings_View();
        $method = new ReflectionMethod( $view, 'country_detection_status' );
        $method->setAccessible( true );
        return $method->invoke( $view );
    }

    private function enable_blocking( $countries, $extra = array() ) {
        update_option(
            WLDELAY_OPTION_NAME,
            array_merge(
                array(
                    'wldelay_trust_proxy_headers'        => true,
                    'wldelay_country_blocking_enabled'   => true,
                    'wldelay_country_blocking_countries' => $countries,
                ),
                $extra
            )
        );
        wldelay_clear_options_cache();
        unset( $GLOBALS['wldelay_parsed_whitelist'] );
    }

    public function test_readout_warns_when_the_owners_own_country_is_on_the_block_list() {
        $this->enable_blocking( "RU\nDE" );

        $_SERVER['HTTP_X_COUNTRY_CODE'] = 'DE';
        $html                           = $this->render_detection_status();
        $this->assertStringContainsString( 'id="wldelay_country_blocking_status"', $html );
        $this->assertStringContainsString( 'id="wldelay_country_blocking_warning"', $html );
        $this->assertStringContainsString( 'Warning: DE is on your block list', $html );

        $_SERVER['HTTP_X_COUNTRY_CODE'] = 'FR';
        $this->assertStringNotContainsString( 'is on your block list', $this->render_detection_status() );
    }

    public function test_readout_reports_the_country_a_site_resolver_enforces() {
        // Header says DE, but the site's resolver answers RU and RU is what the
        // login gate enforces — the readout and warning must say RU.
        $this->enable_blocking( 'RU' );
        $_SERVER['HTTP_X_COUNTRY_CODE'] = 'DE';
        add_filter(
            'wldelay_resolve_country_code',
            function () {
                return 'RU';
            }
        );

        $html = wp_strip_all_tags( $this->render_detection_status() );
        $this->assertStringContainsString( 'RU, supplied by a custom wldelay_resolve_country_code filter', $html );
        $this->assertStringContainsString( 'Warning: RU is on your block list', $html );
        $this->assertStringNotContainsString( 'DE', $html );
    }

    public function test_readout_does_not_warn_a_whitelisted_owner() {
        // A whitelisted IP really does bypass the block, so warning about it
        // (and telling the owner to whitelist themselves) would be wrong.
        $this->enable_blocking(
            'DE',
            array(
                'wldelay_whitelist_enabled' => true,
                'wldelay_whitelist_ips'     => '203.0.113.44',
            )
        );
        wldelay_clear_whitelist_cache();
        $_SERVER['HTTP_X_COUNTRY_CODE'] = 'DE';

        $html = $this->render_detection_status();
        $this->assertStringContainsString( 'Detected country for your current request: <strong>DE</strong>', $html );
        $this->assertStringNotContainsString( 'is on your block list', $html );
    }

    public function test_readout_says_nothing_detected_when_no_country_is_available() {
        $this->enable_blocking( 'DE' );

        $html = $this->render_detection_status();
        $this->assertStringContainsString( 'No country detected for your current request', $html );
        $this->assertStringNotContainsString( 'is on your block list', $html );
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
