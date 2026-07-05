<?php
/**
 * Integration tests for Country Blocking foundation.
 */

class CountryBlockingTest extends WP_UnitTestCase {

    public function setUp(): void {
        parent::setUp();
        $_SERVER['REMOTE_ADDR'] = '203.0.113.44';
        delete_option( WLDELAY_OPTION_NAME );
        wldelay_clear_options_cache();
        remove_all_filters( 'wldelay_resolve_country_code' );
    }

    public function tearDown(): void {
        remove_all_filters( 'wldelay_resolve_country_code' );
        unset( $_SERVER['REMOTE_ADDR'] );
        delete_option( WLDELAY_OPTION_NAME );
        wldelay_clear_options_cache();
        parent::tearDown();
    }

    public function test_authenticate_filter_is_registered_before_core_auth() {
        $this->assertSame( 5, has_filter( 'authenticate', 'wldelay_country_block_authentication' ) );
    }

    public function test_country_blocking_is_off_by_default() {
        add_filter( 'wldelay_resolve_country_code', array( $this, 'resolve_ru' ) );

        $result = wldelay_country_block_authentication( null, 'admin', 'password' );

        $this->assertNull( $result );
    }

    public function test_enabled_country_blocking_blocks_denied_resolved_country() {
        update_option(
            WLDELAY_OPTION_NAME,
            array(
                'wldelay_country_blocking_enabled'   => true,
                'wldelay_country_blocking_countries' => "RU\nCN",
            )
        );
        wldelay_clear_options_cache();
        add_filter( 'wldelay_resolve_country_code', array( $this, 'resolve_ru' ) );

        $result = wldelay_country_block_authentication( null, 'admin', 'password' );

        $this->assertWPError( $result );
        $this->assertSame( 'wldelay_country_blocked', $result->get_error_code() );
    }

    public function test_enabled_country_blocking_allows_empty_resolver_result() {
        update_option(
            WLDELAY_OPTION_NAME,
            array(
                'wldelay_country_blocking_enabled'   => true,
                'wldelay_country_blocking_countries' => 'RU',
            )
        );
        wldelay_clear_options_cache();

        $result = wldelay_country_block_authentication( null, 'admin', 'password' );

        $this->assertNull( $result );
    }

    public function test_whitelisted_ip_bypasses_country_blocking() {
        update_option(
            WLDELAY_OPTION_NAME,
            array(
                'wldelay_country_blocking_enabled'   => true,
                'wldelay_country_blocking_countries' => 'RU',
                'wldelay_whitelist_enabled'          => true,
                'wldelay_whitelist_ips'              => '203.0.113.44',
            )
        );
        wldelay_clear_options_cache();
        wldelay_clear_whitelist_cache();
        add_filter( 'wldelay_resolve_country_code', array( $this, 'resolve_ru' ) );

        $result = wldelay_country_block_authentication( null, 'admin', 'password' );

        $this->assertNull( $result );
    }

    public function test_resolver_receives_client_ip_and_source() {
        update_option(
            WLDELAY_OPTION_NAME,
            array(
                'wldelay_country_blocking_enabled'   => true,
                'wldelay_country_blocking_countries' => 'DE',
            )
        );
        wldelay_clear_options_cache();

        $seen = array();
        add_filter(
            'wldelay_resolve_country_code',
            function ( $country, $ip, $source ) use ( &$seen ) {
                $seen = array( $country, $ip, $source );
                return 'DE';
            },
            10,
            3
        );

        wldelay_country_block_authentication( null, 'admin', 'password' );

        $this->assertSame( array( '', '203.0.113.44', 'wp-login' ), $seen );
    }

    public function resolve_ru( $country = '', $ip = '', $source = '' ) {
        return 'ru';
    }
}
