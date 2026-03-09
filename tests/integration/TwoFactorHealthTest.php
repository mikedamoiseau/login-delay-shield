<?php
/**
 * Integration tests for 2FA health helper functions.
 */

class TwoFactorHealthTest extends WP_UnitTestCase {

    /**
     * @dataProvider provider_detectable_2fa_plugins
     */
    public function test_detect_2fa_provider_for_supported_plugins( $plugin_file, $expected_provider ) {
        $provider = wldelay_detect_2fa_provider( array( $plugin_file ) );

        $this->assertSame( $expected_provider, $provider );
    }

    public function provider_detectable_2fa_plugins() {
        return array(
            array( 'two-factor/two-factor.php', 'two-factor' ),
            array( 'wp-2fa/wp-2fa.php', 'wp-2fa' ),
            array( 'miniorange-2-factor-authentication/miniorange_2_factor_settings.php', 'mini-orange' ),
            array( 'google-authenticator/google-authenticator.php', 'google-authenticator' ),
        );
    }

    public function test_detect_2fa_provider_is_case_insensitive() {
        $provider = wldelay_detect_2fa_provider( array( 'WP-2FA/WP-2FA.PHP' ) );

        $this->assertSame( 'wp-2fa', $provider );
    }

    public function test_detect_2fa_provider_returns_empty_for_unknown_or_invalid_entries() {
        $provider = wldelay_detect_2fa_provider( array( 'akismet/akismet.php', array( 'not-scalar' ) ) );

        $this->assertSame( '', $provider );
    }

    public function test_get_2fa_health_status_with_override_returns_provider_label() {
        $status = wldelay_get_2fa_health_status( array( 'wp-2fa/wp-2fa.php' ) );

        $this->assertTrue( $status['enabled'] );
        $this->assertSame( 'wp-2fa', $status['provider'] );
        $this->assertSame( 'WP 2FA', $status['provider_label'] );
    }

    public function test_get_2fa_provider_label_returns_empty_for_unknown_provider() {
        $this->assertSame( '', wldelay_get_2fa_provider_label( 'unknown-provider' ) );
    }
}
