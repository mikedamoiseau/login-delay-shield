<?php
/**
 * Integration tests for 2FA health helper functions.
 */

class TwoFactorHealthTest extends WP_UnitTestCase {

    public function tear_down(): void {
        remove_all_filters( 'wldelay_2fa_providers' );
        remove_all_filters( 'wldelay_2fa_coverage_checkers' );
        parent::tear_down();
    }

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
        $baseline = wldelay_get_two_factor_privileged_user_coverage();

        $admin_with_2fa = self::factory()->user->create( array( 'role' => 'administrator' ) );
        update_user_meta( $admin_with_2fa, '_two_factor_enabled_providers', array( 'email' ) );

        $status = wldelay_get_2fa_health_status( array( 'two-factor/two-factor.php' ) );

        $this->assertTrue( $status['enabled'] );
        $this->assertSame( 'two-factor', $status['provider'] );
        $this->assertSame( 'Two-Factor', $status['provider_label'] );
        $this->assertTrue( $status['coverage']['supported'] );
        $this->assertSame( $baseline['privileged_total'] + 1, $status['coverage']['privileged_total'] );
        $this->assertSame( $baseline['protected'] + 1, $status['coverage']['protected'] );
        $this->assertSame( $baseline['unprotected'], $status['coverage']['unprotected'] );
    }

    public function test_get_two_factor_privileged_user_coverage_counts_admins_with_and_without_2fa() {
        $baseline = wldelay_get_two_factor_privileged_user_coverage();

        $admin_with_2fa = self::factory()->user->create( array( 'role' => 'administrator' ) );
        $admin_without_2fa = self::factory()->user->create( array( 'role' => 'administrator' ) );
        self::factory()->user->create( array( 'role' => 'subscriber' ) );

        update_user_meta( $admin_with_2fa, '_two_factor_enabled_providers', array( 'email' ) );
        update_user_meta( $admin_without_2fa, '_two_factor_enabled_providers', array() );

        $coverage = wldelay_get_two_factor_privileged_user_coverage();

        $this->assertTrue( $coverage['supported'] );
        $this->assertSame( $baseline['privileged_total'] + 2, $coverage['privileged_total'] );
        $this->assertSame( $baseline['protected'] + 1, $coverage['protected'] );
        $this->assertSame( $baseline['unprotected'] + 1, $coverage['unprotected'] );
        $this->assertSame( $baseline['unknown'], $coverage['unknown'] );
    }

    public function test_get_two_factor_privileged_user_coverage_counts_numeric_user_ids() {
        $admin_with_2fa = self::factory()->user->create( array( 'role' => 'administrator' ) );
        $admin_without_2fa = self::factory()->user->create( array( 'role' => 'administrator' ) );

        update_user_meta( $admin_with_2fa, '_two_factor_enabled_providers', array( 'email' ) );
        update_user_meta( $admin_without_2fa, '_two_factor_enabled_providers', array() );

        $coverage = wldelay_get_two_factor_privileged_user_coverage();

        $this->assertGreaterThanOrEqual( 2, $coverage['privileged_total'] );
        $this->assertGreaterThanOrEqual( 1, $coverage['protected'] );
        $this->assertGreaterThanOrEqual( 1, $coverage['unprotected'] );
    }

    public function test_get_2fa_privileged_user_coverage_uses_filtered_checker() {
        add_filter(
            'wldelay_2fa_coverage_checkers',
            function( $checkers ) {
                $checkers['custom-provider'] = function() {
                    return array(
                        'supported'        => true,
                        'privileged_total' => 3,
                        'protected'        => 2,
                        'unprotected'      => 1,
                        'unknown'          => 0,
                    );
                };

                return $checkers;
            }
        );

        $coverage = wldelay_get_2fa_privileged_user_coverage( 'custom-provider' );

        $this->assertTrue( $coverage['supported'] );
        $this->assertSame( 3, $coverage['privileged_total'] );
        $this->assertSame( 2, $coverage['protected'] );
        $this->assertSame( 1, $coverage['unprotected'] );
    }

    public function test_get_2fa_provider_label_returns_empty_for_unknown_provider() {
        $this->assertSame( '', wldelay_get_2fa_provider_label( 'unknown-provider' ) );
    }
}
