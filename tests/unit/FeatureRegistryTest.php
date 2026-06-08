<?php
/**
 * Unit tests for the declarative feature/defaults registry (F-2-2).
 *
 * These assert the registry exposes every option key that historically carried
 * a default, with the correct default value and schema hint, and that the
 * injected-defaults subset matches the opt-in security flags the options reader
 * materialises at read time.
 */

class FeatureRegistryTest extends LDS_Unit_Test_Case {

    /**
     * The opt-in security flags that wldelay_get_options() injects at read time.
     *
     * @var array<string,mixed>
     */
    private static $injected = array(
        'wldelay_rest_enabled'                  => false,
        'wldelay_application_password_enabled'  => false,
        'wldelay_password_reset_enabled'        => false,
        'wldelay_enumeration_hardening_enabled' => false,
        'wldelay_fail2ban_enabled'              => false,
        'wldelay_fail2ban_log_path'             => '',
        'wldelay_fail2ban_include_lockouts'     => LDS_Settings::_DEFAULT_FAIL2BAN_INCLUDE_LOCKOUTS,
    );

    public function test_defaults_contains_every_known_option_key() {
        $defaults = WLDelay_Features::defaults();

        $expected_keys = array(
            'wldelay_delay',
            'wldelay_delay_random',
            'wldelay_delay_random_min',
            'wldelay_delay_random_max',
            'wldelay_progressive_enabled',
            'wldelay_progressive_increment',
            'wldelay_progressive_max',
            'wldelay_lockout_enabled',
            'wldelay_lockout_threshold',
            'wldelay_lockout_duration',
            'wldelay_lockout_attempt_strategy',
            'wldelay_email_enabled',
            'wldelay_email_address',
            'wldelay_email_threshold',
            'wldelay_email_cooldown',
            'wldelay_log_retention_days',
            'wldelay_xmlrpc_enabled',
            'wldelay_xmlrpc_block',
            'wldelay_rest_enabled',
            'wldelay_application_password_enabled',
            'wldelay_password_reset_enabled',
            'wldelay_enumeration_hardening_enabled',
            'wldelay_fail2ban_enabled',
            'wldelay_fail2ban_log_path',
            'wldelay_fail2ban_include_lockouts',
            'wldelay_protection_profile',
            'wldelay_trust_proxy_headers',
            'wldelay_whitelist_enabled',
            'wldelay_whitelist_ips',
            'wldelay_custom_login_enabled',
            'wldelay_custom_login_slug',
        );

        foreach ( $expected_keys as $key ) {
            $this->assertArrayHasKey( $key, $defaults, "Missing default for {$key}" );
        }

        $this->assertCount( count( $expected_keys ), $defaults, 'Unexpected number of registry keys.' );
    }

    public function test_constant_backed_defaults_match_settings_constants() {
        $defaults = WLDelay_Features::defaults();

        $this->assertSame( LDS_Settings::_DEFAULT_DELAY_IN_SECONDS, $defaults['wldelay_delay'] );
        $this->assertSame( LDS_Settings::_DEFAULT_RANDOM_MIN, $defaults['wldelay_delay_random_min'] );
        $this->assertSame( LDS_Settings::_DEFAULT_RANDOM_MAX, $defaults['wldelay_delay_random_max'] );
        $this->assertSame( LDS_Settings::_DEFAULT_PROGRESSIVE_INCREMENT, $defaults['wldelay_progressive_increment'] );
        $this->assertSame( LDS_Settings::_DEFAULT_PROGRESSIVE_MAX, $defaults['wldelay_progressive_max'] );
        $this->assertSame( LDS_Settings::_DEFAULT_LOCKOUT_THRESHOLD, $defaults['wldelay_lockout_threshold'] );
        $this->assertSame( LDS_Settings::_DEFAULT_LOCKOUT_DURATION, $defaults['wldelay_lockout_duration'] );
        $this->assertSame( LDS_Settings::_DEFAULT_LOCKOUT_ATTEMPT_STRATEGY, $defaults['wldelay_lockout_attempt_strategy'] );
        $this->assertSame( LDS_Settings::_DEFAULT_EMAIL_THRESHOLD, $defaults['wldelay_email_threshold'] );
        $this->assertSame( LDS_Settings::_DEFAULT_EMAIL_COOLDOWN, $defaults['wldelay_email_cooldown'] );
        $this->assertSame( LDS_Settings::_DEFAULT_LOG_RETENTION_DAYS, $defaults['wldelay_log_retention_days'] );
        $this->assertSame( LDS_Settings::_DEFAULT_FAIL2BAN_INCLUDE_LOCKOUTS, $defaults['wldelay_fail2ban_include_lockouts'] );
    }

    public function test_opt_in_flags_default_to_disabled() {
        $defaults = WLDelay_Features::defaults();

        $this->assertFalse( $defaults['wldelay_rest_enabled'] );
        $this->assertFalse( $defaults['wldelay_application_password_enabled'] );
        $this->assertFalse( $defaults['wldelay_password_reset_enabled'] );
        $this->assertFalse( $defaults['wldelay_enumeration_hardening_enabled'] );
        $this->assertFalse( $defaults['wldelay_fail2ban_enabled'] );
        $this->assertSame( '', $defaults['wldelay_fail2ban_log_path'] );
    }

    public function test_each_entry_declares_a_known_type_hint() {
        $allowed = array( 'bool', 'int', 'string', 'enum' );

        foreach ( WLDelay_Features::all() as $key => $meta ) {
            $this->assertArrayHasKey( 'type', $meta, "Missing type hint for {$key}" );
            $this->assertContains( $meta['type'], $allowed, "Unknown type hint for {$key}: {$meta['type']}" );
            $this->assertArrayHasKey( 'default', $meta, "Missing default for {$key}" );
            $this->assertArrayHasKey( 'inject', $meta, "Missing inject flag for {$key}" );
        }
    }

    public function test_type_hints_match_default_value_php_type() {
        foreach ( WLDelay_Features::all() as $key => $meta ) {
            switch ( $meta['type'] ) {
                case 'bool':
                    $this->assertIsBool( $meta['default'], "{$key} declared bool" );
                    break;
                case 'int':
                    $this->assertIsInt( $meta['default'], "{$key} declared int" );
                    break;
                case 'string':
                case 'enum':
                    $this->assertIsString( $meta['default'], "{$key} declared {$meta['type']}" );
                    break;
            }
        }
    }

    public function test_injected_defaults_are_exactly_the_opt_in_security_flags() {
        $this->assertSame( self::$injected, WLDelay_Features::injected_defaults() );
    }
}
