<?php
/**
 * Declarative settings feature / defaults registry (F-2-2).
 *
 * Every option key that carries a default historically did so in one of two
 * hand-rolled places: the opt-in security flags injected into the stored array
 * by wldelay_get_options(), and the constant-backed scalars resolved inline at
 * each read site (delay, progressive, lockout, email, log retention …). This
 * registry collapses both into a single source of truth: per key it records the
 * default value and a type/schema hint, plus whether the default is materialised
 * into the cached options array at read time ('inject' => true) or merely
 * documented here and resolved at the use site ('inject' => false).
 *
 * Flags resolve at read/save time, never on a per-request branch in the hot
 * path: wldelay_get_options() still performs exactly one get_option() call and
 * caches the merged result in $GLOBALS['wldelay_options_cache']. The registry
 * only supplies the default map that the merge consults — it adds no runtime
 * cost beyond the existing array_key_exists guards it replaces.
 *
 * Values are sourced from the canonical LDS_Settings::_DEFAULT_* constants where
 * one exists, so there is a single place to change a default. This file is
 * behaviour-preserving scaffolding; it introduces no new option keys and no new
 * user-facing behaviour.
 *
 * @package login-delay-shield
 */

defined( 'ABSPATH' ) || exit;

/**
 * Registry of plugin option keys, their defaults, and schema hints.
 *
 * The metadata is intentionally static and free of WordPress runtime calls so
 * it is cheap to build and unit-testable without a WP environment.
 */
class WLDelay_Features {

    /**
     * Build the full option metadata map.
     *
     * Each entry is keyed by the option key and carries:
     *  - 'default' : the historical default value for the key.
     *  - 'type'    : a schema hint — one of 'bool', 'int', 'string', 'enum'.
     *  - 'inject'  : true when the default is written into the cached options
     *                array by wldelay_get_options() (the opt-in security flags);
     *                false when the default is resolved at the read site and the
     *                key is therefore absent from the stored array until saved.
     *
     * Values come from the canonical LDS_Settings::_DEFAULT_* constants where
     * one exists so defaults are never duplicated.
     *
     * @return array<string,array{default:mixed,type:string,inject:bool}>
     */
    public static function all() {
        return array(
            // Base delay.
            'wldelay_delay'                          => array(
                'default' => LDS_Settings::_DEFAULT_DELAY_IN_SECONDS,
                'type'    => 'int',
                'inject'  => false,
            ),
            'wldelay_delay_random'                   => array(
                'default' => false,
                'type'    => 'bool',
                'inject'  => false,
            ),
            'wldelay_delay_random_min'               => array(
                'default' => LDS_Settings::_DEFAULT_RANDOM_MIN,
                'type'    => 'int',
                'inject'  => false,
            ),
            'wldelay_delay_random_max'               => array(
                'default' => LDS_Settings::_DEFAULT_RANDOM_MAX,
                'type'    => 'int',
                'inject'  => false,
            ),

            // Progressive delay.
            'wldelay_progressive_enabled'            => array(
                'default' => false,
                'type'    => 'bool',
                'inject'  => false,
            ),
            'wldelay_progressive_increment'          => array(
                'default' => LDS_Settings::_DEFAULT_PROGRESSIVE_INCREMENT,
                'type'    => 'int',
                'inject'  => false,
            ),
            'wldelay_progressive_max'                => array(
                'default' => LDS_Settings::_DEFAULT_PROGRESSIVE_MAX,
                'type'    => 'int',
                'inject'  => false,
            ),

            // IP lockout.
            'wldelay_lockout_enabled'                => array(
                'default' => false,
                'type'    => 'bool',
                'inject'  => false,
            ),
            'wldelay_lockout_threshold'              => array(
                'default' => LDS_Settings::_DEFAULT_LOCKOUT_THRESHOLD,
                'type'    => 'int',
                'inject'  => false,
            ),
            'wldelay_lockout_duration'               => array(
                'default' => LDS_Settings::_DEFAULT_LOCKOUT_DURATION,
                'type'    => 'int',
                'inject'  => false,
            ),
            'wldelay_lockout_attempt_strategy'       => array(
                'default' => LDS_Settings::_DEFAULT_LOCKOUT_ATTEMPT_STRATEGY,
                'type'    => 'enum',
                'inject'  => false,
            ),

            // Challenge mode threshold state. Disabled until explicitly opted
            // in; this stores only local state, not a CAPTCHA provider.
            'wldelay_challenge_mode_enabled'         => array(
                'default' => false,
                'type'    => 'bool',
                'inject'  => true,
            ),
            'wldelay_challenge_mode_threshold'       => array(
                'default' => LDS_Settings::_DEFAULT_CHALLENGE_MODE_THRESHOLD,
                'type'    => 'int',
                'inject'  => true,
            ),
            'wldelay_challenge_mode_provider'        => array(
                'default' => 'math',
                'type'    => 'enum',
                'inject'  => true,
            ),

            // Email notifications.
            'wldelay_email_enabled'                  => array(
                'default' => false,
                'type'    => 'bool',
                'inject'  => false,
            ),
            'wldelay_email_address'                  => array(
                'default' => '',
                'type'    => 'string',
                'inject'  => false,
            ),
            'wldelay_email_threshold'                => array(
                'default' => LDS_Settings::_DEFAULT_EMAIL_THRESHOLD,
                'type'    => 'int',
                'inject'  => false,
            ),
            'wldelay_email_cooldown'                 => array(
                'default' => LDS_Settings::_DEFAULT_EMAIL_COOLDOWN,
                'type'    => 'int',
                'inject'  => false,
            ),

            // Log retention.
            'wldelay_log_retention_days'             => array(
                'default' => LDS_Settings::_DEFAULT_LOG_RETENTION_DAYS,
                'type'    => 'int',
                'inject'  => false,
            ),

            // XML-RPC protection.
            'wldelay_xmlrpc_enabled'                 => array(
                'default' => false,
                'type'    => 'bool',
                'inject'  => false,
            ),
            'wldelay_xmlrpc_block'                   => array(
                'default' => false,
                'type'    => 'bool',
                'inject'  => false,
            ),

            // Opt-in security feature flags — injected into the cached options
            // array at read time so they are always present and stay false until
            // explicitly enabled. This mirrors the historical defaults block.
            'wldelay_rest_enabled'                   => array(
                'default' => false,
                'type'    => 'bool',
                'inject'  => true,
            ),
            'wldelay_application_password_enabled'   => array(
                'default' => false,
                'type'    => 'bool',
                'inject'  => true,
            ),
            'wldelay_password_reset_enabled'         => array(
                'default' => false,
                'type'    => 'bool',
                'inject'  => true,
            ),
            'wldelay_enumeration_hardening_enabled'  => array(
                'default' => false,
                'type'    => 'bool',
                'inject'  => true,
            ),
            'wldelay_fail2ban_enabled'               => array(
                'default' => false,
                'type'    => 'bool',
                'inject'  => true,
            ),
            'wldelay_fail2ban_log_path'              => array(
                'default' => '',
                'type'    => 'string',
                'inject'  => true,
            ),
            'wldelay_fail2ban_include_lockouts'      => array(
                'default' => LDS_Settings::_DEFAULT_FAIL2BAN_INCLUDE_LOCKOUTS,
                'type'    => 'bool',
                'inject'  => true,
            ),

            // Botnet / distributed-attack detection (F-1-9). Default ON:
            // alert-only, never blocks, so enabling retroactively is safe.
            'wldelay_botnet_enabled'                 => array(
                'default' => true,
                'type'    => 'bool',
                'inject'  => true,
            ),
            'wldelay_botnet_ip_threshold'            => array(
                'default' => 5,
                'type'    => 'int',
                'inject'  => true,
            ),
            'wldelay_botnet_window_minutes'          => array(
                'default' => 15,
                'type'    => 'int',
                'inject'  => true,
            ),

            // Protection profile (resolved at the read site; empty when no
            // profile is applied).
            'wldelay_protection_profile'             => array(
                'default' => '',
                'type'    => 'string',
                'inject'  => false,
            ),

            // Proxy / client-IP trust.
            'wldelay_trust_proxy_headers'            => array(
                'default' => false,
                'type'    => 'bool',
                'inject'  => false,
            ),

            // IP whitelist.
            'wldelay_whitelist_enabled'              => array(
                'default' => false,
                'type'    => 'bool',
                'inject'  => false,
            ),
            'wldelay_whitelist_ips'                  => array(
                'default' => '',
                'type'    => 'string',
                'inject'  => false,
            ),

            // Country blocking. Resolver is intentionally filter-only; the
            // plugin ships no GeoIP database or lookup service.
            'wldelay_country_blocking_enabled'       => array(
                'default' => false,
                'type'    => 'bool',
                'inject'  => false,
            ),
            'wldelay_country_blocking_countries'     => array(
                'default' => '',
                'type'    => 'string',
                'inject'  => false,
            ),

            // Custom login URL. The slug default mirrors the read-site fallback
            // in wldelay_get_custom_login_slug() / sanitize_login_slug().
            'wldelay_custom_login_enabled'           => array(
                'default' => false,
                'type'    => 'bool',
                'inject'  => false,
            ),
            'wldelay_custom_login_slug'              => array(
                'default' => 'my-login',
                'type'    => 'string',
                'inject'  => false,
            ),

            // Emergency Recovery URL (opt-in). token_hash/generated_at/
            // last_used_at are written by the recovery handlers, never by the
            // settings form; only the enable flag is form-controlled. Inject the
            // enable flag so reads see a stable false default.
            'wldelay_recovery_enabled'               => array(
                'default' => false,
                'type'    => 'bool',
                'inject'  => true,
            ),
            'wldelay_recovery_token_hash'            => array(
                'default' => '',
                'type'    => 'string',
                'inject'  => false,
            ),
            'wldelay_recovery_generated_at'          => array(
                'default' => '',
                'type'    => 'string',
                'inject'  => false,
            ),
            'wldelay_recovery_last_used_at'          => array(
                'default' => '',
                'type'    => 'string',
                'inject'  => false,
            ),
        );
    }

    /**
     * Map of every option key to its default value.
     *
     * @return array<string,mixed>
     */
    public static function defaults() {
        $defaults = array();
        foreach ( self::all() as $key => $meta ) {
            $defaults[ $key ] = $meta['default'];
        }

        return $defaults;
    }

    /**
     * Map of the option keys whose defaults are materialised into the cached
     * options array at read time (the opt-in security flags).
     *
     * wldelay_get_options() merges only these into the stored array, exactly
     * like the array_key_exists guards it replaced, so the cached option shape
     * is unchanged.
     *
     * @return array<string,mixed>
     */
    public static function injected_defaults() {
        $defaults = array();
        foreach ( self::all() as $key => $meta ) {
            if ( ! empty( $meta['inject'] ) ) {
                $defaults[ $key ] = $meta['default'];
            }
        }

        return $defaults;
    }
}
