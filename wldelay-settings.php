<?php
if ( ! defined( 'ABSPATH' ) ) exit;

require_once dirname( __FILE__ ) . '/wldelay-fail2ban.php';

class LDS_Settings {
    /**
     * Default delay value is 1 second
     */
    const _DEFAULT_DELAY_IN_SECONDS = 1;

    /**
     * Default random delay range
     */
    const _DEFAULT_RANDOM_MIN = 1;
    const _DEFAULT_RANDOM_MAX = 5;

    /**
     * Default email notification threshold
     */
    const _DEFAULT_EMAIL_THRESHOLD = 5;

    /**
     * Default email cooldown (minutes between site-wide emails)
     */
    const _DEFAULT_EMAIL_COOLDOWN = 5;

    /**
     * Default lockout settings
     */
    const _DEFAULT_LOCKOUT_THRESHOLD = 10;
    const _DEFAULT_LOCKOUT_DURATION = 60; // minutes
    const _DEFAULT_LOCKOUT_ATTEMPT_STRATEGY = 'ip';

    /**
     * Default progressive delay settings
     */
    const _DEFAULT_PROGRESSIVE_INCREMENT = 1;
    const _DEFAULT_PROGRESSIVE_MAX = 30;

    /**
     * Default log retention (days)
     */
    const _DEFAULT_LOG_RETENTION_DAYS = 30;

    /**
     * Default fail2ban logging settings
     */
    const _DEFAULT_FAIL2BAN_INCLUDE_LOCKOUTS = true;

    /**
     * Holds the values to be used in the fields callbacks
     */
    private $options;

    /**
     * View instance for rendering
     */
    private $view;

    /**
     * Start up
     */
    public function __construct()
    {
        $this->view = new LDS_Settings_View();
        add_action( 'admin_menu', array( $this, 'add_plugin_page' ) );
        add_action( 'admin_init', array( $this, 'page_init' ) );
    }

    /**
     * Add options page
     */
    public function add_plugin_page()
    {
        // This page will be under "Settings"
        add_options_page(
            'Login Delay Shield Settings',              // page title
            'Login Delay Shield',                       // menu title
            'manage_options',                       // capability
            'login-delay-shield-admin',                 // menu slug
            array( $this, 'create_admin_page' )     // callback function
        );
    }

    /**
     * Options page callback
     */
    public function create_admin_page()
    {
        // Set class property and pass to view
        $this->options = get_option( WLDELAY_OPTION_NAME );
        $this->view->set_options( $this->options );
        $this->view->render();
    }

    /**
     * Register and add settings
     */
    public function page_init()
    {
        register_setting(
            'wldelay_option_group',     // Option group
            WLDELAY_OPTION_NAME,          // Option name
            array( $this, 'sanitize' )  // Sanitize
        );

        add_settings_section(
            'wldelay_setting_section_id', // ID
            'General settings', // Title
            array( $this->view, 'print_section_info' ), // Callback
            'login-delay-shield-admin' // Page
        );

	    add_settings_field(
		    'wldelay_delay_random',                        // id
		    'Check this box to use a random delay',                     // title
		    array( $this->view, 'delay_callback_random' ),       // callback function
		    'login-delay-shield-admin',                 // page
		    'wldelay_setting_section_id'            // section
	    );

        add_settings_field(
            'wldelay_delay',                        // id
            'Set a delay (in seconds)',                     // title
            array( $this->view, 'delay_callback' ),       // callback function
            'login-delay-shield-admin',                 // page
            'wldelay_setting_section_id'            // section
        );

        add_settings_field(
            'wldelay_delay_random_min',
            'Minimum random delay (seconds)',
            array( $this->view, 'delay_callback_random_min' ),
            'login-delay-shield-admin',
            'wldelay_setting_section_id'
        );

        add_settings_field(
            'wldelay_delay_random_max',
            'Maximum random delay (seconds)',
            array( $this->view, 'delay_callback_random_max' ),
            'login-delay-shield-admin',
            'wldelay_setting_section_id'
        );

        add_settings_field(
            'wldelay_progressive_enabled',
            'Enable progressive delay',
            array( $this->view, 'progressive_enabled_callback' ),
            'login-delay-shield-admin',
            'wldelay_setting_section_id'
        );

        add_settings_field(
            'wldelay_progressive_increment',
            'Delay increment per attempt (seconds)',
            array( $this->view, 'progressive_increment_callback' ),
            'login-delay-shield-admin',
            'wldelay_setting_section_id'
        );

        add_settings_field(
            'wldelay_progressive_max',
            'Maximum progressive delay (seconds)',
            array( $this->view, 'progressive_max_callback' ),
            'login-delay-shield-admin',
            'wldelay_setting_section_id'
        );

        // Email notification section
        add_settings_section(
            'wldelay_email_section_id',
            'Email Notifications',
            array( $this->view, 'print_email_section_info' ),
            'login-delay-shield-admin'
        );

        add_settings_field(
            'wldelay_email_enabled',
            'Enable email notifications',
            array( $this->view, 'email_enabled_callback' ),
            'login-delay-shield-admin',
            'wldelay_email_section_id'
        );

        add_settings_field(
            'wldelay_email_threshold',
            'Failed attempts before notification',
            array( $this->view, 'email_threshold_callback' ),
            'login-delay-shield-admin',
            'wldelay_email_section_id'
        );

        add_settings_field(
            'wldelay_email_address',
            'Notification email address',
            array( $this->view, 'email_address_callback' ),
            'login-delay-shield-admin',
            'wldelay_email_section_id'
        );

        add_settings_field(
            'wldelay_email_cooldown',
            'Email cooldown',
            array( $this->view, 'email_cooldown_callback' ),
            'login-delay-shield-admin',
            'wldelay_email_section_id'
        );

        // IP Lockout section
        add_settings_section(
            'wldelay_lockout_section_id',
            'IP Lockout',
            array( $this->view, 'print_lockout_section_info' ),
            'login-delay-shield-admin'
        );

        add_settings_field(
            'wldelay_lockout_enabled',
            'Enable IP lockout',
            array( $this->view, 'lockout_enabled_callback' ),
            'login-delay-shield-admin',
            'wldelay_lockout_section_id'
        );

        add_settings_field(
            'wldelay_lockout_threshold',
            'Failed attempts before lockout',
            array( $this->view, 'lockout_threshold_callback' ),
            'login-delay-shield-admin',
            'wldelay_lockout_section_id'
        );

        add_settings_field(
            'wldelay_lockout_attempt_strategy',
            'Attempt tracking strategy',
            array( $this->view, 'lockout_attempt_strategy_callback' ),
            'login-delay-shield-admin',
            'wldelay_lockout_section_id'
        );

        add_settings_field(
            'wldelay_lockout_duration',
            'Lockout duration (minutes)',
            array( $this->view, 'lockout_duration_callback' ),
            'login-delay-shield-admin',
            'wldelay_lockout_section_id'
        );

        add_settings_field(
            'wldelay_trust_proxy_headers',
            'Trust proxy headers',
            array( $this->view, 'trust_proxy_headers_callback' ),
            'login-delay-shield-admin',
            'wldelay_lockout_section_id'
        );

        // IP Whitelist section
        add_settings_section(
            'wldelay_whitelist_section_id',
            'IP Whitelist',
            array( $this->view, 'print_whitelist_section_info' ),
            'login-delay-shield-admin'
        );

        add_settings_field(
            'wldelay_whitelist_enabled',
            'Enable IP whitelist',
            array( $this->view, 'whitelist_enabled_callback' ),
            'login-delay-shield-admin',
            'wldelay_whitelist_section_id'
        );

        add_settings_field(
            'wldelay_whitelist_ips',
            'Whitelisted IPs',
            array( $this->view, 'whitelist_ips_callback' ),
            'login-delay-shield-admin',
            'wldelay_whitelist_section_id'
        );

        // Log Settings section
        add_settings_section(
            'wldelay_log_section_id',
            'Login Log',
            array( $this->view, 'print_log_section_info' ),
            'login-delay-shield-admin'
        );

        add_settings_field(
            'wldelay_log_retention_days',
            'Log retention (days)',
            array( $this->view, 'log_retention_callback' ),
            'login-delay-shield-admin',
            'wldelay_log_section_id'
        );

        add_settings_field(
            'wldelay_fail2ban_enabled',
            esc_html__( 'Enable fail2ban logging', 'login-delay-shield' ),
            array( $this->view, 'fail2ban_enabled_callback' ),
            'login-delay-shield-admin',
            'wldelay_log_section_id'
        );

        add_settings_field(
            'wldelay_fail2ban_log_path',
            esc_html__( 'Fail2ban log path', 'login-delay-shield' ),
            array( $this->view, 'fail2ban_log_path_callback' ),
            'login-delay-shield-admin',
            'wldelay_log_section_id'
        );

        add_settings_field(
            'wldelay_fail2ban_include_lockouts',
            esc_html__( 'Log lockout events', 'login-delay-shield' ),
            array( $this->view, 'fail2ban_include_lockouts_callback' ),
            'login-delay-shield-admin',
            'wldelay_log_section_id'
        );

        // XMLRPC Protection section
        add_settings_section(
            'wldelay_xmlrpc_section_id',
            'XML-RPC Protection',
            array( $this->view, 'print_xmlrpc_section_info' ),
            'login-delay-shield-admin'
        );

        add_settings_field(
            'wldelay_xmlrpc_enabled',
            'Enable XML-RPC protection',
            array( $this->view, 'xmlrpc_enabled_callback' ),
            'login-delay-shield-admin',
            'wldelay_xmlrpc_section_id'
        );

        add_settings_field(
            'wldelay_xmlrpc_block',
            'Block XML-RPC authentication',
            array( $this->view, 'xmlrpc_block_callback' ),
            'login-delay-shield-admin',
            'wldelay_xmlrpc_section_id'
        );

        add_settings_field(
            'wldelay_rest_enabled',
            'Enable REST API protection',
            array( $this->view, 'rest_enabled_callback' ),
            'login-delay-shield-admin',
            'wldelay_xmlrpc_section_id'
        );

        add_settings_field(
            'wldelay_application_password_enabled',
            'Enable application password protection',
            array( $this->view, 'application_password_enabled_callback' ),
            'login-delay-shield-admin',
            'wldelay_xmlrpc_section_id'
        );

        add_settings_field(
            'wldelay_password_reset_enabled',
            esc_html__( 'Enable password reset protection', 'login-delay-shield' ),
            array( $this->view, 'password_reset_enabled_callback' ),
            'login-delay-shield-admin',
            'wldelay_xmlrpc_section_id'
        );

        // Custom Login URL section
        add_settings_section(
            'wldelay_custom_login_section_id',
            esc_html__( 'Custom Login URL', 'login-delay-shield' ),
            array( $this->view, 'print_custom_login_section_info' ),
            'login-delay-shield-admin'
        );

        add_settings_field(
            'wldelay_custom_login_enabled',
            esc_html__( 'Enable custom login URL', 'login-delay-shield' ),
            array( $this->view, 'custom_login_enabled_callback' ),
            'login-delay-shield-admin',
            'wldelay_custom_login_section_id'
        );

        add_settings_field(
            'wldelay_custom_login_slug',
            esc_html__( 'Custom login slug', 'login-delay-shield' ),
            array( $this->view, 'custom_login_slug_callback' ),
            'login-delay-shield-admin',
            'wldelay_custom_login_section_id'
        );

    }

    /**
     * Sanitize each setting field as needed
     *
     * @param array $input Contains all settings fields as array keys
     */
    public function sanitize( $input )
    {
        $new_input = array();
        if( isset( $input['wldelay_delay'] ) ) {
            $delay = absint( $input['wldelay_delay'] );
            $delay = max( 0, min( 10, $delay ) );
            $new_input['wldelay_delay'] = $delay;
        }

        $new_input['wldelay_delay_random'] = ! empty( $input['wldelay_delay_random'] );

        // Random delay min/max (1-10 seconds range)
        $random_min = isset( $input['wldelay_delay_random_min'] ) ? absint( $input['wldelay_delay_random_min'] ) : self::_DEFAULT_RANDOM_MIN;
        $random_max = isset( $input['wldelay_delay_random_max'] ) ? absint( $input['wldelay_delay_random_max'] ) : self::_DEFAULT_RANDOM_MAX;

        $random_min = max( 1, min( 10, $random_min ) );
        $random_max = max( 1, min( 10, $random_max ) );

        // Ensure min <= max
        if( $random_min > $random_max ) {
            $random_min = $random_max;
        }

        $new_input['wldelay_delay_random_min'] = $random_min;
        $new_input['wldelay_delay_random_max'] = $random_max;

        // Email notification settings
        $new_input['wldelay_email_enabled'] = ! empty( $input['wldelay_email_enabled'] );

        $email_threshold = isset( $input['wldelay_email_threshold'] ) ? absint( $input['wldelay_email_threshold'] ) : self::_DEFAULT_EMAIL_THRESHOLD;
        $new_input['wldelay_email_threshold'] = max( 1, min( 100, $email_threshold ) );

        // Sanitize email address (allow empty for fallback to admin email)
        $email_address = isset( $input['wldelay_email_address'] ) ? sanitize_email( $input['wldelay_email_address'] ) : '';
        $new_input['wldelay_email_address'] = $email_address;

        // Email cooldown (0-60 minutes, 0 = disabled)
        $email_cooldown = isset( $input['wldelay_email_cooldown'] )
            ? absint( $input['wldelay_email_cooldown'] )
            : self::_DEFAULT_EMAIL_COOLDOWN;
        $new_input['wldelay_email_cooldown'] = min( 60, $email_cooldown );

        // IP Lockout settings
        $new_input['wldelay_lockout_enabled'] = ! empty( $input['wldelay_lockout_enabled'] );

        $lockout_threshold = isset( $input['wldelay_lockout_threshold'] )
            ? absint( $input['wldelay_lockout_threshold'] )
            : self::_DEFAULT_LOCKOUT_THRESHOLD;
        $new_input['wldelay_lockout_threshold'] = max( 1, min( 100, $lockout_threshold ) );

        $lockout_duration = isset( $input['wldelay_lockout_duration'] )
            ? absint( $input['wldelay_lockout_duration'] )
            : self::_DEFAULT_LOCKOUT_DURATION;
        $new_input['wldelay_lockout_duration'] = max( 1, min( 1440, $lockout_duration ) );

        $lockout_strategy = isset( $input['wldelay_lockout_attempt_strategy'] )
            ? (string) $input['wldelay_lockout_attempt_strategy']
            : self::_DEFAULT_LOCKOUT_ATTEMPT_STRATEGY;
        if ( ! in_array( $lockout_strategy, array( 'ip', 'ip_username' ), true ) ) {
            $lockout_strategy = self::_DEFAULT_LOCKOUT_ATTEMPT_STRATEGY;
        }
        $new_input['wldelay_lockout_attempt_strategy'] = $lockout_strategy;

        // Trust proxy headers (off by default for security)
        $new_input['wldelay_trust_proxy_headers'] = ! empty( $input['wldelay_trust_proxy_headers'] );

        // Progressive delay settings
        $new_input['wldelay_progressive_enabled'] = ! empty( $input['wldelay_progressive_enabled'] );

        $progressive_increment = isset( $input['wldelay_progressive_increment'] )
            ? absint( $input['wldelay_progressive_increment'] )
            : self::_DEFAULT_PROGRESSIVE_INCREMENT;
        $new_input['wldelay_progressive_increment'] = max( 1, min( 10, $progressive_increment ) );

        $progressive_max = isset( $input['wldelay_progressive_max'] )
            ? absint( $input['wldelay_progressive_max'] )
            : self::_DEFAULT_PROGRESSIVE_MAX;
        $new_input['wldelay_progressive_max'] = max( 5, min( 60, $progressive_max ) );

        // IP Whitelist settings
        $new_input['wldelay_whitelist_enabled'] = ! empty( $input['wldelay_whitelist_enabled'] );

        $whitelist_ips = isset( $input['wldelay_whitelist_ips'] ) ? $input['wldelay_whitelist_ips'] : '';
        $new_input['wldelay_whitelist_ips'] = $this->sanitize_whitelist_ips( $whitelist_ips );

        // Log retention settings (1-365 days, 0 = keep forever)
        $log_retention = isset( $input['wldelay_log_retention_days'] )
            ? absint( $input['wldelay_log_retention_days'] )
            : self::_DEFAULT_LOG_RETENTION_DAYS;
        $new_input['wldelay_log_retention_days'] = min( 365, $log_retention );

        // fail2ban-compatible file logging is disabled by default.
        $new_input['wldelay_fail2ban_enabled'] = ! empty( $input['wldelay_fail2ban_enabled'] );
        $raw_fail2ban_log_path = isset( $input['wldelay_fail2ban_log_path'] ) ? (string) $input['wldelay_fail2ban_log_path'] : '';
        $new_input['wldelay_fail2ban_log_path'] = $raw_fail2ban_log_path !== ''
            ? wldelay_sanitize_fail2ban_log_path( $raw_fail2ban_log_path )
            : '';
        if ( $raw_fail2ban_log_path !== '' && $new_input['wldelay_fail2ban_log_path'] === '' ) {
            $new_input['wldelay_fail2ban_enabled'] = false;
            if ( function_exists( 'add_settings_error' ) ) {
                add_settings_error(
                    WLDELAY_OPTION_NAME,
                    'wldelay_fail2ban_log_path_invalid',
                    esc_html__( 'fail2ban logging was disabled because the selected log path is not allowed. Use a .log file in the protected default directory, or leave the path empty for the protected default log location.', 'login-delay-shield' ),
                    'error'
                );
            }
        }
        $new_input['wldelay_fail2ban_include_lockouts'] = ! empty( $input['wldelay_fail2ban_include_lockouts'] );

        // XMLRPC Protection settings
        $new_input['wldelay_xmlrpc_enabled'] = ! empty( $input['wldelay_xmlrpc_enabled'] );
        $new_input['wldelay_xmlrpc_block'] = ! empty( $input['wldelay_xmlrpc_block'] );
        $new_input['wldelay_rest_enabled'] = ! empty( $input['wldelay_rest_enabled'] );
        $new_input['wldelay_application_password_enabled'] = ! empty( $input['wldelay_application_password_enabled'] );
        $new_input['wldelay_password_reset_enabled'] = ! empty( $input['wldelay_password_reset_enabled'] );

        // Custom Login URL settings
        $new_input['wldelay_custom_login_enabled'] = ! empty( $input['wldelay_custom_login_enabled'] );
        $raw_slug = isset( $input['wldelay_custom_login_slug'] ) ? (string) $input['wldelay_custom_login_slug'] : '';
        $new_input['wldelay_custom_login_slug'] = $this->sanitize_login_slug( $raw_slug );

        return $new_input;
    }

    /**
     * Sanitize a custom login slug.
     *
     * Produces a lowercase alphanumeric + hyphen slug. Rejects reserved slugs.
     *
     * @param string $slug Raw slug input.
     * @return string Sanitized slug, or 'my-login' if empty/invalid/reserved.
     */
    public function sanitize_login_slug( $slug ) {
        // Lowercase and strip anything that isn't a-z, 0-9, or hyphen.
        $slug = strtolower( (string) $slug );
        $slug = preg_replace( '/[^a-z0-9-]/', '', $slug );
        $slug = trim( $slug, '-' );

        if ( empty( $slug ) ) {
            return 'my-login';
        }

        // Block slugs that would conflict with WordPress core paths.
        // Note: entries are compared AFTER sanitization (lowercase, a-z0-9- only),
        // so entries like 'wp-login.php' are excluded — they cannot match.
        $reserved = array(
            'wp-admin',
            'wp-login',
            'admin',
            'login',
            'wp-cron',
            'wp-json',
            'wp-content',
            'wp-includes',
            'wp-signup',
            'wp-activate',
            'xmlrpc',
            'feed',
            'robots',
            'sitemap',
        );

        if ( in_array( $slug, $reserved, true ) ) {
            return 'my-login';
        }

        return $slug;
    }

    /**
     * Sanitize whitelist IPs
     * Validates each IP/CIDR and removes invalid entries
     *
     * @param string $input Raw textarea input
     * @return string Sanitized IPs, one per line
     */
    public function sanitize_whitelist_ips( $input )
    {
        if ( empty( $input ) ) {
            return '';
        }

        $lines = explode( "\n", $input );
        $valid_ips = array();

        foreach ( $lines as $line ) {
            $line = trim( $line );
            if ( empty( $line ) ) {
                continue;
            }

            // Check for CIDR notation
            if ( strpos( $line, '/' ) !== false ) {
                list( $ip, $mask ) = explode( '/', $line, 2 );
                $ip = trim( $ip );
                $mask = (int) trim( $mask );

                // Validate IPv4 CIDR
                if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) && $mask >= 0 && $mask <= 32 ) {
                    $valid_ips[] = $ip . '/' . $mask;
                }
                // Validate IPv6 CIDR
                elseif ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) && $mask >= 0 && $mask <= 128 ) {
                    $valid_ips[] = $ip . '/' . $mask;
                }
            } else {
                // Plain IP address
                if ( filter_var( $line, FILTER_VALIDATE_IP ) ) {
                    $valid_ips[] = $line;
                }
            }
        }

        return implode( "\n", $valid_ips );
    }

}
