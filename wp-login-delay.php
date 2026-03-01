<?php
if ( ! defined( 'ABSPATH' ) ) exit;

define( 'WLDELAY_VERSION', '2.1.1' );
define( 'WLDELAY_PLUGIN_FILE', __FILE__ );
define( 'WLDELAY_OPTION_NAME', 'wldelay_options' );

/*
Plugin Name: Login Delay Shield
Plugin URI: https://damoiseau.me
Description: Protects against brute-force attacks with login delays, progressive throttling, IP lockout, whitelist, XML-RPC protection, and email alerts.
Version: 2.1.1
Author: Mike
Author URI: https://damoiseau.me
License: GPL2
Text Domain: login-delay-shield
*/

/**
 * Load plugin textdomain for translations
 */
function wldelay_load_textdomain() {
    load_plugin_textdomain(
        'login-delay-shield',
        false,
        dirname( plugin_basename( WLDELAY_PLUGIN_FILE ) ) . '/languages'
    );
}
add_action( 'plugins_loaded', 'wldelay_load_textdomain' );

/**
 * Settings
 * @see http://codex.wordpress.org/Settings_API
 */
require_once dirname( __FILE__ ) . '/wldelay-settings-view.php';
require_once dirname( __FILE__ ) . '/wldelay-settings.php';
if( is_admin() ) {
    $wldelay_settings_page = new LDS_Settings();
}

/**
 * Add Settings link on plugins page
 */
function wldelay_plugin_action_links( $links ) {
    $settings_link = sprintf(
        '<a href="%s">%s</a>',
        admin_url( 'options-general.php?page=login-delay-shield-admin' ),
        __( 'Settings', 'login-delay-shield' )
    );
    array_unshift( $links, $settings_link );
    return $links;
}
add_filter( 'plugin_action_links_' . plugin_basename( WLDELAY_PLUGIN_FILE ), 'wldelay_plugin_action_links' );

/**
 * Dashboard Widget
 */
function wldelay_add_dashboard_widget() {
    wp_add_dashboard_widget(
        'wldelay_failed_logins_widget',
        __( 'Recent Failed Login Attempts', 'login-delay-shield' ),
        'wldelay_dashboard_widget_content'
    );
}
add_action( 'wp_dashboard_setup', 'wldelay_add_dashboard_widget' );

/**
 * Enqueue admin styles
 */
function wldelay_enqueue_admin_styles( $hook ) {
    // Only load on dashboard and our settings page
    if ( $hook !== 'index.php' && $hook !== 'settings_page_login-delay-shield-admin' ) {
        return;
    }

    wp_enqueue_style(
        'wldelay-admin',
        plugin_dir_url( WLDELAY_PLUGIN_FILE ) . 'admin.css',
        array(),
        WLDELAY_VERSION
    );
}
add_action( 'admin_enqueue_scripts', 'wldelay_enqueue_admin_styles' );

/**
 * Build the unlock-current-IP admin action URL.
 *
 * @return string URL to admin-post endpoint with nonce.
 */
function wldelay_get_unlock_current_ip_url() {
    $url = add_query_arg(
        array(
            'action' => 'wldelay_unlock_current_ip',
        ),
        admin_url( 'admin-post.php' )
    );

    return wp_nonce_url( $url, 'wldelay_unlock_current_ip' );
}

/**
 * Build the export-login-log admin action URL.
 *
 * @return string URL to admin-post endpoint with nonce.
 */
function wldelay_get_export_login_log_url() {
    $url = add_query_arg(
        array(
            'action' => 'wldelay_export_login_log',
        ),
        admin_url( 'admin-post.php' )
    );

    return wp_nonce_url( $url, 'wldelay_export_login_log' );
}

/**
 * Get registry option name for transient keys managed by this plugin.
 *
 * @return string
 */
function wldelay_get_transient_registry_option_name() {
    return 'wldelay_transient_registry';
}

/**
 * Track a transient key in the plugin registry.
 *
 * @param string $transient_name Transient key name (without WordPress prefix).
 */
function wldelay_register_transient_key( $transient_name ) {
    if ( empty( $transient_name ) ) {
        return;
    }

    $option_name = wldelay_get_transient_registry_option_name();
    $registry = get_option( $option_name, array() );

    if ( ! is_array( $registry ) ) {
        $registry = array();
    }

    if ( ! in_array( $transient_name, $registry, true ) ) {
        $registry[] = $transient_name;
        update_option( $option_name, $registry, false );
    }
}

/**
 * Remove a transient key from the plugin registry.
 *
 * @param string $transient_name Transient key name (without WordPress prefix).
 */
function wldelay_unregister_transient_key( $transient_name ) {
    if ( empty( $transient_name ) ) {
        return;
    }

    $option_name = wldelay_get_transient_registry_option_name();
    $registry = get_option( $option_name, array() );

    if ( ! is_array( $registry ) || empty( $registry ) ) {
        return;
    }

    $registry = array_values( array_filter( $registry, function( $key ) use ( $transient_name ) {
        return $key !== $transient_name;
    } ) );

    update_option( $option_name, $registry, false );
}

/**
 * Remove lockout and failure transients for a specific IP.
 *
 * In IP+username strategy mode, this also clears tuple keys for the given
 * username (if provided), while keeping backward compatibility with IP-only mode.
 *
 * @param string $ip IP address.
 * @param string $username Optional username.
 * @return int Number of transients removed.
 */
function wldelay_delete_lockout_for_ip( $ip, $username = '' ) {
    if ( empty( $ip ) ) {
        return 0;
    }

    $deleted = 0;

    $lockout_ip_key = wldelay_get_lockout_transient_key( $ip, '' );
    $fails_ip_key   = wldelay_get_failure_transient_key( $ip, '' );

    if ( delete_transient( $lockout_ip_key ) ) {
        $deleted++;
    }
    wldelay_unregister_transient_key( $lockout_ip_key );

    if ( delete_transient( $fails_ip_key ) ) {
        $deleted++;
    }
    wldelay_unregister_transient_key( $fails_ip_key );

    if ( ! empty( $username ) ) {
        $pair_options = array( 'wldelay_lockout_attempt_strategy' => 'ip_username' );

        $lockout_pair_key = wldelay_get_lockout_transient_key( $ip, $username, $pair_options );
        if ( $lockout_pair_key !== $lockout_ip_key && delete_transient( $lockout_pair_key ) ) {
            $deleted++;
        }
        wldelay_unregister_transient_key( $lockout_pair_key );

        $fails_pair_key = wldelay_get_failure_transient_key( $ip, $username, $pair_options );
        if ( $fails_pair_key !== $fails_ip_key && delete_transient( $fails_pair_key ) ) {
            $deleted++;
        }
        wldelay_unregister_transient_key( $fails_pair_key );
    }

    return $deleted;
}

/**
 * Flush all lockout and failure transients managed by this plugin.
 *
 * @return int Number of transients removed.
 */
function wldelay_flush_lockout_transients() {
    global $wpdb;

    $deleted = 0;

    $registry = get_option( wldelay_get_transient_registry_option_name(), array() );
    if ( is_array( $registry ) ) {
        foreach ( $registry as $transient_name ) {
            if ( strpos( $transient_name, 'wldelay_lockout_' ) !== 0 && strpos( $transient_name, 'wldelay_fails_' ) !== 0 ) {
                continue;
            }

            if ( delete_transient( $transient_name ) ) {
                $deleted++;
            }
        }
    }

    // Fallback cleanup for DB-backed transients not present in the registry.
    $option_name_like_lockouts = $wpdb->esc_like( '_transient_wldelay_lockout_' ) . '%';
    $option_name_like_fails    = $wpdb->esc_like( '_transient_wldelay_fails_' ) . '%';

    $option_names = $wpdb->get_col(
        $wpdb->prepare(
            "SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s",
            $option_name_like_lockouts,
            $option_name_like_fails
        )
    );

    foreach ( $option_names as $option_name ) {
        $transient_name = str_replace( '_transient_', '', $option_name );
        if ( delete_transient( $transient_name ) ) {
            $deleted++;
        }
    }

    update_option( wldelay_get_transient_registry_option_name(), array(), false );

    return $deleted;
}

/**
 * Handle admin action to unlock the current IP.
 */
function wldelay_handle_unlock_current_ip() {
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_die( esc_html__( 'You are not allowed to perform this action.', 'login-delay-shield' ) );
    }

    check_admin_referer( 'wldelay_unlock_current_ip' );

    $ip = wldelay_get_client_ip();
    $username = '';

    if ( function_exists( 'wp_get_current_user' ) ) {
        $current_user = wp_get_current_user();
        if ( $current_user instanceof WP_User ) {
            $username = $current_user->user_login;
        }
    }

    $deleted = wldelay_delete_lockout_for_ip( $ip, $username );

    $redirect_url = add_query_arg(
        array(
            'page' => 'login-delay-shield-admin',
            'wldelay_unlock_ip' => $deleted > 0 ? 'success' : 'none',
        ),
        admin_url( 'options-general.php' )
    );

    wp_safe_redirect( $redirect_url );
    exit;
}
add_action( 'admin_post_wldelay_unlock_current_ip', 'wldelay_handle_unlock_current_ip' );

/**
 * Mitigate CSV formula injection for values opened in spreadsheet tools.
 *
 * @param string $value
 * @return string
 */
function wldelay_csv_sanitize_cell( $value ) {
    $value = (string) $value;
    if ( $value !== '' && preg_match( '/^[ \\t]*[=+\\-@]/', $value ) ) {
        return "'" . $value;
    }
    return $value;
}

/**
 * Handle admin action to export login log as CSV.
 */
function wldelay_handle_export_login_log() {
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_die( esc_html__( 'You are not allowed to perform this action.', 'login-delay-shield' ) );
    }

    check_admin_referer( 'wldelay_export_login_log' );

    global $wpdb;
    $table_name = wldelay_get_log_table_name();

    $attempts = $wpdb->get_results( "SELECT source, ip_address, username, attempted_at FROM $table_name ORDER BY attempted_at DESC" );

    // In CLI/test runtime, headers may already be sent by bootstrap output.
    // Avoid PHP warnings while still streaming CSV content for test assertions.
    if ( ! headers_sent() ) {
        nocache_headers();
        header( 'Content-Type: text/csv; charset=utf-8' );
        header( 'Content-Disposition: attachment; filename="login-delay-shield-login-log-' . gmdate( 'Y-m-d' ) . '.csv"' );
    }

    $out = fopen( 'php://output', 'w' );
    if ( $out ) {
        fputcsv( $out, array( 'source', 'ip', 'username', 'timestamp' ) );

        foreach ( $attempts as $attempt ) {
            fputcsv(
                $out,
                array(
                    wldelay_csv_sanitize_cell( $attempt->source ),
                    wldelay_csv_sanitize_cell( $attempt->ip_address ),
                    wldelay_csv_sanitize_cell( $attempt->username ),
                    wldelay_csv_sanitize_cell( $attempt->attempted_at ),
                )
            );
        }

        fclose( $out );
    }

    $should_exit = apply_filters( 'wldelay_export_login_log_should_exit', true );
    if ( $should_exit ) {
        exit;
    }
}
add_action( 'admin_post_wldelay_export_login_log', 'wldelay_handle_export_login_log' );

/**
 * Render admin notice after unlock-current-IP action.
 */
function wldelay_render_unlock_notice() {
    if ( ! is_admin() || ! current_user_can( 'manage_options' ) ) {
        return;
    }

    if ( ! isset( $_GET['page'] ) || $_GET['page'] !== 'login-delay-shield-admin' ) {
        return;
    }

    if ( ! isset( $_GET['wldelay_unlock_ip'] ) ) {
        return;
    }

    $status = sanitize_text_field( wp_unslash( $_GET['wldelay_unlock_ip'] ) );
    $class = ( $status === 'success' ) ? 'notice-success' : 'notice-warning';
    $message = ( $status === 'success' )
        ? __( 'Current IP lockout removed.', 'login-delay-shield' )
        : __( 'No active lockout was found for your current IP.', 'login-delay-shield' );

    echo '<div class="notice ' . esc_attr( $class ) . ' is-dismissible"><p>' . esc_html( $message ) . '</p></div>';
}
add_action( 'admin_notices', 'wldelay_render_unlock_notice' );

if ( defined( 'WP_CLI' ) && WP_CLI ) {
    /**
     * WP-CLI commands for Login Delay Shield.
     */
    class WLDelay_CLI_Command {
        /**
         * Unlock a specific IP.
         *
         * ## OPTIONS
         *
         * <ip>
         * : IP address to unlock.
         *
         * ## EXAMPLES
         *
         *     wp login-delay-shield unlock-ip 203.0.113.10
         *
         * @when after_wp_load
         */
        public function unlock_ip( $args ) {
            list( $ip ) = $args;

            if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
                WP_CLI::error( __( 'Invalid IP address provided.', 'login-delay-shield' ) );
            }

            $deleted = wldelay_delete_lockout_for_ip( $ip );

            if ( $deleted > 0 ) {
                WP_CLI::success(
                    sprintf(
                        /* translators: %1$s: IP address, %2$d: number of removed entries */
                        _n(
                            'Removed lockout/failure data for %1$s (%2$d entry).',
                            'Removed lockout/failure data for %1$s (%2$d entries).',
                            $deleted,
                            'login-delay-shield'
                        ),
                        $ip,
                        $deleted
                    )
                );
                return;
            }

            WP_CLI::warning(
                sprintf(
                    /* translators: %s: IP address */
                    __( 'No active lockout found for %s.', 'login-delay-shield' ),
                    $ip
                )
            );
        }

        /**
         * Flush all lockouts.
         *
         * ## EXAMPLES
         *
         *     wp login-delay-shield flush-lockouts
         *
         * @when after_wp_load
         */
        public function flush_lockouts() {
            $deleted = wldelay_flush_lockout_transients();

            WP_CLI::success(
                sprintf(
                    /* translators: %d: number of removed lockout/failure entries */
                    _n(
                        'Removed %d lockout/failure entry.',
                        'Removed %d lockout/failure entries.',
                        $deleted,
                        'login-delay-shield'
                    ),
                    $deleted
                )
            );
        }
    }

    WP_CLI::add_command( 'login-delay-shield', 'WLDelay_CLI_Command' );
}

function wldelay_dashboard_widget_content() {
    $cache_key = 'wldelay_dashboard_attempts';
    $attempts  = get_transient( $cache_key );

    if ( false === $attempts ) {
        $attempts = wldelay_get_recent_failed_attempts( 10 );
        set_transient( $cache_key, $attempts, 2 * MINUTE_IN_SECONDS );
    }

    if ( empty( $attempts ) ) {
        echo '<p>' . esc_html__( 'No failed login attempts recorded.', 'login-delay-shield' ) . '</p>';
        return;
    }

    echo '<table class="widefat striped">';
    echo '<caption class="screen-reader-text">' . esc_html__( 'Recent failed login attempts', 'login-delay-shield' ) . '</caption>';
    echo '<thead><tr>';
    echo '<th scope="col">' . esc_html__( 'Time', 'login-delay-shield' ) . '</th>';
    echo '<th scope="col">' . esc_html__( 'Username', 'login-delay-shield' ) . '</th>';
    echo '<th scope="col">' . esc_html__( 'IP Address', 'login-delay-shield' ) . '</th>';
    echo '<th scope="col">' . esc_html__( 'Source', 'login-delay-shield' ) . '</th>';
    echo '</tr></thead>';
    echo '<tbody>';

    foreach ( $attempts as $attempt ) {
        $time_ago = human_time_diff( strtotime( $attempt->attempted_at ), time() );
        $source = isset( $attempt->source ) ? $attempt->source : 'wp-login';
        $source_class = 'wldelay-source-' . sanitize_html_class( $source );
        $source_label = wldelay_get_login_source_label( $source );

        echo '<tr>';
        /* translators: %1$s: time ago, %2$s: exact timestamp */
        $time_text = sprintf( __( '%1$s ago', 'login-delay-shield' ), $time_ago );
        echo '<td><time datetime="' . esc_attr( $attempt->attempted_at ) . '" title="' . esc_attr( $attempt->attempted_at ) . '">' . esc_html( $time_text ) . '</time></td>';
        echo '<td>' . esc_html( $attempt->username ) . '</td>';
        echo '<td>' . esc_html( $attempt->ip_address ) . '</td>';
        echo '<td><span class="wldelay-source-badge ' . esc_attr( $source_class ) . '">' . esc_html( $source_label ) . '</span></td>';
        echo '</tr>';
    }

    echo '</tbody></table>';

    $settings_url = admin_url( 'options-general.php?page=login-delay-shield-admin' );
    echo '<p class="wldelay-widget-footer" style="margin-top: 10px; text-align: right;">';
    echo '<a href="' . esc_url( $settings_url ) . '">' . esc_html__( 'Settings', 'login-delay-shield' ) . '</a>';
    echo '</p>';
}

/**
 * Database table functions
 */
function wldelay_get_log_table_name() {
    static $table_name = null;

    if ( $table_name === null ) {
        global $wpdb;
        $table_name = $wpdb->prefix . 'wldelay_login_log';
    }

    return $table_name;
}

function wldelay_create_log_table() {
    global $wpdb;

    $table_name = wldelay_get_log_table_name();
    $charset_collate = $wpdb->get_charset_collate();

    $sql = "CREATE TABLE $table_name (
        id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
        ip_address varchar(45) NOT NULL,
        username varchar(60) NOT NULL,
        attempted_at datetime NOT NULL,
        source varchar(20) NOT NULL DEFAULT 'wp-login',
        PRIMARY KEY  (id),
        KEY attempted_at (attempted_at),
        KEY ip_address (ip_address)
    ) $charset_collate;";

    require_once( ABSPATH . 'wp-admin/includes/upgrade.php' );
    dbDelta( $sql );

    update_option( 'wldelay_db_version', WLDELAY_VERSION );
}

register_activation_hook( WLDELAY_PLUGIN_FILE, 'wldelay_create_log_table' );

/**
 * Log cleanup cron job
 */
function wldelay_schedule_cleanup() {
    if ( ! wp_next_scheduled( 'wldelay_cleanup_logs' ) ) {
        wp_schedule_event( time(), 'daily', 'wldelay_cleanup_logs' );
    }
}
add_action( 'wp', 'wldelay_schedule_cleanup' );

function wldelay_unschedule_cleanup() {
    $timestamp = wp_next_scheduled( 'wldelay_cleanup_logs' );
    if ( $timestamp ) {
        wp_unschedule_event( $timestamp, 'wldelay_cleanup_logs' );
    }
}
register_deactivation_hook( WLDELAY_PLUGIN_FILE, 'wldelay_unschedule_cleanup' );

/**
 * Delete log entries older than the retention period
 */
function wldelay_cleanup_old_logs() {
    global $wpdb;

    $options = get_option( WLDELAY_OPTION_NAME );
    $retention_days = isset( $options['wldelay_log_retention_days'] )
        ? (int) $options['wldelay_log_retention_days']
        : LDS_Settings::_DEFAULT_LOG_RETENTION_DAYS;

    // 0 means keep forever
    if ( $retention_days <= 0 ) {
        return;
    }

    $table_name = wldelay_get_log_table_name();
    $cutoff_date = gmdate( 'Y-m-d H:i:s', strtotime( "-{$retention_days} days" ) );

    // Delete in batches to avoid locking large tables
    $batch_size = 1000;
    $total_deleted = 0;

    do {
        $deleted = $wpdb->query(
            $wpdb->prepare(
                "DELETE FROM $table_name WHERE attempted_at < %s LIMIT %d",
                $cutoff_date,
                $batch_size
            )
        );

        if ( $deleted > 0 ) {
            $total_deleted += $deleted;
        }
    } while ( $deleted === $batch_size );

    // Invalidate dashboard widget cache after cleanup
    if ( $total_deleted > 0 ) {
        delete_transient( 'wldelay_dashboard_attempts' );
    }
}
add_action( 'wldelay_cleanup_logs', 'wldelay_cleanup_old_logs' );

/**
 * Check if database needs upgrade
 */
function wldelay_maybe_upgrade_db() {
    $installed_version = get_option( 'wldelay_db_version' );
    if ( $installed_version !== WLDELAY_VERSION ) {
        wldelay_create_log_table();
    }
}
add_action( 'plugins_loaded', 'wldelay_maybe_upgrade_db' );

/**
 * Show upgrade notice for name change
 */
function wldelay_show_upgrade_notice() {
    // Only show to users who can manage options
    if ( ! current_user_can( 'manage_options' ) ) {
        return;
    }

    // Check if notice was dismissed
    if ( get_option( 'wldelay_name_change_notice_dismissed' ) ) {
        return;
    }

    // Only show if upgrading from an older version (before 1.8.0)
    $previous_version = get_option( 'wldelay_previous_version' );
    if ( $previous_version && version_compare( $previous_version, '1.8.0', '>=' ) ) {
        return;
    }

    // Check if this is an existing installation (has options saved)
    $options = get_option( WLDELAY_OPTION_NAME );
    if ( empty( $options ) ) {
        // New installation, no need to show notice
        update_option( 'wldelay_name_change_notice_dismissed', true );
        return;
    }

    ?>
    <div class="notice notice-info is-dismissible wldelay-name-change-notice">
        <p>
            <strong><?php esc_html_e( 'Login Delay Shield', 'login-delay-shield' ); ?></strong> —
            <?php esc_html_e( 'This plugin was formerly known as "WP Login Delay". The name has changed, but all your settings have been preserved.', 'login-delay-shield' ); ?>
        </p>
    </div>
    <script>
        jQuery(document).ready(function($) {
            $(document).on('click', '.wldelay-name-change-notice .notice-dismiss', function() {
                $.post(ajaxurl, {
                    action: 'wldelay_dismiss_name_change_notice',
                    _wpnonce: '<?php echo wp_create_nonce( 'wldelay_dismiss_notice' ); ?>'
                });
            });
        });
    </script>
    <?php
}
add_action( 'admin_notices', 'wldelay_show_upgrade_notice' );

function wldelay_dismiss_name_change_notice() {
    check_ajax_referer( 'wldelay_dismiss_notice', '_wpnonce' );

    if ( ! current_user_can( 'manage_options' ) ) {
        wp_die();
    }

    update_option( 'wldelay_name_change_notice_dismissed', true );
    wp_die();
}
add_action( 'wp_ajax_wldelay_dismiss_name_change_notice', 'wldelay_dismiss_name_change_notice' );

function wldelay_track_version() {
    $stored_version = get_option( 'wldelay_plugin_version' );
    if ( $stored_version !== WLDELAY_VERSION ) {
        if ( $stored_version ) {
            update_option( 'wldelay_previous_version', $stored_version );
        }
        update_option( 'wldelay_plugin_version', WLDELAY_VERSION );
    }
}
add_action( 'plugins_loaded', 'wldelay_track_version' );

// @see http://codex.wordpress.org/Function_Reference/add_filter
// @see https://codex.wordpress.org/Plugin_API/Filter_Reference/wp_authenticate_user

function wldelay_get_options() {
    if ( ! isset( $GLOBALS['wldelay_options_cache'] ) ) {
        $GLOBALS['wldelay_options_cache'] = get_option( WLDELAY_OPTION_NAME );
    }

    return $GLOBALS['wldelay_options_cache'];
}

/**
 * Clear the options cache. Useful for testing.
 */
function wldelay_clear_options_cache() {
    unset( $GLOBALS['wldelay_options_cache'] );
}

// Auto-clear cache when option is updated
add_action( 'update_option_wldelay_options', 'wldelay_clear_options_cache' );
add_action( 'add_option_wldelay_options', 'wldelay_clear_options_cache' );
add_action( 'delete_option_wldelay_options', 'wldelay_clear_options_cache' );

/**
 * Calculate the delay value based on settings
 *
 * @param int $failure_count Number of previous failed attempts (for progressive delay)
 * @return int Delay in seconds
 */
function wldelay_get_delay_value( $failure_count = 0 ) {

    $options = wldelay_get_options();

    // Get base delay (random or fixed)
    $useRandomDelay = ! empty( $options['wldelay_delay_random'] );
    if( $useRandomDelay ) {
        $min = isset( $options['wldelay_delay_random_min'] ) ? (int) $options['wldelay_delay_random_min'] : LDS_Settings::_DEFAULT_RANDOM_MIN;
        $max = isset( $options['wldelay_delay_random_max'] ) ? (int) $options['wldelay_delay_random_max'] : LDS_Settings::_DEFAULT_RANDOM_MAX;
        $base_delay = wp_rand( $min, $max );
    } else {
        $base_delay = isset( $options['wldelay_delay'] ) ? (int) $options['wldelay_delay'] : LDS_Settings::_DEFAULT_DELAY_IN_SECONDS;
    }

    // Apply progressive delay if enabled
    $progressive_enabled = ! empty( $options['wldelay_progressive_enabled'] );
    if ( $progressive_enabled && $failure_count > 0 ) {
        $increment = isset( $options['wldelay_progressive_increment'] )
            ? (int) $options['wldelay_progressive_increment']
            : LDS_Settings::_DEFAULT_PROGRESSIVE_INCREMENT;
        $max_delay = isset( $options['wldelay_progressive_max'] )
            ? (int) $options['wldelay_progressive_max']
            : LDS_Settings::_DEFAULT_PROGRESSIVE_MAX;

        $progressive_delay = $base_delay + ( $increment * $failure_count );
        $delay = min( $progressive_delay, $max_delay );
    } else {
        $delay = $base_delay;
    }

    return $delay;
}

function wldelay_get_client_ip() {
    $options = get_option( WLDELAY_OPTION_NAME, [] );
    $trust_proxy = ! empty( $options['wldelay_trust_proxy_headers'] );

    $ip = '';

    // Only check proxy headers if explicitly trusted (they can be spoofed)
    if ( $trust_proxy ) {
        $client_ip = isset( $_SERVER['HTTP_CLIENT_IP'] ) ? trim( $_SERVER['HTTP_CLIENT_IP'] ) : '';
        $forwarded = isset( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ? trim( $_SERVER['HTTP_X_FORWARDED_FOR'] ) : '';

        if ( ! empty( $client_ip ) ) {
            $ip = $client_ip;
        } elseif ( ! empty( $forwarded ) ) {
            // Take the first IP (client IP) from the chain
            $ip = trim( explode( ',', $forwarded )[0] );
        }
    }

    // Fall back to REMOTE_ADDR (the actual TCP connection IP)
    if ( empty( $ip ) && ! empty( $_SERVER['REMOTE_ADDR'] ) ) {
        $ip = $_SERVER['REMOTE_ADDR'];
    }

    return sanitize_text_field( trim( $ip ) );
}

/**
 * Get lockout attempt strategy.
 *
 * @param array|null $options Optional options array.
 * @return string Strategy: ip or ip_username.
 */
function wldelay_get_lockout_attempt_strategy( $options = null ) {
    if ( $options === null ) {
        $options = wldelay_get_options();
    }

    $strategy = isset( $options['wldelay_lockout_attempt_strategy'] )
        ? (string) $options['wldelay_lockout_attempt_strategy']
        : LDS_Settings::_DEFAULT_LOCKOUT_ATTEMPT_STRATEGY;

    if ( ! in_array( $strategy, array( 'ip', 'ip_username' ), true ) ) {
        $strategy = LDS_Settings::_DEFAULT_LOCKOUT_ATTEMPT_STRATEGY;
    }

    return $strategy;
}

/**
 * Normalize username for attempt tracking keys.
 *
 * @param string $username Username input.
 * @return string Normalized username.
 */
function wldelay_normalize_username( $username ) {
    $username = is_string( $username ) ? trim( $username ) : '';
    if ( $username === '' ) {
        return '';
    }

    return strtolower( sanitize_user( $username, true ) );
}

/**
 * Get the identifier string for failure/lockout tracking.
 *
 * @param string $ip IP address.
 * @param string $username Username attempted.
 * @param array|null $options Optional options array.
 * @return string Identifier string used for transient keys.
 */
function wldelay_get_attempt_identifier( $ip, $username = '', $options = null ) {
    $strategy = wldelay_get_lockout_attempt_strategy( $options );
    $normalized_username = wldelay_normalize_username( $username );

    if ( $strategy === 'ip_username' && $normalized_username !== '' ) {
        return $ip . '|' . $normalized_username;
    }

    return $ip;
}

/**
 * Get transient key used for failed-attempt counter.
 *
 * @param string $ip IP address.
 * @param string $username Username attempted.
 * @param array|null $options Optional options array.
 * @return string Transient key.
 */
function wldelay_get_failure_transient_key( $ip, $username = '', $options = null ) {
    return 'wldelay_fails_' . md5( wldelay_get_attempt_identifier( $ip, $username, $options ) );
}

/**
 * Get transient key used for lockouts.
 *
 * @param string $ip IP address.
 * @param string $username Username attempted.
 * @param array|null $options Optional options array.
 * @return string Transient key.
 */
function wldelay_get_lockout_transient_key( $ip, $username = '', $options = null ) {
    return 'wldelay_lockout_' . md5( wldelay_get_attempt_identifier( $ip, $username, $options ) );
}

/**
 * Get username from current login request.
 *
 * @return string Normalized username or empty string.
 */
function wldelay_get_requested_login_username() {
    if ( isset( $_POST['log'] ) ) {
        return wldelay_normalize_username( $_POST['log'] );
    }

    return '';
}

/**
 * Get lockout duration in seconds.
 *
 * @param array|null $options Optional options array.
 * @return int Duration in seconds.
 */
function wldelay_get_lockout_duration_seconds( $options = null ) {
    if ( $options === null ) {
        $options = wldelay_get_options();
    }

    $duration_minutes = isset( $options['wldelay_lockout_duration'] )
        ? (int) $options['wldelay_lockout_duration']
        : LDS_Settings::_DEFAULT_LOCKOUT_DURATION;

    $duration_minutes = max( 1, min( 1440, $duration_minutes ) );

    return $duration_minutes * MINUTE_IN_SECONDS;
}

/**
 * Get remaining lockout time in seconds.
 *
 * @param string|null $ip Optional IP. Defaults to current client IP.
 * @param string $username Optional username for IP+username strategy.
 * @return int Remaining seconds. 0 if not locked.
 */
function wldelay_get_lockout_remaining_seconds( $ip = null, $username = '' ) {
    if ( $ip === null ) {
        $ip = wldelay_get_client_ip();
    }
    if ( empty( $ip ) ) {
        return 0;
    }

    $transient_key = wldelay_get_lockout_transient_key( $ip, $username );
    $locked_at = get_transient( $transient_key );
    if ( false === $locked_at ) {
        return 0;
    }

    $lockout_duration = wldelay_get_lockout_duration_seconds();
    if ( is_numeric( $locked_at ) ) {
        $remaining = $lockout_duration - ( time() - (int) $locked_at );
        return max( 1, (int) $remaining );
    }

    // Fallback for unexpected transient values.
    return $lockout_duration;
}

/**
 * Build lockout error message including a countdown when available.
 *
 * @param string|null $ip Optional IP.
 * @param string $username Optional username.
 * @return string Error message.
 */
function wldelay_get_lockout_error_message( $ip = null, $username = '' ) {
    $remaining = wldelay_get_lockout_remaining_seconds( $ip, $username );
    if ( $remaining > 0 ) {
        $time_text = human_time_diff( time(), time() + $remaining );
        return sprintf(
            /* translators: %s: remaining lockout duration, e.g. "2 minutes" */
            __( 'Too many failed login attempts. Please try again in %s.', 'login-delay-shield' ),
            $time_text
        );
    }

    return __( 'Too many failed login attempts. Please try again later.', 'login-delay-shield' );
}

/**
 * Check if the current request is an XMLRPC request
 *
 * @return bool True if this is an XMLRPC request
 */
function wldelay_is_xmlrpc_request() {
    // Check WordPress constant first (set early in xmlrpc.php)
    if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
        return true;
    }

    // Fallback: check the request URI
    if ( isset( $_SERVER['REQUEST_URI'] ) && strpos( $_SERVER['REQUEST_URI'], 'xmlrpc.php' ) !== false ) {
        return true;
    }

    return false;
}

/**
 * Check if the current request is a REST API request.
 *
 * @return bool True if this is a REST request.
 */
function wldelay_is_rest_request() {
    if ( defined( 'REST_REQUEST' ) && REST_REQUEST ) {
        return true;
    }

    if ( isset( $_SERVER['REQUEST_URI'] ) && strpos( $_SERVER['REQUEST_URI'], '/wp-json/' ) !== false ) {
        return true;
    }

    return false;
}

/**
 * Get username from PHP auth headers.
 *
 * @return string Normalized username or empty string.
 */
function wldelay_get_php_auth_username() {
    if ( isset( $_SERVER['PHP_AUTH_USER'] ) ) {
        return wldelay_normalize_username( wp_unslash( $_SERVER['PHP_AUTH_USER'] ) );
    }

    return '';
}

/**
 * Detect whether current request is attempting application-password auth.
 *
 * @return bool True when PHP auth headers are present.
 */
function wldelay_is_application_password_attempt() {
    return isset( $_SERVER['PHP_AUTH_USER'] ) && isset( $_SERVER['PHP_AUTH_PW'] );
}

/**
 * Get the source of the login attempt.
 *
 * @return string Source key: xmlrpc, rest, or wp-login.
 */
function wldelay_get_login_source() {
    if ( wldelay_is_xmlrpc_request() ) {
        return 'xmlrpc';
    }

    if ( wldelay_is_rest_request() ) {
        return 'rest';
    }

    return 'wp-login';
}

/**
 * Get display label for a login source value.
 *
 * @param string $source Source key.
 * @return string Human-readable label.
 */
function wldelay_get_login_source_label( $source ) {
    switch ( $source ) {
        case 'xmlrpc':
            return 'XML-RPC';
        case 'rest':
            return __( 'REST API', 'login-delay-shield' );
        case 'application-password':
            return __( 'Application Password', 'login-delay-shield' );
        case 'wp-login':
        default:
            return __( 'Login', 'login-delay-shield' );
    }
}

/**
 * Check if an IP address is within a CIDR range
 *
 * @param string $ip The IP address to check
 * @param string $range The CIDR range (e.g., 192.168.1.0/24)
 * @return bool True if IP is in range
 */
function wldelay_ip_in_range( $ip, $range ) {
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

/**
 * Check if the client IP is whitelisted
 *
 * @param string|null $ip Optional IP to check. Defaults to client IP.
 * @return bool True if IP is whitelisted
 */
function wldelay_is_ip_whitelisted( $ip = null ) {
    $options = wldelay_get_options();

    // Whitelist must be enabled
    if ( empty( $options['wldelay_whitelist_enabled'] ) ) {
        return false;
    }

    // Get whitelist IPs
    $whitelist = isset( $options['wldelay_whitelist_ips'] ) ? $options['wldelay_whitelist_ips'] : '';
    if ( empty( $whitelist ) ) {
        return false;
    }

    // Get client IP if not provided
    if ( $ip === null ) {
        $ip = wldelay_get_client_ip();
    }
    if ( empty( $ip ) ) {
        return false;
    }

    // Check against each whitelisted IP/range
    $whitelist_lines = explode( "\n", $whitelist );
    foreach ( $whitelist_lines as $range ) {
        $range = trim( $range );
        if ( empty( $range ) ) {
            continue;
        }
        if ( wldelay_ip_in_range( $ip, $range ) ) {
            return true;
        }
    }

    return false;
}

/**
 * Check if the current IP/username is locked.
 *
 * @param string|null $ip Optional IP. Defaults to current client IP.
 * @param string $username Optional username for IP+username strategy.
 * @return bool True if locked.
 */
function wldelay_is_ip_locked( $ip = null, $username = '' ) {
    if ( $ip === null ) {
        $ip = wldelay_get_client_ip();
    }

    if ( empty( $ip ) ) {
        return false;
    }

    $transient_key = wldelay_get_lockout_transient_key( $ip, $username );

    return get_transient( $transient_key ) !== false;
}

/**
 * Get the current failure count for an IP address
 *
 * @param string|null $ip Optional IP to check. Defaults to client IP.
 * @param string $username Optional username for IP+username strategy.
 * @return int Number of failed attempts
 */
function wldelay_get_failure_count( $ip = null, $username = '' ) {
    if ( $ip === null ) {
        $ip = wldelay_get_client_ip();
    }
    if ( empty( $ip ) ) {
        return 0;
    }

    $transient_key = wldelay_get_failure_transient_key( $ip, $username );
    $failed_attempts = get_transient( $transient_key );

    return ( false === $failed_attempts ) ? 0 : (int) $failed_attempts;
}

/**
 * Lock a specific IP/username combination based on configured strategy.
 *
 * @param string $ip IP address.
 * @param string $username Optional username for IP+username strategy.
 */
function wldelay_lock_ip( $ip, $username = '' ) {
    $options = wldelay_get_options();
    $lockout_duration = wldelay_get_lockout_duration_seconds( $options );
    $transient_key = wldelay_get_lockout_transient_key( $ip, $username, $options );
    set_transient( $transient_key, time(), $lockout_duration );
    wldelay_register_transient_key( $transient_key );
}

/**
 * Log a failed login attempt to the database
 *
 * @param string $ip IP address
 * @param string $username Username attempted
 * @param string $source Optional source of the attempt (wp-login, xmlrpc)
 */
function wldelay_log_failed_attempt( $ip, $username, $source = null ) {
    global $wpdb;

    if ( $source === null ) {
        $source = wldelay_get_login_source();
    }

    $table_name = wldelay_get_log_table_name();

    $wpdb->insert(
        $table_name,
        array(
            'ip_address'   => $ip,
            'username'     => $username,
            'attempted_at' => current_time( 'mysql' ),
            'source'       => $source,
        ),
        array( '%s', '%s', '%s', '%s' )
    );

    // Invalidate dashboard widget cache so new attempts appear immediately
    delete_transient( 'wldelay_dashboard_attempts' );
}

/**
 * Get recent failed login attempts
 *
 * @param int $limit Number of attempts to retrieve
 * @return array Array of failed attempt records
 */
function wldelay_get_recent_failed_attempts( $limit = 20 ) {
    global $wpdb;

    $table_name = wldelay_get_log_table_name();

    return $wpdb->get_results(
        $wpdb->prepare(
            "SELECT * FROM $table_name ORDER BY attempted_at DESC LIMIT %d",
            $limit
        )
    );
}

/**
 * Handle wp_login_failed action - logs all failed attempts
 *
 * @param string $username Username attempted
 */
function wldelay_on_login_failed( $username ) {
    // Skip if IP is whitelisted
    if ( wldelay_is_ip_whitelisted() ) {
        return;
    }

    $ip = wldelay_get_client_ip();
    if ( empty( $ip ) ) {
        return;
    }

    // Log to database with source
    wldelay_log_failed_attempt( $ip, $username );
}
add_action( 'wp_login_failed', 'wldelay_on_login_failed' );

/**
 * Block XMLRPC authentication if configured
 * This runs AFTER WordPress authentication (priority 99) to intercept successful logins
 *
 * @param null|WP_User|WP_Error $user
 * @param string $username
 * @param string $password
 * @return null|WP_User|WP_Error
 */
function wldelay_block_xmlrpc_auth( $user, $username, $password ) {
    // Only apply to XMLRPC requests
    if ( ! wldelay_is_xmlrpc_request() ) {
        return $user;
    }

    // Check if XMLRPC protection is enabled
    $options = get_option( WLDELAY_OPTION_NAME ); // Get fresh options, not cached

    // If XMLRPC protection is disabled, let the request through
    if ( empty( $options['wldelay_xmlrpc_enabled'] ) ) {
        return $user;
    }

    // Check if IP is whitelisted
    if ( wldelay_is_ip_whitelisted() ) {
        return $user;
    }

    // Check if XMLRPC auth should be completely blocked
    if ( ! empty( $options['wldelay_xmlrpc_block'] ) ) {
        // Log the blocked attempt (only if this is a real auth attempt with username)
        if ( ! empty( $username ) ) {
            $ip = wldelay_get_client_ip();
            if ( ! empty( $ip ) ) {
                wldelay_log_failed_attempt( $ip, $username, 'xmlrpc' );
            }
        }

        return new WP_Error(
            'wldelay_xmlrpc_blocked',
            __( 'XML-RPC authentication is disabled on this site.', 'login-delay-shield' )
        );
    }

    // Check if IP is locked out
    if ( ! empty( $options['wldelay_lockout_enabled'] ) && wldelay_is_ip_locked( null, $username ) ) {
        return new WP_Error(
            'wldelay_ip_locked',
            wldelay_get_lockout_error_message( null, $username )
        );
    }

    return $user;
}
// Run late (priority 99) to intercept after WordPress authentication
add_filter( 'authenticate', 'wldelay_block_xmlrpc_auth', 99, 3 );

/**
 * Handle REST authentication failures and lockout checks.
 *
 * @param null|WP_Error|WP_User $errors Existing REST auth result.
 * @return null|WP_Error|WP_User
 */
function wldelay_handle_rest_authentication( $errors ) {
    $options = wldelay_get_options();
    if ( empty( $options['wldelay_rest_enabled'] ) ) {
        return $errors;
    }

    if ( ! wldelay_is_rest_request() ) {
        return $errors;
    }

    if ( wldelay_is_ip_whitelisted() ) {
        return $errors;
    }

    // Let application-password protection own those attempts only when WordPress can actually process them.
    $app_passwords_available = function_exists( 'wp_is_application_passwords_available' )
        ? wp_is_application_passwords_available()
        : true;

    if ( ! empty( $options['wldelay_application_password_enabled'] ) && $app_passwords_available && wldelay_is_application_password_attempt() ) {
        return $errors;
    }

    $username = wldelay_get_php_auth_username();
    $ip       = wldelay_get_client_ip();

    if ( ! empty( $options['wldelay_lockout_enabled'] ) && wldelay_is_ip_locked( null, $username ) ) {
        return new WP_Error(
            'wldelay_ip_locked',
            wldelay_get_lockout_error_message( null, $username ),
            array( 'status' => 403 )
        );
    }

    if ( ! is_wp_error( $errors ) || empty( $ip ) ) {
        return $errors;
    }

    $failure_count = wldelay_get_failure_count( null, $username );
    $delay         = wldelay_get_delay_value( $failure_count );
    if ( empty( $delay ) ) {
        $delay = LDS_Settings::_DEFAULT_DELAY_IN_SECONDS;
    }

    $failed_attempts = wldelay_track_failed_attempt( $username );
    wldelay_log_failed_attempt( $ip, $username, 'rest' );
    sleep( $delay );

    if ( ! empty( $options['wldelay_lockout_enabled'] ) && $failed_attempts > 0 && wldelay_is_ip_locked( null, $username ) ) {
        return new WP_Error(
            'wldelay_ip_locked',
            wldelay_get_lockout_error_message( null, $username ),
            array( 'status' => 403 )
        );
    }

    return $errors;
}
add_filter( 'rest_authentication_errors', 'wldelay_handle_rest_authentication', 20 );

/**
 * Handle application-password authentication failures and lockout checks.
 *
 * @param null|WP_User|WP_Error $user Existing auth result.
 * @param string $username Username.
 * @param string $password Password.
 * @return null|WP_User|WP_Error
 */
function wldelay_handle_application_password_auth( $user, $username, $password ) {
    $options = wldelay_get_options();
    if ( empty( $options['wldelay_application_password_enabled'] ) ) {
        return $user;
    }

    if ( ! wldelay_is_application_password_attempt() ) {
        return $user;
    }

    if ( wldelay_is_ip_whitelisted() ) {
        return $user;
    }

    $username = wldelay_normalize_username( $username );
    if ( empty( $username ) ) {
        $username = wldelay_get_php_auth_username();
    }

    $ip = wldelay_get_client_ip();
    if ( empty( $ip ) ) {
        return $user;
    }

    if ( ! empty( $options['wldelay_lockout_enabled'] ) && wldelay_is_ip_locked( null, $username ) ) {
        return new WP_Error(
            'wldelay_ip_locked',
            wldelay_get_lockout_error_message( null, $username )
        );
    }

    if ( ! is_wp_error( $user ) ) {
        return $user;
    }

    $failure_count = wldelay_get_failure_count( null, $username );
    $delay         = wldelay_get_delay_value( $failure_count );
    if ( empty( $delay ) ) {
        $delay = LDS_Settings::_DEFAULT_DELAY_IN_SECONDS;
    }

    $failed_attempts = wldelay_track_failed_attempt( $username );
    wldelay_log_failed_attempt( $ip, $username, 'application-password' );
    sleep( $delay );

    if ( ! empty( $options['wldelay_lockout_enabled'] ) && $failed_attempts > 0 && wldelay_is_ip_locked( null, $username ) ) {
        return new WP_Error(
            'wldelay_ip_locked',
            wldelay_get_lockout_error_message( null, $username )
        );
    }

    return $user;
}
add_filter( 'authenticate', 'wldelay_handle_application_password_auth', 25, 3 );

/**
 * Track a failed login attempt for counters, notifications, and lockout.
 *
 * @param string $username Username attempted.
 * @return int Updated failure count for the current tracking key. 0 if tracking is skipped.
 */
function wldelay_track_failed_attempt( $username ) {
    $ip = wldelay_get_client_ip();
    if ( empty( $ip ) ) {
        return 0;
    }

    $username = wldelay_normalize_username( $username );
    $options = wldelay_get_options();
    $email_enabled = ! empty( $options['wldelay_email_enabled'] );
    $lockout_enabled = ! empty( $options['wldelay_lockout_enabled'] );
    $progressive_enabled = ! empty( $options['wldelay_progressive_enabled'] );

    // Skip tracking if no feature needs failure counters.
    if ( ! $email_enabled && ! $lockout_enabled && ! $progressive_enabled ) {
        return 0;
    }

    $transient_key = wldelay_get_failure_transient_key( $ip, $username, $options );
    $failed_attempts = get_transient( $transient_key );

    if ( false === $failed_attempts ) {
        $failed_attempts = 0;
    }

    $failed_attempts++;
    set_transient( $transient_key, $failed_attempts, HOUR_IN_SECONDS );
    wldelay_register_transient_key( $transient_key );

    // Check email notification threshold
    if ( $email_enabled ) {
        $email_threshold = isset( $options['wldelay_email_threshold'] ) ? (int) $options['wldelay_email_threshold'] : LDS_Settings::_DEFAULT_EMAIL_THRESHOLD;

        if ( $failed_attempts === $email_threshold ) {
            wldelay_send_notification_email( $ip, $username, $failed_attempts );
        }
    }

    // Check lockout threshold
    if ( $lockout_enabled ) {
        $lockout_threshold = isset( $options['wldelay_lockout_threshold'] )
            ? (int) $options['wldelay_lockout_threshold']
            : LDS_Settings::_DEFAULT_LOCKOUT_THRESHOLD;

        if ( $failed_attempts >= $lockout_threshold ) {
            wldelay_lock_ip( $ip, $username );
        }
    }

    return $failed_attempts;
}

function wldelay_send_notification_email( $ip, $username, $attempts ) {
    $options = wldelay_get_options();

    // Check site-wide email cooldown
    $cooldown_minutes = isset( $options['wldelay_email_cooldown'] )
        ? (int) $options['wldelay_email_cooldown']
        : LDS_Settings::_DEFAULT_EMAIL_COOLDOWN;

    if ( $cooldown_minutes > 0 ) {
        $cooldown_key = 'wldelay_email_cooldown';
        $last_sent = get_transient( $cooldown_key );

        if ( false !== $last_sent ) {
            // Still in cooldown period, skip sending
            return;
        }

        // Set cooldown transient
        set_transient( $cooldown_key, time(), $cooldown_minutes * MINUTE_IN_SECONDS );
    }

    $to = ! empty( $options['wldelay_email_address'] ) ? $options['wldelay_email_address'] : get_option( 'admin_email' );
    $site_name = get_bloginfo( 'name' );
    $subject = sprintf( '[%s] Failed login attempts alert', $site_name );

    $message = sprintf(
        "Multiple failed login attempts detected on %s.\n\n" .
        "IP Address: %s\n" .
        "Username attempted: %s\n" .
        "Failed attempts: %d\n" .
        "Time: %s\n\n" .
        "This is an automated alert from Login Delay Shield.",
        $site_name,
        $ip,
        $username,
        $attempts,
        current_time( 'mysql' )
    );

    wp_mail( $to, $subject, $message );
}

function wldelay_auth_login ($user, $password) {
    // Check if IP is whitelisted - bypass all security measures
    if ( wldelay_is_ip_whitelisted() ) {
        return $user;
    }

    $username = wldelay_get_requested_login_username();

    // Check lockout first (before any processing)
    $options = wldelay_get_options();
    if ( ! empty( $options['wldelay_lockout_enabled'] ) && wldelay_is_ip_locked( null, $username ) ) {
        return new WP_Error(
            'wldelay_ip_locked',
            wldelay_get_lockout_error_message( null, $username )
        );
    }

    if( is_wp_error( $user ) ) {
        // Get current failure count BEFORE incrementing (for progressive delay)
        $failure_count = wldelay_get_failure_count( null, $username );

        // Calculate delay with progressive increase if enabled
        $delay = wldelay_get_delay_value( $failure_count );

        if( empty( $delay ) ) {
            $delay = LDS_Settings::_DEFAULT_DELAY_IN_SECONDS;
        }

        // Track failed attempt for email notifications and lockout
        $failed_attempts = wldelay_track_failed_attempt( $username );

        sleep( $delay );

        if ( ! empty( $options['wldelay_lockout_enabled'] ) && $failed_attempts > 0 ) {
            $lockout_threshold = isset( $options['wldelay_lockout_threshold'] )
                ? (int) $options['wldelay_lockout_threshold']
                : LDS_Settings::_DEFAULT_LOCKOUT_THRESHOLD;
            $remaining_attempts = $lockout_threshold - $failed_attempts;

            if ( $remaining_attempts > 0 ) {
                $user->add(
                    'wldelay_attempts_remaining',
                    sprintf(
                        /* translators: %d: number of failed login attempts remaining before lockout */
                        _n(
                            'Login failed. %d attempt remaining before temporary lockout.',
                            'Login failed. %d attempts remaining before temporary lockout.',
                            $remaining_attempts,
                            'login-delay-shield'
                        ),
                        $remaining_attempts
                    )
                );
            } elseif ( wldelay_is_ip_locked( null, $username ) ) {
                return new WP_Error(
                    'wldelay_ip_locked',
                    wldelay_get_lockout_error_message( null, $username )
                );
            }
        }
    }

    return $user;
}
add_filter('wp_authenticate_user', 'wldelay_auth_login',1, 2);
