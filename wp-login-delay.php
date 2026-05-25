<?php
if ( ! defined( 'ABSPATH' ) ) exit;

define( 'WLDELAY_VERSION', '2.2.4' );
define( 'WLDELAY_PLUGIN_FILE', __FILE__ );
define( 'WLDELAY_OPTION_NAME', 'wldelay_options' );

/*
Plugin Name: Login Delay Shield
Plugin URI: https://damoiseau.me
Description: Protects against brute-force attacks with login delays, progressive throttling, IP lockout, whitelist, XML-RPC protection, custom login URL, and email alerts.
Version: 2.2.4
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
 * Enqueue admin assets.
 *
 * Loads JavaScript across admin pages for dismissible notices and settings-page
 * interactions, while limiting styles to the dashboard and plugin settings page.
 *
 * @param string $hook Current admin page hook.
 */
function wldelay_enqueue_admin_assets( $hook ) {
    wp_enqueue_script(
        'wldelay-admin-script',
        plugin_dir_url( WLDELAY_PLUGIN_FILE ) . 'admin.js',
        array( 'jquery' ),
        WLDELAY_VERSION,
        true
    );

    $health = wldelay_get_security_score();
    $score_weights = array();
    foreach ( $health['features'] as $key => $feat ) {
        $score_weights[ $key ] = array(
            'points' => $feat['points'],
            'label'  => $feat['label'],
        );
    }

    wp_localize_script(
        'wldelay-admin-script',
        'wldelayAdmin',
        array(
            'ajaxUrl'            => admin_url( 'admin-ajax.php' ),
            'dismissNoticeNonce' => wp_create_nonce( 'wldelay_dismiss_notice' ),
            'badgeEnabled'       => __( 'Enabled', 'login-delay-shield' ),
            'badgeDisabled'      => __( 'Disabled', 'login-delay-shield' ),
            'scoreWeights'       => $score_weights,
            /* translators: 1: feature name (HTML), 2: points value */
            'recommendTpl'       => __( 'Next recommended: enable %1$s (+%2$d points)', 'login-delay-shield' ),
        )
    );

    // Only load styles on dashboard and our settings page.
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
add_action( 'admin_enqueue_scripts', 'wldelay_enqueue_admin_assets' );

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
 * Convert sanitized login-log filters to public query arguments.
 *
 * @param array $filters Raw or sanitized filter values.
 * @return array Query arguments using wldelay_log_* keys.
 */
function wldelay_login_log_filters_to_query_args( $filters = array() ) {
    $filters = wldelay_sanitize_login_log_filters( $filters );

    $query_args = array();
    $key_map    = array(
        'source'   => 'wldelay_log_source',
        'ip'       => 'wldelay_log_ip',
        'username' => 'wldelay_log_username',
        'from'     => 'wldelay_log_from',
        'to'       => 'wldelay_log_to',
    );

    foreach ( $key_map as $short_key => $query_key ) {
        if ( $filters[ $short_key ] !== '' ) {
            $query_args[ $query_key ] = $filters[ $short_key ];
        }
    }

    return $query_args;
}

/**
 * Build the export-login-log admin action URL.
 *
 * @return string URL to admin-post endpoint with nonce.
 */
function wldelay_get_export_login_log_url( $filters = array() ) {
    $query_args = array_merge(
        array( 'action' => 'wldelay_export_login_log' ),
        wldelay_login_log_filters_to_query_args( $filters )
    );

    $url = add_query_arg( $query_args, admin_url( 'admin-post.php' ) );

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
            $username = wldelay_normalize_username( $current_user->user_login );
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

    if ( defined( 'WP_TESTS_DOMAIN' ) ) {
        return;
    }
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
 * Validate a Y-m-d date string.
 *
 * @param string $value Date string to validate.
 * @return bool True if the value is a valid Y-m-d date.
 */
function wldelay_is_valid_date( $value ) {
    if ( $value === '' || ! preg_match( '/^\\d{4}-\\d{2}-\\d{2}$/', $value ) ) {
        return false;
    }
    $dt = DateTimeImmutable::createFromFormat( 'Y-m-d', $value );
    if ( ! $dt ) {
        return false;
    }
    return $dt->format( 'Y-m-d' ) === $value;
}

/**
 * Sanitize login-log filter input (admin UI + CSV export).
 *
 * Accepts either raw request keys (wldelay_log_*) or short keys (source, ip, etc.).
 *
 * @param array $input Raw filter input from $_GET or short-key array.
 * @return array{source:string,ip:string,username:string,from:string,to:string}
 */
function wldelay_sanitize_login_log_filters( $input ) {
    if ( ! is_array( $input ) ) {
        $input = array();
    }

    $key_map = array(
        'source'   => 'wldelay_log_source',
        'ip'       => 'wldelay_log_ip',
        'username' => 'wldelay_log_username',
        'from'     => 'wldelay_log_from',
        'to'       => 'wldelay_log_to',
    );

    $raw = array();
    foreach ( $key_map as $short => $long ) {
        if ( isset( $input[ $long ] ) ) {
            $raw[ $short ] = $input[ $long ];
        } elseif ( isset( $input[ $short ] ) ) {
            $raw[ $short ] = $input[ $short ];
        } else {
            $raw[ $short ] = '';
        }
    }

    $source = strtolower( trim( sanitize_text_field( (string) $raw['source'] ) ) );
    if ( $source !== '' && ! preg_match( '/^[a-z0-9-]{1,20}$/', $source ) ) {
        $source = '';
    }

    $ip = trim( sanitize_text_field( (string) $raw['ip'] ) );
    if ( $ip !== '' && ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
        $ip = '';
    }

    $username = trim( sanitize_text_field( (string) $raw['username'] ) );
    if ( strlen( $username ) > 60 ) {
        $username = substr( $username, 0, 60 );
    }

    $from = trim( sanitize_text_field( (string) $raw['from'] ) );
    $to   = trim( sanitize_text_field( (string) $raw['to'] ) );

    if ( ! wldelay_is_valid_date( $from ) ) {
        $from = '';
    }
    if ( ! wldelay_is_valid_date( $to ) ) {
        $to = '';
    }

    if ( $from !== '' && $to !== '' && $from > $to ) {
        $tmp  = $from;
        $from = $to;
        $to   = $tmp;
    }

    return array(
        'source'   => $source,
        'ip'       => $ip,
        'username' => $username,
        'from'     => $from,
        'to'       => $to,
    );
}

/**
 * Get sanitized login-log filters from the current request.
 *
 * Only reads expected wldelay_log_* keys from $_GET to avoid collisions
 * with unrelated query parameters.
 *
 * @return array{source:string,ip:string,username:string,from:string,to:string}
 */
function wldelay_get_login_log_filters_from_request() {
    $expected_keys = array(
        'wldelay_log_source',
        'wldelay_log_ip',
        'wldelay_log_username',
        'wldelay_log_from',
        'wldelay_log_to',
    );

    return wldelay_sanitize_login_log_filters(
        wp_unslash( array_intersect_key( $_GET, array_flip( $expected_keys ) ) )
    );
}

/**
 * Query failed login attempts with optional filters.
 *
 * Filters are always sanitized internally — callers may pass raw request data.
 *
 * @param array $args {
 *     @type array  $filters Raw or sanitized filter values (sanitized internally).
 *     @type int    $limit   Maximum rows to return. Default 20.
 *     @type int    $offset  Offset for pagination. Default 0.
 *     @type string $fields  SQL fields to select (must match allowlist).
 * }
 * @return array Array of result objects.
 */
function wldelay_get_login_log_attempts( $args = array() ) {
    global $wpdb;

    $args = wp_parse_args(
        $args,
        array(
            'filters' => array(),
            'limit'   => 20,
            'offset'  => 0,
            'fields'  => '*',
        )
    );

    $filters = wldelay_sanitize_login_log_filters( $args['filters'] );

    $allowed_fields = array(
        '*',
        'source, ip_address, username, attempted_at',
    );
    $fields = in_array( $args['fields'], $allowed_fields, true ) ? $args['fields'] : '*';

    $table_name   = wldelay_get_log_table_name();
    $where_parts  = wldelay_build_login_log_where_clause( $filters );
    $where_clause = $where_parts['where'];
    $params       = $where_parts['params'];

    // $fields and $table_name are safe to interpolate: $fields is validated against
    // a strict allowlist above, and $table_name is derived from $wpdb->prefix (not
    // user input). $wpdb->prepare() cannot parameterize SQL identifiers.
    $sql = "SELECT $fields FROM $table_name{$where_clause} ORDER BY attempted_at DESC";

    $limit = absint( $args['limit'] );
    if ( $limit < 1 ) {
        $limit = 1;
    }
    $sql     .= ' LIMIT %d';
    $params[] = $limit;

    $offset = absint( $args['offset'] );
    if ( $offset > 0 ) {
        $sql     .= ' OFFSET %d';
        $params[] = $offset;
    }

    return $wpdb->get_results( $wpdb->prepare( $sql, $params ) );
}


/**
 * Build a reusable WHERE clause for login-log filters.
 *
 * @param array $filters Raw or sanitized filter values.
 * @return array{where:string,params:array}
 */
function wldelay_build_login_log_where_clause( $filters ) {
    global $wpdb;

    $filters = wldelay_sanitize_login_log_filters( $filters );

    $where  = array();
    $params = array();

    if ( $filters['source'] !== '' ) {
        $where[]  = 'source = %s';
        $params[] = $filters['source'];
    }

    if ( $filters['ip'] !== '' ) {
        $where[]  = 'ip_address = %s';
        $params[] = $filters['ip'];
    }

    if ( $filters['username'] !== '' ) {
        $where[]  = 'username LIKE %s';
        $params[] = '%' . $wpdb->esc_like( $filters['username'] ) . '%';
    }

    if ( $filters['from'] !== '' ) {
        $where[]  = 'attempted_at >= %s';
        $params[] = $filters['from'] . ' 00:00:00';
    }

    if ( $filters['to'] !== '' ) {
        $where[]  = 'attempted_at <= %s';
        $params[] = $filters['to'] . ' 23:59:59';
    }

    return array(
        'where'  => ! empty( $where ) ? ' WHERE ' . implode( ' AND ', $where ) : '',
        'params' => $params,
    );
}

/**
 * Count failed login attempts matching optional filters.
 *
 * @param array $filters Raw or sanitized filter values.
 * @return int Matching row count.
 */
function wldelay_count_login_log_attempts( $filters = array() ) {
    global $wpdb;

    $table_name   = wldelay_get_log_table_name();
    $where_parts  = wldelay_build_login_log_where_clause( $filters );
    $where_clause = $where_parts['where'];
    $params       = $where_parts['params'];

    $sql = "SELECT COUNT(*) FROM $table_name{$where_clause}";

    if ( empty( $params ) ) {
        return (int) $wpdb->get_var( $sql );
    }

    return (int) $wpdb->get_var( $wpdb->prepare( $sql, $params ) );
}

/**
 * Compute a lightweight snapshot hash for telemetry pagination.
 *
 * @param int   $total   Total matching rows.
 * @param array $filters Active filters.
 * @return string 8-char hex hash.
 */
function wldelay_get_telemetry_snapshot_hash( $total, $filters = array() ) {
    global $wpdb;

    $filters      = wldelay_sanitize_login_log_filters( $filters );
    $table_name   = wldelay_get_log_table_name();
    $where_parts  = wldelay_build_login_log_where_clause( $filters );
    $where_clause = $where_parts['where'];
    $params       = $where_parts['params'];

    $sql    = "SELECT MAX(id) FROM $table_name{$where_clause}";
    $max_id = empty( $params )
        ? (int) $wpdb->get_var( $sql )
        : (int) $wpdb->get_var( $wpdb->prepare( $sql, $params ) );

    $payload = $total . '|' . $max_id . '|' . implode( '|', $filters );
    return substr( md5( $payload ), 0, 8 );
}

/**
 * Get filtered telemetry summary data for the login log admin view.
 *
 * @param array $filters Raw or sanitized filter values.
 * @param int   $limit   Maximum grouped rows for source/IP lists.
 * @return array{total_attempts:int,daily_counts:array<array{date:string,count:int}>,source_counts:array<array{source:string,count:int}>,top_ips:array<array{ip_address:string,count:int}>,top_usernames:array<array{username:string,count:int}>}
 */
function wldelay_get_login_log_summary( $filters = array(), $limit = 5 ) {
    global $wpdb;

    $limit        = max( 1, absint( $limit ) );
    $table_name   = wldelay_get_log_table_name();
    $where_parts  = wldelay_build_login_log_where_clause( $filters );
    $where_clause = $where_parts['where'];
    $params       = $where_parts['params'];

    $run_query = function ( $sql, $extra_params = array() ) use ( $wpdb, $params ) {
        $all_params = array_merge( $params, $extra_params );
        if ( empty( $all_params ) ) {
            return $wpdb->get_results( $sql );
        }

        return $wpdb->get_results( $wpdb->prepare( $sql, $all_params ) );
    };

    $daily_rows = $run_query(
        "SELECT DATE(attempted_at) AS attempted_date, COUNT(*) AS failures
        FROM $table_name{$where_clause}
        GROUP BY DATE(attempted_at)
        ORDER BY attempted_date DESC
        LIMIT %d",
        array( 31 )
    );

    $daily_rows = array_reverse( $daily_rows );

    $daily_counts = array();
    foreach ( $daily_rows as $row ) {
        $daily_counts[] = array(
            'date'  => (string) $row->attempted_date,
            'count' => (int) $row->failures,
        );
    }

    $source_rows = $run_query(
        "SELECT source, COUNT(*) AS failures
        FROM $table_name{$where_clause}
        GROUP BY source
        ORDER BY failures DESC, source ASC
        LIMIT %d",
        array( $limit )
    );

    $source_counts = array();
    foreach ( $source_rows as $row ) {
        $source_counts[] = array(
            'source' => (string) $row->source,
            'count'  => (int) $row->failures,
        );
    }

    $ip_rows = $run_query(
        "SELECT ip_address, COUNT(*) AS failures
        FROM $table_name{$where_clause}
        GROUP BY ip_address
        ORDER BY failures DESC, ip_address ASC
        LIMIT %d",
        array( $limit )
    );

    $top_ips = array();
    foreach ( $ip_rows as $row ) {
        $top_ips[] = array(
            'ip_address' => (string) $row->ip_address,
            'count'      => (int) $row->failures,
        );
    }

    // Exclude NULL and blank/whitespace-only usernames from ranking — these are
    // noise from bots that submit empty credentials.  Other aggregations (IPs,
    // sources) keep all rows because those columns are always meaningful.
    $username_where_clause = $where_clause === ''
        ? ' WHERE username IS NOT NULL AND TRIM(username) <> %s'
        : $where_clause . ' AND username IS NOT NULL AND TRIM(username) <> %s';

    $username_rows = $run_query(
        "SELECT username, COUNT(*) AS failures
        FROM $table_name{$username_where_clause}
        GROUP BY username
        ORDER BY failures DESC, username ASC
        LIMIT %d",
        array( '', $limit )
    );

    $top_usernames = array();
    foreach ( $username_rows as $row ) {
        $top_usernames[] = array(
            'username' => (string) $row->username,
            'count'    => (int) $row->failures,
        );
    }

    return array(
        'total_attempts' => wldelay_count_login_log_attempts( $filters ),
        'daily_counts'   => $daily_counts,
        'source_counts'  => $source_counts,
        'top_ips'        => $top_ips,
        'top_usernames'  => $top_usernames,
    );
}

/**
 * Handle admin action to export login log as CSV.
 *
 * Streams results in batches to avoid loading the entire log table into memory.
 */
function wldelay_handle_export_login_log() {
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_die( esc_html__( 'You are not allowed to perform this action.', 'login-delay-shield' ) );
    }

    check_admin_referer( 'wldelay_export_login_log' );

    $batch_size = 1000;

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

        $offset = 0;

        do {
            $attempts = wldelay_get_login_log_attempts(
                array(
                    'filters' => wldelay_get_login_log_filters_from_request(),
                    'limit'   => $batch_size,
                    'offset'  => $offset,
                    'fields'  => 'source, ip_address, username, attempted_at',
                )
            );

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

            $offset += $batch_size;
        } while ( count( $attempts ) === $batch_size );

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
    $dashboard_data = get_transient( $cache_key );

    if (
        false === $dashboard_data ||
        ! is_array( $dashboard_data ) ||
        ! isset( $dashboard_data['attempts'] ) ||
        ! isset( $dashboard_data['trends'] )
    ) {
        $dashboard_data = array(
            'attempts' => wldelay_get_recent_failed_attempts( 10 ),
            'trends'   => wldelay_get_failed_login_trends( 7 ),
        );
        set_transient( $cache_key, $dashboard_data, 2 * MINUTE_IN_SECONDS );
    }

    $attempts = $dashboard_data['attempts'];
    $trends   = $dashboard_data['trends'];

    if ( empty( $attempts ) ) {
        echo '<p>' . esc_html__( 'No failed login attempts recorded.', 'login-delay-shield' ) . '</p>';
        return;
    }

    wldelay_render_dashboard_trends( $trends );

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
 * Get lightweight failed-login trends for the dashboard widget.
 *
 * Queries are scoped to a recent date window and keep grouped results small.
 *
 * @param int $days Number of days to include.
 * @return array{
 *     window_days:int,
 *     total_attempts:int,
 *     peak_day:array{date:string,count:int},
 *     daily_counts:array<int,array{date:string,count:int}>,
 *     source_counts:array<int,array{source:string,count:int}>,
 *     top_ips:array<int,array{ip_address:string,count:int}>
 * }
 */
function wldelay_get_failed_login_trends( $days = 7 ) {
    global $wpdb;

    $days = absint( $days );
    if ( $days < 1 ) {
        $days = 1;
    }

    $table_name = wldelay_get_log_table_name();
    $cutoff     = gmdate( 'Y-m-d H:i:s', current_time( 'timestamp' ) - ( $days * DAY_IN_SECONDS ) );

    $daily_rows = $wpdb->get_results(
        $wpdb->prepare(
            "SELECT DATE(attempted_at) AS attempted_date, COUNT(*) AS failures
            FROM $table_name
            WHERE attempted_at >= %s
            GROUP BY DATE(attempted_at)
            ORDER BY attempted_date ASC",
            $cutoff
        )
    );

    $counts_by_date = array();
    foreach ( $daily_rows as $row ) {
        $counts_by_date[ $row->attempted_date ] = (int) $row->failures;
    }

    $daily_counts    = array();
    $total_attempts  = 0;
    $peak_day        = array(
        'date'  => '',
        'count' => 0,
    );
    $current_time_ts = current_time( 'timestamp' );

    for ( $offset = $days - 1; $offset >= 0; $offset-- ) {
        $date_key = gmdate( 'Y-m-d', $current_time_ts - ( $offset * DAY_IN_SECONDS ) );
        $count    = isset( $counts_by_date[ $date_key ] ) ? (int) $counts_by_date[ $date_key ] : 0;

        $daily_counts[] = array(
            'date'  => $date_key,
            'count' => $count,
        );

        $total_attempts += $count;

        if ( $count >= $peak_day['count'] ) {
            $peak_day = array(
                'date'  => $date_key,
                'count' => $count,
            );
        }
    }

    $source_rows = $wpdb->get_results(
        $wpdb->prepare(
            "SELECT source, COUNT(*) AS failures
            FROM $table_name
            WHERE attempted_at >= %s
            GROUP BY source
            ORDER BY failures DESC, source ASC
            LIMIT 3",
            $cutoff
        )
    );

    $source_counts = array();
    foreach ( $source_rows as $row ) {
        $source_counts[] = array(
            'source' => (string) $row->source,
            'count'  => (int) $row->failures,
        );
    }

    $ip_rows = $wpdb->get_results(
        $wpdb->prepare(
            "SELECT ip_address, COUNT(*) AS failures
            FROM $table_name
            WHERE attempted_at >= %s
            GROUP BY ip_address
            ORDER BY failures DESC, ip_address ASC
            LIMIT 3",
            $cutoff
        )
    );

    $top_ips = array();
    foreach ( $ip_rows as $row ) {
        $top_ips[] = array(
            'ip_address' => (string) $row->ip_address,
            'count'      => (int) $row->failures,
        );
    }

    return array(
        'window_days'    => $days,
        'total_attempts' => $total_attempts,
        'peak_day'       => $peak_day,
        'daily_counts'   => $daily_counts,
        'source_counts'  => $source_counts,
        'top_ips'        => $top_ips,
    );
}

/**
 * Render the dashboard trends panel.
 *
 * @param array $trends Trend data from wldelay_get_failed_login_trends().
 */
function wldelay_render_dashboard_trends( $trends ) {
    $window_days = isset( $trends['window_days'] ) ? (int) $trends['window_days'] : 7;
    $total       = isset( $trends['total_attempts'] ) ? (int) $trends['total_attempts'] : 0;
    $peak_day    = isset( $trends['peak_day'] ) && is_array( $trends['peak_day'] ) ? $trends['peak_day'] : array();
    $daily_counts = isset( $trends['daily_counts'] ) && is_array( $trends['daily_counts'] ) ? $trends['daily_counts'] : array();
    $source_counts = isset( $trends['source_counts'] ) && is_array( $trends['source_counts'] ) ? $trends['source_counts'] : array();
    $top_ips = isset( $trends['top_ips'] ) && is_array( $trends['top_ips'] ) ? $trends['top_ips'] : array();

    echo '<div class="wldelay-widget-trends" aria-labelledby="wldelay-widget-trends-title">';
    echo '<h3 id="wldelay-widget-trends-title" class="wldelay-widget-trends-title">';
    printf(
        /* translators: %d: number of days in the dashboard trends window */
        esc_html__( 'Failed login trends: last %d days', 'login-delay-shield' ),
        esc_html( $window_days )
    );
    echo '</h3>';

    echo '<p class="wldelay-widget-trends-summary">';
    printf(
        /* translators: %s: number of failed login attempts */
        esc_html__( '%s failed attempts recorded in the selected window.', 'login-delay-shield' ),
        '<strong>' . esc_html( number_format_i18n( $total ) ) . '</strong>'
    );

    if ( ! empty( $peak_day['date'] ) && ! empty( $peak_day['count'] ) ) {
        $peak_label = date_i18n(
            _x( 'M j', 'date format for failed login trend labels', 'login-delay-shield' ),
            strtotime( $peak_day['date'] . ' 00:00:00' )
        );

        echo ' ';
        printf(
            /* translators: 1: date label, 2: number of failed attempts */
            esc_html__( 'Busiest day: %1$s (%2$s).', 'login-delay-shield' ),
            esc_html( $peak_label ),
            esc_html( number_format_i18n( (int) $peak_day['count'] ) )
        );
    }
    echo '</p>';

    echo '<div class="wldelay-widget-trends-grid">';

    echo '<section class="wldelay-trend-card" aria-labelledby="wldelay-trend-daily-title">';
    echo '<h4 id="wldelay-trend-daily-title">' . esc_html__( 'Daily activity', 'login-delay-shield' ) . '</h4>';
    echo '<ul class="wldelay-trend-list">';
    foreach ( $daily_counts as $day ) {
        $day_label = date_i18n(
            _x( 'M j', 'date format for failed login trend labels', 'login-delay-shield' ),
            strtotime( $day['date'] . ' 00:00:00' )
        );
        echo '<li><span>' . esc_html( $day_label ) . '</span><strong>' . esc_html( number_format_i18n( (int) $day['count'] ) ) . '</strong></li>';
    }
    echo '</ul>';
    echo '</section>';

    echo '<section class="wldelay-trend-card" aria-labelledby="wldelay-trend-sources-title">';
    echo '<h4 id="wldelay-trend-sources-title">' . esc_html__( 'Top sources', 'login-delay-shield' ) . '</h4>';
    echo '<ul class="wldelay-trend-list">';
    if ( empty( $source_counts ) ) {
        echo '<li><span>' . esc_html__( 'No recent data', 'login-delay-shield' ) . '</span><strong>0</strong></li>';
    } else {
        foreach ( $source_counts as $source_count ) {
            echo '<li><span>' . esc_html( wldelay_get_login_source_label( $source_count['source'] ) ) . '</span><strong>' . esc_html( number_format_i18n( (int) $source_count['count'] ) ) . '</strong></li>';
        }
    }
    echo '</ul>';
    echo '</section>';

    echo '<section class="wldelay-trend-card" aria-labelledby="wldelay-trend-ips-title">';
    echo '<h4 id="wldelay-trend-ips-title">' . esc_html__( 'Top IPs', 'login-delay-shield' ) . '</h4>';
    echo '<ol class="wldelay-trend-list wldelay-trend-list-ordered">';
    if ( empty( $top_ips ) ) {
        echo '<li><span>' . esc_html__( 'No recent data', 'login-delay-shield' ) . '</span><strong>0</strong></li>';
    } else {
        foreach ( $top_ips as $ip_count ) {
            echo '<li><span>' . esc_html( $ip_count['ip_address'] ) . '</span><strong>' . esc_html( number_format_i18n( (int) $ip_count['count'] ) ) . '</strong></li>';
        }
    }
    echo '</ol>';
    echo '</section>';

    echo '</div>';
    echo '</div>';
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
        KEY ip_address (ip_address),
        KEY username (username),
        KEY source (source)
    ) $charset_collate;";

    require_once( ABSPATH . 'wp-admin/includes/upgrade.php' );
    dbDelta( $sql );

    update_option( 'wldelay_db_version', WLDELAY_VERSION );
}

register_activation_hook( WLDELAY_PLUGIN_FILE, 'wldelay_create_log_table' );

// ==========================================================================
// Trend Analytics Queries
// ==========================================================================

/**
 * Get the top IP addresses by failed login count within a period.
 *
 * @param int $days  Number of days to look back (defaults to 7 if <= 0).
 * @param int $limit Maximum rows to return (defaults to 10 if <= 0).
 * @return array Array of objects with ip_address and attempt_count properties.
 */
function wldelay_get_top_ips( $days = 7, $limit = 10 ) {
    global $wpdb;

    $days  = max( 1, (int) $days );
    $limit = max( 1, (int) $limit );

    $table_name = wldelay_get_log_table_name();
    $since = gmdate( 'Y-m-d H:i:s', time() - ( $days * DAY_IN_SECONDS ) );

    return $wpdb->get_results( $wpdb->prepare(
        "SELECT ip_address, COUNT(*) AS attempt_count
         FROM $table_name
         WHERE attempted_at >= %s
         GROUP BY ip_address
         ORDER BY attempt_count DESC
         LIMIT %d",
        $since,
        $limit
    ) );
}

/**
 * Get the top usernames by failed login count within a period.
 *
 * @param int $days  Number of days to look back (defaults to 7 if <= 0).
 * @param int $limit Maximum rows to return (defaults to 10 if <= 0).
 * @return array Array of objects with username and attempt_count properties.
 */
function wldelay_get_top_usernames( $days = 7, $limit = 10 ) {
    global $wpdb;

    $days  = max( 1, (int) $days );
    $limit = max( 1, (int) $limit );

    $table_name = wldelay_get_log_table_name();
    $since = gmdate( 'Y-m-d H:i:s', time() - ( $days * DAY_IN_SECONDS ) );

    return $wpdb->get_results( $wpdb->prepare(
        "SELECT username, COUNT(*) AS attempt_count
         FROM $table_name
         WHERE attempted_at >= %s
         GROUP BY username
         ORDER BY attempt_count DESC
         LIMIT %d",
        $since,
        $limit
    ) );
}

/**
 * Get daily failed login attempt counts within a period.
 *
 * @param int $days Number of days to look back (defaults to 7 if <= 0).
 * @return array Array of objects with log_date (Y-m-d) and attempt_count properties, ordered ASC.
 */
function wldelay_get_daily_attempts( $days = 7 ) {
    global $wpdb;

    $days = max( 1, (int) $days );

    $table_name = wldelay_get_log_table_name();
    $since = gmdate( 'Y-m-d H:i:s', time() - ( $days * DAY_IN_SECONDS ) );

    return $wpdb->get_results( $wpdb->prepare(
        "SELECT DATE(attempted_at) AS log_date, COUNT(*) AS attempt_count
         FROM $table_name
         WHERE attempted_at >= %s
         GROUP BY log_date
         ORDER BY log_date ASC",
        $since
    ) );
}

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

/**
 * Compute a 0–100 security health score based on enabled features.
 *
 * Each feature carries a weight reflecting its defensive value. Returns
 * the score, the list of scored features, and the top disabled feature
 * to recommend next.
 *
 * @param array|null $options Optional options array.
 * @return array{score:int,max:int,features:array,recommendation:array{key:string,label:string,points:int}|null}
 */
function wldelay_get_security_score( $options = null ) {
    if ( $options === null ) {
        $options = wldelay_get_options();
    }

    $features = array(
        'wldelay_lockout_enabled'              => array( 'label' => __( 'IP Lockout', 'login-delay-shield' ), 'points' => 20 ),
        'wldelay_progressive_enabled'          => array( 'label' => __( 'Progressive Delay', 'login-delay-shield' ), 'points' => 15 ),
        'wldelay_custom_login_enabled'         => array( 'label' => __( 'Custom Login URL', 'login-delay-shield' ), 'points' => 15 ),
        'wldelay_xmlrpc_enabled'               => array( 'label' => __( 'XML-RPC Protection', 'login-delay-shield' ), 'points' => 15 ),
        'wldelay_email_enabled'                => array( 'label' => __( 'Email Alerts', 'login-delay-shield' ), 'points' => 10 ),
        'wldelay_whitelist_enabled'            => array( 'label' => __( 'IP Whitelist', 'login-delay-shield' ), 'points' => 5 ),
        'wldelay_rest_enabled'                 => array( 'label' => __( 'REST API Protection', 'login-delay-shield' ), 'points' => 5 ),
        'wldelay_application_password_enabled' => array( 'label' => __( 'Application Password Protection', 'login-delay-shield' ), 'points' => 5 ),
        'wldelay_fail2ban_enabled'             => array( 'label' => __( 'fail2ban Logging', 'login-delay-shield' ), 'points' => 10 ),
    );

    $score          = 0;
    $max            = 0;
    $recommendation = null;
    $scored         = array();

    foreach ( $features as $key => $feature ) {
        $enabled       = ! empty( $options[ $key ] );
        $max          += $feature['points'];
        $scored[ $key ] = array(
            'label'   => $feature['label'],
            'points'  => $feature['points'],
            'enabled' => $enabled,
        );

        if ( $enabled ) {
            $score += $feature['points'];
        } elseif ( $recommendation === null || $feature['points'] > $recommendation['points'] ) {
            $recommendation = array(
                'key'    => $key,
                'label'  => $feature['label'],
                'points' => $feature['points'],
            );
        }
    }

    return array(
        'score'          => $score,
        'max'            => $max,
        'features'       => $scored,
        'recommendation' => $recommendation,
    );
}

// @see http://codex.wordpress.org/Function_Reference/add_filter
// @see https://codex.wordpress.org/Plugin_API/Filter_Reference/wp_authenticate_user

function wldelay_get_options() {
    if ( ! isset( $GLOBALS['wldelay_options_cache'] ) ) {
        $options = get_option( WLDELAY_OPTION_NAME );
        if ( ! is_array( $options ) ) {
            $options = array();
        }

        // Security feature defaults must stay opt-in.
        if ( ! array_key_exists( 'wldelay_rest_enabled', $options ) ) {
            $options['wldelay_rest_enabled'] = false;
        }

        if ( ! array_key_exists( 'wldelay_application_password_enabled', $options ) ) {
            $options['wldelay_application_password_enabled'] = false;
        }

        if ( ! array_key_exists( 'wldelay_fail2ban_enabled', $options ) ) {
            $options['wldelay_fail2ban_enabled'] = false;
        }

        if ( ! array_key_exists( 'wldelay_fail2ban_log_path', $options ) ) {
            $options['wldelay_fail2ban_log_path'] = '';
        }

        if ( ! array_key_exists( 'wldelay_fail2ban_include_lockouts', $options ) ) {
            $options['wldelay_fail2ban_include_lockouts'] = LDS_Settings::_DEFAULT_FAIL2BAN_INCLUDE_LOCKOUTS;
        }

        $GLOBALS['wldelay_options_cache'] = $options;
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
 * Applies the default WordPress normalization (lowercase + sanitize_user),
 * then passes the result through `wldelay_normalize_username` filter so
 * plugins with custom auth backends (LDAP, email-as-login) can override.
 *
 * @param string $username Username input.
 * @return string Normalized username.
 */
function wldelay_normalize_username( $username ) {
    $username = is_string( $username ) ? trim( $username ) : '';
    if ( $username === '' ) {
        return '';
    }

    $normalized = strtolower( sanitize_user( wp_unslash( $username ), true ) );

    /**
     * Filter the normalized username used for lockout and failure tracking.
     *
     * Allows plugins with custom authentication backends (LDAP, email-based
     * login, SSO) to map login input to a canonical identifier before it
     * enters the lockout/failure tracking key.
     *
     * Returning an empty string is treated as invalid and falls back to the
     * default normalization. Callbacks must be idempotent — the filter fires
     * exactly once per raw input, but callers must not depend on that changing.
     *
     * @param string $normalized The default-normalized username.
     * @param string $username   The raw username input before normalization.
     */
    $filtered = (string) apply_filters( 'wldelay_normalize_username', $normalized, $username );

    return $filtered !== '' ? $filtered : $normalized;
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

    if ( $strategy === 'ip_username' && $username !== '' ) {
        return $ip . '|' . $username;
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
 * Detect known 2FA plugin provider from active plugin list.
 *
 * @param array<int,string> $active_plugins Active plugin basenames.
 * @return string Provider key or empty string when not detected.
 */
function wldelay_detect_2fa_provider( $active_plugins ) {
    if ( ! is_array( $active_plugins ) ) {
        return '';
    }

    $active = array();
    foreach ( $active_plugins as $plugin_file ) {
        if ( is_scalar( $plugin_file ) ) {
            $active[] = strtolower( (string) $plugin_file );
        }
    }

    $providers = array(
        'two-factor' => array(
            'two-factor/two-factor.php',
        ),
        'wp-2fa' => array(
            'wp-2fa/wp-2fa.php',
        ),
        'mini-orange' => array(
            'miniorange-2-factor-authentication/miniorange_2_factor_settings.php',
        ),
        'google-authenticator' => array(
            'google-authenticator/google-authenticator.php',
        ),
    );

    /**
     * Filter the list of known 2FA plugin providers.
     *
     * Each key is a provider slug and each value is an array of plugin basenames
     * (e.g. 'my-2fa/my-2fa.php') that map to that provider.
     *
     * @param array<string,array<int,string>> $providers Provider map.
     */
    $providers = apply_filters( 'wldelay_2fa_providers', $providers );

    if ( ! is_array( $providers ) ) {
        return '';
    }

    foreach ( $providers as $provider => $candidates ) {
        if ( ! is_string( $provider ) || ! is_array( $candidates ) ) {
            continue;
        }
        foreach ( $candidates as $plugin_file ) {
            if ( is_string( $plugin_file ) && in_array( strtolower( $plugin_file ), $active, true ) ) {
                return $provider;
            }
        }
    }

    return '';
}

/**
 * Build lightweight 2FA health status for admin UI.
 *
 * @param array<int,string>|null $active_plugins Optional active plugin basenames override (for tests).
 * @return array<string,mixed>
 */
function wldelay_get_2fa_health_status( $active_plugins = null ) {
    if ( ! is_array( $active_plugins ) ) {
        $active_plugins = (array) get_option( 'active_plugins', array() );

        if ( is_multisite() ) {
            $sitewide = (array) get_site_option( 'active_sitewide_plugins', array() );
            $active_plugins = array_merge( $active_plugins, array_keys( $sitewide ) );
        }
    }

    $provider = wldelay_detect_2fa_provider( $active_plugins );
    $coverage = wldelay_get_2fa_privileged_user_coverage( $provider );

    return array(
        'enabled'         => $provider !== '',
        'provider'        => $provider,
        'provider_label'  => wldelay_get_2fa_provider_label( $provider ),
        'coverage'        => $coverage,
    );
}

/**
 * Get privileged user 2FA coverage data for a detected provider.
 *
 * The returned array is safe for admin UI consumption even when the provider
 * does not expose coverage details. Third parties can add support for custom
 * providers through the `wldelay_2fa_coverage_checkers` filter.
 *
 * @param string $provider Provider key.
 * @return array{supported:bool,privileged_total:int,protected:int,unprotected:int,unknown:int}
 */
function wldelay_get_2fa_privileged_user_coverage( $provider ) {
    $empty = array(
        'supported'        => false,
        'privileged_total' => 0,
        'protected'        => 0,
        'unprotected'      => 0,
        'unknown'          => 0,
    );

    if ( ! is_string( $provider ) || '' === $provider ) {
        return $empty;
    }

    $checkers = array(
        'two-factor' => 'wldelay_get_two_factor_privileged_user_coverage',
    );

    /**
     * Filter provider-specific privileged-user 2FA coverage callbacks.
     *
     * Each callback should return an array with keys: supported,
     * privileged_total, protected, unprotected, unknown.
     *
     * @param array<string,callable|string> $checkers Coverage checker map.
     */
    $checkers = apply_filters( 'wldelay_2fa_coverage_checkers', $checkers );

    if ( ! is_array( $checkers ) || empty( $checkers[ $provider ] ) || ! is_callable( $checkers[ $provider ] ) ) {
        return $empty;
    }

    $coverage = call_user_func( $checkers[ $provider ] );

    if ( ! is_array( $coverage ) ) {
        return $empty;
    }

    return array(
        'supported'        => ! empty( $coverage['supported'] ),
        'privileged_total' => max( 0, (int) ( $coverage['privileged_total'] ?? 0 ) ),
        'protected'        => max( 0, (int) ( $coverage['protected'] ?? 0 ) ),
        'unprotected'      => max( 0, (int) ( $coverage['unprotected'] ?? 0 ) ),
        'unknown'          => max( 0, (int) ( $coverage['unknown'] ?? 0 ) ),
    );
}

/**
 * Get coverage details for privileged users when the Two-Factor plugin is active.
 *
 * @return array{supported:bool,privileged_total:int,protected:int,unprotected:int,unknown:int}
 */
function wldelay_get_two_factor_privileged_user_coverage() {
    $user_ids = get_users(
        array(
            'role__in'    => array( 'administrator' ),
            'fields'      => 'ID',
            'number'      => -1,
            'count_total' => false,
        )
    );

    $coverage = array(
        'supported'        => true,
        'privileged_total' => count( $user_ids ),
        'protected'        => 0,
        'unprotected'      => 0,
        'unknown'          => 0,
    );

    foreach ( $user_ids as $user_id ) {
        $user_id = (int) $user_id;

        if ( $user_id <= 0 ) {
            continue;
        }

        if ( wldelay_is_two_factor_enabled_for_user( $user_id ) ) {
            $coverage['protected']++;
            continue;
        }

        $coverage['unprotected']++;
    }

    return $coverage;
}

/**
 * Determine whether the Two-Factor plugin appears enabled for a specific user.
 *
 * @param int $user_id User ID.
 * @return bool
 */
function wldelay_is_two_factor_enabled_for_user( $user_id ) {
    $user_id = (int) $user_id;

    if ( $user_id <= 0 ) {
        return false;
    }

    if ( class_exists( 'Two_Factor_Core' ) && method_exists( 'Two_Factor_Core', 'get_enabled_providers_for_user' ) ) {
        $user = get_userdata( $user_id );

        if ( $user instanceof WP_User ) {
            $providers = Two_Factor_Core::get_enabled_providers_for_user( $user );

            return is_array( $providers ) && ! empty( $providers );
        }
    }

    $enabled = get_user_meta( $user_id, '_two_factor_enabled_providers', true );

    if ( is_array( $enabled ) ) {
        return ! empty( array_filter( $enabled ) );
    }

    return is_string( $enabled ) && '' !== trim( $enabled );
}

/**
 * Get a human-readable label for a detected 2FA provider key.
 *
 * @param string $provider Provider key.
 * @return string Label for admin UI.
 */
function wldelay_get_2fa_provider_label( $provider ) {
    switch ( $provider ) {
        case 'two-factor':
            return __( 'Two-Factor', 'login-delay-shield' );
        case 'wp-2fa':
            return __( 'WP 2FA', 'login-delay-shield' );
        case 'mini-orange':
            return __( 'miniOrange 2-Factor Authentication', 'login-delay-shield' );
        case 'google-authenticator':
            return __( 'Google Authenticator', 'login-delay-shield' );
        default:
            return '';
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

        // Build a 128-bit (16-byte) binary mask for IPv6 CIDR comparison.
        // Full 0xff bytes cover complete octets ($netmask / 8).
        // For any partial octet, left-shift 0xff by (8 - remaining bits) to
        // zero out the host bits within that byte (e.g. /68 → 4 remainder bits
        // → 0xff << 4 = 0xf0). The mask is then zero-padded to 16 bytes so
        // bitwise AND with inet_pton() output isolates the network prefix.
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
 * Parse the whitelist into exact IPs and CIDR ranges.
 *
 * Result is cached per-request in $GLOBALS and invalidated when options change.
 *
 * @return array{exact:array<string,true>,cidr:array<int,string>}
 */
function wldelay_get_parsed_whitelist() {
    if ( isset( $GLOBALS['wldelay_parsed_whitelist'] ) ) {
        return $GLOBALS['wldelay_parsed_whitelist'];
    }

    $options = wldelay_get_options();
    $whitelist = isset( $options['wldelay_whitelist_ips'] ) ? $options['wldelay_whitelist_ips'] : '';

    $exact = array();
    $cidr  = array();

    if ( $whitelist !== '' ) {
        foreach ( explode( "\n", $whitelist ) as $line ) {
            $line = trim( $line );
            if ( $line === '' ) {
                continue;
            }
            if ( strpos( $line, '/' ) !== false ) {
                $cidr[] = $line;
            } else {
                $exact[ $line ] = true;
            }
        }
    }

    $GLOBALS['wldelay_parsed_whitelist'] = array( 'exact' => $exact, 'cidr' => $cidr );

    return $GLOBALS['wldelay_parsed_whitelist'];
}

/**
 * Clear the parsed whitelist cache.
 */
function wldelay_clear_whitelist_cache() {
    unset( $GLOBALS['wldelay_parsed_whitelist'] );
}

add_action( 'update_option_wldelay_options', 'wldelay_clear_whitelist_cache' );
add_action( 'add_option_wldelay_options', 'wldelay_clear_whitelist_cache' );
add_action( 'delete_option_wldelay_options', 'wldelay_clear_whitelist_cache' );

/**
 * Check if the client IP is whitelisted
 *
 * Uses a parsed cache: exact IPs are checked via hash lookup (O(1)),
 * CIDR ranges are checked only if the exact lookup misses.
 *
 * @param string|null $ip Optional IP to check. Defaults to client IP.
 * @return bool True if IP is whitelisted
 */
function wldelay_is_ip_whitelisted( $ip = null ) {
    $options = wldelay_get_options();

    if ( empty( $options['wldelay_whitelist_enabled'] ) ) {
        return false;
    }

    $whitelist = isset( $options['wldelay_whitelist_ips'] ) ? $options['wldelay_whitelist_ips'] : '';
    if ( empty( $whitelist ) ) {
        return false;
    }

    if ( $ip === null ) {
        $ip = wldelay_get_client_ip();
    }
    if ( empty( $ip ) ) {
        return false;
    }

    $parsed = wldelay_get_parsed_whitelist();

    if ( isset( $parsed['exact'][ $ip ] ) ) {
        return true;
    }

    foreach ( $parsed['cidr'] as $range ) {
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
 * @param string|null $source Optional source of the lockout event.
 */
function wldelay_lock_ip( $ip, $username = '', $source = null ) {
    $options = wldelay_get_options();
    $lockout_duration = wldelay_get_lockout_duration_seconds( $options );
    $transient_key = wldelay_get_lockout_transient_key( $ip, $username, $options );
    set_transient( $transient_key, time(), $lockout_duration );
    wldelay_register_transient_key( $transient_key );
    wldelay_write_fail2ban_log( 'lockout', $ip, $username, $source );
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

    wldelay_write_fail2ban_log( 'failed login', $ip, $username, $source );
}

/**
 * Get recent failed login attempts
 *
 * @param int $limit Number of attempts to retrieve
 * @return array Array of failed attempt records
 */
function wldelay_get_recent_failed_attempts( $limit = 20 ) {
    return wldelay_get_login_log_attempts(
        array(
            'limit'  => $limit,
            'fields' => '*',
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

    $username = wldelay_normalize_username( $username );

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

    $failed_attempts = wldelay_track_failed_attempt( $username, 'rest' );
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

    $failed_attempts = wldelay_track_failed_attempt( $username, 'application-password' );
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
 * @param string|null $source Optional login source for lockout logging.
 * @return int Updated failure count for the current tracking key. 0 if tracking is skipped.
 */
function wldelay_track_failed_attempt( $username, $source = null ) {
    $ip = wldelay_get_client_ip();
    if ( empty( $ip ) ) {
        return 0;
    }
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
            wldelay_lock_ip( $ip, $username, $source );
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
    /* translators: %s: site name */
    $subject = sprintf( __( '[%s] Failed login attempts alert', 'login-delay-shield' ), $site_name );

    /* translators: 1: site name, 2: IP address, 3: attempted username, 4: failed attempt count, 5: timestamp */
    $message = sprintf(
        __( "Multiple failed login attempts detected on %1\$s.\n\nIP Address: %2\$s\nUsername attempted: %3\$s\nFailed attempts: %4\$d\nTime: %5\$s\n\nThis is an automated alert from Login Delay Shield.", 'login-delay-shield' ),
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
        $failed_attempts = wldelay_track_failed_attempt( $username, wldelay_get_login_source() );

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

// ==========================================================================
// Custom Login URL
// ==========================================================================

/**
 * Check whether the custom login URL feature is active.
 *
 * @return bool
 */
function wldelay_custom_login_is_active() {
    if ( defined( 'WLDELAY_DISABLE_CUSTOM_LOGIN' ) && WLDELAY_DISABLE_CUSTOM_LOGIN ) {
        return false;
    }

    $options = wldelay_get_options();

    if ( empty( $options['wldelay_custom_login_enabled'] ) ) {
        return false;
    }

    $slug = isset( $options['wldelay_custom_login_slug'] ) ? trim( $options['wldelay_custom_login_slug'] ) : '';

    return $slug !== '';
}

/**
 * Get the configured custom login slug.
 *
 * @return string
 */
function wldelay_get_custom_login_slug() {
    $options = wldelay_get_options();
    return isset( $options['wldelay_custom_login_slug'] ) ? trim( $options['wldelay_custom_login_slug'] ) : 'my-login';
}

/**
 * Register the custom login slug rewrite rule and prevent canonical redirect
 * from leaking the custom slug when someone visits /wp-login.php.
 */
function wldelay_custom_login_init() {
    if ( ! wldelay_custom_login_is_active() ) {
        return;
    }

    $slug = wldelay_get_custom_login_slug();
    add_rewrite_rule( '^' . preg_quote( $slug, '/' ) . '/?$', 'index.php?wldelay_custom_login=1', 'top' );

    // Intercept any redirect that would expose the custom slug when someone
    // visits /wp-login.php. Covers canonical redirect and any other source.
    add_filter( 'wp_redirect', 'wldelay_block_login_slug_leak', 1, 2 );
}
add_action( 'init', 'wldelay_custom_login_init' );

/**
 * Block any redirect that would expose the custom login slug.
 *
 * Hooked on wp_redirect with priority 1 so it fires before the redirect is
 * sent. If the original request was for /wp-login.php and WordPress tries to
 * redirect to the custom slug URL, we serve a 404 instead.
 *
 * @param string $location The redirect destination URL.
 * @param int    $status   HTTP status code.
 * @return string|false The redirect URL, or false to cancel.
 */
function wldelay_block_login_slug_leak( $location, $status = 302 ) {
    $request_path = trim( parse_url( $_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH ), '/' );

    // Only act when the original request targets wp-login.php.
    if ( $request_path !== 'wp-login.php' && $request_path !== 'wp-loginphp' ) {
        return $location;
    }

    $slug = wldelay_get_custom_login_slug();

    // Only block if the redirect destination contains our custom slug.
    if ( strpos( $location, $slug ) === false ) {
        return $location;
    }

    status_header( 404 );
    nocache_headers();

    $template = function_exists( 'get_404_template' ) ? get_404_template() : '';
    if ( $template && file_exists( $template ) ) {
        include $template;
    } else {
        echo '<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><h1>Not Found</h1></body></html>';
    }

    if ( defined( 'WP_TESTS_DOMAIN' ) ) {
        return false;
    }
    exit;
}

/**
 * Register custom query var so WordPress recognises the slug.
 *
 * @param array $vars Existing query vars.
 * @return array
 */
function wldelay_custom_login_query_vars( $vars ) {
    $vars[] = 'wldelay_custom_login';
    return $vars;
}
add_filter( 'query_vars', 'wldelay_custom_login_query_vars' );

/**
 * On template_redirect, load wp-login.php when the custom slug is requested.
 */
function wldelay_custom_login_template_redirect() {
    if ( ! wldelay_custom_login_is_active() ) {
        return;
    }

    // Check both the URL path and the query var set by the rewrite rule.
    $slug = wldelay_get_custom_login_slug();
    $request = trim( parse_url( $_SERVER['REQUEST_URI'], PHP_URL_PATH ), '/' );

    if ( $request === $slug || get_query_var( 'wldelay_custom_login' ) ) {
        require_once ABSPATH . 'wp-login.php';
        exit;
    }
}
add_action( 'template_redirect', 'wldelay_custom_login_template_redirect' );

/**
 * Secondary guard on login_init — blocks any direct wp-login.php access that
 * somehow bypassed the earlier init-level check (e.g. non-GET methods that
 * should not reach the login form).
 *
 * The primary block runs on init in wldelay_custom_login_init().
 */
function wldelay_custom_login_block_direct_access() {
    if ( ! wldelay_custom_login_is_active() ) {
        return;
    }

    // POST requests must pass through (form submissions).
    if ( 'POST' === ( $_SERVER['REQUEST_METHOD'] ?? '' ) ) {
        return;
    }

    $slug = wldelay_get_custom_login_slug();
    $request_uri = isset( $_SERVER['REQUEST_URI'] ) ? $_SERVER['REQUEST_URI'] : '';
    $path = trim( parse_url( $request_uri, PHP_URL_PATH ), '/' );

    // Allow requests via the custom slug.
    if ( strpos( $path, $slug ) !== false ) {
        return;
    }

    // Only block if the user-facing URL is exactly "wp-login.php" at the site
    // root. Internal paths like /wp/wp-login.php are legitimate WordPress
    // redirects (e.g. unauthenticated wp-admin access) and must pass through.
    if ( $path !== 'wp-login.php' ) {
        return;
    }

    status_header( 404 );
    nocache_headers();

    if ( defined( 'WP_TESTS_DOMAIN' ) ) {
        return;
    }
    exit;
}
add_action( 'login_init', 'wldelay_custom_login_block_direct_access' );

/**
 * Filter wp_login_url() to use the custom slug.
 *
 * @param string $login_url    The login URL.
 * @param string $redirect     The path to redirect to on login.
 * @param bool   $force_reauth Whether to force reauth.
 * @return string
 */
function wldelay_filter_login_url( $login_url, $redirect = '', $force_reauth = false ) {
    if ( ! wldelay_custom_login_is_active() ) {
        return $login_url;
    }

    $slug = wldelay_get_custom_login_slug();
    $custom_url = home_url( $slug );

    if ( ! empty( $redirect ) ) {
        $custom_url = add_query_arg( 'redirect_to', urlencode( $redirect ), $custom_url );
    }

    if ( $force_reauth ) {
        $custom_url = add_query_arg( 'reauth', '1', $custom_url );
    }

    return $custom_url;
}
add_filter( 'login_url', 'wldelay_filter_login_url', 10, 3 );

/**
 * Filter logout_url() to use the custom slug.
 *
 * @param string $logout_url The logout URL.
 * @param string $redirect   Redirect destination.
 * @return string
 */
function wldelay_filter_logout_url( $logout_url, $redirect = '' ) {
    if ( ! wldelay_custom_login_is_active() ) {
        return $logout_url;
    }

    // Extract query string from the original logout URL (contains _wpnonce, action=logout).
    $parsed = wp_parse_url( $logout_url );
    $slug = wldelay_get_custom_login_slug();
    $custom_url = home_url( $slug );

    if ( ! empty( $parsed['query'] ) ) {
        $custom_url .= '?' . $parsed['query'];
    }

    return $custom_url;
}
add_filter( 'logout_url', 'wldelay_filter_logout_url', 10, 2 );

/**
 * Filter lostpassword_url() to use the custom slug.
 *
 * @param string $lostpassword_url The lost password URL.
 * @param string $redirect         Redirect destination.
 * @return string
 */
function wldelay_filter_lostpassword_url( $lostpassword_url, $redirect = '' ) {
    if ( ! wldelay_custom_login_is_active() ) {
        return $lostpassword_url;
    }

    $slug = wldelay_get_custom_login_slug();
    $custom_url = add_query_arg( 'action', 'lostpassword', home_url( $slug ) );

    if ( ! empty( $redirect ) ) {
        $custom_url = add_query_arg( 'redirect_to', urlencode( $redirect ), $custom_url );
    }

    return $custom_url;
}
add_filter( 'lostpassword_url', 'wldelay_filter_lostpassword_url', 10, 2 );

/**
 * Replace wp-login.php references in the password reset email with the custom slug.
 *
 * @param string $message    Email message body.
 * @param string $key        Password reset key.
 * @param string $user_login Username.
 * @param object $user_data  WP_User object.
 * @return string
 */
function wldelay_filter_retrieve_password_message( $message, $key, $user_login, $user_data ) {
    if ( ! wldelay_custom_login_is_active() ) {
        return $message;
    }

    $slug = wldelay_get_custom_login_slug();
    $old_url = network_site_url( 'wp-login.php', 'login' );
    $new_url = home_url( $slug );

    return str_replace( $old_url, $new_url, $message );
}
add_filter( 'retrieve_password_message', 'wldelay_filter_retrieve_password_message', 10, 4 );
