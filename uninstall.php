<?php
/**
 * Uninstall routine for Login Delay Shield.
 *
 * Runs only when the plugin is deleted from the WordPress admin. Removes all
 * data the plugin created: options, the failed-login log table, registered
 * transients, and the plugin-owned fail2ban log directory. Custom fail2ban log
 * paths configured by the site owner are left untouched.
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
    exit;
}

require_once dirname( __FILE__ ) . '/wldelay-fail2ban.php';

/**
 * Recursively delete a directory and its contents.
 *
 * @param string $dir Absolute directory path.
 */
function wldelay_uninstall_rmdir( $dir ) {
    if ( ! is_dir( $dir ) ) {
        return;
    }

    $entries = @scandir( $dir );
    if ( false === $entries ) {
        return;
    }

    foreach ( $entries as $entry ) {
        if ( '.' === $entry || '..' === $entry ) {
            continue;
        }

        $path = $dir . '/' . $entry;
        if ( is_dir( $path ) ) {
            wldelay_uninstall_rmdir( $path );
        } else {
            @unlink( $path );
        }
    }

    @rmdir( $dir );
}

/**
 * Remove all plugin data for the current site context.
 */
function wldelay_uninstall_cleanup_site() {
    global $wpdb;

    // Delete the plugin-owned default fail2ban log directory (custom paths are left alone).
    if ( function_exists( 'wldelay_fail2ban_get_default_log_path' ) ) {
        $default_dir = dirname( wldelay_fail2ban_get_default_log_path() );
        wldelay_uninstall_rmdir( $default_dir );
    }

    // Delete registered transients before dropping the registry option.
    $registry = get_option( 'wldelay_transient_registry', array() );
    if ( is_array( $registry ) ) {
        foreach ( $registry as $transient_name ) {
            if ( is_string( $transient_name ) && '' !== $transient_name ) {
                delete_transient( $transient_name );
            }
        }
    }
    delete_transient( 'wldelay_dashboard_attempts' );

    // Remove plugin options.
    delete_option( 'wldelay_options' );
    delete_option( 'wldelay_fail2ban_default_token' );
    delete_option( 'wldelay_transient_registry' );
    delete_option( 'wldelay_db_version' );
    delete_option( 'wldelay_settings_version' );

    // Drop the failed-login log table.
    $table_name = $wpdb->prefix . 'wldelay_login_log';
    $wpdb->query( "DROP TABLE IF EXISTS `{$table_name}`" ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.SchemaChange

    // Drop the persistent lockout table (F-2-1).
    $lockout_table = $wpdb->prefix . 'wldelay_lockouts';
    $wpdb->query( "DROP TABLE IF EXISTS `{$lockout_table}`" ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.SchemaChange

    // Clear plugin-owned scheduled cron events (F-4-9 async backstop + the
    // daily log-cleanup event) so no orphan hooks linger after deletion.
    $async_cron = wp_next_scheduled( 'wldelay_async_cron' );
    if ( $async_cron ) {
        wp_unschedule_event( $async_cron, 'wldelay_async_cron' );
    }
    wp_clear_scheduled_hook( 'wldelay_async_cron' );

    $cleanup_cron = wp_next_scheduled( 'wldelay_cleanup_logs' );
    if ( $cleanup_cron ) {
        wp_unschedule_event( $cleanup_cron, 'wldelay_cleanup_logs' );
    }
    wp_clear_scheduled_hook( 'wldelay_cleanup_logs' );
}

if ( is_multisite() ) {
    $site_ids = get_sites( array( 'fields' => 'ids' ) );
    foreach ( $site_ids as $site_id ) {
        switch_to_blog( $site_id );
        wldelay_uninstall_cleanup_site();
        restore_current_blog();
    }
} else {
    wldelay_uninstall_cleanup_site();
}
