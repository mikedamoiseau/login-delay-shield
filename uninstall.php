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

    // Drop the failed-login log table.
    $table_name = $wpdb->prefix . 'wldelay_login_log';
    $wpdb->query( "DROP TABLE IF EXISTS `{$table_name}`" ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.SchemaChange
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
