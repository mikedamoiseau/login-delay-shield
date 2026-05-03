<?php
if ( ! defined( 'ABSPATH' ) ) exit;

/**
 * Fail2ban-compatible logging helpers.
 */

/**
 * Normalize a filesystem path for validation.
 *
 * @param string $path Raw path.
 * @return string Normalized path.
 */
function wldelay_fail2ban_normalize_path( $path ) {
    $path = function_exists( 'wp_unslash' ) ? wp_unslash( $path ) : $path;
    $path = str_replace( "\0", '', (string) $path );
    $path = preg_replace( '/[\x00-\x1F\x7F]/', '', $path );
    $path = str_replace( '\\', '/', trim( $path ) );
    $path = preg_replace( '#/+#', '/', $path );

    return $path;
}

/**
 * Determine whether a path is absolute.
 *
 * @param string $path Normalized path.
 * @return bool
 */
function wldelay_fail2ban_path_is_absolute( $path ) {
    return preg_match( '#^(?:[A-Za-z]:)?/#', (string) $path ) === 1;
}

/**
 * Collapse path segments and reject traversal.
 *
 * @param string $path Raw path.
 * @return string Collapsed path, or empty string when unsafe.
 */
function wldelay_fail2ban_collapse_path( $path ) {
    $path = wldelay_fail2ban_normalize_path( $path );

    if ( $path === '' || strpos( $path, '://' ) !== false ) {
        return '';
    }

    $drive = '';
    if ( preg_match( '#^[A-Za-z]:/#', $path ) ) {
        $drive = substr( $path, 0, 2 );
        $path  = substr( $path, 2 );
    }

    $absolute = strpos( $path, '/' ) === 0;
    $segments = explode( '/', trim( $path, '/' ) );
    $safe     = array();

    foreach ( $segments as $segment ) {
        if ( $segment === '' || $segment === '.' ) {
            continue;
        }

        if ( $segment === '..' ) {
            return '';
        }

        if ( preg_match( '/[<>:"|?*]/', $segment ) ) {
            return '';
        }

        $safe[] = $segment;
    }

    $collapsed = implode( '/', $safe );

    if ( $drive !== '' ) {
        return $drive . '/' . $collapsed;
    }

    if ( $absolute ) {
        return '/' . $collapsed;
    }

    return $collapsed;
}

/**
 * Get the uploads base directory for the default fail2ban log.
 *
 * @return string Normalized uploads path.
 */
function wldelay_fail2ban_get_uploads_basedir() {
    if ( function_exists( 'wp_upload_dir' ) ) {
        $uploads = wp_upload_dir( null, false );
        if ( is_array( $uploads ) && ! empty( $uploads['basedir'] ) ) {
            return rtrim( wldelay_fail2ban_collapse_path( $uploads['basedir'] ), '/' );
        }
    }

    if ( defined( 'WP_CONTENT_DIR' ) ) {
        return rtrim( wldelay_fail2ban_collapse_path( WP_CONTENT_DIR . '/uploads' ), '/' );
    }

    return rtrim( wldelay_fail2ban_collapse_path( ABSPATH . 'wp-content/uploads' ), '/' );
}

/**
 * Get the default fail2ban log path.
 *
 * @return string
 */
function wldelay_fail2ban_get_default_log_path() {
    return wldelay_fail2ban_get_uploads_basedir() . '/login-delay-shield-fail2ban.log';
}

/**
 * Get directories where fail2ban log writes are allowed.
 *
 * @return array<int,string>
 */
function wldelay_fail2ban_get_allowed_log_dirs() {
    $dirs = array( wldelay_fail2ban_get_uploads_basedir() );

    if ( function_exists( 'apply_filters' ) ) {
        /**
         * Filter directories where fail2ban-compatible log writes are allowed.
         *
         * Keep this list narrow. Paths entered in settings must resolve under
         * one of these directories before Login Delay Shield writes to them.
         *
         * @param array<int,string> $dirs Allowed absolute directory paths.
         */
        $dirs = apply_filters( 'wldelay_fail2ban_allowed_log_dirs', $dirs );
    }

    if ( ! is_array( $dirs ) ) {
        $dirs = array();
    }

    $normalized = array();
    foreach ( $dirs as $dir ) {
        $dir = rtrim( wldelay_fail2ban_collapse_path( $dir ), '/' );
        if ( $dir !== '' && wldelay_fail2ban_path_is_absolute( $dir ) ) {
            $normalized[] = $dir;
        }
    }

    return array_values( array_unique( $normalized ) );
}

/**
 * Check whether a path is under an allowed log directory.
 *
 * @param string $path Absolute path.
 * @return bool
 */
function wldelay_fail2ban_path_is_allowed( $path ) {
    $path = rtrim( wldelay_fail2ban_collapse_path( $path ), '/' );
    if ( $path === '' || ! wldelay_fail2ban_path_is_absolute( $path ) ) {
        return false;
    }

    foreach ( wldelay_fail2ban_get_allowed_log_dirs() as $dir ) {
        if ( $path === $dir || strpos( $path . '/', $dir . '/' ) === 0 ) {
            return true;
        }
    }

    return false;
}

/**
 * Sanitize an explicit fail2ban log path from settings.
 *
 * Empty input is preserved as empty so runtime can use the safe default path.
 *
 * @param string $path Raw path.
 * @return string Sanitized absolute path, or empty string.
 */
function wldelay_sanitize_fail2ban_log_path( $path ) {
    $path = wldelay_fail2ban_collapse_path( $path );

    if ( $path === '' ) {
        return '';
    }

    if ( strtolower( substr( $path, -4 ) ) !== '.log' ) {
        return '';
    }

    if ( ! wldelay_fail2ban_path_is_absolute( $path ) ) {
        $path = wldelay_fail2ban_get_uploads_basedir() . '/' . ltrim( $path, '/' );
        $path = wldelay_fail2ban_collapse_path( $path );
    }

    if ( ! wldelay_fail2ban_path_is_allowed( $path ) ) {
        return '';
    }

    return $path;
}

/**
 * Resolve a saved fail2ban log path to the actual write target.
 *
 * @param string $path Saved path.
 * @return string Safe absolute path, or empty string.
 */
function wldelay_fail2ban_resolve_log_path( $path = '' ) {
    if ( trim( (string) $path ) === '' ) {
        $default = wldelay_fail2ban_get_default_log_path();
        return wldelay_fail2ban_path_is_allowed( $default ) ? $default : '';
    }

    return wldelay_sanitize_fail2ban_log_path( $path );
}

/**
 * Sanitize a fail2ban line field.
 *
 * @param string $value Raw field value.
 * @param int    $max_length Maximum output length.
 * @return string Token-safe field value.
 */
function wldelay_fail2ban_sanitize_field( $value, $max_length = 120 ) {
    $value = function_exists( 'wp_unslash' ) ? wp_unslash( $value ) : $value;
    $value = (string) $value;

    if ( function_exists( 'sanitize_text_field' ) ) {
        $value = sanitize_text_field( $value );
    } else {
        $value = strip_tags( $value );
    }

    $value = preg_replace( '/[\r\n\t ]+/', '_', trim( $value ) );
    $value = preg_replace( '/[^A-Za-z0-9@._:+-]/', '', $value );

    if ( $value === '' ) {
        return '-';
    }

    return substr( $value, 0, max( 1, (int) $max_length ) );
}

/**
 * Format a single fail2ban-compatible log line.
 *
 * @param string          $event Event key or label.
 * @param string          $ip IP address.
 * @param string          $username Attempted username.
 * @param string|null     $source Login source.
 * @param int|string|null $timestamp Optional timestamp for tests.
 * @return string Log line, or empty string when required data is invalid.
 */
function wldelay_format_fail2ban_line( $event, $ip, $username, $source = null, $timestamp = null ) {
    $ip = trim( (string) $ip );
    if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
        return '';
    }

    $event = (string) $event;
    if ( ! in_array( $event, array( 'failed login', 'lockout' ), true ) ) {
        $event = 'failed login';
    }

    if ( $source === null && function_exists( 'wldelay_get_login_source' ) ) {
        $source = wldelay_get_login_source();
    }

    if ( $timestamp === null ) {
        $timestamp = time();
    }

    if ( is_numeric( $timestamp ) ) {
        $timestamp = gmdate( 'c', (int) $timestamp );
    } else {
        $timestamp = wldelay_fail2ban_sanitize_field( $timestamp, 40 );
    }

    return sprintf(
        '%s Login Delay Shield: %s source=%s ip=%s username=%s',
        $timestamp,
        $event,
        wldelay_fail2ban_sanitize_field( $source, 40 ),
        $ip,
        wldelay_fail2ban_sanitize_field( $username, 120 )
    );
}

/**
 * Check whether fail2ban logging is enabled for an event.
 *
 * @param string $event Event key.
 * @param array  $options Plugin options.
 * @return bool
 */
function wldelay_fail2ban_should_log_event( $event, $options ) {
    if ( ! is_array( $options ) ) {
        $options = array();
    }

    if ( empty( $options['wldelay_fail2ban_enabled'] ) ) {
        return false;
    }

    if ( $event === 'lockout' ) {
        $include_lockouts = array_key_exists( 'wldelay_fail2ban_include_lockouts', $options )
            ? ! empty( $options['wldelay_fail2ban_include_lockouts'] )
            : ( class_exists( 'LDS_Settings' ) ? LDS_Settings::_DEFAULT_FAIL2BAN_INCLUDE_LOCKOUTS : true );

        if ( ! $include_lockouts ) {
            return false;
        }
    }

    return true;
}

/**
 * Write a fail2ban-compatible log line when enabled.
 *
 * @param string      $event Event key.
 * @param string      $ip IP address.
 * @param string      $username Attempted username.
 * @param string|null $source Login source.
 * @return bool True when a line was written.
 */
function wldelay_write_fail2ban_log( $event, $ip, $username, $source = null ) {
    if ( ! function_exists( 'wldelay_get_options' ) ) {
        return false;
    }

    $options = wldelay_get_options();
    if ( ! wldelay_fail2ban_should_log_event( $event, $options ) ) {
        return false;
    }

    $path = isset( $options['wldelay_fail2ban_log_path'] )
        ? wldelay_fail2ban_resolve_log_path( $options['wldelay_fail2ban_log_path'] )
        : wldelay_fail2ban_resolve_log_path();

    if ( $path === '' ) {
        return false;
    }

    $line = wldelay_format_fail2ban_line( $event, $ip, $username, $source );
    if ( $line === '' ) {
        return false;
    }

    $dir = dirname( $path );
    if ( ! is_dir( $dir ) ) {
        if ( function_exists( 'wp_mkdir_p' ) ) {
            wp_mkdir_p( $dir );
        } else {
            @mkdir( $dir, 0755, true );
        }
    }

    if ( ! is_dir( $dir ) || ! is_writable( $dir ) ) {
        return false;
    }

    return false !== @file_put_contents( $path, $line . PHP_EOL, FILE_APPEND | LOCK_EX );
}
