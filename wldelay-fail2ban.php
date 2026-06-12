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
 * Get the plugin-owned base directory for the default fail2ban log.
 *
 * Returns WP_CONTENT_DIR (not its parent) so the default log directory never
 * lands inside the document root. Combined with the unguessable token from
 * wldelay_fail2ban_get_default_dir_token(), the default log file is not
 * reachable by URL guessing even on Nginx-fronted installs where .htaccess
 * is ignored.
 *
 * @return string Normalized directory path.
 */
function wldelay_fail2ban_get_default_base_dir() {
    if ( defined( 'WP_CONTENT_DIR' ) ) {
        return rtrim( wldelay_fail2ban_collapse_path( WP_CONTENT_DIR ), '/' );
    }

    return rtrim( wldelay_fail2ban_collapse_path( rtrim( ABSPATH, '/\\' ) . '/wp-content' ), '/' );
}

/**
 * Get (and lazily persist) the per-install random token used in the default
 * fail2ban log directory name. The token makes the default log path
 * non-enumerable from outside, so static-file servers (Nginx, etc.) cannot
 * be used to download the log even if directory listing is on.
 *
 * @return string 16-char alphanumeric token.
 */
function wldelay_fail2ban_get_default_dir_token() {
    static $cache = null;

    if ( is_string( $cache ) && $cache !== '' ) {
        return $cache;
    }

    $token = '';
    if ( function_exists( 'get_option' ) ) {
        $stored = get_option( 'wldelay_fail2ban_default_token' );
        if ( is_string( $stored ) && preg_match( '/^[A-Za-z0-9]{16}$/', $stored ) ) {
            $token = $stored;
        }
    }

    if ( $token === '' ) {
        if ( function_exists( 'wp_generate_password' ) ) {
            $token = wp_generate_password( 16, false, false );
        } else {
            try {
                $token = substr( bin2hex( random_bytes( 8 ) ), 0, 16 );
            } catch ( Exception $e ) {
                $token = substr( md5( uniqid( '', true ) ), 0, 16 );
            }
        }

        if ( function_exists( 'update_option' ) ) {
            update_option( 'wldelay_fail2ban_default_token', $token, false );
        }
    }

    $cache = $token;
    return $token;
}

/**
 * Get the default fail2ban log path.
 *
 * @return string
 */
function wldelay_fail2ban_get_default_log_path() {
    return wldelay_fail2ban_get_default_base_dir() . '/login-delay-shield-fail2ban-' . wldelay_fail2ban_get_default_dir_token() . '/login-delay-shield-fail2ban.log';
}

/**
 * Get directories where fail2ban log writes are allowed.
 *
 * @return array<int,string>
 */
function wldelay_fail2ban_get_allowed_log_dirs() {
    $dirs = array( dirname( wldelay_fail2ban_get_default_log_path() ) );

    if ( function_exists( 'apply_filters' ) ) {
        /**
         * Filter directories where fail2ban-compatible log writes are allowed.
         *
         * Keep this list narrow. Paths entered in settings must resolve under
         * one of these directories before Login Delay Shield writes to them.
         *
         * @param array<int,string> $dirs Allowed absolute directory paths. The plugin-owned default log directory is allowed by default; add explicit directories here only when they are protected by server configuration.
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
        $path = dirname( wldelay_fail2ban_get_default_log_path() ) . '/' . ltrim( $path, '/' );
        $path = wldelay_fail2ban_collapse_path( $path );
    }

    if ( ! wldelay_fail2ban_path_is_allowed( $path ) ) {
        return '';
    }

    $uploads_base = rtrim( wldelay_fail2ban_get_uploads_basedir(), '/' );
    if ( $uploads_base !== '' && rtrim( dirname( $path ), '/' ) === $uploads_base ) {
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
 * Add lightweight web-server protections to any log directory the plugin writes to.
 *
 * Guards are written for every writable log directory (the protected default
 * directory and any directory added via the wldelay_fail2ban_allowed_log_dirs
 * filter). The files are harmless on directories that are already protected by
 * server configuration, and they close the gap for site owners who allowlist a
 * web-served directory without realizing it needs protection.
 *
 * @param string $dir Log directory.
 */
function wldelay_fail2ban_protect_log_dir( $dir ) {
    $dir = rtrim( wldelay_fail2ban_collapse_path( $dir ), '/' );

    if ( $dir === '' || ! is_dir( $dir ) ) {
        return;
    }

    $htaccess = $dir . '/.htaccess';
    if ( ! file_exists( $htaccess ) ) {
        @file_put_contents( $htaccess, "<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\nDeny from all\n</IfModule>\n", LOCK_EX );
    }

    $index_html = $dir . '/index.html';
    if ( ! file_exists( $index_html ) ) {
        @file_put_contents( $index_html, '', LOCK_EX );
    }

    // Silence under Nginx+PHP-FPM: ignores .htaccess, so add a PHP guard too.
    $index_php = $dir . '/index.php';
    if ( ! file_exists( $index_php ) ) {
        @file_put_contents( $index_php, "<?php\n// Silence is golden.\n", LOCK_EX );
    }
}

/**
 * Get the maximum fail2ban log size (in bytes) before rotation.
 *
 * Prevents the plugin-owned default log from growing without bound on installs
 * that have no external logrotate watching the file. Return 0 (via the filter)
 * to disable plugin-side rotation entirely and rely on system log rotation.
 *
 * @return int Maximum size in bytes, or 0 when rotation is disabled.
 */
function wldelay_fail2ban_get_max_log_bytes() {
    $default = 5 * 1024 * 1024; // 5 MB.
    $max     = $default;

    if ( function_exists( 'apply_filters' ) ) {
        /**
         * Filter the maximum fail2ban log size before rotation.
         *
         * @param int $default Maximum size in bytes. Return 0 to disable plugin-side rotation.
         */
        $max = apply_filters( 'wldelay_fail2ban_max_log_bytes', $default );
    }

    $max = (int) $max;

    return $max > 0 ? $max : 0;
}

/**
 * Rotate the log when it reaches the configured maximum size.
 *
 * Keeps a single backup (<path>.1) so an existing fail2ban jail can keep
 * tailing the active file after it is truncated by rotation.
 *
 * @param string   $path Absolute log path.
 * @param int|null $max_bytes Optional override; defaults to the filtered maximum.
 * @return bool True when the log was rotated.
 */
function wldelay_fail2ban_maybe_rotate_log( $path, $max_bytes = null ) {
    if ( $max_bytes === null ) {
        $max_bytes = wldelay_fail2ban_get_max_log_bytes();
    }

    $max_bytes = (int) $max_bytes;
    if ( $max_bytes <= 0 || ! is_file( $path ) ) {
        return false;
    }

    $size = @filesize( $path );
    if ( $size === false || $size < $max_bytes ) {
        return false;
    }

    $backup = $path . '.1';
    if ( file_exists( $backup ) ) {
        @unlink( $backup );
    }

    return @rename( $path, $backup );
}

/**
 * Request-scoped fail2ban line buffer (F-4-5).
 *
 * Lines are formatted at call time (the timestamp must reflect the attempt,
 * not the flush) and appended to the log in ONE locked write on shutdown,
 * taking file I/O off the auth hot path. A fatal before shutdown loses at
 * most this request's lines — the accepted trade-off vs. a sync write per
 * attempt. WP-CLI fires shutdown at process end, so CLI lines flush too.
 *
 * @return array<int,string> Reference to the buffer.
 */
function &wldelay_get_fail2ban_buffer() {
    static $buffer = array();
    return $buffer;
}

/**
 * Test helper: empty the buffer between unit tests.
 */
function wldelay_reset_fail2ban_buffer() {
    $buffer = &wldelay_get_fail2ban_buffer();
    $buffer = array();
}

/**
 * Buffer a fail2ban-compatible log line for the shutdown flush.
 *
 * Same validation/enable gating as the old synchronous writer; only the file
 * write is deferred, and path/dir checks now happen at flush time (an unusable
 * path means buffered lines are dropped then, not rejected here).
 *
 * @param string      $event    Event key ('failed login'|'lockout').
 * @param string      $ip       IP address.
 * @param string      $username Attempted username.
 * @param string|null $source   Login source.
 * @return bool True when the line was buffered.
 */
function wldelay_buffer_fail2ban_line( $event, $ip, $username, $source = null ) {
    if ( ! function_exists( 'wldelay_get_options' ) ) {
        return false;
    }

    $options = wldelay_get_options();
    if ( ! wldelay_fail2ban_should_log_event( $event, $options ) ) {
        return false;
    }

    $line = wldelay_format_fail2ban_line( $event, $ip, $username, $source );
    if ( $line === '' ) {
        return false;
    }

    $buffer   = &wldelay_get_fail2ban_buffer();
    $buffer[] = $line;

    if ( count( $buffer ) === 1 && function_exists( 'add_action' ) ) {
        // Flush AFTER wldelay_flush_deferred_tasks (shutdown@10): deferred handlers
        // (m3 botnet task, any future deferred lockout) may buffer f2b lines during
        // the queue drain; flushing last keeps them from stranding in the buffer.
        add_action( 'shutdown', 'wldelay_flush_fail2ban_buffer', PHP_INT_MAX );
    }

    return true;
}

/**
 * Flush buffered fail2ban lines in a single locked append.
 *
 * Registered lazily on shutdown by the first buffered line. Path resolution,
 * directory protection, and rotation run once per flush instead of per line.
 *
 * @return int Lines written (0 when buffer empty or path unusable; buffered
 *             lines are DISCARDED when the path is unusable at flush time).
 */
function wldelay_flush_fail2ban_buffer() {
    $buffer = &wldelay_get_fail2ban_buffer();
    if ( empty( $buffer ) ) {
        return 0;
    }

    $lines  = $buffer;
    $buffer = array();

    $options = wldelay_get_options();
    $path    = isset( $options['wldelay_fail2ban_log_path'] )
        ? wldelay_fail2ban_resolve_log_path( $options['wldelay_fail2ban_log_path'] )
        : wldelay_fail2ban_resolve_log_path();

    if ( $path === '' ) {
        error_log( sprintf( 'Login Delay Shield: fail2ban flush dropped %d line(s): unresolvable log path.', count( $lines ) ) ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
        return 0;
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
        error_log( sprintf( 'Login Delay Shield: fail2ban flush dropped %d line(s): log directory not writable.', count( $lines ) ) ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
        return 0;
    }

    wldelay_fail2ban_protect_log_dir( $dir );
    wldelay_fail2ban_maybe_rotate_log( $path );

    $payload = implode( PHP_EOL, $lines ) . PHP_EOL;
    if ( false === @file_put_contents( $path, $payload, FILE_APPEND | LOCK_EX ) ) {
        error_log( sprintf( 'Login Delay Shield: fail2ban flush dropped %d line(s): write failed.', count( $lines ) ) ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
        return 0;
    }

    return count( $lines );
}

/**
 * Buffer a fail2ban-compatible log line when enabled.
 *
 * BC wrapper around wldelay_buffer_fail2ban_line() (F-4-5): the line is no
 * longer written synchronously — it is buffered and appended to the log in a
 * single locked write on the shutdown hook.
 *
 * @param string      $event Event key.
 * @param string      $ip IP address.
 * @param string      $username Attempted username.
 * @param string|null $source Login source.
 * @return bool True when a line was buffered (not yet written).
 */
function wldelay_write_fail2ban_log( $event, $ip, $username, $source = null ) {
    return wldelay_buffer_fail2ban_line( $event, $ip, $username, $source );
}
