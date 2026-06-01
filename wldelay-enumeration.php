<?php
/**
 * Username-enumeration hardening (F-3-5).
 *
 * Gated behind the `wldelay_enumeration_hardening_enabled` option (default
 * OFF). When enabled this module:
 *
 *   1. Collapses distinct login errors (unknown username vs wrong password)
 *      into a single generic message so attackers cannot tell which usernames
 *      exist. Hooked on `login_errors` — a one-time output filter that fires
 *      only when the login screen renders an error, NOT on the per-attempt
 *      delay/lockout hot path.
 *   2. Blocks `?author=N` / author-archive enumeration for unauthenticated
 *      visitors. Hooked on `template_redirect`.
 *   3. Removes the unauthenticated `GET` handlers for both the
 *      `/wp/v2/users` collection and the `/wp/v2/users/<id>` single-user
 *      route (the latter is publicly readable for authors with published
 *      posts, so it leaks names/slugs on its own). Hooked on `rest_endpoints`
 *      (runs once when routes are built).
 *
 * Whitelist interaction: these guards are GLOBAL recon defenses, not per-IP
 * access controls. Generic login errors are site-wide UX; the author and REST
 * guards protect the public attack surface regardless of source IP. The IP
 * whitelist (which bypasses per-IP delay/lockout) therefore deliberately does
 * NOT exempt these guards — a whitelisted IP still gets generic errors and the
 * blocked author/REST surface.
 *
 * @package login-delay-shield
 */

defined( 'ABSPATH' ) || exit;

/**
 * Whether username-enumeration hardening is enabled.
 *
 * @return bool
 */
function wldelay_enumeration_hardening_is_active() {
    $options = wldelay_get_options();
    return ! empty( $options['wldelay_enumeration_hardening_enabled'] );
}

/**
 * The single generic login-error message shown for every failed login when
 * hardening is enabled.
 *
 * Pure helper (no WordPress runtime dependency beyond the translation
 * function) so it is unit-testable. Intentionally reveals neither the username
 * nor the password field.
 *
 * @return string
 */
function wldelay_get_generic_login_error_message() {
    return __( 'Error: Invalid login credentials.', 'login-delay-shield' );
}

/**
 * Collapse all login errors into one generic message.
 *
 * WordPress core emits distinct messages/codes for unknown usernames
 * (`invalid_username` / `incorrect_username`) and wrong passwords
 * (`incorrect_password`), which leaks which accounts exist. This filter
 * replaces any non-empty error string with a single neutral message.
 *
 * Empty strings (e.g. logout/expired-session confirmations that are not
 * authentication failures) are passed through untouched.
 *
 * @param string $error_message The HTML error message about to be shown.
 * @return string
 */
function wldelay_filter_login_errors( $error_message ) {
    if ( ! wldelay_enumeration_hardening_is_active() ) {
        return $error_message;
    }

    // Nothing to genericize — leave informational/empty messages alone.
    if ( ! is_string( $error_message ) || '' === trim( $error_message ) ) {
        return $error_message;
    }

    return wldelay_get_generic_login_error_message();
}

/**
 * Decide whether the current request is an unauthenticated author-enumeration
 * attempt that should be blocked.
 *
 * Returns true when hardening is active, the visitor is not logged in, and the
 * request resolves to an author archive (either `?author=N` or a pretty author
 * permalink). Logged-in users keep author archives for legitimate use.
 *
 * @return bool
 */
function wldelay_should_block_author_enumeration() {
    if ( ! wldelay_enumeration_hardening_is_active() ) {
        return false;
    }

    // Authenticated users are not the recon target; allow author archives.
    if ( is_user_logged_in() ) {
        return false;
    }

    // `?author=N` sets the `author` query var; pretty permalinks resolve to an
    // author archive. Cover both.
    $author_qv = get_query_var( 'author' );
    if ( '' !== $author_qv && null !== $author_qv ) {
        return true;
    }

    $author_name_qv = get_query_var( 'author_name' );
    if ( '' !== $author_name_qv && null !== $author_name_qv ) {
        return true;
    }

    if ( function_exists( 'is_author' ) && is_author() ) {
        return true;
    }

    return false;
}

/**
 * Serve a 404 instead of redirecting `?author=N` to the author archive slug.
 *
 * Hooked on `template_redirect`. This is a one-time per-request guard, not
 * per-login-attempt work.
 *
 * @return void
 */
function wldelay_block_author_enumeration() {
    if ( ! wldelay_should_block_author_enumeration() ) {
        return;
    }

    global $wp_query;
    if ( isset( $wp_query ) && is_object( $wp_query ) ) {
        $wp_query->set_404();
    }

    status_header( 404 );
    nocache_headers();

    $template = function_exists( 'get_404_template' ) ? get_404_template() : '';
    if ( $template && file_exists( $template ) ) {
        include $template;
    } else {
        echo '<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><h1>Not Found</h1></body></html>';
    }

    // Allow the integration test harness to continue instead of killing PHP.
    if ( defined( 'WP_TESTS_DOMAIN' ) ) {
        return;
    }

    exit;
}

/**
 * Restrict the unauthenticated REST users endpoints.
 *
 * Removes the `GET` handler from BOTH the `/wp/v2/users` collection route and
 * the `/wp/v2/users/<id>` single-user route for visitors who cannot already
 * `list_users`. The single-user route is publicly readable for any author with
 * published posts, so leaving it in place keeps usernames/slugs enumerable one
 * id at a time even after the collection route is removed. Authenticated,
 * capable users keep full access. Hooked on `rest_endpoints`, which fires once
 * while routes are assembled — not on the per-attempt path.
 *
 * @param array $endpoints REST endpoints, keyed by route.
 * @return array
 */
function wldelay_restrict_rest_user_endpoints( $endpoints ) {
    if ( ! wldelay_enumeration_hardening_is_active() ) {
        return $endpoints;
    }

    // Users who may list users (admins) are not enumeration risks.
    if ( current_user_can( 'list_users' ) ) {
        return $endpoints;
    }

    // Both the collection and the numeric single-user route leak account data
    // to the public; the `/wp/v2/users/me` route (a different key) is left
    // untouched because it only ever reflects the current, authenticated user.
    $routes = array(
        '/wp/v2/users',
        '/wp/v2/users/(?P<id>[\d]+)',
    );

    foreach ( $routes as $route ) {
        if ( empty( $endpoints[ $route ] ) ) {
            continue;
        }

        foreach ( $endpoints[ $route ] as $index => $handler ) {
            if ( ! isset( $handler['methods'] ) ) {
                continue;
            }

            // Drop only the read (GET) handler so the public cannot enumerate
            // users; leave other methods (e.g. POST/create) intact.
            $methods = $handler['methods'];
            $is_get  = ( is_array( $methods ) && ! empty( $methods['GET'] ) )
                || ( is_string( $methods ) && false !== stripos( $methods, 'GET' ) );

            if ( $is_get ) {
                unset( $endpoints[ $route ][ $index ] );
            }
        }

        // If the route has no handlers left, remove it entirely so core does
        // not register an empty route.
        if ( empty( $endpoints[ $route ] ) ) {
            unset( $endpoints[ $route ] );
        }
    }

    return $endpoints;
}

// Register guards only in a real WordPress runtime. The unit-test bootstrap
// loads this file without WordPress (no add_action), so guard the hooks.
if ( function_exists( 'add_filter' ) ) {
    add_filter( 'login_errors', 'wldelay_filter_login_errors', 20 );
    add_action( 'template_redirect', 'wldelay_block_author_enumeration', 0 );
    add_filter( 'rest_endpoints', 'wldelay_restrict_rest_user_endpoints', 20 );
}
