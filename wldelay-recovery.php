<?php
/**
 * Emergency Recovery URL.
 *
 * Opt-in, time-boxed, unauthenticated URL that clears ONLY the caller's own IP
 * lockout — never grants access, never disables the shield. The raw token is
 * never stored; only its sha256 hash lives in wldelay_options. GET renders a
 * confirm landing page; the unlock fires from a nonce-protected POST so email/
 * AV link-scanner prefetches cannot trigger it. See the design doc for rationale.
 *
 * @package WP_Login_Delay
 */

defined( 'ABSPATH' ) || exit;

if ( ! defined( 'WLDELAY_RECOVERY_QUERY_VAR' ) ) {
	define( 'WLDELAY_RECOVERY_QUERY_VAR', 'wldelay_recovery' );
}
if ( ! defined( 'WLDELAY_RECOVERY_NAG_DAYS' ) ) {
	define( 'WLDELAY_RECOVERY_NAG_DAYS', 90 );
}
if ( ! defined( 'WLDELAY_RECOVERY_RL_MAX' ) ) {
	define( 'WLDELAY_RECOVERY_RL_MAX', 5 );
}
if ( ! defined( 'WLDELAY_RECOVERY_RL_WINDOW' ) ) {
	define( 'WLDELAY_RECOVERY_RL_WINDOW', 900 );
}
if ( ! defined( 'WLDELAY_RECOVERY_REVEAL_TTL' ) ) {
	define( 'WLDELAY_RECOVERY_REVEAL_TTL', 300 );
}

/**
 * Whether the recovery feature is switched on.
 *
 * @return bool
 */
function wldelay_recovery_is_enabled() {
	$options = wldelay_get_options();
	return ! empty( $options['wldelay_recovery_enabled'] );
}

/**
 * sha256 hex of a raw token.
 *
 * @param string $token Raw token.
 * @return string
 */
function wldelay_recovery_hash( $token ) {
	return hash( 'sha256', (string) $token );
}

/**
 * Constant-time check of a candidate token against the stored hash.
 *
 * @param string $token Candidate raw token.
 * @return bool
 */
function wldelay_recovery_token_matches( $token ) {
	$token = (string) $token;
	if ( '' === $token ) {
		return false;
	}
	$options = wldelay_get_options();
	$stored  = isset( $options['wldelay_recovery_token_hash'] ) ? (string) $options['wldelay_recovery_token_hash'] : '';
	if ( '' === $stored ) {
		return false;
	}
	return hash_equals( $stored, wldelay_recovery_hash( $token ) );
}

/**
 * Build the full recovery URL for a raw token.
 *
 * @param string $token Raw token.
 * @return string
 */
function wldelay_recovery_build_url( $token ) {
	return home_url( '/?' . WLDELAY_RECOVERY_QUERY_VAR . '=' . rawurlencode( $token ) );
}

/**
 * Generate a fresh token, store ONLY its hash + the generation timestamp, and
 * return the raw token (the only time it is ever available in plaintext).
 *
 * @return string Raw token.
 */
function wldelay_recovery_generate_token() {
	$token = bin2hex( random_bytes( 32 ) );

	$options = wldelay_get_options();
	$options['wldelay_recovery_token_hash']   = wldelay_recovery_hash( $token );
	$options['wldelay_recovery_generated_at'] = current_time( 'mysql', true );
	update_option( 'wldelay_options', $options );

	return $token;
}

/**
 * Age of the current token in whole days, or null when never generated.
 *
 * @return int|null
 */
function wldelay_recovery_generated_age_days() {
	$options = wldelay_get_options();
	$at      = isset( $options['wldelay_recovery_generated_at'] ) ? (string) $options['wldelay_recovery_generated_at'] : '';
	if ( '' === $at ) {
		return null;
	}
	$generated = strtotime( $at . ' UTC' );
	$now       = strtotime( current_time( 'mysql', true ) . ' UTC' );
	if ( ! $generated || ! $now || $now < $generated ) {
		return 0;
	}
	return (int) floor( ( $now - $generated ) / DAY_IN_SECONDS );
}

/**
 * Whether the token is old enough to nag the admin to rotate it.
 *
 * @return bool
 */
function wldelay_recovery_needs_rotation() {
	$age = wldelay_recovery_generated_age_days();
	return ( null !== $age && $age >= WLDELAY_RECOVERY_NAG_DAYS );
}

/**
 * Record a hit for the caller IP and report whether it has now exceeded the
 * allowed number of attempts inside the rolling window.
 *
 * @param string $ip Caller IP.
 * @return bool True when the caller is over the limit (should be refused).
 */
function wldelay_recovery_rate_limit_hit( $ip ) {
	$key   = 'wldelay_recovery_rl_' . md5( (string) $ip );
	$count = (int) get_transient( $key );
	$count++;
	set_transient( $key, $count, WLDELAY_RECOVERY_RL_WINDOW );
	return ( $count > WLDELAY_RECOVERY_RL_MAX );
}

/**
 * Stash the raw recovery URL for a short, one-time reveal window so the settings
 * page and the .txt download can show it right after generation. Never persisted
 * to options.
 *
 * @param int    $user_id Admin user id.
 * @param string $url     Full recovery URL.
 * @return void
 */
function wldelay_recovery_set_reveal( $user_id, $url ) {
	set_transient( 'wldelay_recovery_reveal_' . (int) $user_id, (string) $url, WLDELAY_RECOVERY_REVEAL_TTL );
}

/**
 * Read the one-time reveal URL for a user (null when absent/expired).
 *
 * @param int $user_id Admin user id.
 * @return string|null
 */
function wldelay_recovery_get_reveal( $user_id ) {
	$url = get_transient( 'wldelay_recovery_reveal_' . (int) $user_id );
	return ( is_string( $url ) && '' !== $url ) ? $url : null;
}

/**
 * Email the recovery URL to the site admin address.
 *
 * @param string $url Full recovery URL.
 * @return void
 */
function wldelay_recovery_send_email( $url ) {
	$blogname = wp_specialchars_decode( get_option( 'blogname' ), ENT_QUOTES );

	$subject = sprintf(
		/* translators: %s: site name. */
		__( '[%s] Your Login Delay Shield emergency recovery URL', 'wp-login-delay' ),
		$blogname
	);

	$message = sprintf(
		/* translators: 1: recovery URL. */
		__(
			'Save this emergency recovery URL somewhere safe and OUTSIDE this site (a password manager, a note on another device).

%1$s

If you are ever locked out of the login page, open this URL and confirm to clear the lockout for your current IP address. It does not log you in — you still sign in normally afterwards.

Anyone who has this URL can clear their own lockout, so treat it like a password. Regenerate it from Settings to invalidate this one.',
			'wp-login-delay'
		),
		$url
	);

	wp_mail( get_option( 'admin_email' ), $subject, $message );
}

/**
 * Admin URL that regenerates the recovery token.
 *
 * @return string
 */
function wldelay_recovery_generate_admin_url() {
	$url = add_query_arg(
		array( 'action' => 'wldelay_recovery_generate' ),
		admin_url( 'admin-post.php' )
	);
	return wp_nonce_url( $url, 'wldelay_recovery_generate' );
}

/**
 * Admin URL that downloads the once-revealed recovery URL as a .txt file.
 *
 * @return string
 */
function wldelay_recovery_download_admin_url() {
	$url = add_query_arg(
		array( 'action' => 'wldelay_recovery_download' ),
		admin_url( 'admin-post.php' )
	);
	return wp_nonce_url( $url, 'wldelay_recovery_download' );
}

/**
 * Handle the authed "generate / regenerate" action: mint a token, store its
 * hash, set the one-time reveal, email it, then redirect back to settings.
 *
 * @return void
 */
function wldelay_recovery_handle_generate() {
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_die( esc_html__( 'You are not allowed to perform this action.', 'wp-login-delay' ) );
	}
	check_admin_referer( 'wldelay_recovery_generate' );

	$token = wldelay_recovery_generate_token();
	$url   = wldelay_recovery_build_url( $token );

	wldelay_recovery_set_reveal( get_current_user_id(), $url );
	wldelay_recovery_send_email( $url );

	if ( function_exists( 'wldelay_audit_log' ) ) {
		wldelay_audit_log( 'recovery_url_generated', array( 'object' => 'recovery_url' ) );
	}

	$redirect = add_query_arg(
		array(
			'page'                 => 'login-delay-shield-admin',
			'wldelay_recovery_new' => '1',
		),
		admin_url( 'options-general.php' )
	);
	wp_safe_redirect( $redirect );

	if ( defined( 'WP_TESTS_DOMAIN' ) ) {
		return;
	}
	exit;
}
if ( function_exists( 'add_action' ) ) {
	add_action( 'admin_post_wldelay_recovery_generate', 'wldelay_recovery_handle_generate' );
}

/**
 * Handle the authed .txt download of the once-revealed recovery URL.
 *
 * @return void
 */
function wldelay_recovery_handle_download() {
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_die( esc_html__( 'You are not allowed to perform this action.', 'wp-login-delay' ) );
	}
	check_admin_referer( 'wldelay_recovery_download' );

	$url = wldelay_recovery_get_reveal( get_current_user_id() );
	if ( null === $url ) {
		wp_die( esc_html__( 'The recovery URL is no longer available to download. Regenerate it to get a fresh one.', 'wp-login-delay' ) );
	}

	$body = sprintf(
		"Login Delay Shield — Emergency Recovery URL\n\n%s\n\nKeep this somewhere safe and off this site. Opening it lets you clear the login lockout for your current IP. It does not log you in.\n",
		$url
	);

	nocache_headers();
	header( 'Content-Type: text/plain; charset=utf-8' );
	header( 'Content-Disposition: attachment; filename="login-delay-recovery-url.txt"' );
	header( 'Content-Length: ' . strlen( $body ) );

	if ( defined( 'WP_TESTS_DOMAIN' ) ) {
		return;
	}
	echo $body; // phpcs:ignore WordPress.Security.EscapeOutput -- plain-text file body.
	exit;
}
if ( function_exists( 'add_action' ) ) {
	add_action( 'admin_post_wldelay_recovery_download', 'wldelay_recovery_handle_download' );
}
