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
