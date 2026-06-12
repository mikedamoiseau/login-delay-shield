<?php
/**
 * Shared failed-authentication pipeline (F-2-4).
 *
 * Single chokepoint for every auth entry point's failure handling: gate
 * (safe mode / whitelist / missing IP), progressive-delay computation, failure
 * tracking, DB + fail2ban logging, and the `failed_attempt` event that feeds
 * cross-request detection (F-1-9).
 *
 * Entry points keep their hook signatures, WP_Error shaping, and sleep()
 * placement — the pipeline returns data, it never blocks or sleeps.
 *
 * @package login-delay-shield
 */

defined( 'ABSPATH' ) || exit;

/**
 * Process a failed authentication attempt through the shared pipeline.
 *
 * @param string $username Normalized username (may be '').
 * @param string $source   Entry point: wp-login|xmlrpc|rest|application-password|password-reset.
 * @param array  $context  {
 *     Optional step toggles, matching each entry point's historical behavior.
 *
 *     @type bool $track   Increment the failure counter (email/lockout thresholds). Default true.
 *     @type bool $log     Insert into the login log and emit `failed_attempt`. Default true.
 *     @type bool $delay   Compute the progressive delay value. Default true.
 *     @type bool $lockout Look up the post-attempt lockout state. Default true.
 * }
 * @return array {
 *     @type bool   $processed       False when gated; no side effects occurred.
 *     @type string $ip              Client IP ('' when gated).
 *     @type int    $failed_attempts Post-increment counter (0 when tracking skipped).
 *     @type int    $delay           Seconds the caller should sleep (0 when skipped).
 *     @type bool   $locked          Lockout state after this attempt. Always false when the lockout lookup is skipped.
 * }
 */
function wldelay_process_failed_attempt( $username, $source, $context = array() ) {
    $context = array_merge(
        array(
            'track'   => true,
            'log'     => true,
            'delay'   => true,
            'lockout' => true,
        ),
        (array) $context
    );

    $result = array(
        'processed'       => false,
        'ip'              => '',
        'failed_attempts' => 0,
        'delay'           => 0,
        'locked'          => false,
    );

    if ( wldelay_is_safe_mode() || wldelay_is_ip_whitelisted() ) {
        return $result;
    }

    $ip = wldelay_get_client_ip();
    if ( empty( $ip ) ) {
        return $result;
    }

    $result['processed'] = true;
    $result['ip']        = $ip;

    if ( $context['delay'] ) {
        // Pre-increment count: progressive delay reflects attempts BEFORE this one.
        $failure_count   = wldelay_get_failure_count( null, $username );
        $delay           = wldelay_get_delay_value( $failure_count );
        $result['delay'] = empty( $delay ) ? LDS_Settings::_DEFAULT_DELAY_IN_SECONDS : $delay;
    }

    if ( $context['track'] ) {
        $result['failed_attempts'] = wldelay_track_failed_attempt( $username, $source );
    }

    if ( $context['log'] ) {
        wldelay_log_failed_attempt( $ip, $username, $source );

        // Tracked paths report the post-increment count; untracked paths read
        // the current counter so the event contract is consistent either way.
        $event_attempts = $context['track']
            ? $result['failed_attempts']
            : (int) wldelay_get_failure_count( null, $username );

        wldelay_emit_event(
            'failed_attempt',
            array(
                'ip'              => $ip,
                'username'        => (string) $username,
                'source'          => (string) $source,
                'failed_attempts' => $event_attempts,
            )
        );
    }

    if ( $context['lockout'] ) {
        $options          = wldelay_get_options();
        $result['locked'] = ! empty( $options['wldelay_lockout_enabled'] )
            && wldelay_is_ip_locked( null, $username );
    }

    return $result;
}
