<?php
/**
 * Declarative test fixture builder for integration tests (F-2-5).
 *
 * Removes the per-test boilerplate that the auth-entry-point integration tests
 * repeat: option setup + cache clear, lockout creation, failed-attempt loops,
 * whitelist wiring and `$_SERVER` juggling. The builder drives the REAL
 * production functions and persistence store so the materialised state is
 * byte-for-byte what production would produce — there is no parallel
 * reimplementation of lockout/option logic that could drift.
 *
 * Usage:
 *
 *     WLDelay_Test_Fixture::make()
 *         ->with_current_ip( '192.168.1.100' )
 *         ->with_option( 'wldelay_lockout_enabled', true )
 *         ->with_lockout( '192.168.1.100' )
 *         ->apply();
 *
 * Teardown collapses to a single call:
 *
 *     WLDelay_Test_Fixture::reset();
 *
 * @package login-delay-shield
 */

defined( 'ABSPATH' ) || exit;

/**
 * Fluent builder that materialises plugin state for integration tests.
 */
class WLDelay_Test_Fixture {

    /**
     * Accumulated option overrides, merged into a single update_option() call.
     *
     * @var array<string,mixed>
     */
    private $options = array();

    /**
     * Registered lockouts to create on apply().
     *
     * Each entry: [ ip, username, duration, type, source ].
     *
     * @var array[]
     */
    private $lockouts = array();

    /**
     * Registered failed attempts to track on apply().
     *
     * Each entry: [ ip, username, count ].
     *
     * @var array[]
     */
    private $failed_attempts = array();

    /**
     * IP to assign to $_SERVER['REMOTE_ADDR'] on apply(), or null to leave it.
     *
     * @var string|null
     */
    private $current_ip = null;

    /**
     * Static factory.
     *
     * @return self New, empty fixture instance.
     */
    public static function make() {
        return new self();
    }

    /**
     * Set a single option override.
     *
     * @param string $key   Option key inside the wldelay_options array.
     * @param mixed  $value Value to store.
     * @return self
     */
    public function with_option( $key, $value ) {
        $this->options[ $key ] = $value;

        return $this;
    }

    /**
     * Merge in multiple option overrides at once.
     *
     * @param array<string,mixed> $opts Option overrides.
     * @return self
     */
    public function with_options( array $opts ) {
        $this->options = array_merge( $this->options, $opts );

        return $this;
    }

    /**
     * Register a lockout to create on apply().
     *
     * @param string $ip       IP address to lock.
     * @param string $username Username (empty for IP-only strategy).
     * @param int    $duration Lockout duration in seconds.
     * @param string $type     Lockout type ('login' or 'password-reset').
     * @param string $source   Originating source label.
     * @return self
     */
    public function with_lockout( $ip, $username = '', $duration = 900, $type = 'login', $source = 'wp-login' ) {
        $this->lockouts[] = array(
            'ip'       => $ip,
            'username' => $username,
            'duration' => (int) $duration,
            'type'     => $type,
            'source'   => $source,
        );

        return $this;
    }

    /**
     * Register N failed attempts to track on apply().
     *
     * @param string $ip       IP the attempts originate from.
     * @param string $username Username attempted.
     * @param int    $count    Number of attempts to record.
     * @return self
     */
    public function with_failed_attempt( $ip, $username = '', $count = 1 ) {
        $this->failed_attempts[] = array(
            'ip'       => $ip,
            'username' => $username,
            'count'    => (int) $count,
        );

        return $this;
    }

    /**
     * Convenience: enable the whitelist with the given IPs/CIDRs.
     *
     * @param array $ips List of IP addresses or CIDR ranges.
     * @return self
     */
    public function with_whitelist( array $ips ) {
        $this->options['wldelay_whitelist_enabled'] = true;
        $this->options['wldelay_whitelist_ips']     = implode( "\n", $ips );

        return $this;
    }

    /**
     * Set the current client IP via $_SERVER['REMOTE_ADDR'].
     *
     * @param string $ip IP address.
     * @return self
     */
    public function with_current_ip( $ip ) {
        $this->current_ip = $ip;

        return $this;
    }

    /**
     * Materialise all accumulated state by driving real production code.
     *
     * Order matters: the current IP and options are set first (lockout/tracking
     * functions read both), then lockouts, then failed-attempt loops.
     *
     * @return self
     */
    public function apply() {
        if ( null !== $this->current_ip ) {
            $_SERVER['REMOTE_ADDR'] = $this->current_ip;
        }

        if ( ! empty( $this->options ) ) {
            update_option( WLDELAY_OPTION_NAME, $this->options );
            wldelay_clear_options_cache();
        }

        foreach ( $this->lockouts as $lockout ) {
            $this->create_lockout( $lockout );
        }

        foreach ( $this->failed_attempts as $attempt ) {
            $this->track_attempts( $attempt );
        }

        return $this;
    }

    /**
     * Alias for apply() — some callers read more naturally as build().
     *
     * @return self
     */
    public function build() {
        return $this->apply();
    }

    /**
     * Create one registered lockout using real production paths.
     *
     * For login lockouts this drives wldelay_lock_ip() — the exact function
     * production uses — so the transient fast-path, the durable store row and
     * the recorded transient_key all match a real lockout. The requested
     * duration is honoured by setting wldelay_lockout_duration (the option
     * wldelay_lock_ip reads) for the lock and restoring it afterwards.
     *
     * For non-login types (e.g. password-reset) wldelay_lock_ip has no equivalent
     * entry point, so the lockout is written through the same store + transient
     * pair wldelay_lock_ip would use, keeping fixtures faithful.
     *
     * @param array $lockout Lockout spec (ip, username, duration, type, source).
     */
    private function create_lockout( array $lockout ) {
        $ip       = $lockout['ip'];
        $username = $lockout['username'];
        $duration = $lockout['duration'];
        $type     = $lockout['type'];
        $source   = $lockout['source'];

        if ( 'login' === $type ) {
            // Temporarily pin the duration option so wldelay_lock_ip uses the
            // requested duration, then restore it so the lock does not leak a
            // duration into later assertions.
            //
            // Production login lockouts are MINUTE-granular: wldelay_lock_ip()
            // reads wldelay_lockout_duration (minutes) via
            // wldelay_get_lockout_duration_seconds(), so a sub-minute login
            // lockout is not state production can create. The seconds duration
            // is therefore quantised to whole minutes here. Round UP (ceil) so
            // the materialised lockout is never SHORTER than requested — a
            // round-to-nearest could expire before the caller's duration and
            // make an expiry/boundary test exercise the wrong state. Callers
            // needing exact-second control should use a non-login type, whose
            // branch below honours the raw seconds.
            $options          = wldelay_get_options();
            $previous_minutes = isset( $options['wldelay_lockout_duration'] )
                ? $options['wldelay_lockout_duration']
                : null;

            $options['wldelay_lockout_duration'] = max( 1, (int) ceil( $duration / MINUTE_IN_SECONDS ) );
            update_option( WLDELAY_OPTION_NAME, $options );
            wldelay_clear_options_cache();

            wldelay_lock_ip( $ip, $username, $source );

            if ( null === $previous_minutes ) {
                unset( $options['wldelay_lockout_duration'] );
            } else {
                $options['wldelay_lockout_duration'] = $previous_minutes;
            }
            update_option( WLDELAY_OPTION_NAME, $options );
            wldelay_clear_options_cache();

            return;
        }

        // Non-login lockout: mirror wldelay_lock_ip's transient + durable write.
        // Select the transient-key builder by type so a password-reset fixture
        // sets the reset transient (wldelay_reset_lockout_*) production uses —
        // not the login transient, which would falsely lock the normal login
        // path while leaving the real reset path untouched.
        $transient_key = ( 'password-reset' === $type )
            ? wldelay_get_password_reset_lockout_transient_key( $ip, $username )
            : wldelay_get_lockout_transient_key( $ip, $username );
        set_transient( $transient_key, time(), $duration );
        wldelay_register_transient_key( $transient_key );

        wldelay_get_persistence_store()->add_lockout(
            $ip,
            wldelay_get_effective_lockout_username( $username ),
            $duration,
            $type,
            $source,
            $transient_key
        );
    }

    /**
     * Record N failed attempts for one spec using wldelay_track_failed_attempt().
     *
     * track_failed_attempt only increments when a feature that consumes the
     * counter is enabled (email / lockout / progressive). The fixture enables
     * lockout tracking for the duration of the loop if the test left every
     * counter-consuming feature off, so the requested count is always recorded,
     * then restores the prior options.
     *
     * @param array $attempt Attempt spec (ip, username, count).
     */
    private function track_attempts( array $attempt ) {
        if ( $attempt['count'] < 1 ) {
            return;
        }

        // track_failed_attempt() reads the client IP from REMOTE_ADDR, so the
        // attempt IP must be active for the loop. Save and restore the prior
        // value so seeding attempts from one IP never silently overrides the
        // fixture's declared with_current_ip() — otherwise the simulated
        // request would end up originating from the last attempt's IP.
        $had_remote_addr  = array_key_exists( 'REMOTE_ADDR', $_SERVER );
        $previous_remote  = $had_remote_addr ? $_SERVER['REMOTE_ADDR'] : null;

        $_SERVER['REMOTE_ADDR'] = $attempt['ip'];

        $options  = wldelay_get_options();
        $tracking = ! empty( $options['wldelay_email_enabled'] )
            || ! empty( $options['wldelay_lockout_enabled'] )
            || ! empty( $options['wldelay_progressive_enabled'] );

        if ( ! $tracking ) {
            // Enable lockout tracking with a threshold high enough that the
            // requested attempts never trip an actual lockout, so the counter is
            // recorded without changing observable lockout state.
            $restore = $options;
            $options['wldelay_lockout_enabled']   = true;
            $options['wldelay_lockout_threshold'] = $attempt['count'] + 1;
            update_option( WLDELAY_OPTION_NAME, $options );
            wldelay_clear_options_cache();

            for ( $i = 0; $i < $attempt['count']; $i++ ) {
                wldelay_track_failed_attempt( $attempt['username'] );
            }

            update_option( WLDELAY_OPTION_NAME, $restore );
            wldelay_clear_options_cache();
        } else {
            for ( $i = 0; $i < $attempt['count']; $i++ ) {
                wldelay_track_failed_attempt( $attempt['username'] );
            }
        }

        // Restore the IP the fixture declared (or remove the key if there was
        // none) so the final simulated request reflects with_current_ip().
        if ( $had_remote_addr ) {
            $_SERVER['REMOTE_ADDR'] = $previous_remote;
        } else {
            unset( $_SERVER['REMOTE_ADDR'] );
        }
    }

    /**
     * Reset all plugin state to a clean slate.
     *
     * Clears options + cache, every lockout/failure transient (registry +
     * DB-backed fallback), the persistent-store rows, the persistence
     * same-request cache, and the auth-related $_SERVER keys. A test's tearDown
     * collapses to a single call to this.
     */
    public static function reset() {
        // Transients first (the flush reads the registry option), then options.
        if ( function_exists( 'wldelay_flush_lockout_transients' ) ) {
            wldelay_flush_lockout_transients();
        }

        if ( function_exists( 'wldelay_get_persistence_store' ) ) {
            wldelay_get_persistence_store()->clear_all();
        }

        if ( function_exists( 'wldelay_reset_persistence_runtime_cache' ) ) {
            wldelay_reset_persistence_runtime_cache();
        }

        delete_option( WLDELAY_OPTION_NAME );

        if ( function_exists( 'wldelay_clear_options_cache' ) ) {
            wldelay_clear_options_cache();
        }

        unset(
            $_SERVER['REMOTE_ADDR'],
            $_SERVER['HTTP_X_FORWARDED_FOR'],
            $_SERVER['HTTP_CLIENT_IP'],
            $_POST['log']
        );
    }
}
