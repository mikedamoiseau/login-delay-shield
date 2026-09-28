<?php
/**
 * Self-hosted login challenge providers.
 *
 * Activates the challenge-mode foundation shipped in v2.6.0
 * (wldelay-pipeline.php): once an IP crosses the failed-attempt threshold, the
 * login form presents a self-hosted challenge that must be solved before
 * credentials are checked. No third-party CAPTCHA.
 *
 * Contents: the abstract provider base, three built-in providers, a filterable
 * registry, per-IP transient state, and the enforcement hooks that wire it into
 * authentication (the wp_authenticate_user gate, a late `authenticate` backstop
 * for non-interactive sources, the REST guard, and the login-form renderer).
 *
 * @package login-delay-shield
 */

defined( 'ABSPATH' ) || exit;

/**
 * Base class every challenge provider extends.
 */
abstract class LDS_Challenge_Provider {

    /** @return string Stable provider id (dropdown value). */
    abstract public function id();

    /** @return string Translated dropdown label. */
    abstract public function label();

    /**
     * Whether this provider can run for the given subject right now.
     *
     * @param string      $username Submitted username (may be '').
     * @param string|null $ip       Client IP.
     * @return bool
     */
    public function is_available( $username, $ip ) {
        return true;
    }

    /**
     * Create the challenge and return the state fragment to persist.
     *
     * @param string      $username Submitted username.
     * @param string|null $ip       Client IP.
     * @return array Provider-specific state (persisted verbatim; add 'answer' hash etc).
     */
    abstract public function issue( $username, $ip );

    /**
     * Echo the challenge form fields (WCAG AA).
     *
     * @param array $state Persisted state from issue().
     * @return void
     */
    abstract public function render( array $state );

    /**
     * Verify the submitted response against persisted state.
     *
     * @param string      $input    Submitted wldelay_challenge_response.
     * @param array       $state    Persisted state from issue().
     * @param string      $username Submitted username.
     * @param string|null $ip       Client IP.
     * @return bool
     */
    abstract public function verify( $input, array $state, $username, $ip );
}

/**
 * Default provider: server-side arithmetic question. Zero dependencies.
 */
class LDS_Math_Challenge_Provider extends LDS_Challenge_Provider {

    public function id() {
        return 'math';
    }

    public function label() {
        return __( 'Question / math', 'wp-login-delay' );
    }

    public function issue( $username, $ip ) {
        $a = (int) wp_rand( 1, 9 );
        $b = (int) wp_rand( 1, 9 );
        return array(
            'a'      => $a,
            'b'      => $b,
            'answer' => wp_hash( (string) ( $a + $b ) ),
        );
    }

    public function render( array $state ) {
        if ( ! isset( $state['a'], $state['b'] ) ) {
            return;
        }
        $question = sprintf(
            /* translators: %1$d and %2$d are single-digit numbers. */
            __( 'Security check — what is %1$d + %2$d?', 'wp-login-delay' ),
            (int) $state['a'],
            (int) $state['b']
        );
        printf(
            '<p><label for="wldelay_challenge_response">%1$s</label>'
            . '<input type="text" inputmode="numeric" autocomplete="off" class="input" '
            . 'id="wldelay_challenge_response" name="wldelay_challenge_response" value="" size="10" '
            . 'aria-describedby="wldelay_challenge_desc" /></p>',
            esc_html( $question )
        );
    }

    public function verify( $input, array $state, $username, $ip ) {
        if ( ! isset( $state['answer'] ) ) {
            return false;
        }
        return hash_equals( (string) $state['answer'], wp_hash( (string) trim( $input ) ) );
    }
}

/**
 * Email one-time-code provider. Self-hosted via wp_mail(); no third party.
 */
class LDS_Email_Challenge_Provider extends LDS_Challenge_Provider {

    public function id() {
        return 'email';
    }

    public function label() {
        return __( 'Email code', 'wp-login-delay' );
    }

    /**
     * Resolve the account email for a submitted username or email.
     *
     * @param string $username Submitted username.
     * @return string Resolved email or ''.
     */
    private function resolve_email( $username ) {
        $username = (string) $username;
        if ( '' === $username || ! function_exists( 'get_user_by' ) ) {
            return '';
        }
        $user = get_user_by( 'login', $username );
        if ( ! $user ) {
            $user = get_user_by( 'email', $username );
        }
        return ( $user instanceof WP_User ) ? (string) $user->user_email : '';
    }

    public function is_available( $username, $ip ) {
        return '' !== $this->resolve_email( $username );
    }

    public function issue( $username, $ip ) {
        $email  = $this->resolve_email( $username );
        $rl_key = 'wldelay_challenge_email_rl_' . substr( md5( (string) $ip ), 0, 20 );
        $sent   = (int) get_transient( $rl_key );

        // Also cap per recipient: the per-IP limit alone lets many IPs, each
        // over the threshold, take turns flooding one account owner's inbox.
        $to_key  = 'wldelay_challenge_email_to_' . substr( md5( strtolower( $email ) ), 0, 20 );
        $to_sent = (int) get_transient( $to_key );

        // Only mint + persist a new code when we can actually deliver one.
        // Generating a fresh hash on a rate-limited or failed send would
        // overwrite a previously delivered (working) code with one the user
        // never received, stranding them for the rest of the window.
        if ( '' !== $email && $sent < 5 && $to_sent < 5 ) {
            $code      = sprintf( '%06d', (int) wp_rand( 0, 999999 ) );
            $delivered = wp_mail(
                $email,
                __( 'Your login verification code', 'wp-login-delay' ),
                sprintf(
                    /* translators: %s is a 6-digit numeric code. */
                    __( 'Your login verification code is: %s', 'wp-login-delay' ),
                    $code
                )
            );
            if ( $delivered ) {
                set_transient( $rl_key, $sent + 1, 600 );
                set_transient( $to_key, $to_sent + 1, 600 );
                return array( 'answer' => wp_hash( $code ) );
            }
        }

        // Nothing delivered this round: preserve any prior email challenge so an
        // already-received code still verifies — but only when it was issued for
        // THIS account, so a code minted for another account on the same IP is
        // never reused.
        $prior = wldelay_get_challenge_state( $ip );
        if ( isset( $prior['provider'], $prior['answer'], $prior['user'] )
            && 'email' === $prior['provider']
            && hash_equals( (string) $prior['user'], (string) $username ) ) {
            return array( 'answer' => (string) $prior['answer'] );
        }

        // No prior code and none delivered: fail closed with an unmatchable
        // hash rather than accepting an empty or guessable answer.
        return array( 'answer' => wp_hash( wp_generate_password( 32, false ) ) );
    }

    public function render( array $state ) {
        printf(
            '<p><label for="wldelay_challenge_response">%1$s</label>'
            . '<input type="text" inputmode="numeric" autocomplete="one-time-code" class="input" '
            . 'id="wldelay_challenge_response" name="wldelay_challenge_response" value="" size="10" '
            . 'aria-describedby="wldelay_challenge_desc" /></p>',
            esc_html__( 'Enter the 6-digit code we emailed you', 'wp-login-delay' )
        );
    }

    public function verify( $input, array $state, $username, $ip ) {
        if ( ! isset( $state['answer'] ) ) {
            return false;
        }
        return hash_equals( (string) $state['answer'], wp_hash( (string) trim( $input ) ) );
    }
}

/**
 * Proof-of-work provider. Browser computes a SHA-256 nonce; no third party.
 * No-JS clients cannot solve it and are told so; on plain HTTP (no crypto.subtle)
 * the gate uses the math question instead — see wldelay_get_active_challenge_provider().
 */
class LDS_Pow_Challenge_Provider extends LDS_Challenge_Provider {

    const DIFFICULTY = 4;

    /**
     * Whether the login page is served in a browser secure context, where
     * crypto.subtle (needed to solve the challenge) exists: HTTPS, or a
     * localhost host, which browsers treat as secure over plain HTTP.
     *
     * @return bool
     */
    public static function is_secure_context() {
        if ( is_ssl() ) {
            return true;
        }
        $host = isset( $_SERVER['HTTP_HOST'] ) ? strtolower( sanitize_text_field( wp_unslash( $_SERVER['HTTP_HOST'] ) ) ) : '';
        $host = preg_replace( '/:\d+$/', '', $host );
        return 'localhost' === $host || '127.0.0.1' === $host || '[::1]' === $host
            || '.localhost' === substr( $host, -10 );
    }

    public function id() {
        return 'pow';
    }

    public function label() {
        return __( 'Proof of work', 'wp-login-delay' );
    }

    public function issue( $username, $ip ) {
        return array(
            'challenge'  => wp_generate_password( 16, false ),
            'difficulty' => self::DIFFICULTY,
        );
    }

    public function render( array $state ) {
        if ( ! isset( $state['challenge'], $state['difficulty'] ) ) {
            return;
        }
        $challenge  = (string) $state['challenge'];
        $difficulty = (int) $state['difficulty'];

        echo '<input type="hidden" id="wldelay_challenge_response" name="wldelay_challenge_response" value="" />';
        // Empty until the script runs, so a no-JS visitor sees only the
        // noscript notice below, not a "verifying" line that never finishes.
        echo '<p id="wldelay_pow_status" class="wldelay-pow-status" role="status" aria-live="polite"></p>';
        printf(
            '<noscript><p class="wldelay-pow-status">%s</p></noscript>',
            esc_html__( 'This security check needs JavaScript. Enable JavaScript in your browser, then reload this page.', 'wp-login-delay' )
        );

        // The status line is announced (aria-live) when the check finishes or
        // cannot run, and the sign-in button waits for a solution, so a quick
        // submit does not bounce back with a fresh challenge.
        $js = sprintf(
            "(function(){var C=%s,D=%d,M=%s,f=document.getElementById('wldelay_challenge_response'),"
            . "st=document.getElementById('wldelay_pow_status'),sb=document.getElementById('wp-submit');"
            . "if(!f){return;}"
            . "if(!window.crypto||!crypto.subtle||!window.TextEncoder){if(st){st.textContent=M.unsupported;}return;}"
            . "if(st){st.textContent=M.working;}if(sb){sb.disabled=true;}"
            . "var pfx=Array(D+1).join('0');"
            . "function h(s){return crypto.subtle.digest('SHA-256',new TextEncoder().encode(s)).then(function(b){"
            . "return Array.prototype.map.call(new Uint8Array(b),function(x){return('0'+x.toString(16)).slice(-2);}).join('');});}"
            . "function done(){f.value=String(n);if(st){st.textContent=M.done;}if(sb){sb.disabled=false;}}"
            . "function fail(){if(st){st.textContent=M.unsupported;}if(sb){sb.disabled=false;}}"
            . "var n=0;function step(){h(C+n).then(function(hx){if(hx.slice(0,D)===pfx){done();}else{n++;(n%%500===0)?setTimeout(step,0):step();}},fail);}step();})();",
            wp_json_encode( $challenge ),
            $difficulty,
            wp_json_encode(
                array(
                    'working'     => __( 'Verifying your browser…', 'wp-login-delay' ),
                    'done'        => __( 'Verification complete. You can sign in now.', 'wp-login-delay' ),
                    'unsupported' => __( 'Your browser cannot complete this security check. Please use a current browser.', 'wp-login-delay' ),
                )
            )
        );
        echo '<script>' . $js . '</script>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- literal JS with json-encoded challenge
    }

    public function verify( $input, array $state, $username, $ip ) {
        if ( ! isset( $state['challenge'], $state['difficulty'] ) ) {
            return false;
        }
        $nonce = trim( (string) $input );
        if ( '' === $nonce ) {
            return false;
        }
        $difficulty = (int) $state['difficulty'];
        $hash       = hash( 'sha256', (string) $state['challenge'] . $nonce );
        return 0 === strncmp( $hash, str_repeat( '0', $difficulty ), $difficulty );
    }
}

/**
 * Provider registry. Built-ins are registered THROUGH the same filter that
 * third parties use, so custom providers compose cleanly.
 *
 * @return LDS_Challenge_Provider[] Keyed by provider id.
 */
function wldelay_get_challenge_providers() {
    $providers = array(
        'math'  => new LDS_Math_Challenge_Provider(),
        'email' => new LDS_Email_Challenge_Provider(),
        'pow'   => new LDS_Pow_Challenge_Provider(),
    );

    /**
     * Filter the registered challenge providers.
     *
     * @param LDS_Challenge_Provider[] $providers Keyed by id.
     */
    $providers = apply_filters( 'wldelay_challenge_providers', $providers );

    // Drop anything a filter added that is not a provider, so callers (the
    // settings dropdown, sanitize, the gate) never call methods on junk.
    return is_array( $providers )
        ? array_filter(
            $providers,
            function ( $provider ) {
                return $provider instanceof LDS_Challenge_Provider;
            }
        )
        : array();
}

/**
 * Look up a provider by id.
 *
 * @param string $id Provider id.
 * @return LDS_Challenge_Provider|null
 */
function wldelay_get_challenge_provider( $id ) {
    $providers = wldelay_get_challenge_providers();
    return isset( $providers[ $id ] ) ? $providers[ $id ] : null;
}

/**
 * Resolve the configured active provider, falling back to math.
 *
 * @param array|null $options Optional options array.
 * @return LDS_Challenge_Provider
 */
function wldelay_get_active_challenge_provider( $options = null ) {
    if ( null === $options ) {
        $options = wldelay_get_options();
    }
    $id       = isset( $options['wldelay_challenge_mode_provider'] ) ? (string) $options['wldelay_challenge_mode_provider'] : 'math';
    $provider = wldelay_get_challenge_provider( $id );
    if ( ! $provider instanceof LDS_Challenge_Provider ) {
        $provider = wldelay_get_challenge_provider( 'math' );
    }
    // Proof of work needs crypto.subtle, which browsers only expose in a secure
    // context. On plain HTTP no browser can solve it, so every challenged user
    // would be stuck; present the math question instead.
    if ( $provider instanceof LDS_Pow_Challenge_Provider && ! LDS_Pow_Challenge_Provider::is_secure_context() ) {
        $provider = wldelay_get_challenge_provider( 'math' );
    }
    // Hard fallback: a filter that removed the built-in math provider must not
    // be able to make this return null and fatal the caller.
    if ( ! $provider instanceof LDS_Challenge_Provider ) {
        $provider = new LDS_Math_Challenge_Provider();
    }
    return $provider;
}

/**
 * Transient key for a client IP's active challenge state.
 *
 * @param string $ip Client IP.
 * @return string
 */
function wldelay_challenge_state_key( $ip ) {
    return 'wldelay_challenge_' . substr( md5( (string) $ip ), 0, 20 );
}

/**
 * Read the persisted challenge state for an IP.
 *
 * @param string $ip Client IP.
 * @return array Empty array when no state.
 */
function wldelay_get_challenge_state( $ip ) {
    $state = get_transient( wldelay_challenge_state_key( $ip ) );
    return is_array( $state ) ? $state : array();
}

/**
 * Persist challenge state for an IP (10-minute TTL).
 *
 * @param string $ip    Client IP.
 * @param array  $state State fragment.
 * @return void
 */
function wldelay_set_challenge_state( $ip, array $state ) {
    set_transient( wldelay_challenge_state_key( $ip ), $state, 600 );
}

/**
 * Clear challenge state for an IP.
 *
 * @param string $ip Client IP.
 * @return void
 */
function wldelay_clear_challenge_state( $ip ) {
    delete_transient( wldelay_challenge_state_key( $ip ) );
}

/**
 * Issue a challenge and persist its state (tagged with the provider id).
 *
 * @param LDS_Challenge_Provider $provider Active provider.
 * @param string                 $username Username.
 * @param string                 $ip       Client IP.
 * @return void
 */
function wldelay_issue_challenge( $provider, $username, $ip ) {
    $prior             = wldelay_get_challenge_state( $ip );
    $state             = (array) $provider->issue( $username, $ip );
    $state['provider'] = $provider->id();
    // Bind the challenge to the account it was issued for. State is per-IP, so
    // without this an attacker could clear account B's challenge with a code
    // minted for account A on the same IP.
    $state['user'] = (string) $username;
    // Carry the wrong-answer count across a re-issue for the same account and
    // provider. A provider may re-present the same answer (the email provider
    // does when it cannot send a new code); resetting the count on every blank
    // submission would let one code be guessed at indefinitely.
    if ( isset( $prior['fails'], $prior['user'], $prior['provider'] )
        && $prior['provider'] === $state['provider']
        && hash_equals( (string) $prior['user'], $state['user'] ) ) {
        $state['fails'] = (int) $prior['fails'];
    }
    wldelay_set_challenge_state( $ip, $state );
}

/**
 * The identity a challenge is keyed by: the submitted identity the failure
 * counter records.
 *
 * The login form posts it as `log`. XML-RPC posts no form fields, so it comes
 * from the username the current `authenticate` chain was started with —
 * the same value core later passes to wp_login_failed, which is what the counter
 * records. Keying XML-RPC by `log` read the IP-only counter and, under the
 * ip_username strategy, never matched.
 *
 * @return string Normalized username, or '' (the IP-only key).
 */
function wldelay_get_challenge_subject_username() {
    if ( isset( $_POST['log'] ) ) {
        return wldelay_get_requested_login_username();
    }

    return isset( $GLOBALS['wldelay_authenticate_username'] ) ? (string) $GLOBALS['wldelay_authenticate_username'] : '';
}

/**
 * Whether we are inside an `authenticate` chain started by wp_authenticate().
 *
 * A passed challenge is only remembered within one chain, so it can never carry
 * over to a later, separate authentication in the same request.
 *
 * @return bool
 */
function wldelay_in_authentication_chain() {
    return isset( $GLOBALS['wldelay_authenticate_username'] );
}

/**
 * Start of an `authenticate` chain: remember the submitted username and forget
 * any challenge passed during a previous chain in this request.
 *
 * @param null|WP_User|WP_Error $user     Auth result so far.
 * @param string                $username Submitted username.
 * @return null|WP_User|WP_Error Unchanged.
 */
function wldelay_challenge_begin_authentication( $user, $username ) {
    $GLOBALS['wldelay_authenticate_username'] = wldelay_normalize_username( (string) $username );
    unset( $GLOBALS['wldelay_challenge_passed_user'] );
    return $user;
}

/**
 * End of an `authenticate` chain: drop the per-chain state again.
 *
 * @param null|WP_User|WP_Error $user Auth result.
 * @return null|WP_User|WP_Error Unchanged.
 */
function wldelay_challenge_end_authentication( $user ) {
    unset( $GLOBALS['wldelay_authenticate_username'], $GLOBALS['wldelay_challenge_passed_user'] );
    return $user;
}

/**
 * Interactive + hard-block challenge gate.
 *
 * Hooks wp_authenticate_user, which core fires after the username resolves to a
 * WP_User but BEFORE wp_check_password(). Returning a WP_Error here stops
 * authentication without the password ever being checked, and cannot be
 * clobbered by core's later credential re-check (the `authenticate` filter
 * can). Password validity therefore never leaks: an over-threshold attacker is
 * met by the challenge whether or not the password is correct.
 *
 * @param WP_User|WP_Error $user     Resolved user (or a prior error).
 * @param string           $password Submitted password (unused; gate is pre-check).
 * @return WP_User|WP_Error
 */
function wldelay_challenge_authenticate_user( $user, $password ) {
    if ( ! ( $user instanceof WP_User ) ) {
        return $user;
    }

    // Already passed for this account earlier in this authentication chain.
    // When user_login is itself an email address, core resolves the account on
    // the username path AND on the email path and fires this filter on both.
    // The first pass consumed the solved challenge; re-challenging on the
    // second would turn the real result (a wrong password) into a gate
    // rejection that is never counted.
    if ( wldelay_in_authentication_chain() && isset( $GLOBALS['wldelay_challenge_passed_user'] ) && (int) $GLOBALS['wldelay_challenge_passed_user'] === (int) $user->ID ) {
        return $user;
    }

    // Key by the SUBMITTED identity — the exact value the failure counter is
    // recorded under, empty string included (which maps to the IP-only key).
    // Falling back to the resolved $user->user_login would query a different
    // key than the counter was recorded under: under the ip_username strategy
    // that both misses an email-address login and mismatches a request that
    // posted no username.
    $username = wldelay_get_challenge_subject_username();

    if ( ! wldelay_is_challenge_required( $username ) ) {
        return $user;
    }

    $source = wldelay_is_application_password_attempt()
        ? 'application-password'
        : wldelay_get_login_source();

    // Non-interactive entry points cannot render/complete a challenge: deny.
    if ( 'wp-login' !== $source ) {
        wldelay_mark_login_gate_rejection();
        return new WP_Error(
            'wldelay_challenge_required',
            __( 'Additional verification is required. Complete it on the login page.', 'wp-login-delay' )
        );
    }

    $ip       = wldelay_get_client_ip();
    $provider = wldelay_get_active_challenge_provider();

    if ( ! $provider->is_available( $username, $ip ) ) {
        wldelay_mark_login_gate_rejection();
        return new WP_Error(
            'wldelay_challenge_unavailable',
            __( 'Additional verification is required but cannot be completed for this account.', 'wp-login-delay' )
        );
    }

    $answer = isset( $_POST['wldelay_challenge_response'] )
        ? sanitize_text_field( wp_unslash( $_POST['wldelay_challenge_response'] ) )
        : '';
    $state = wldelay_get_challenge_state( $ip );

    // Issue a fresh challenge when there is none, when the pending one was
    // issued for a different account (per-IP state, bound to the account), or
    // when the active provider changed since issue (invalidate the stale one
    // rather than verifying it with a mismatched provider).
    $stale = empty( $state )
        || ! isset( $state['user'] ) || ! hash_equals( (string) $state['user'], (string) $username )
        || empty( $state['provider'] ) || $state['provider'] !== $provider->id();

    if ( '' === $answer || $stale ) {
        wldelay_issue_challenge( $provider, $username, $ip );
        wldelay_mark_login_gate_rejection();
        return new WP_Error(
            'wldelay_challenge_required',
            __( 'Security check required. Complete the verification below and sign in again.', 'wp-login-delay' )
        );
    }

    // Consume the single-use challenge before verifying, so a solved challenge
    // cannot be replayed across near-concurrent requests. (Transients offer no
    // atomic compare-and-delete, so a tiny residual race remains — layered
    // behind the delay and lockout that are already in force at this point.)
    wldelay_clear_challenge_state( $ip );

    if ( $provider->verify( $answer, $state, $username, $ip ) ) {
        if ( wldelay_in_authentication_chain() ) {
            $GLOBALS['wldelay_challenge_passed_user'] = (int) $user->ID;
        }
        return $user;
    }

    // Wrong answer: re-present the SAME challenge (restore the state consumed
    // above) rather than minting a new one, so an already-delivered email code
    // stays valid — but only for a bounded number of tries. After the cap the
    // challenge is abandoned (left consumed) so the next attempt mints a fresh
    // one, preventing a single 6-digit code from being ground indefinitely.
    // A *solved* challenge always stays consumed and cannot be replayed.
    $state['fails'] = isset( $state['fails'] ) ? (int) $state['fails'] + 1 : 1;
    if ( $state['fails'] < 5 ) {
        wldelay_set_challenge_state( $ip, $state );
    }
    return new WP_Error(
        'wldelay_challenge_failed',
        __( 'Verification failed. Please complete the security check below and try again.', 'wp-login-delay' )
    );
}

/**
 * Hard-block credentialed REST / application-password attempts that require a
 * challenge. Native Application Password auth runs on determine_current_user
 * and never fires the authenticate chain, so guard it here (mirrors the
 * country-block REST guard).
 *
 * @param null|bool|WP_Error $result Current REST auth result.
 * @return null|bool|WP_Error
 */
function wldelay_challenge_rest_authentication( $result ) {
    if ( is_wp_error( $result ) ) {
        return $result;
    }
    if ( ! wldelay_is_application_password_attempt() ) {
        return $result;
    }
    // A cookie-authenticated user is already signed in, not guessing
    // credentials. Behind ambient HTTP Basic auth (an htpasswd staging site)
    // every REST call carries PHP_AUTH_*, and without this the editor got 403
    // for as long as the IP stayed over the threshold. A user authenticated BY
    // an application password is still checked.
    if ( get_current_user_id() && ! ( function_exists( 'rest_get_authenticated_app_password' ) && rest_get_authenticated_app_password() ) ) {
        return $result;
    }
    // Key by the submitted PHP-auth username so the counter matches under the
    // ip_username strategy (an IP-only check would miss the IP|username key).
    if ( wldelay_is_challenge_required( wldelay_get_php_auth_username() ) ) {
        return new WP_Error(
            'wldelay_challenge_required',
            __( 'Additional verification is required. Complete it on the login page.', 'wp-login-delay' ),
            array( 'status' => 403 )
        );
    }
    return $result;
}

/**
 * Backstop the hard-block for XML-RPC after every other authenticator has run.
 *
 * The gate above lives on wp_authenticate_user, which core's application-
 * password authenticator (`authenticate` @20, XML-RPC and REST) never fires: it
 * validates the application password and returns the WP_User directly,
 * discarding the gate's rejection. So a valid XML-RPC application password from
 * an over-threshold IP got in. Same reasoning and priority as the country
 * block's late backstop. The login form is left to the gate (it presents the
 * challenge there); REST has its own guard above.
 *
 * @param null|WP_User|WP_Error $user     Auth result so far.
 * @param string                $username Submitted username.
 * @param string                $password Submitted password.
 * @return null|WP_User|WP_Error
 */
function wldelay_challenge_late_authentication( $user, $username, $password ) {
    if ( ! ( $user instanceof WP_User ) || ! wldelay_is_xmlrpc_request() ) {
        return $user;
    }

    if ( ! wldelay_is_challenge_required( wldelay_get_challenge_subject_username() ) ) {
        return $user;
    }

    wldelay_mark_login_gate_rejection();
    return new WP_Error(
        'wldelay_challenge_required',
        __( 'Additional verification is required. Complete it on the login page.', 'wp-login-delay' )
    );
}

/**
 * Render the active challenge's fields on the login form.
 *
 * @return void
 */
function wldelay_render_challenge_field() {
    $ip    = wldelay_get_client_ip();
    $state = wldelay_get_challenge_state( $ip );
    if ( empty( $state ) || empty( $state['provider'] ) ) {
        return;
    }
    $provider = wldelay_get_challenge_provider( $state['provider'] );
    if ( ! $provider instanceof LDS_Challenge_Provider ) {
        return;
    }
    echo '<div class="wldelay-challenge">';
    printf(
        '<p id="wldelay_challenge_desc" class="description">%s</p>',
        esc_html__( 'This extra step protects the account after repeated failed sign-ins.', 'wp-login-delay' )
    );
    $provider->render( $state );
    echo '</div>';
}

// Hook registration is guarded so the module can be required in the no-WP unit
// bootstrap without fatal (add_* are undefined there).
if ( function_exists( 'add_filter' ) ) {
    add_filter( 'authenticate', 'wldelay_challenge_begin_authentication', 0, 2 );
    add_filter( 'wp_authenticate_user', 'wldelay_challenge_authenticate_user', 10, 2 );
    add_filter( 'authenticate', 'wldelay_challenge_late_authentication', 9999, 3 );
    add_filter( 'authenticate', 'wldelay_challenge_end_authentication', PHP_INT_MAX );
    add_filter( 'rest_authentication_errors', 'wldelay_challenge_rest_authentication', 6 );
    add_action( 'login_form', 'wldelay_render_challenge_field' );
}
