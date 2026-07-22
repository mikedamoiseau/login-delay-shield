<?php
/**
 * Self-hosted login challenge providers.
 *
 * Activates the challenge-mode foundation shipped in v2.6.0
 * (wldelay-pipeline.php): once an IP crosses the failed-attempt threshold, the
 * login form presents a self-hosted challenge that must be solved before
 * credentials are checked. No third-party CAPTCHA.
 *
 * This file (M1) provides the provider library only — the abstract base, three
 * built-in providers, a filterable registry, and per-IP transient state. The
 * enforcement hooks that wire it into authentication live in M2.
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

        // Only mint + persist a new code when we can actually deliver one.
        // Generating a fresh hash on a rate-limited or failed send would
        // overwrite a previously delivered (working) code with one the user
        // never received, stranding them for the rest of the window.
        if ( '' !== $email && $sent < 5 ) {
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
                return array( 'answer' => wp_hash( $code ) );
            }
        }

        // Nothing delivered this round: preserve any prior email challenge so an
        // already-received code still verifies.
        $prior = wldelay_get_challenge_state( $ip );
        if ( isset( $prior['provider'], $prior['answer'] ) && 'email' === $prior['provider'] ) {
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
 * No-JS clients cannot solve it and are blocked by design (documented).
 */
class LDS_Pow_Challenge_Provider extends LDS_Challenge_Provider {

    const DIFFICULTY = 4;

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
        printf(
            '<p class="wldelay-pow-status" role="status" aria-live="polite">%s</p>',
            esc_html__( 'Verifying your browser…', 'wp-login-delay' )
        );

        $js = sprintf(
            "(function(){var C=%s,D=%d,f=document.getElementById('wldelay_challenge_response');"
            . "if(!f||!window.crypto||!crypto.subtle){return;}"
            . "var pfx=Array(D+1).join('0');"
            . "function h(s){return crypto.subtle.digest('SHA-256',new TextEncoder().encode(s)).then(function(b){"
            . "return Array.prototype.map.call(new Uint8Array(b),function(x){return('0'+x.toString(16)).slice(-2);}).join('');});}"
            . "var n=0;function step(){h(C+n).then(function(hx){if(hx.slice(0,D)===pfx){f.value=String(n);}else{n++;(n%%500===0)?setTimeout(step,0):step();}});}step();})();",
            wp_json_encode( $challenge ),
            $difficulty
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

    return is_array( $providers ) ? $providers : array();
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
