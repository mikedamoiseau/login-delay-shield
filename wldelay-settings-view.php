<?php
if ( ! defined( 'ABSPATH' ) ) exit;

/**
 * Build the "Learn more" documentation URL for a settings feature card (F-5-6).
 *
 * Each feature card's primary tooltip links to the matching section anchor in
 * the public user guide. The base URL is filterable via `wldelay_help_base_url`
 * so it can be repointed (self-hosted docs, white-label) or disabled entirely —
 * returning an empty string from the filter suppresses every doc link.
 *
 * The `$section` argument is matched against a fixed whitelist (which equals the
 * anchor id), so a typo or arbitrary value yields no link rather than a broken
 * one. Keep this list in sync with the section ids on the user-guide page.
 *
 * @param string $section Feature key / user-guide anchor id.
 * @return string Absolute doc URL, or '' when disabled or unknown.
 */
function wldelay_get_doc_url( $section ) {
    /**
     * Filter the base URL for in-plugin "Learn more" documentation links.
     *
     * Return an empty string to disable all doc links.
     *
     * @param string $base_url Trailing-slashed user-guide base URL.
     */
    $base = apply_filters( 'wldelay_help_base_url', 'https://damoiseau.xyz/docs/login-delay-shield/user-guide/' );

    if ( ! is_string( $base ) || '' === trim( $base ) ) {
        return '';
    }

    $anchors = array(
        'delay-settings',
        'progressive-delay',
        'email-notifications',
        'ip-lockout',
        'lockout-strategy',
        'ip-whitelist',
        'login-log',
        'fail2ban',
        'xmlrpc-protection',
        'rest-api-protection',
        'custom-login-url',
        'distributed-attack',
    );

    if ( ! in_array( $section, $anchors, true ) ) {
        return '';
    }

    return trailingslashit( $base ) . '#' . $section;
}

/**
 * Handles all rendering/view logic for the settings page
 */
class LDS_Settings_View {
    /**
     * Options array passed from settings class
     */
    private $options;

    /**
     * Set the options for rendering
     *
     * @param array $options Plugin options
     */
    public function set_options( $options ) {
        $this->options = $options;
    }

    /**
     * Counter for generating unique tooltip IDs
     */
    private static $tooltip_counter = 0;

    /**
     * Render a tooltip icon with hover text
     * Accessible via keyboard focus and screen readers
     *
     * @param string $text The tooltip text to display
     * @return string HTML for the tooltip
     */
    private function tooltip( $text, $help_url = '' ) {
        self::$tooltip_counter++;
        $tooltip_id = 'wldelay-tooltip-' . self::$tooltip_counter;

        $learn_more = '';
        if ( $help_url !== '' ) {
            $learn_more = sprintf(
                ' <a href="%s" class="wldelay-tooltip-learn-more" target="_blank" rel="noopener noreferrer">%s <span class="dashicons dashicons-external" aria-hidden="true"></span></a>',
                esc_url( $help_url ),
                esc_html__( 'Learn more', 'wp-login-delay' )
            );
        }

        return sprintf(
            '<span class="wldelay-tooltip" tabindex="0" aria-describedby="%s">' .
            '<span class="dashicons dashicons-editor-help" aria-hidden="true"></span>' .
            '<span class="screen-reader-text">%s</span>' .
            '<span id="%s" class="wldelay-tooltip-text" role="tooltip">%s%s</span>' .
            '</span>',
            esc_attr( $tooltip_id ),
            esc_html__( 'Help', 'wp-login-delay' ),
            esc_attr( $tooltip_id ),
            esc_html( $text ),
            $learn_more
        );
    }

    /**
     * Render the admin page
     */
    public function render() {
        ?>
        <div class="wrap wldelay-wrap">
            <h1>Login Delay Shield Settings</h1>

            <?php echo $this->render_summary_box(); ?>
            <?php $this->render_2fa_health_notice(); ?>
            <?php $this->render_proxy_health_notice(); ?>
            <?php $this->render_enumeration_hardening_notice(); ?>
            <?php $this->render_object_cache_notice(); ?>

            <form id="wldelay-telemetry-filter-form" method="get" action="<?php echo esc_url( admin_url( 'options-general.php' ) ); ?>"></form>
            <form id="wldelay-audit-filter-form" method="get" action="<?php echo esc_url( admin_url( 'options-general.php' ) ); ?>"></form>

            <form method="post" action="options.php">
                <?php settings_fields( 'wldelay_option_group' ); ?>

                <?php $this->render_setup_wizard(); ?>

                <div class="wldelay-card">
                    <h2 class="wldelay-card-header" role="button" tabindex="0" aria-expanded="true" aria-controls="wldelay-delay-body">
                        <span class="dashicons dashicons-clock" aria-hidden="true"></span>
                        <?php esc_html_e( 'Delay Settings', 'wp-login-delay' ); ?>
                        <span class="dashicons dashicons-arrow-down-alt2 wldelay-toggle" aria-hidden="true"></span>
                    </h2>
                    <div id="wldelay-delay-body" class="wldelay-card-body">
                        <?php $this->do_settings_section_fields( 'wldelay_setting_section_id' ); ?>
                    </div>
                </div>

                <div class="wldelay-grid">
                    <div class="wldelay-card">
                        <h2 class="wldelay-card-header" role="button" tabindex="0" aria-expanded="true" aria-controls="wldelay-email-body">
                            <span class="dashicons dashicons-email-alt" aria-hidden="true"></span>
                            <?php esc_html_e( 'Email Notifications', 'wp-login-delay' ); ?>
                            <?php echo $this->get_status_badge( 'wldelay_email_enabled', __( 'Email Notifications', 'wp-login-delay' ) ); ?>
                            <span class="dashicons dashicons-arrow-down-alt2 wldelay-toggle" aria-hidden="true"></span>
                        </h2>
                        <div id="wldelay-email-body" class="wldelay-card-body">
                            <p class="description"><?php esc_html_e( 'Receive email alerts when multiple failed login attempts are detected from the same IP address.', 'wp-login-delay' ); ?></p>
                            <?php $this->do_settings_section_fields( 'wldelay_email_section_id' ); ?>
                        </div>
                    </div>

                    <div class="wldelay-card">
                        <h2 class="wldelay-card-header" role="button" tabindex="0" aria-expanded="true" aria-controls="wldelay-lockout-body">
                            <span class="dashicons dashicons-lock" aria-hidden="true"></span>
                            <?php esc_html_e( 'IP Lockout', 'wp-login-delay' ); ?>
                            <?php echo $this->get_status_badge( 'wldelay_lockout_enabled', __( 'IP Lockout', 'wp-login-delay' ) ); ?>
                            <span class="dashicons dashicons-arrow-down-alt2 wldelay-toggle" aria-hidden="true"></span>
                        </h2>
                        <div id="wldelay-lockout-body" class="wldelay-card-body">
                            <p class="description"><?php esc_html_e( 'Temporarily block repeated failed login attempts by IP address or by IP + username.', 'wp-login-delay' ); ?></p>
                            <?php $this->do_settings_section_fields( 'wldelay_lockout_section_id' ); ?>
                            <p>
                                <a class="button button-secondary" href="<?php echo esc_url( wldelay_get_unlock_current_ip_url() ); ?>">
                                    <?php esc_html_e( 'Unlock Current IP', 'wp-login-delay' ); ?>
                                </a>
                            </p>
                            <p class="description" id="wldelay_unlock_current_ip_desc">
                                <?php esc_html_e( 'Emergency recovery: remove lockout for your current IP address.', 'wp-login-delay' ); ?>
                            </p>
                        </div>
                    </div>

                    <div class="wldelay-card">
                        <h2 class="wldelay-card-header" role="button" tabindex="0" aria-expanded="false" aria-controls="wldelay-recovery-body">
                            <span class="dashicons dashicons-sos" aria-hidden="true"></span>
                            <?php esc_html_e( 'Emergency Recovery URL', 'wp-login-delay' ); ?>
                            <?php echo $this->get_status_badge( 'wldelay_recovery_enabled', __( 'Emergency Recovery URL', 'wp-login-delay' ) ); ?>
                            <span class="dashicons dashicons-arrow-down-alt2 wldelay-toggle" aria-hidden="true"></span>
                        </h2>
                        <div id="wldelay-recovery-body" class="wldelay-card-body">
                            <p class="description">
                                <?php esc_html_e( 'A secret URL you can open if you are ever locked out with no admin or server access. It clears the lockout for your current IP only — it never logs you in or disables protection.', 'wp-login-delay' ); ?>
                            </p>
                            <?php $this->do_settings_section_fields( 'wldelay_recovery_section_id' ); ?>

                            <?php
                            $reveal    = function_exists( 'wldelay_recovery_get_reveal' ) ? wldelay_recovery_get_reveal( get_current_user_id() ) : null;
                            $has_token = ! empty( wldelay_get_options()['wldelay_recovery_token_hash'] );
                            ?>

                            <?php if ( null !== $reveal ) : ?>
                                <div class="notice notice-warning inline" role="region" aria-label="<?php esc_attr_e( 'New recovery URL', 'wp-login-delay' ); ?>">
                                    <p><strong><?php esc_html_e( 'Copy this URL now — it is shown only once.', 'wp-login-delay' ); ?></strong></p>
                                    <p>
                                        <input type="text" readonly class="large-text code" id="wldelay-recovery-url" value="<?php echo esc_attr( $reveal ); ?>" onclick="this.select()">
                                    </p>
                                    <p>
                                        <button type="button" class="button" id="wldelay-recovery-copy" data-target="wldelay-recovery-url"><?php esc_html_e( 'Copy to clipboard', 'wp-login-delay' ); ?></button>
                                        <a class="button" href="<?php echo esc_url( wldelay_recovery_download_admin_url() ); ?>"><?php esc_html_e( 'Download as .txt', 'wp-login-delay' ); ?></a>
                                    </p>
                                    <p class="description"><?php esc_html_e( 'A copy has also been emailed to the site admin address.', 'wp-login-delay' ); ?></p>
                                </div>
                            <?php endif; ?>

                            <?php if ( $has_token ) : ?>
                                <?php $age = wldelay_recovery_generated_age_days(); ?>
                                <p class="description" aria-live="polite">
                                    <?php
                                    printf(
                                        /* translators: %d: number of days. */
                                        esc_html__( 'Active — generated %d day(s) ago.', 'wp-login-delay' ),
                                        (int) $age
                                    );
                                    ?>
                                </p>
                                <?php if ( wldelay_recovery_needs_rotation() ) : ?>
                                    <p class="notice notice-warning inline" aria-live="polite">
                                        <?php
                                        printf(
                                            /* translators: %d: nag threshold in days. */
                                            esc_html__( 'This recovery URL is over %d days old. Regenerate it for safety.', 'wp-login-delay' ),
                                            (int) WLDELAY_RECOVERY_NAG_DAYS
                                        );
                                        ?>
                                    </p>
                                <?php endif; ?>
                            <?php endif; ?>

                            <p>
                                <a class="button button-secondary" href="<?php echo esc_url( wldelay_recovery_generate_admin_url() ); ?>">
                                    <?php echo $has_token ? esc_html__( 'Regenerate recovery URL', 'wp-login-delay' ) : esc_html__( 'Generate recovery URL', 'wp-login-delay' ); ?>
                                </a>
                            </p>
                            <p class="description"><?php esc_html_e( 'Regenerating immediately invalidates the previous URL.', 'wp-login-delay' ); ?></p>
                        </div>
                    </div>

                    <div class="wldelay-card">
                        <h2 class="wldelay-card-header" role="button" tabindex="0" aria-expanded="true" aria-controls="wldelay-whitelist-body">
                            <span class="dashicons dashicons-shield-alt" aria-hidden="true"></span>
                            <?php esc_html_e( 'IP Whitelist', 'wp-login-delay' ); ?>
                            <?php echo $this->get_status_badge( 'wldelay_whitelist_enabled', __( 'IP Whitelist', 'wp-login-delay' ) ); ?>
                            <span class="dashicons dashicons-arrow-down-alt2 wldelay-toggle" aria-hidden="true"></span>
                        </h2>
                        <div id="wldelay-whitelist-body" class="wldelay-card-body">
                            <p class="description"><?php esc_html_e( 'Skip delay and lockout for trusted IP addresses (e.g., office, VPN).', 'wp-login-delay' ); ?></p>
                            <?php $this->do_settings_section_fields( 'wldelay_whitelist_section_id' ); ?>
                        </div>
                    </div>

                    <div class="wldelay-card">
                        <h2 class="wldelay-card-header" role="button" tabindex="0" aria-expanded="true" aria-controls="wldelay-log-body">
                            <span class="dashicons dashicons-list-view" aria-hidden="true"></span>
                            <?php esc_html_e( 'Login Log', 'wp-login-delay' ); ?>
                            <?php echo $this->get_status_badge( 'wldelay_fail2ban_enabled', __( 'fail2ban Logging', 'wp-login-delay' ) ); ?>
                            <span class="dashicons dashicons-arrow-down-alt2 wldelay-toggle" aria-hidden="true"></span>
                        </h2>
                        <div id="wldelay-log-body" class="wldelay-card-body">
                            <p class="description"><?php esc_html_e( 'Failed login attempts are logged and displayed in the dashboard widget.', 'wp-login-delay' ); ?></p>
                            <?php $this->do_settings_section_fields( 'wldelay_log_section_id' ); ?>
                            <?php $this->render_login_log_telemetry(); ?>
                        </div>
                    </div>

                    <div class="wldelay-card">
                        <h2 class="wldelay-card-header" role="button" tabindex="0" aria-expanded="true" aria-controls="wldelay-audit-body">
                            <span class="dashicons dashicons-shield" aria-hidden="true"></span>
                            <?php esc_html_e( 'Audit Log', 'wp-login-delay' ); ?>
                            <span class="dashicons dashicons-arrow-down-alt2 wldelay-toggle" aria-hidden="true"></span>
                        </h2>
                        <div id="wldelay-audit-body" class="wldelay-card-body">
                            <p class="description"><?php esc_html_e( 'A read-only record of sensitive administrative actions — settings changes, manual unlocks, and whitelist edits — for compliance and forensic review.', 'wp-login-delay' ); ?></p>
                            <?php $this->render_audit_log(); ?>
                        </div>
                    </div>

                    <div class="wldelay-card">
                        <h2 class="wldelay-card-header" role="button" tabindex="0" aria-expanded="true" aria-controls="wldelay-xmlrpc-body">
                            <span class="dashicons dashicons-rss" aria-hidden="true"></span>
                            <?php esc_html_e( 'XML-RPC Protection', 'wp-login-delay' ); ?>
                            <?php echo $this->get_status_badge( 'wldelay_xmlrpc_enabled', __( 'XML-RPC Protection', 'wp-login-delay' ) ); ?>
                            <span class="dashicons dashicons-arrow-down-alt2 wldelay-toggle" aria-hidden="true"></span>
                        </h2>
                        <div id="wldelay-xmlrpc-body" class="wldelay-card-body">
                            <p class="description"><?php esc_html_e( 'Protect against brute-force attacks via XML-RPC (used by the WordPress mobile app and remote publishing).', 'wp-login-delay' ); ?></p>
                            <?php $this->do_settings_section_fields( 'wldelay_xmlrpc_section_id' ); ?>
                        </div>
                    </div>

                    <div class="wldelay-card">
                        <h2 class="wldelay-card-header" role="button" tabindex="0" aria-expanded="true" aria-controls="wldelay-custom-login-body">
                            <span class="dashicons dashicons-admin-links" aria-hidden="true"></span>
                            <?php esc_html_e( 'Custom Login URL', 'wp-login-delay' ); ?>
                            <?php echo $this->get_status_badge( 'wldelay_custom_login_enabled', __( 'Custom Login URL', 'wp-login-delay' ) ); ?>
                            <span class="dashicons dashicons-arrow-down-alt2 wldelay-toggle" aria-hidden="true"></span>
                        </h2>
                        <div id="wldelay-custom-login-body" class="wldelay-card-body">
                            <p class="description"><?php esc_html_e( 'Hide wp-login.php behind a custom URL slug to reduce automated attacks targeting the default login path.', 'wp-login-delay' ); ?></p>
                            <?php $this->do_settings_section_fields( 'wldelay_custom_login_section_id' ); ?>
                        </div>
                    </div>

                    <div class="wldelay-card">
                        <h2 class="wldelay-card-header" role="button" tabindex="0" aria-expanded="true" aria-controls="wldelay-botnet-body">
                            <span class="dashicons dashicons-networking" aria-hidden="true"></span>
                            <?php esc_html_e( 'Distributed Attack Detection', 'wp-login-delay' ); ?>
                            <?php echo $this->get_status_badge( 'wldelay_botnet_enabled', __( 'Distributed Attack Detection', 'wp-login-delay' ) ); ?>
                            <span class="dashicons dashicons-arrow-down-alt2 wldelay-toggle" aria-hidden="true"></span>
                        </h2>
                        <div id="wldelay-botnet-body" class="wldelay-card-body">
                            <p class="description"><?php esc_html_e( 'Alerts when one username is targeted from many different IP addresses — the pattern per-IP lockouts cannot see. Detection never blocks logins; it informs you via the dashboard, the audit log, and (if email alerts are enabled) email.', 'wp-login-delay' ); ?></p>
                            <?php $this->do_settings_section_fields( 'wldelay_botnet_section_id' ); ?>
                        </div>
                    </div>
                </div>

                <?php submit_button(); ?>
            </form>

            <?php
            // Rendered OUTSIDE the settings <form action="options.php">: this card
            // emits its own POST forms (per-row Unlock + Clear-all targeting
            // admin-post.php). Nesting a <form> inside another <form> is invalid
            // HTML — the first inner submit would bind to the outer form (wrong
            // handler) and the inner </form> would close the settings form early,
            // breaking Save Settings whenever lockouts exist (F-1-1 review).
            ?>
            <div class="wldelay-card">
                <h2 class="wldelay-card-header" role="button" tabindex="0" aria-expanded="true" aria-controls="wldelay-active-lockouts-body">
                    <span class="dashicons dashicons-unlock" aria-hidden="true"></span>
                    <?php esc_html_e( 'Active Lockouts', 'wp-login-delay' ); ?>
                    <span class="dashicons dashicons-arrow-down-alt2 wldelay-toggle" aria-hidden="true"></span>
                </h2>
                <div id="wldelay-active-lockouts-body" class="wldelay-card-body">
                    <p class="description"><?php esc_html_e( 'IP addresses and accounts currently blocked from logging in. Unlock an individual subject if a legitimate user got caught, or clear them all.', 'wp-login-delay' ); ?></p>
                    <?php $this->render_active_lockouts(); ?>
                </div>
            </div>
        </div>
        <?php
    }

    /**
     * Render the guided setup wizard with protection profiles.
     */
    private function render_setup_wizard() {
        $profiles        = wldelay_get_protection_profiles();
        // Active profile actually stored (empty when settings were edited manually).
        $active_profile  = isset( $this->options['wldelay_protection_profile'] ) ? wldelay_sanitize_protection_profile_id( $this->options['wldelay_protection_profile'] ) : '';
        // Radio pre-selection: fall back to balanced as a suggested starting point.
        $selected        = $active_profile !== '' ? $active_profile : 'balanced';
        $current_label   = $active_profile !== '' ? $profiles[ $active_profile ]['label'] : __( 'Custom', 'wp-login-delay' );
        $profile_effects = array(
            'conservative' => array(
                __( 'Lockout after 10 failed attempts', 'wp-login-delay' ),
                __( 'Progressive delay up to 15 seconds', 'wp-login-delay' ),
                __( 'Password reset protection', 'wp-login-delay' ),
            ),
            'balanced'     => array(
                __( 'Lockout after 7 failed attempts', 'wp-login-delay' ),
                __( 'Protects REST API and application passwords', 'wp-login-delay' ),
                __( 'Password reset protection', 'wp-login-delay' ),
            ),
            'aggressive'   => array(
                __( 'Lockout after 5 failed attempts', 'wp-login-delay' ),
                __( 'Blocks XML-RPC authentication', 'wp-login-delay' ),
                __( 'Longer progressive delay window', 'wp-login-delay' ),
            ),
        );
        ?>
        <section class="wldelay-setup-wizard" aria-labelledby="wldelay-setup-wizard-title">
            <div class="wldelay-setup-wizard-header">
                <span class="dashicons dashicons-admin-generic" aria-hidden="true"></span>
                <div>
                    <h2 id="wldelay-setup-wizard-title"><?php esc_html_e( 'Security Setup Wizard', 'wp-login-delay' ); ?></h2>
                    <p class="description"><?php esc_html_e( 'Choose a protection profile to quickly configure the main security controls. You can still adjust every setting below.', 'wp-login-delay' ); ?></p>
                </div>
                <span class="wldelay-current-profile" aria-live="polite">
                    <?php
                    printf(
                        /* translators: %s: selected protection profile label */
                        esc_html__( 'Current profile: %s', 'wp-login-delay' ),
                        esc_html( $current_label )
                    );
                    ?>
                </span>
            </div>

            <fieldset class="wldelay-profile-fieldset" aria-describedby="wldelay-profile-help">
                <legend><?php esc_html_e( 'Protection Profiles', 'wp-login-delay' ); ?></legend>
                <p id="wldelay-profile-help" class="description"><?php esc_html_e( 'Profiles update delay, progressive delay, lockout, email alert, and authentication endpoint settings.', 'wp-login-delay' ); ?></p>

                <div class="wldelay-profile-grid">
                    <?php foreach ( $profiles as $profile_id => $profile ) : ?>
                        <?php $input_id = 'wldelay_profile_' . $profile_id; ?>
                        <label class="wldelay-profile-option" for="<?php echo esc_attr( $input_id ); ?>">
                            <input
                                type="radio"
                                id="<?php echo esc_attr( $input_id ); ?>"
                                name="wldelay_options[wldelay_protection_profile]"
                                value="<?php echo esc_attr( $profile_id ); ?>"
                                <?php checked( $selected, $profile_id ); ?>
                            />
                            <span class="wldelay-profile-content">
                                <span class="wldelay-profile-title">
                                    <?php echo esc_html( $profile['label'] ); ?>
                                    <span class="wldelay-profile-tagline"><?php echo esc_html( $profile['tagline'] ); ?></span>
                                </span>
                                <span class="wldelay-profile-description"><?php echo esc_html( $profile['description'] ); ?></span>
                                <span class="wldelay-profile-effects">
                                    <?php foreach ( $profile_effects[ $profile_id ] as $effect ) : ?>
                                        <span>
                                            <span class="dashicons dashicons-yes-alt" aria-hidden="true"></span>
                                            <?php echo esc_html( $effect ); ?>
                                        </span>
                                    <?php endforeach; ?>
                                </span>
                            </span>
                        </label>
                    <?php endforeach; ?>
                </div>
            </fieldset>

            <p class="wldelay-profile-actions">
                <?php // Action carried by a hidden field so an implicit Enter-key submit from any settings field cannot apply a profile; the apply button sets it only on an explicit click. ?>
                <input type="hidden" name="wldelay_options[wldelay_profile_action]" id="wldelay-profile-action" value="" />
                <button type="button" class="button button-primary wldelay-apply-profile" data-profile-action="apply">
                    <?php esc_html_e( 'Apply selected profile', 'wp-login-delay' ); ?>
                </button>
                <span class="description"><?php esc_html_e( 'Applying a profile overwrites matching settings below, then saves the page.', 'wp-login-delay' ); ?></span>
            </p>
        </section>
        <?php
    }

    /**
     * Render the summary box at the top of the page
     */
    private function render_summary_box() {
        $features = array(
            'wldelay_email_enabled' => __( 'Email Alerts', 'wp-login-delay' ),
            'wldelay_lockout_enabled' => __( 'IP Lockout', 'wp-login-delay' ),
            'wldelay_whitelist_enabled' => __( 'IP Whitelist', 'wp-login-delay' ),
            'wldelay_progressive_enabled' => __( 'Progressive Delay', 'wp-login-delay' ),
            'wldelay_xmlrpc_enabled' => __( 'XML-RPC Protection', 'wp-login-delay' ),
            'wldelay_rest_enabled' => __( 'REST API Protection', 'wp-login-delay' ),
            'wldelay_application_password_enabled' => __( 'Application Password Protection', 'wp-login-delay' ),
            'wldelay_password_reset_enabled' => __( 'Password Reset Protection', 'wp-login-delay' ),
            'wldelay_custom_login_enabled' => __( 'Custom Login URL', 'wp-login-delay' ),
            'wldelay_recovery_enabled' => __( 'Emergency Recovery URL', 'wp-login-delay' ),
            'wldelay_fail2ban_enabled' => __( 'fail2ban Logging', 'wp-login-delay' ),
        );

        $enabled_count = 0;
        $feature_html = '';

        foreach ( $features as $key => $label ) {
            $is_enabled = ! empty( $this->options[ $key ] );
            if ( $is_enabled ) {
                $enabled_count++;
            }
            $class = $is_enabled ? 'wldelay-feature-on' : 'wldelay-feature-off';
            $icon = $is_enabled ? 'yes' : 'no-alt';
            $status = $is_enabled ? __( 'enabled', 'wp-login-delay' ) : __( 'disabled', 'wp-login-delay' );
            $feature_html .= sprintf(
                '<span class="%s" data-feature="%s">' .
                '<span class="dashicons dashicons-%s" aria-hidden="true"></span>' .
                '<span class="screen-reader-text">%s: %s</span>' .
                '<span aria-hidden="true">%s</span>' .
                '</span>',
                esc_attr( $class ),
                esc_attr( $key ),
                esc_attr( $icon ),
                esc_html( $label ),
                esc_html( $status ),
                esc_html( $label )
            );
        }

        $total = count( $features );

        $health = wldelay_get_security_score( $this->options );
        $score  = $health['score'];
        $max    = $health['max'];
        $pct    = $max > 0 ? (int) round( ( $score / $max ) * 100 ) : 0;

        $recommendation_html = '';
        if ( $health['recommendation'] !== null ) {
            $recommendation_html = sprintf(
                '<div class="wldelay-summary-recommendation"><span class="dashicons dashicons-lightbulb" aria-hidden="true"></span> %s</div>',
                sprintf(
                    /* translators: 1: feature name, 2: points value */
                    esc_html__( 'Next recommended: enable %1$s (+%2$d points)', 'wp-login-delay' ),
                    '<strong>' . esc_html( $health['recommendation']['label'] ) . '</strong>',
                    $health['recommendation']['points']
                )
            );
        }

        return sprintf(
            '<div class="wldelay-summary" role="status" aria-label="%s">
                <div class="wldelay-summary-score">
                    <div class="wldelay-score-circle" style="--score-pct: %d" aria-hidden="true">
                        <span class="wldelay-score-value">%d</span>
                    </div>
                    <div class="wldelay-score-label">%s</div>
                </div>
                <div class="wldelay-summary-text">
                    <div class="wldelay-summary-title">%s <span class="wldelay-summary-fraction">(%d/%d)</span></div>
                    <div class="wldelay-summary-features" aria-live="polite">%s</div>
                    %s
                </div>
            </div>',
            esc_attr__( 'Protection status summary', 'wp-login-delay' ),
            $pct,
            $pct,
            esc_html__( 'Security Score', 'wp-login-delay' ),
            esc_html__( 'Protection Features Enabled', 'wp-login-delay' ),
            $enabled_count,
            $total,
            $feature_html,
            $recommendation_html
        );
    }

    /**
     * Render a lightweight 2FA plugin detection notice.
     */
    private function render_2fa_health_notice() {
        $status = wldelay_get_2fa_health_status();

        if ( ! empty( $status['enabled'] ) ) {
            $provider_label = (string) $status['provider_label'];
            $coverage       = isset( $status['coverage'] ) && is_array( $status['coverage'] ) ? $status['coverage'] : array();
            $supported      = ! empty( $coverage['supported'] );
            $unprotected    = isset( $coverage['unprotected'] ) ? (int) $coverage['unprotected'] : 0;
            $privileged     = isset( $coverage['privileged_total'] ) ? (int) $coverage['privileged_total'] : 0;

            if ( $supported && $privileged > 0 && $unprotected <= 0 ) {
                ?>
                <div class="wldelay-health-notice" role="note">
                    <span class="dashicons dashicons-yes-alt" aria-hidden="true"></span>
                    <span>
                        <strong><?php esc_html_e( '2FA plugin check:', 'wp-login-delay' ); ?></strong>
                        <?php
                        echo esc_html(
                            sprintf(
                                /* translators: 1: detected 2FA provider, 2: number of privileged accounts */
                                _n(
                                    '%1$s is active and the detected administrator account appears to have 2FA enabled.',
                                    '%1$s is active and all %2$d detected administrator accounts appear to have 2FA enabled.',
                                    $privileged,
                                    'wp-login-delay'
                                ),
                                $provider_label,
                                $privileged
                            )
                        );
                        ?>
                    </span>
                </div>
                <?php
                return;
            }

            if ( $supported && $privileged > 0 && $unprotected > 0 ) {
                ?>
                <div class="wldelay-health-notice" role="note">
                    <span class="dashicons dashicons-warning" aria-hidden="true"></span>
                    <span>
                        <strong><?php esc_html_e( '2FA plugin check:', 'wp-login-delay' ); ?></strong>
                        <?php
                        echo esc_html(
                            sprintf(
                                /* translators: 1: detected 2FA provider, 2: number of unprotected privileged accounts, 3: total privileged accounts */
                                _n(
                                    '%1$s is active, but %2$d administrator account out of %3$d detected does not appear to have 2FA enabled yet.',
                                    '%1$s is active, but %2$d administrator accounts out of %3$d detected do not appear to have 2FA enabled yet.',
                                    $unprotected,
                                    'wp-login-delay'
                                ),
                                $provider_label,
                                $unprotected,
                                $privileged
                            )
                        );
                        ?>
                    </span>
                </div>
                <?php
                return;
            }
            ?>
            <div class="wldelay-health-notice" role="note">
                <span class="dashicons dashicons-shield" aria-hidden="true"></span>
                <span>
                    <strong><?php esc_html_e( '2FA plugin check:', 'wp-login-delay' ); ?></strong>
                    <?php
                    printf(
                        /* translators: %s: detected plugin with 2FA capability */
                        esc_html__( 'Detected installed plugin with 2FA capability: %s. Verify 2FA is configured for your administrator accounts.', 'wp-login-delay' ),
                        esc_html( $provider_label )
                    );
                    ?>
                </span>
            </div>
            <?php
            return;
        }

        ?>
        <div class="wldelay-health-notice" role="note">
            <span class="dashicons dashicons-warning" aria-hidden="true"></span>
            <span>
                <strong><?php esc_html_e( '2FA plugin check:', 'wp-login-delay' ); ?></strong>
                <?php esc_html_e( 'No detected common 2FA plugin. If you use a custom or must-use solution, verify administrator 2FA coverage manually.', 'wp-login-delay' ); ?>
            </span>
        </div>
        <?php
    }

    /**
     * Render a proxy/CDN configuration health notice.
     *
     * Surfaces the two dangerous misconfigurations: proxy headers present
     * while trust is disabled (every visitor shares the CDN IP — one attacker
     * locks out everyone), and trust enabled with no proxy in front (any
     * attacker can spoof their IP). Silent when nothing is wrong.
     */
    private function render_proxy_health_notice() {
        $health = wldelay_get_proxy_health_status();

        if ( 'misconfigured-cdn' === $health['status'] ) {
            ?>
            <div class="wldelay-health-notice" role="note">
                <span class="dashicons dashicons-warning" aria-hidden="true"></span>
                <span>
                    <strong><?php esc_html_e( 'Proxy check:', 'wp-login-delay' ); ?></strong>
                    <?php
                    printf(
                        /* translators: %s: comma-separated list of detected proxy headers, e.g. "CF-Connecting-IP, X-Forwarded-For". */
                        esc_html__( 'This site appears to be behind a proxy or CDN (detected: %s), but "Trust proxy headers" is disabled. Visitors currently share the proxy\'s IP address, so a single attacker could lock out all users. Enable "Trust proxy headers" under Advanced settings.', 'wp-login-delay' ),
                        esc_html( implode( ', ', $health['headers'] ) )
                    );
                    ?>
                </span>
            </div>
            <?php
            return;
        }

        if ( 'spoofable' === $health['status'] ) {
            ?>
            <div class="wldelay-health-notice" role="note">
                <span class="dashicons dashicons-warning" aria-hidden="true"></span>
                <span>
                    <strong><?php esc_html_e( 'Proxy check:', 'wp-login-delay' ); ?></strong>
                    <?php esc_html_e( '"Trust proxy headers" is enabled, but no proxy headers were detected on this request. If this site is not behind a proxy or CDN, attackers can spoof their IP address to bypass lockouts — disable "Trust proxy headers" under Advanced settings.', 'wp-login-delay' ); ?>
                </span>
            </div>
            <?php
        }
    }

    /**
     * Render a coherence/validator warning when username-enumeration hardening
     * is enabled, reminding the admin that login feedback becomes intentionally
     * generic and public author/REST listings are restricted.
     */
    private function render_enumeration_hardening_notice() {
        if ( empty( $this->options['wldelay_enumeration_hardening_enabled'] ) ) {
            return;
        }
        ?>
        <div class="wldelay-health-notice" role="note">
            <span class="dashicons dashicons-shield" aria-hidden="true"></span>
            <span>
                <strong><?php esc_html_e( 'Enumeration hardening active:', 'wp-login-delay' ); ?></strong>
                <?php esc_html_e( 'Login failures now show one generic error, and author-archive and public REST user listings are blocked. Verify your support guidance reflects this before relying on it.', 'wp-login-delay' ); ?>
            </span>
        </div>
        <?php
    }

    /**
     * Render object cache notice if no persistent cache is detected.
     */
    private function render_object_cache_notice() {
        // Only show notice if no external object cache is in use
        if ( wp_using_ext_object_cache() ) {
            return;
        }

        ?>
        <div class="wldelay-cache-tip" role="note">
            <span class="dashicons dashicons-info-outline" aria-hidden="true"></span>
            <span>
                <strong><?php esc_html_e( 'Performance tip:', 'wp-login-delay' ); ?></strong>
                <?php esc_html_e( 'For high-traffic sites, consider using a persistent object cache (Redis, Memcached) to reduce database load during attacks.', 'wp-login-delay' ); ?>
            </span>
        </div>
        <?php
    }


    /**
     * Render filtered login-log telemetry controls, summary, and results.
     */
    private function render_login_log_telemetry() {
        $filters      = wldelay_get_login_log_filters_from_request();
        $current_page = isset( $_GET['wldelay_log_page'] ) ? max( 1, absint( wp_unslash( $_GET['wldelay_log_page'] ) ) ) : 1;
        $per_page     = 25;
        $total        = wldelay_admin_throttled_log_count( $filters );
        $total_pages  = max( 1, (int) ceil( $total / $per_page ) );

        if ( $current_page > $total_pages ) {
            $current_page = $total_pages;
        }

        $snapshot_hash    = wldelay_get_telemetry_snapshot_hash( $total, $filters );
        $previous_hash    = isset( $_GET['wldelay_log_snap'] ) ? sanitize_text_field( wp_unslash( $_GET['wldelay_log_snap'] ) ) : '';
        $data_has_drifted = $previous_hash !== '' && $previous_hash !== $snapshot_hash;
        $pagination_hash  = $previous_hash !== '' ? $previous_hash : $snapshot_hash;

        $attempts = wldelay_get_login_log_attempts(
            array(
                'filters' => $filters,
                'limit'   => $per_page,
                'offset'  => ( $current_page - 1 ) * $per_page,
                'fields'  => 'source, ip_address, username, attempted_at',
            )
        );
        $summary = wldelay_get_login_log_summary( $filters );
        ?>
        <hr />
        <?php if ( $data_has_drifted ) : ?>
            <div class="notice notice-warning inline"><p>
                <?php esc_html_e( 'New login attempts were recorded since you started browsing. Totals and page numbers may have shifted.', 'wp-login-delay' ); ?>
                <a href="<?php echo esc_url( add_query_arg( array_merge( array( 'page' => 'login-delay-shield-admin' ), wldelay_login_log_filters_to_query_args( $filters ) ), admin_url( 'options-general.php' ) ) ); ?>"><?php esc_html_e( 'Refresh', 'wp-login-delay' ); ?></a>
            </p></div>
        <?php endif; ?>
        <div class="wldelay-telemetry" aria-labelledby="wldelay-telemetry-title">
            <h3 id="wldelay-telemetry-title"><?php esc_html_e( 'Failed Login Telemetry', 'wp-login-delay' ); ?></h3>
            <p class="description"><?php esc_html_e( 'Filter failed login attempts, inspect recent patterns, and export the matching rows as CSV.', 'wp-login-delay' ); ?></p>

            <div class="wldelay-telemetry-filters">
                <input form="wldelay-telemetry-filter-form" type="hidden" name="page" value="login-delay-shield-admin" />
                <div class="wldelay-filter-grid">
                    <label for="wldelay_log_source">
                        <?php esc_html_e( 'Source', 'wp-login-delay' ); ?>
                        <select id="wldelay_log_source" name="wldelay_log_source" form="wldelay-telemetry-filter-form">
                            <option value=""><?php esc_html_e( 'All sources', 'wp-login-delay' ); ?></option>
                            <?php foreach ( $this->get_login_log_source_options( $summary, $filters ) as $source ) : ?>
                                <option value="<?php echo esc_attr( $source ); ?>" <?php selected( $filters['source'], $source ); ?>><?php echo esc_html( wldelay_get_login_source_label( $source ) ); ?></option>
                            <?php endforeach; ?>
                        </select>
                    </label>
                    <label for="wldelay_log_ip">
                        <?php esc_html_e( 'IP address', 'wp-login-delay' ); ?>
                        <input id="wldelay_log_ip" name="wldelay_log_ip" form="wldelay-telemetry-filter-form" type="text" value="<?php echo esc_attr( $filters['ip'] ); ?>" placeholder="<?php echo esc_attr__( 'Any IP', 'wp-login-delay' ); ?>" />
                    </label>
                    <label for="wldelay_log_username">
                        <?php esc_html_e( 'Username', 'wp-login-delay' ); ?>
                        <input id="wldelay_log_username" name="wldelay_log_username" form="wldelay-telemetry-filter-form" type="text" value="<?php echo esc_attr( $filters['username'] ); ?>" placeholder="<?php echo esc_attr__( 'Partial match', 'wp-login-delay' ); ?>" />
                    </label>
                    <label for="wldelay_log_from">
                        <?php esc_html_e( 'From', 'wp-login-delay' ); ?>
                        <input id="wldelay_log_from" name="wldelay_log_from" form="wldelay-telemetry-filter-form" type="date" value="<?php echo esc_attr( $filters['from'] ); ?>" />
                    </label>
                    <label for="wldelay_log_to">
                        <?php esc_html_e( 'To', 'wp-login-delay' ); ?>
                        <input id="wldelay_log_to" name="wldelay_log_to" form="wldelay-telemetry-filter-form" type="date" value="<?php echo esc_attr( $filters['to'] ); ?>" />
                    </label>
                </div>
                <p class="wldelay-telemetry-actions">
                    <button type="submit" form="wldelay-telemetry-filter-form" class="button button-primary"><?php esc_html_e( 'Apply filters', 'wp-login-delay' ); ?></button>
                    <a class="button button-secondary" href="<?php echo esc_url( admin_url( 'options-general.php?page=login-delay-shield-admin' ) ); ?>"><?php esc_html_e( 'Reset', 'wp-login-delay' ); ?></a>
                    <a class="button button-secondary" href="<?php echo esc_url( wldelay_get_export_login_log_url( $filters ) ); ?>"><?php esc_html_e( 'Export filtered CSV', 'wp-login-delay' ); ?></a>
                </p>
            </div>

            <?php $this->render_login_log_summary( $summary ); ?>
            <?php $this->render_login_log_table( $attempts, $total, $current_page, $total_pages, $filters, $pagination_hash ); ?>
        </div>
        <?php
    }


    /**
     * Get source dropdown options, preserving active legacy/future source values.
     *
     * @param array $summary Summary data.
     * @param array $filters Active filters.
     * @return array<int,string>
     */
    private function get_login_log_source_options( $summary, $filters ) {
        $sources = array( 'wp-login', 'xmlrpc', 'rest', 'application-password', 'password-reset' );

        if ( ! empty( $summary['source_counts'] ) && is_array( $summary['source_counts'] ) ) {
            foreach ( $summary['source_counts'] as $source_count ) {
                if ( ! empty( $source_count['source'] ) ) {
                    $sources[] = (string) $source_count['source'];
                }
            }
        }

        if ( ! empty( $filters['source'] ) ) {
            $sources[] = (string) $filters['source'];
        }

        return array_values( array_unique( array_filter( $sources ) ) );
    }

    /**
     * Render telemetry summary cards.
     *
     * @param array $summary Summary data.
     */
    private function render_login_log_summary( $summary ) {
        ?>
        <div class="wldelay-telemetry-summary">
            <section class="wldelay-trend-card">
                <h4><?php esc_html_e( 'Total attempts', 'wp-login-delay' ); ?></h4>
                <p class="wldelay-telemetry-total"><?php echo esc_html( number_format_i18n( (int) $summary['total_attempts'] ) ); ?></p>
            </section>
            <section class="wldelay-trend-card">
                <h4><?php esc_html_e( 'Daily activity', 'wp-login-delay' ); ?></h4>
                <?php $this->render_count_list( $summary['daily_counts'], 'date' ); ?>
            </section>
            <section class="wldelay-trend-card">
                <h4><?php esc_html_e( 'Top sources', 'wp-login-delay' ); ?></h4>
                <?php $this->render_count_list( $summary['source_counts'], 'source' ); ?>
            </section>
            <section class="wldelay-trend-card">
                <h4><?php esc_html_e( 'Top IPs', 'wp-login-delay' ); ?></h4>
                <?php $this->render_count_list( $summary['top_ips'], 'ip_address' ); ?>
            </section>
            <section class="wldelay-trend-card">
                <h4><?php esc_html_e( 'Top usernames', 'wp-login-delay' ); ?></h4>
                <p class="description"><?php esc_html_e( 'Usernames most targeted by failed login attempts.', 'wp-login-delay' ); ?></p>
                <?php $this->render_count_list( $summary['top_usernames'], 'username' ); ?>
            </section>
            <section class="wldelay-trend-card">
                <h4><?php esc_html_e( 'Top target pairs', 'wp-login-delay' ); ?></h4>
                <p class="description"><?php esc_html_e( 'Most common IP and username combinations from failed login attempts.', 'wp-login-delay' ); ?></p>
                <?php $this->render_count_list( $summary['top_target_pairs'], 'target_pair' ); ?>
            </section>
        </div>
        <?php
    }

    /**
     * Render a compact label/count list.
     *
     * @param array  $rows      Count rows.
     * @param string $label_key Row key to use for label.
     */
    private function render_count_list( $rows, $label_key ) {
        echo '<ul class="wldelay-trend-list">';
        if ( empty( $rows ) ) {
            echo '<li><span>' . esc_html__( 'No matching data', 'wp-login-delay' ) . '</span><strong>0</strong></li>';
            echo '</ul>';
            return;
        }

        foreach ( $rows as $row ) {
            $label = isset( $row[ $label_key ] ) ? (string) $row[ $label_key ] : '';
            if ( $label_key === 'source' ) {
                $label = wldelay_get_login_source_label( $label );
            } elseif ( $label_key === 'date' ) {
                $label = date_i18n( _x( 'M j, Y', 'date format for login log telemetry', 'wp-login-delay' ), strtotime( $label . ' 00:00:00' ) );
            } elseif ( $label_key === 'target_pair' ) {
                $label = sprintf(
                    /* translators: 1: IP address, 2: username. */
                    __( '%1$s / %2$s', 'wp-login-delay' ),
                    isset( $row['ip_address'] ) ? (string) $row['ip_address'] : '',
                    isset( $row['username'] ) ? (string) $row['username'] : ''
                );
            }
            echo '<li><span>' . esc_html( $label ) . '</span><strong>' . esc_html( number_format_i18n( (int) $row['count'] ) ) . '</strong></li>';
        }
        echo '</ul>';
    }

    /**
     * Render filtered login-log table and pagination.
     *
     * @param array $attempts    Attempt rows.
     * @param int   $total       Total matching attempts.
     * @param int   $current_page Current page number.
     * @param int   $total_pages Total page count.
     * @param array $filters     Active filters.
     */
    private function render_login_log_table( $attempts, $total, $current_page, $total_pages, $filters, $snapshot_hash = '' ) {
        ?>
        <div class="wldelay-telemetry-results">
            <h4><?php esc_html_e( 'Matching attempts', 'wp-login-delay' ); ?></h4>
            <p class="description">
                <?php
                printf(
                    /* translators: %s: number of matching failed login attempts */
                    esc_html__( '%s matching failed login attempts.', 'wp-login-delay' ),
                    esc_html( number_format_i18n( $total ) )
                );
                ?>
            </p>
            <?php if ( empty( $attempts ) ) : ?>
                <p class="wldelay-empty-state"><?php esc_html_e( 'No failed login attempts match the current filters.', 'wp-login-delay' ); ?></p>
            <?php else : ?>
                <table class="widefat striped wldelay-telemetry-table">
                    <caption class="screen-reader-text"><?php esc_html_e( 'Filtered failed login attempts', 'wp-login-delay' ); ?></caption>
                    <thead>
                        <tr>
                            <th scope="col"><?php esc_html_e( 'Time', 'wp-login-delay' ); ?></th>
                            <th scope="col"><?php esc_html_e( 'Username', 'wp-login-delay' ); ?></th>
                            <th scope="col"><?php esc_html_e( 'IP address', 'wp-login-delay' ); ?></th>
                            <th scope="col"><?php esc_html_e( 'Source', 'wp-login-delay' ); ?></th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ( $attempts as $attempt ) : ?>
                            <?php $source = ! empty( $attempt->source ) ? (string) $attempt->source : 'wp-login'; ?>
                            <tr>
                                <td><?php echo esc_html( mysql2date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $attempt->attempted_at ) ); ?></td>
                                <td><?php echo esc_html( $attempt->username ); ?></td>
                                <td><?php echo esc_html( $attempt->ip_address ); ?></td>
                                <td><span class="wldelay-source-badge <?php echo esc_attr( 'wldelay-source-' . sanitize_html_class( $source ) ); ?>"><?php echo esc_html( wldelay_get_login_source_label( $source ) ); ?></span></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
                <?php $this->render_login_log_pagination( $current_page, $total_pages, $filters, $snapshot_hash ); ?>
            <?php endif; ?>
        </div>
        <?php
    }

    /**
     * Render telemetry pagination links.
     *
     * @param int   $current_page Current page number.
     * @param int   $total_pages Total page count.
     * @param array $filters Active filters.
     */
    private function render_login_log_pagination( $current_page, $total_pages, $filters, $snapshot_hash = '' ) {
        if ( $total_pages <= 1 ) {
            return;
        }

        $base_args = array_merge(
            array( 'page' => 'login-delay-shield-admin' ),
            wldelay_login_log_filters_to_query_args( $filters )
        );

        if ( $snapshot_hash !== '' ) {
            $base_args['wldelay_log_snap'] = $snapshot_hash;
        }

        echo '<nav class="wldelay-pagination" aria-label="' . esc_attr__( 'Login log pagination', 'wp-login-delay' ) . '">';
        if ( $current_page > 1 ) {
            echo '<a class="button button-secondary" href="' . esc_url( add_query_arg( array_merge( $base_args, array( 'wldelay_log_page' => $current_page - 1 ) ), admin_url( 'options-general.php' ) ) ) . '">' . esc_html__( 'Previous', 'wp-login-delay' ) . '</a> ';
        }
        printf(
            '<span class="wldelay-pagination-status">%s</span>',
            esc_html(
                sprintf(
                    /* translators: 1: current page, 2: total pages */
                    __( 'Page %1$d of %2$d', 'wp-login-delay' ),
                    $current_page,
                    $total_pages
                )
            )
        );
        if ( $current_page < $total_pages ) {
            echo ' <a class="button button-secondary" href="' . esc_url( add_query_arg( array_merge( $base_args, array( 'wldelay_log_page' => $current_page + 1 ) ), admin_url( 'options-general.php' ) ) ) . '">' . esc_html__( 'Next', 'wp-login-delay' ) . '</a>';
        }
        echo '</nav>';
    }

    /**
     * Render the read-only audit-log view: filters, table, and pagination.
     *
     * Surfaces the F-2-7 admin/security action trail. Read-only by design — no
     * edit or delete controls. All output is escaped; the underlying query
     * functions sanitize the request filters internally.
     */
    /**
     * Render the Active Lockout Manager table (F-1-1).
     *
     * Lists currently-active lockouts from the durable store, each with a
     * per-row Unlock form (POST -> admin-post, own nonce) that removes only that
     * (IP, username) subject, plus a Clear-all form. The list is bounded by the
     * store's default limit; if it is truncated the table says so.
     */
    private function render_active_lockouts() {
        $limit    = 200;
        $lockouts = wldelay_get_persistence_store()->get_active_lockouts( $limit );
        $now      = time();

        // A FALSE return is a DB read failure (table probe / SELECT), distinct
        // from a genuine empty list. Surface it as an error so the admin does not
        // mistake a fault for "nothing is locked" (F-3-1, read-failure contract).
        $read_failed = ( false === $lockouts );
        if ( $read_failed ) {
            $lockouts = array();
        }
        ?>
        <div class="wldelay-active-lockouts" aria-labelledby="wldelay-active-lockouts-title">
            <h3 id="wldelay-active-lockouts-title" class="screen-reader-text"><?php esc_html_e( 'Active lockouts', 'wp-login-delay' ); ?></h3>

            <?php if ( $read_failed ) : ?>
                <div class="notice notice-error inline" role="alert">
                    <p><?php esc_html_e( 'The list of active lockouts could not be read from the database. Active lockouts may still be in force — this is not a confirmation that nothing is blocked.', 'wp-login-delay' ); ?></p>
                </div>
            <?php elseif ( empty( $lockouts ) ) : ?>
                <p class="wldelay-empty-state" role="status" aria-live="polite"><?php esc_html_e( 'No active lockouts. Nothing is currently blocked.', 'wp-login-delay' ); ?></p>
            <?php else : ?>
                <table class="widefat striped wldelay-active-lockouts-table">
                    <caption class="screen-reader-text"><?php esc_html_e( 'Currently active login lockouts', 'wp-login-delay' ); ?></caption>
                    <thead>
                        <tr>
                            <th scope="col"><?php esc_html_e( 'IP address', 'wp-login-delay' ); ?></th>
                            <th scope="col"><?php esc_html_e( 'Username', 'wp-login-delay' ); ?></th>
                            <th scope="col"><?php esc_html_e( 'Type', 'wp-login-delay' ); ?></th>
                            <th scope="col"><?php esc_html_e( 'Source', 'wp-login-delay' ); ?></th>
                            <th scope="col"><?php esc_html_e( 'Time remaining', 'wp-login-delay' ); ?></th>
                            <th scope="col"><?php esc_html_e( 'Locked since', 'wp-login-delay' ); ?></th>
                            <th scope="col"><?php esc_html_e( 'Actions', 'wp-login-delay' ); ?></th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ( $lockouts as $lockout ) : ?>
                            <?php
                            $ip          = isset( $lockout['ip_address'] ) ? (string) $lockout['ip_address'] : '';
                            $username    = isset( $lockout['username'] ) ? (string) $lockout['username'] : '';
                            $lockout_key = isset( $lockout['lockout_key'] ) ? (string) $lockout['lockout_key'] : '';
                            $type        = isset( $lockout['lockout_type'] ) ? (string) $lockout['lockout_type'] : '';
                            $source    = isset( $lockout['source'] ) ? (string) $lockout['source'] : '';
                            $expires   = isset( $lockout['expires_at'] ) ? (int) $lockout['expires_at'] : 0;
                            $created   = isset( $lockout['created_at'] ) ? (int) $lockout['created_at'] : 0;
                            $remaining = $expires > $now
                                ? sprintf(
                                    /* translators: %s: human-readable duration, e.g. "5 mins" */
                                    __( '%s left', 'wp-login-delay' ),
                                    human_time_diff( $now, $expires )
                                )
                                : __( 'Expiring', 'wp-login-delay' );
                            $since = $created > 0
                                ? sprintf(
                                    /* translators: %s: human-readable duration, e.g. "5 mins" */
                                    __( '%s ago', 'wp-login-delay' ),
                                    human_time_diff( $created, $now )
                                )
                                : __( 'Unknown', 'wp-login-delay' );
                            ?>
                            <tr>
                                <td><?php echo esc_html( $ip ); ?></td>
                                <td><?php
                                if ( '' !== $username ) {
                                    echo esc_html( $username );
                                } else {
                                    echo esc_html__( '(any)', 'wp-login-delay' );
                                    // "(any)" is an IP-level lockout: it covers every
                                    // username attempted from this IP, not a single
                                    // account. Spell that out for admins unfamiliar
                                    // with the IP-only strategy (R4-7).
                                    echo ' ' . $this->tooltip( __( 'IP-level lockout: it applies to every username attempted from this IP address, not one specific account.', 'wp-login-delay' ) );
                                }
                                ?></td>
                                <td><?php echo esc_html( $type ); ?></td>
                                <td><?php echo esc_html( $source ); ?></td>
                                <td><?php echo esc_html( $remaining ); ?></td>
                                <td><?php echo esc_html( $since ); ?></td>
                                <td>
                                    <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="wldelay-unlock-form" data-wldelay-confirm="<?php echo esc_attr( '' !== $username
                                        /* translators: 1: username, 2: IP address */
                                        ? sprintf( __( 'Unlock %1$s on IP %2$s? They will be able to attempt logins again immediately.', 'wp-login-delay' ), $username, $ip )
                                        /* translators: %s: IP address */
                                        : sprintf( __( 'Unlock IP %s? It will be able to attempt logins again immediately.', 'wp-login-delay' ), $ip ) ); ?>">
                                        <input type="hidden" name="action" value="wldelay_unlock_lockout" />
                                        <input type="hidden" name="wldelay_lockout_ip" value="<?php echo esc_attr( $ip ); ?>" />
                                        <input type="hidden" name="wldelay_lockout_key" value="<?php echo esc_attr( $lockout_key ); ?>" />
                                        <?php // Display-only forensic label for the audit entry; matching is by lockout_key, not this value. ?>
                                        <input type="hidden" name="wldelay_lockout_username" value="<?php echo esc_attr( $username ); ?>" />
                                        <input type="hidden" name="wldelay_lockout_type" value="<?php echo esc_attr( $type ); ?>" />
                                        <?php wp_nonce_field( 'wldelay_unlock_lockout' ); ?>
                                        <button type="submit" class="button button-secondary button-small">
                                            <?php esc_html_e( 'Unlock', 'wp-login-delay' ); ?>
                                            <span class="screen-reader-text">
                                                <?php
                                                if ( '' !== $username ) {
                                                    printf(
                                                        /* translators: 1: username, 2: IP address */
                                                        esc_html__( 'Unlock %1$s on IP %2$s', 'wp-login-delay' ),
                                                        esc_html( $username ),
                                                        esc_html( $ip )
                                                    );
                                                } else {
                                                    printf(
                                                        /* translators: %s: IP address */
                                                        esc_html__( 'Unlock IP %s', 'wp-login-delay' ),
                                                        esc_html( $ip )
                                                    );
                                                }
                                                ?>
                                            </span>
                                        </button>
                                    </form>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>

                <?php if ( count( $lockouts ) >= $limit ) : ?>
                    <p class="description" role="status" aria-live="polite">
                        <?php
                        printf(
                            /* translators: %s: maximum number of lockouts shown */
                            esc_html__( 'Showing the most recent %s lockouts; older active lockouts are not listed.', 'wp-login-delay' ),
                            esc_html( number_format_i18n( $limit ) )
                        );
                        ?>
                    </p>
                <?php endif; ?>

                <div class="wldelay-clear-all">
                    <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="wldelay-clear-all-form" data-wldelay-confirm="<?php echo esc_attr__( 'Clear ALL active lockouts? Every currently blocked IP and account will be able to attempt logins again immediately. This cannot be undone.', 'wp-login-delay' ); ?>">
                        <input type="hidden" name="action" value="wldelay_clear_all_lockouts" />
                        <?php wp_nonce_field( 'wldelay_clear_all_lockouts' ); ?>
                        <button type="submit" class="button button-secondary"><?php esc_html_e( 'Clear all active lockouts', 'wp-login-delay' ); ?></button>
                    </form>
                </div>
            <?php endif; ?>
        </div>
        <?php
    }

    private function render_audit_log() {
        $filters      = wldelay_get_audit_filters_from_request();
        $per_page     = 25;
        $current_page = isset( $_GET['wldelay_audit_page'] ) ? max( 1, absint( wp_unslash( $_GET['wldelay_audit_page'] ) ) ) : 1;
        $total        = wldelay_count_audit_log( $filters );
        $total_pages  = max( 1, (int) ceil( $total / $per_page ) );

        if ( $current_page > $total_pages ) {
            $current_page = $total_pages;
        }

        $entries        = wldelay_query_audit_log( $filters, $current_page, $per_page );
        $action_options = wldelay_get_audit_action_options();
        ?>
        <div class="wldelay-audit" aria-labelledby="wldelay-audit-title">
            <h3 id="wldelay-audit-title" class="screen-reader-text"><?php esc_html_e( 'Audit log entries', 'wp-login-delay' ); ?></h3>

            <?php if ( function_exists( 'wldelay_audit_log_is_degraded' ) && wldelay_audit_log_is_degraded() ) : ?>
                <div class="notice notice-error inline" role="alert">
                    <p>
                        <?php esc_html_e( 'One or more audit-log entries could not be written, so this trail is permanently incomplete — the lost events cannot be recovered. This warning persists until an administrator acknowledges the gap.', 'wp-login-delay' ); ?>
                        <?php if ( function_exists( 'wldelay_get_audit_ack_gap_url' ) ) : ?>
                            <a href="<?php echo esc_url( wldelay_get_audit_ack_gap_url() ); ?>"><?php esc_html_e( 'Acknowledge gap', 'wp-login-delay' ); ?></a>
                        <?php endif; ?>
                    </p>
                </div>
            <?php endif; ?>

            <div class="wldelay-telemetry-filters">
                <input form="wldelay-audit-filter-form" type="hidden" name="page" value="login-delay-shield-admin" />
                <div class="wldelay-filter-grid">
                    <label for="wldelay_audit_action">
                        <?php esc_html_e( 'Action', 'wp-login-delay' ); ?>
                        <select id="wldelay_audit_action" name="wldelay_audit_action" form="wldelay-audit-filter-form">
                            <option value=""><?php esc_html_e( 'All actions', 'wp-login-delay' ); ?></option>
                            <?php foreach ( $action_options as $action_key ) : ?>
                                <option value="<?php echo esc_attr( $action_key ); ?>" <?php selected( $filters['action'], $action_key ); ?>><?php echo esc_html( wldelay_get_audit_action_label( $action_key ) ); ?></option>
                            <?php endforeach; ?>
                        </select>
                    </label>
                    <label for="wldelay_audit_actor">
                        <?php esc_html_e( 'Actor', 'wp-login-delay' ); ?>
                        <input id="wldelay_audit_actor" name="wldelay_audit_actor" form="wldelay-audit-filter-form" type="text" value="<?php echo esc_attr( $filters['actor'] ); ?>" placeholder="<?php echo esc_attr__( 'Login or user ID', 'wp-login-delay' ); ?>" />
                    </label>
                    <label for="wldelay_audit_from">
                        <?php esc_html_e( 'From', 'wp-login-delay' ); ?>
                        <input id="wldelay_audit_from" name="wldelay_audit_from" form="wldelay-audit-filter-form" type="date" value="<?php echo esc_attr( $filters['from'] ); ?>" />
                    </label>
                    <label for="wldelay_audit_to">
                        <?php esc_html_e( 'To', 'wp-login-delay' ); ?>
                        <input id="wldelay_audit_to" name="wldelay_audit_to" form="wldelay-audit-filter-form" type="date" value="<?php echo esc_attr( $filters['to'] ); ?>" />
                    </label>
                </div>
                <p class="wldelay-telemetry-actions">
                    <button type="submit" form="wldelay-audit-filter-form" class="button button-primary"><?php esc_html_e( 'Apply filters', 'wp-login-delay' ); ?></button>
                    <a class="button button-secondary" href="<?php echo esc_url( admin_url( 'options-general.php?page=login-delay-shield-admin' ) ); ?>"><?php esc_html_e( 'Reset', 'wp-login-delay' ); ?></a>
                </p>
            </div>

            <div class="wldelay-telemetry-results">
                <?php
                // Showing X–Y of Z. Date filters are ISO (YYYY-MM-DD) from the
                // date inputs, so a lexical compare detects an inverted range
                // (from after to) which would otherwise look identical to a
                // legitimately empty result set.
                $shown_count   = count( $entries );
                $range_start   = $total > 0 ? ( ( $current_page - 1 ) * $per_page ) + 1 : 0;
                $range_end     = $total > 0 ? ( $range_start + $shown_count - 1 ) : 0;
                $range_invalid = ( '' !== $filters['from'] && '' !== $filters['to'] && $filters['from'] > $filters['to'] );
                ?>
                <?php if ( $range_invalid ) : ?>
                    <p class="wldelay-empty-state" role="alert">
                        <?php esc_html_e( 'The “From” date is after the “To” date, so nothing can match. Swap the dates or clear one of them.', 'wp-login-delay' ); ?>
                    </p>
                <?php endif; ?>
                <p class="description" aria-live="polite">
                    <?php
                    if ( $total > 0 ) {
                        printf(
                            /* translators: 1: first entry shown on this page, 2: last entry shown, 3: total matching entries */
                            esc_html__( 'Showing %1$s–%2$s of %3$s matching audit entries.', 'wp-login-delay' ),
                            esc_html( number_format_i18n( $range_start ) ),
                            esc_html( number_format_i18n( $range_end ) ),
                            esc_html( number_format_i18n( $total ) )
                        );
                    } else {
                        esc_html_e( 'No audit entries match the current filters.', 'wp-login-delay' );
                    }
                    ?>
                </p>
                <?php if ( empty( $entries ) ) : ?>
                    <p class="wldelay-empty-state"><?php esc_html_e( 'No audit entries match the current filters.', 'wp-login-delay' ); ?></p>
                <?php else : ?>
                    <table class="widefat striped wldelay-audit-table">
                        <caption class="screen-reader-text"><?php esc_html_e( 'Audit log of administrative and security actions', 'wp-login-delay' ); ?></caption>
                        <thead>
                            <tr>
                                <th scope="col"><?php esc_html_e( 'Time', 'wp-login-delay' ); ?></th>
                                <th scope="col"><?php esc_html_e( 'Actor', 'wp-login-delay' ); ?></th>
                                <th scope="col"><?php esc_html_e( 'Action', 'wp-login-delay' ); ?></th>
                                <th scope="col"><?php esc_html_e( 'Object', 'wp-login-delay' ); ?></th>
                                <th scope="col"><?php esc_html_e( 'Details', 'wp-login-delay' ); ?></th>
                                <th scope="col"><?php esc_html_e( 'IP address', 'wp-login-delay' ); ?></th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ( $entries as $entry ) : ?>
                                <?php
                                $actor = '' !== (string) $entry->actor_login
                                    ? (string) $entry->actor_login
                                    : ( (int) $entry->actor_id > 0
                                        ? sprintf( /* translators: %d: user ID */ __( 'User #%d', 'wp-login-delay' ), (int) $entry->actor_id )
                                        : __( 'System', 'wp-login-delay' ) );
                                ?>
                                <tr>
                                    <td><?php echo esc_html( mysql2date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), get_date_from_gmt( (string) $entry->created_at ) ) ); ?></td>
                                    <td><?php echo esc_html( $actor ); ?></td>
                                    <td><?php echo esc_html( wldelay_get_audit_action_label( $entry->action ) ); ?></td>
                                    <td><?php echo esc_html( (string) $entry->object ); ?></td>
                                    <td><?php echo esc_html( $this->format_audit_detail( $entry ) ); ?></td>
                                    <td><?php echo esc_html( (string) $entry->ip_address ); ?></td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                    <?php $this->render_audit_pagination( $current_page, $total_pages, $filters ); ?>
                <?php endif; ?>
            </div>
        </div>
        <?php
    }

    /**
     * Build a compact, human-readable detail string for an audit row.
     *
     * Renders the changed-key diff (settings_changed) or the structured
     * new_value payload as `key: old -> new` / `key: value` fragments. Always
     * returns plain text; the caller escapes it.
     *
     * @param object $entry Audit row.
     * @return string
     */
    private function format_audit_detail( $entry ) {
        $new = isset( $entry->new_value ) && '' !== (string) $entry->new_value
            ? json_decode( (string) $entry->new_value, true )
            : null;

        if ( ! is_array( $new ) ) {
            return isset( $entry->new_value ) ? (string) $entry->new_value : '';
        }

        $fragments = array();
        foreach ( $new as $key => $value ) {
            if ( is_array( $value ) && array_key_exists( 'old', $value ) && array_key_exists( 'new', $value ) ) {
                $fragments[] = sprintf(
                    '%s: %s -> %s',
                    $key,
                    $this->scalarize_audit_value( $value['old'] ),
                    $this->scalarize_audit_value( $value['new'] )
                );
            } else {
                $fragments[] = sprintf( '%s: %s', $key, $this->scalarize_audit_value( $value ) );
            }
        }

        return implode( '; ', $fragments );
    }

    /**
     * Flatten an audit value to a short display string.
     *
     * @param mixed $value Raw value from the decoded diff.
     * @return string
     */
    private function scalarize_audit_value( $value ) {
        if ( null === $value ) {
            return '∅';
        }
        if ( is_bool( $value ) ) {
            return $value ? 'true' : 'false';
        }
        if ( is_array( $value ) ) {
            $encoded = wp_json_encode( $value );
            return false === $encoded ? '' : $encoded;
        }
        return (string) $value;
    }

    /**
     * Render audit-log pagination links.
     *
     * @param int   $current_page Current page number.
     * @param int   $total_pages  Total page count.
     * @param array $filters      Active filters.
     */
    private function render_audit_pagination( $current_page, $total_pages, $filters ) {
        if ( $total_pages <= 1 ) {
            return;
        }

        $query_args = array();
        $key_map    = array(
            'action' => 'wldelay_audit_action',
            'actor'  => 'wldelay_audit_actor',
            'from'   => 'wldelay_audit_from',
            'to'     => 'wldelay_audit_to',
        );
        foreach ( $key_map as $short => $long ) {
            if ( isset( $filters[ $short ] ) && '' !== $filters[ $short ] ) {
                $query_args[ $long ] = $filters[ $short ];
            }
        }

        $base_args = array_merge(
            array( 'page' => 'login-delay-shield-admin' ),
            $query_args
        );

        echo '<nav class="wldelay-pagination" aria-label="' . esc_attr__( 'Audit log pagination', 'wp-login-delay' ) . '">';
        if ( $current_page > 1 ) {
            echo '<a class="button button-secondary" href="' . esc_url( add_query_arg( array_merge( $base_args, array( 'wldelay_audit_page' => $current_page - 1 ) ), admin_url( 'options-general.php' ) ) ) . '">' . esc_html__( 'Previous', 'wp-login-delay' ) . '</a> ';
        }
        printf(
            '<span class="wldelay-pagination-status">%s</span>',
            esc_html(
                sprintf(
                    /* translators: 1: current page, 2: total pages */
                    __( 'Page %1$d of %2$d', 'wp-login-delay' ),
                    $current_page,
                    $total_pages
                )
            )
        );
        if ( $current_page < $total_pages ) {
            echo ' <a class="button button-secondary" href="' . esc_url( add_query_arg( array_merge( $base_args, array( 'wldelay_audit_page' => $current_page + 1 ) ), admin_url( 'options-general.php' ) ) ) . '">' . esc_html__( 'Next', 'wp-login-delay' ) . '</a>';
        }
        echo '</nav>';
    }

    /**
     * Generate status badge HTML with screen reader context
     *
     * @param string $option_key Option key to check
     * @param string $feature_name Optional feature name for screen reader context
     */
    private function get_status_badge( $option_key, $feature_name = '' ) {
        $is_enabled = ! empty( $this->options[ $option_key ] );
        $class = $is_enabled ? 'wldelay-badge-enabled' : 'wldelay-badge-disabled';
        $text = $is_enabled ? __( 'Enabled', 'wp-login-delay' ) : __( 'Disabled', 'wp-login-delay' );

        // Screen reader text provides context
        $sr_text = $feature_name
            ? sprintf(
                /* translators: 1: feature name, 2: enabled or disabled */
                __( '%1$s: %2$s', 'wp-login-delay' ),
                $feature_name,
                $text
            )
            : $text;

        return sprintf(
            '<span class="wldelay-badge %s" data-toggle="%s" aria-live="polite">' .
            '<span class="screen-reader-text">%s</span>' .
            '<span aria-hidden="true">%s</span>' .
            '</span>',
            esc_attr( $class ),
            esc_attr( $option_key ),
            esc_html( $sr_text ),
            esc_html( $text )
        );
    }

    /**
     * Output fields for a specific settings section
     */
    private function do_settings_section_fields( $section_id ) {
        global $wp_settings_fields;

        if ( ! isset( $wp_settings_fields['login-delay-shield-admin'][ $section_id ] ) ) {
            return;
        }

        echo '<table class="form-table" role="presentation">';
        foreach ( $wp_settings_fields['login-delay-shield-admin'][ $section_id ] as $field ) {
            echo '<tr>';
            printf(
                '<th scope="row"><label for="%s">%s</label></th>',
                esc_attr( $field['id'] ),
                $field['title']
            );
            echo '<td>';
            call_user_func( $field['callback'], $field['args'] );
            echo '</td>';
            echo '</tr>';
        }
        echo '</table>';
    }


    /**
     * Print the Section text
     */
    public function print_section_info() {
        // Section description is now in card structure
    }

    /**
     * Print email section info
     */
    public function print_email_section_info() {
        // Description is now in card structure
    }

    /**
     * Print lockout section info
     */
    public function print_lockout_section_info() {
        // Description is now in card structure
    }

    /**
     * Print whitelist section info
     */
    public function print_whitelist_section_info() {
        // Description is now in card structure
    }

    /**
     * Print log section info
     */
    public function print_log_section_info() {
        // Description is now in card structure
    }

    /**
     * Print XMLRPC section info
     */
    public function print_xmlrpc_section_info() {
        // Description is now in card structure
    }

    /**
     * Delay field callback
     */
    public function delay_callback() {
        printf(
            '<input type="text" id="wldelay_delay" name="wldelay_options[wldelay_delay]" value="%d" />',
            isset( $this->options['wldelay_delay'] ) ? esc_attr( $this->options['wldelay_delay']) : esc_attr( LDS_Settings::_DEFAULT_DELAY_IN_SECONDS )
        );
        echo $this->tooltip( __( 'A fixed delay applied to every login attempt. Higher values slow down brute-force attacks but may slightly delay legitimate users.', 'wp-login-delay' ), wldelay_get_doc_url( 'delay-settings' ) );
    }

    /**
     * Random delay checkbox callback
     */
    public function delay_callback_random() {
        printf(
            '<input type="checkbox" id="wldelay_delay_random" name="wldelay_options[wldelay_delay_random]" value="1" %s />',
            ! empty( $this->options['wldelay_delay_random'] ) ? 'checked="checked"' : ''
        );
        echo $this->tooltip( __( 'Randomized delays make it harder for attackers to detect patterns or time their attempts. Recommended for better security.', 'wp-login-delay' ) );
    }

    /**
     * Random delay minimum callback
     */
    public function delay_callback_random_min() {
        printf(
            '<input type="number" id="wldelay_delay_random_min" name="wldelay_options[wldelay_delay_random_min]" value="%d" min="1" max="10" />',
            isset( $this->options['wldelay_delay_random_min'] ) ? esc_attr( $this->options['wldelay_delay_random_min'] ) : esc_attr( LDS_Settings::_DEFAULT_RANDOM_MIN )
        );
        echo $this->tooltip( __( 'The shortest possible delay. Each login attempt will wait at least this many seconds.', 'wp-login-delay' ) );
    }

    /**
     * Random delay maximum callback
     */
    public function delay_callback_random_max() {
        printf(
            '<input type="number" id="wldelay_delay_random_max" name="wldelay_options[wldelay_delay_random_max]" value="%d" min="1" max="10" />',
            isset( $this->options['wldelay_delay_random_max'] ) ? esc_attr( $this->options['wldelay_delay_random_max'] ) : esc_attr( LDS_Settings::_DEFAULT_RANDOM_MAX )
        );
        echo $this->tooltip( __( 'The longest possible delay. Each login attempt will wait up to this many seconds.', 'wp-login-delay' ) );
    }

    /**
     * Email enabled callback
     */
    public function email_enabled_callback() {
        printf(
            '<input type="checkbox" id="wldelay_email_enabled" name="wldelay_options[wldelay_email_enabled]" value="1" %s />',
            ! empty( $this->options['wldelay_email_enabled'] ) ? 'checked="checked"' : ''
        );
        echo $this->tooltip( __( 'Get notified when someone is trying to break into your site. Alerts are sent once per IP until the attack stops.', 'wp-login-delay' ), wldelay_get_doc_url( 'email-notifications' ) );
    }

    /**
     * Email threshold callback
     */
    public function email_threshold_callback() {
        printf(
            '<input type="number" id="wldelay_email_threshold" name="wldelay_options[wldelay_email_threshold]" value="%d" min="1" max="100" />',
            isset( $this->options['wldelay_email_threshold'] ) ? esc_attr( $this->options['wldelay_email_threshold'] ) : esc_attr( LDS_Settings::_DEFAULT_EMAIL_THRESHOLD )
        );
        echo $this->tooltip( __( 'Number of failed attempts from one IP before sending an alert. Lower values mean earlier warnings but more emails.', 'wp-login-delay' ) );
    }

    /**
     * Email address callback
     */
    public function email_address_callback() {
        printf(
            '<input type="email" id="wldelay_email_address" name="wldelay_options[wldelay_email_address]" value="%s" class="regular-text" placeholder="%s" aria-describedby="wldelay_email_address_desc" />',
            isset( $this->options['wldelay_email_address'] ) ? esc_attr( $this->options['wldelay_email_address'] ) : '',
            esc_attr( get_option( 'admin_email' ) )
        );
        echo $this->tooltip( __( 'Where to send security alerts. If left blank, emails go to the WordPress admin address.', 'wp-login-delay' ) );
        echo '<p id="wldelay_email_address_desc" class="description">' . esc_html__( 'Leave empty to use the site admin email.', 'wp-login-delay' ) . '</p>';
    }

    /**
     * Email cooldown callback
     */
    public function email_cooldown_callback() {
        printf(
            '<input type="number" id="wldelay_email_cooldown" name="wldelay_options[wldelay_email_cooldown]" value="%d" min="0" max="60" aria-describedby="wldelay_email_cooldown_desc" />',
            isset( $this->options['wldelay_email_cooldown'] ) ? esc_attr( $this->options['wldelay_email_cooldown'] ) : esc_attr( LDS_Settings::_DEFAULT_EMAIL_COOLDOWN )
        );
        echo ' <span class="description">' . esc_html__( 'minutes', 'wp-login-delay' ) . '</span>';
        echo $this->tooltip( __( 'Minimum time between alert emails site-wide. Prevents inbox flooding during coordinated attacks from multiple IPs. Set to 0 to disable.', 'wp-login-delay' ) );
        echo '<p id="wldelay_email_cooldown_desc" class="description">' . esc_html__( 'Set to 0 to send an email for every IP that hits the threshold.', 'wp-login-delay' ) . '</p>';
    }

    /**
     * Lockout enabled callback
     */
    public function lockout_enabled_callback() {
        printf(
            '<input type="checkbox" id="wldelay_lockout_enabled" name="wldelay_options[wldelay_lockout_enabled]" value="1" %s />',
            ! empty( $this->options['wldelay_lockout_enabled'] ) ? 'checked="checked"' : ''
        );
        echo $this->tooltip( __( 'Temporarily block IPs after too many failures. Effective at stopping automated attacks cold.', 'wp-login-delay' ), wldelay_get_doc_url( 'ip-lockout' ) );
    }

    /**
     * Lockout threshold callback
     */
    public function lockout_threshold_callback() {
        printf(
            '<input type="number" id="wldelay_lockout_threshold" name="wldelay_options[wldelay_lockout_threshold]" value="%d" min="1" max="100" />',
            isset( $this->options['wldelay_lockout_threshold'] )
                ? esc_attr( $this->options['wldelay_lockout_threshold'] )
                : esc_attr( LDS_Settings::_DEFAULT_LOCKOUT_THRESHOLD )
        );
        echo $this->tooltip( __( 'How many failed attempts before lockout is triggered for the selected strategy.', 'wp-login-delay' ) );
    }

    /**
     * Lockout attempt strategy callback
     */
    public function lockout_attempt_strategy_callback() {
        $strategy = isset( $this->options['wldelay_lockout_attempt_strategy'] )
            ? $this->options['wldelay_lockout_attempt_strategy']
            : LDS_Settings::_DEFAULT_LOCKOUT_ATTEMPT_STRATEGY;

        if ( ! in_array( $strategy, array( 'ip', 'ip_username' ), true ) ) {
            $strategy = LDS_Settings::_DEFAULT_LOCKOUT_ATTEMPT_STRATEGY;
        }

        $ip_selected = ( 'ip' === $strategy ) ? 'selected="selected"' : '';
        $pair_selected = ( 'ip_username' === $strategy ) ? 'selected="selected"' : '';

        printf(
            '<select id="wldelay_lockout_attempt_strategy" name="wldelay_options[wldelay_lockout_attempt_strategy]" aria-describedby="wldelay_lockout_attempt_strategy_desc">
                <option value="ip" %s>%s</option>
                <option value="ip_username" %s>%s</option>
            </select>',
            $ip_selected,
            esc_html__( 'IP only', 'wp-login-delay' ),
            $pair_selected,
            esc_html__( 'IP + username', 'wp-login-delay' )
        );

        echo $this->tooltip( __( 'Choose how failed attempts are grouped for progressive delay and lockout. "IP + username" is better for shared networks.', 'wp-login-delay' ) );
        echo '<p id="wldelay_lockout_attempt_strategy_desc" class="description">' . esc_html__( 'IP only = one counter per IP. IP + username = separate counters per username on the same IP.', 'wp-login-delay' ) . '</p>';
    }

    /**
     * Lockout duration callback
     */
    public function lockout_duration_callback() {
        printf(
            '<input type="number" id="wldelay_lockout_duration" name="wldelay_options[wldelay_lockout_duration]" value="%d" min="1" max="1440" aria-describedby="wldelay_lockout_duration_desc" />',
            isset( $this->options['wldelay_lockout_duration'] )
                ? esc_attr( $this->options['wldelay_lockout_duration'] )
                : esc_attr( LDS_Settings::_DEFAULT_LOCKOUT_DURATION )
        );
        echo $this->tooltip( __( 'How long to block an IP. Longer durations discourage persistent attackers but may inconvenience legitimate users who forgot their password.', 'wp-login-delay' ) );
        echo '<p id="wldelay_lockout_duration_desc" class="description">' . esc_html__( 'Maximum: 1440 minutes (24 hours)', 'wp-login-delay' ) . '</p>';
    }

    /**
     * Trust proxy headers callback
     */
    public function trust_proxy_headers_callback() {
        printf(
            '<input type="checkbox" id="wldelay_trust_proxy_headers" name="wldelay_options[wldelay_trust_proxy_headers]" value="1" %s aria-describedby="wldelay_trust_proxy_desc" />',
            ! empty( $this->options['wldelay_trust_proxy_headers'] ) ? 'checked="checked"' : ''
        );
        echo $this->tooltip( __( 'Enable this only if your site is behind a reverse proxy or load balancer (e.g., Cloudflare, nginx proxy, AWS ELB). When disabled, only the direct connection IP is used, preventing attackers from spoofing their IP address.', 'wp-login-delay' ) );
        echo '<p id="wldelay_trust_proxy_desc" class="description">' . esc_html__( 'Required when behind a proxy or CDN (Cloudflare, Sucuri, nginx) so visitors are identified by their real IP. Supported headers: CF-Connecting-IP (validated against Cloudflare\'s published IP ranges), X-Sucuri-ClientIP, Client-IP, X-Real-IP, X-Forwarded-For. Leave disabled on direct-connection sites — enabling it there allows IP spoofing.', 'wp-login-delay' ) . '</p>';
    }

    /**
     * Progressive enabled callback
     */
    public function progressive_enabled_callback() {
        printf(
            '<input type="checkbox" id="wldelay_progressive_enabled" name="wldelay_options[wldelay_progressive_enabled]" value="1" %s aria-describedby="wldelay_progressive_enabled_desc" />',
            ! empty( $this->options['wldelay_progressive_enabled'] ) ? 'checked="checked"' : ''
        );
        echo $this->tooltip( __( 'Delays grow longer with each failed attempt. First try might be 1s, second 2s, third 3s, etc. Very effective against automated attacks.', 'wp-login-delay' ) );
        echo '<p id="wldelay_progressive_enabled_desc" class="description">' . esc_html__( 'Increase delay with each consecutive failed attempt from the same IP.', 'wp-login-delay' ) . '</p>';
    }

    /**
     * Progressive increment callback
     */
    public function progressive_increment_callback() {
        printf(
            '<input type="number" id="wldelay_progressive_increment" name="wldelay_options[wldelay_progressive_increment]" value="%d" min="1" max="10" aria-describedby="wldelay_progressive_increment_desc" />',
            isset( $this->options['wldelay_progressive_increment'] )
                ? esc_attr( $this->options['wldelay_progressive_increment'] )
                : esc_attr( LDS_Settings::_DEFAULT_PROGRESSIVE_INCREMENT )
        );
        echo $this->tooltip( __( 'How much to increase the delay after each failed attempt. Higher values penalize repeat offenders more aggressively.', 'wp-login-delay' ) );
        echo '<p id="wldelay_progressive_increment_desc" class="description">' . esc_html__( 'Additional seconds added per failed attempt (1-10).', 'wp-login-delay' ) . '</p>';
    }

    /**
     * Progressive max callback
     */
    public function progressive_max_callback() {
        printf(
            '<input type="number" id="wldelay_progressive_max" name="wldelay_options[wldelay_progressive_max]" value="%d" min="5" max="60" aria-describedby="wldelay_progressive_max_desc" />',
            isset( $this->options['wldelay_progressive_max'] )
                ? esc_attr( $this->options['wldelay_progressive_max'] )
                : esc_attr( LDS_Settings::_DEFAULT_PROGRESSIVE_MAX )
        );
        echo $this->tooltip( __( 'The delay stops increasing at this value. Prevents excessively long waits that could tie up server resources.', 'wp-login-delay' ) );
        echo '<p id="wldelay_progressive_max_desc" class="description">' . esc_html__( 'Maximum total delay in seconds (5-60).', 'wp-login-delay' ) . '</p>';
    }

    /**
     * Whitelist enabled callback
     */
    public function whitelist_enabled_callback() {
        printf(
            '<input type="checkbox" id="wldelay_whitelist_enabled" name="wldelay_options[wldelay_whitelist_enabled]" value="1" %s />',
            ! empty( $this->options['wldelay_whitelist_enabled'] ) ? 'checked="checked"' : ''
        );
        echo $this->tooltip( __( 'Bypass all protection for trusted IPs. Useful for office networks or VPNs where delays would be annoying.', 'wp-login-delay' ), wldelay_get_doc_url( 'ip-whitelist' ) );
    }

    /**
     * Whitelist IPs callback
     */
    public function whitelist_ips_callback() {
        printf(
            '<textarea id="wldelay_whitelist_ips" name="wldelay_options[wldelay_whitelist_ips]" rows="5" cols="40" class="large-text code" aria-describedby="wldelay_whitelist_ips_desc">%s</textarea>',
            isset( $this->options['wldelay_whitelist_ips'] ) ? esc_textarea( $this->options['wldelay_whitelist_ips'] ) : ''
        );
        echo $this->tooltip( __( 'Enter trusted IP addresses. CIDR notation (e.g., 192.168.1.0/24) allows whitelisting entire networks.', 'wp-login-delay' ) );
        echo '<p id="wldelay_whitelist_ips_desc" class="description">' . esc_html__( 'One IP address or CIDR range per line (e.g., 192.168.1.1 or 10.0.0.0/8).', 'wp-login-delay' ) . '</p>';
    }

    /**
     * Log retention callback
     */
    public function log_retention_callback() {
        printf(
            '<input type="number" id="wldelay_log_retention_days" name="wldelay_options[wldelay_log_retention_days]" value="%d" min="0" max="365" aria-describedby="wldelay_log_retention_desc" />',
            isset( $this->options['wldelay_log_retention_days'] )
                ? esc_attr( $this->options['wldelay_log_retention_days'] )
                : esc_attr( LDS_Settings::_DEFAULT_LOG_RETENTION_DAYS )
        );
        echo $this->tooltip( __( 'Old logs are automatically cleaned up to save database space. Shorter retention = smaller database.', 'wp-login-delay' ), wldelay_get_doc_url( 'login-log' ) );
        echo '<p id="wldelay_log_retention_desc" class="description">' . esc_html__( 'Automatically delete log entries older than this many days. Set to 0 to keep logs forever.', 'wp-login-delay' ) . '</p>';
    }

    /**
     * fail2ban logging enabled callback.
     */
    public function fail2ban_enabled_callback() {
        printf(
            '<input type="checkbox" id="wldelay_fail2ban_enabled" name="wldelay_options[wldelay_fail2ban_enabled]" value="1" %s aria-describedby="wldelay_fail2ban_enabled_desc" />',
            ! empty( $this->options['wldelay_fail2ban_enabled'] ) ? 'checked="checked"' : ''
        );
        echo $this->tooltip( __( 'Write a fail2ban-compatible line when Login Delay Shield records an authentication failure.', 'wp-login-delay' ) );
        echo '<p id="wldelay_fail2ban_enabled_desc" class="description">' . esc_html__( 'Disabled by default. Enable only after configuring a fail2ban jail to watch the selected log file.', 'wp-login-delay' ) . '</p>';
    }

    /**
     * fail2ban log path callback.
     */
    public function fail2ban_log_path_callback() {
        $path = isset( $this->options['wldelay_fail2ban_log_path'] ) ? $this->options['wldelay_fail2ban_log_path'] : '';
        $default_path = wldelay_fail2ban_get_default_log_path();

        printf(
            '<input type="text" id="wldelay_fail2ban_log_path" name="wldelay_options[wldelay_fail2ban_log_path]" value="%s" class="regular-text code" placeholder="%s" aria-describedby="wldelay_fail2ban_log_path_desc" />',
            esc_attr( $path ),
            esc_attr( $default_path )
        );
        echo $this->tooltip( __( 'Leave empty to use the protected default log directory. Custom paths are restricted to the protected default directory by default; use the filter only for server-protected directories.', 'wp-login-delay' ) );
        printf(
            '<p id="wldelay_fail2ban_log_path_desc" class="description">%s <code>%s</code></p>',
            esc_html__( 'Leave empty to write to the protected default path:', 'wp-login-delay' ),
            esc_html( $default_path )
        );
    }

    /**
     * fail2ban lockout event callback.
     */
    public function fail2ban_include_lockouts_callback() {
        $include_lockouts = array_key_exists( 'wldelay_fail2ban_include_lockouts', (array) $this->options )
            ? ! empty( $this->options['wldelay_fail2ban_include_lockouts'] )
            : LDS_Settings::_DEFAULT_FAIL2BAN_INCLUDE_LOCKOUTS;

        printf(
            '<input type="checkbox" id="wldelay_fail2ban_include_lockouts" name="wldelay_options[wldelay_fail2ban_include_lockouts]" value="1" %s aria-describedby="wldelay_fail2ban_include_lockouts_desc" />',
            $include_lockouts ? 'checked="checked"' : ''
        );
        echo $this->tooltip( __( 'Also write a line when Login Delay Shield creates a temporary lockout.', 'wp-login-delay' ) );
        echo '<p id="wldelay_fail2ban_include_lockouts_desc" class="description">' . esc_html__( 'Useful when your jail should ban on plugin lockouts as well as individual failed-login lines.', 'wp-login-delay' ) . '</p>';
    }

    /**
     * fail2ban config download button callback (F-5-8).
     */
    public function fail2ban_config_download_callback() {
        ?>
        <a class="button" href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=wldelay_download_fail2ban_config' ), 'wldelay_fail2ban_config' ) ); ?>" aria-describedby="wldelay-f2b-config-desc">
            <?php esc_html_e( 'Download fail2ban config', 'wp-login-delay' ); ?>
        </a>
        <p class="description" id="wldelay-f2b-config-desc"><?php esc_html_e( 'Generates filter.d/wldelay.conf and a jail.local snippet matching your current log path and format.', 'wp-login-delay' ); ?></p>
        <?php
    }

    /**
     * XMLRPC enabled callback
     */
    public function xmlrpc_enabled_callback() {
        printf(
            '<input type="checkbox" id="wldelay_xmlrpc_enabled" name="wldelay_options[wldelay_xmlrpc_enabled]" value="1" %s aria-describedby="wldelay_xmlrpc_enabled_desc" />',
            ! empty( $this->options['wldelay_xmlrpc_enabled'] ) ? 'checked="checked"' : ''
        );
        echo $this->tooltip( __( 'XML-RPC is often targeted by attackers because it allows multiple login attempts in a single request. Protecting it is strongly recommended.', 'wp-login-delay' ), wldelay_get_doc_url( 'xmlrpc-protection' ) );
        echo '<p id="wldelay_xmlrpc_enabled_desc" class="description">' . esc_html__( 'Apply delay and lockout protection to XML-RPC authentication requests.', 'wp-login-delay' ) . '</p>';
    }

    /**
     * XMLRPC block callback
     */
    public function xmlrpc_block_callback() {
        printf(
            '<input type="checkbox" id="wldelay_xmlrpc_block" name="wldelay_options[wldelay_xmlrpc_block]" value="1" %s aria-describedby="wldelay_xmlrpc_block_desc" />',
            ! empty( $this->options['wldelay_xmlrpc_block'] ) ? 'checked="checked"' : ''
        );
        echo $this->tooltip( __( 'Completely disables XML-RPC login. Enable this if you manage your site only via the web interface and don\'t use Jetpack or the WP mobile app.', 'wp-login-delay' ) );
        echo '<p id="wldelay_xmlrpc_block_desc" class="description">' . esc_html__( 'Completely block XML-RPC authentication. Use this if you don\'t need remote publishing or the WordPress mobile app.', 'wp-login-delay' ) . '</p>';
    }

    /**
     * REST protection callback.
     */
    public function rest_enabled_callback() {
        printf(
            '<input type="checkbox" id="wldelay_rest_enabled" name="wldelay_options[wldelay_rest_enabled]" value="1" %s aria-describedby="wldelay_rest_enabled_desc" />',
            ! empty( $this->options['wldelay_rest_enabled'] ) ? 'checked="checked"' : ''
        );
        echo $this->tooltip( __( 'Apply delay and lockout checks to failed REST API authentication requests.', 'wp-login-delay' ) );
        echo '<p id="wldelay_rest_enabled_desc" class="description">' . esc_html__( 'Protect failed REST authentication attempts with the same delay/lockout behavior.', 'wp-login-delay' ) . '</p>';
    }

    /**
     * Print custom login section info
     */
    public function print_custom_login_section_info() {
        // Bookmark warning + recovery instructions. Competing login-URL
        // plugins are notorious for stranding admins behind a 404; surfacing
        // the recovery path BEFORE enabling is deliberate.
        echo '<p class="description">' . esc_html__( 'After enabling, bookmark your new login URL immediately — the standard wp-login.php will return a 404. The new URL is also emailed to the site admin, and the plugin verifies the URL works before leaving the feature enabled.', 'wp-login-delay' ) . '</p>';
        printf(
            '<p class="description">%s</p>',
            sprintf(
                /* translators: 1: WLDELAY_DISABLE_CUSTOM_LOGIN constant code snippet, 2: wp-config.php file name. */
                esc_html__( 'Emergency recovery: add %1$s to %2$s to restore wp-login.php at any time, without disabling the plugin.', 'wp-login-delay' ),
                '<code>define( \'WLDELAY_DISABLE_CUSTOM_LOGIN\', true );</code>',
                '<code>wp-config.php</code>'
            )
        );
    }

    /**
     * Custom login enabled callback
     */
    public function custom_login_enabled_callback() {
        printf(
            '<input type="checkbox" id="wldelay_custom_login_enabled" name="wldelay_options[wldelay_custom_login_enabled]" value="1" %s aria-describedby="wldelay_custom_login_enabled_desc" />',
            ! empty( $this->options['wldelay_custom_login_enabled'] ) ? 'checked="checked"' : ''
        );
        echo $this->tooltip( __( 'When enabled, the default wp-login.php URL will return a 404, and only the custom slug will load the login page.', 'wp-login-delay' ), wldelay_get_doc_url( 'custom-login-url' ) );
        echo '<p id="wldelay_custom_login_enabled_desc" class="description">' . esc_html__( 'Replace wp-login.php with a custom URL slug.', 'wp-login-delay' ) . '</p>';
    }

    /**
     * Custom login slug callback
     */
    public function custom_login_slug_callback() {
        $slug = isset( $this->options['wldelay_custom_login_slug'] ) ? $this->options['wldelay_custom_login_slug'] : 'my-login';
        printf(
            '<code>%s/</code><input type="text" id="wldelay_custom_login_slug" name="wldelay_options[wldelay_custom_login_slug]" value="%s" class="regular-text" aria-describedby="wldelay_custom_login_slug_desc" />',
            esc_html( home_url() ),
            esc_attr( $slug )
        );
        echo $this->tooltip( __( 'Choose a unique, hard-to-guess slug. Only lowercase letters, numbers, and hyphens are allowed.', 'wp-login-delay' ) );
        echo '<p id="wldelay_custom_login_slug_desc" class="description">' . esc_html__( 'Lowercase letters, numbers, and hyphens only. Reserved slugs (wp-admin, login, etc.) are rejected.', 'wp-login-delay' ) . '</p>';
    }

    /**
     * Print recovery section info
     */
    public function print_recovery_section_info() {
        // Intro text lives in the card body; nothing extra needed here.
    }

    /**
     * Recovery enabled callback
     */
    public function recovery_enabled_callback() {
        printf(
            '<input type="checkbox" id="wldelay_recovery_enabled" name="wldelay_options[wldelay_recovery_enabled]" value="1" %s aria-describedby="wldelay_recovery_enabled_desc" />',
            ! empty( $this->options['wldelay_recovery_enabled'] ) ? 'checked="checked"' : ''
        );
        echo '<p id="wldelay_recovery_enabled_desc" class="description">' . esc_html__( 'Turn on a secret URL that can clear your own IP lockout if you are ever locked out.', 'wp-login-delay' ) . '</p>';
    }

    /**
     * Application password protection callback.
     */
    public function application_password_enabled_callback() {
        printf(
            '<input type="checkbox" id="wldelay_application_password_enabled" name="wldelay_options[wldelay_application_password_enabled]" value="1" %s aria-describedby="wldelay_application_password_enabled_desc" />',
            ! empty( $this->options['wldelay_application_password_enabled'] ) ? 'checked="checked"' : ''
        );
        echo $this->tooltip( __( 'Apply delay and lockout checks to application-password authentication attempts.', 'wp-login-delay' ) );
        echo '<p id="wldelay_application_password_enabled_desc" class="description">' . esc_html__( 'Protect failed application-password attempts and log them separately.', 'wp-login-delay' ) . '</p>';
    }

    /**
     * Password reset protection callback.
     */
    public function password_reset_enabled_callback() {
        printf(
            '<input type="checkbox" id="wldelay_password_reset_enabled" name="wldelay_options[wldelay_password_reset_enabled]" value="1" %s aria-describedby="wldelay_password_reset_enabled_desc" />',
            ! empty( $this->options['wldelay_password_reset_enabled'] ) ? 'checked="checked"' : ''
        );
        echo $this->tooltip( __( 'Apply delay, lockout checks, and logging to password reset submissions without revealing whether an account exists.', 'wp-login-delay' ) );
        echo '<p id="wldelay_password_reset_enabled_desc" class="description">' . esc_html__( 'Protect password reset requests with the same delay and lockout behavior.', 'wp-login-delay' ) . '</p>';
    }

    /**
     * Print botnet section info.
     */
    public function print_botnet_section_info() {
        // Description is now in card structure.
    }

    /**
     * Botnet detection enabled callback.
     */
    public function botnet_enabled_callback() {
        printf(
            '<input type="checkbox" id="wldelay_botnet_enabled" name="wldelay_options[wldelay_botnet_enabled]" value="1" %s aria-describedby="wldelay_botnet_enabled_desc" />',
            ! empty( $this->options['wldelay_botnet_enabled'] ) ? 'checked="checked"' : ''
        );
        echo $this->tooltip( __( 'Watches whether a single username is targeted from many different IP addresses inside a short window — the pattern per-IP lockouts cannot see. Generates dashboard banner alerts, audit log entries, and optional emails. Never blocks logins.', 'wp-login-delay' ), wldelay_get_doc_url( 'distributed-attack' ) );
        echo '<p id="wldelay_botnet_enabled_desc" class="description">' . esc_html__( 'Enable cross-IP botnet / credential-stuffing detection (alert only, never blocks).', 'wp-login-delay' ) . '</p>';
    }

    /**
     * Botnet distinct-IP threshold callback.
     */
    public function botnet_ip_threshold_callback() {
        printf(
            '<input type="number" id="wldelay_botnet_ip_threshold" name="wldelay_options[wldelay_botnet_ip_threshold]" value="%d" min="2" max="100" aria-describedby="wldelay_botnet_ip_threshold_desc" />',
            isset( $this->options['wldelay_botnet_ip_threshold'] )
                ? esc_attr( $this->options['wldelay_botnet_ip_threshold'] )
                : 5
        );
        echo $this->tooltip( __( 'How many distinct source IP addresses targeting the same username within the detection window triggers an alert. Lower values catch slower attacks; higher values reduce false positives on shared networks.', 'wp-login-delay' ) );
        echo '<p id="wldelay_botnet_ip_threshold_desc" class="description">' . esc_html__( 'Number of distinct source IPs (2–100) that trigger an alert.', 'wp-login-delay' ) . '</p>';
    }

    /**
     * Botnet detection window callback.
     */
    public function botnet_window_minutes_callback() {
        printf(
            '<input type="number" id="wldelay_botnet_window_minutes" name="wldelay_options[wldelay_botnet_window_minutes]" value="%d" min="5" max="60" aria-describedby="wldelay_botnet_window_minutes_desc" />',
            isset( $this->options['wldelay_botnet_window_minutes'] )
                ? esc_attr( $this->options['wldelay_botnet_window_minutes'] )
                : 15
        );
        echo ' <span class="description">' . esc_html__( 'minutes', 'wp-login-delay' ) . '</span>';
        echo $this->tooltip( __( 'Sliding time window over which distinct source IPs are counted. Shorter windows catch faster attacks; longer windows catch slow-and-slow distributed campaigns.', 'wp-login-delay' ) );
        echo '<p id="wldelay_botnet_window_minutes_desc" class="description">' . esc_html__( 'Detection window in minutes (5–60).', 'wp-login-delay' ) . '</p>';
    }

    /**
     * Username enumeration hardening callback.
     */
    public function enumeration_hardening_enabled_callback() {
        printf(
            '<input type="checkbox" id="wldelay_enumeration_hardening_enabled" name="wldelay_options[wldelay_enumeration_hardening_enabled]" value="1" %s aria-describedby="wldelay_enumeration_hardening_enabled_desc wldelay_enumeration_hardening_enabled_note" />',
            ! empty( $this->options['wldelay_enumeration_hardening_enabled'] ) ? 'checked="checked"' : ''
        );
        echo $this->tooltip( __( 'Reduces common username-enumeration paths: failed logins all show one generic error, ?author=N enumeration is blocked, unauthenticated REST user listings are restricted, and the public users sitemap is removed. Note: this does not cover the password-reset (lost password) flow, which can still reveal whether an account exists.', 'wp-login-delay' ) );
        echo '<p id="wldelay_enumeration_hardening_enabled_desc" class="description">' . esc_html__( 'Return a single generic login error for both unknown usernames and wrong passwords, block author-archive enumeration, restrict unauthenticated REST user listings, and remove the public users sitemap. Does not change the password-reset flow.', 'wp-login-delay' ) . '</p>';
        echo '<p id="wldelay_enumeration_hardening_enabled_note" class="description wldelay-enumeration-note"><span class="dashicons dashicons-info-outline" aria-hidden="true"></span> ' . esc_html__( 'Heads up: legitimate users will no longer be told whether they mistyped their username or their password on the login screen, and the password-reset form can still disclose whether an account exists. Make sure your support flow accounts for this before enabling.', 'wp-login-delay' ) . '</p>';
    }
}
