<?php
if ( ! defined( 'ABSPATH' ) ) exit;

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
                esc_html__( 'Learn more', 'login-delay-shield' )
            );
        }

        return sprintf(
            '<span class="wldelay-tooltip" tabindex="0" aria-describedby="%s">' .
            '<span class="dashicons dashicons-editor-help" aria-hidden="true"></span>' .
            '<span class="screen-reader-text">%s</span>' .
            '<span id="%s" class="wldelay-tooltip-text" role="tooltip">%s%s</span>' .
            '</span>',
            esc_attr( $tooltip_id ),
            esc_html__( 'Help', 'login-delay-shield' ),
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
            <?php $this->render_object_cache_notice(); ?>

            <form id="wldelay-telemetry-filter-form" method="get" action="<?php echo esc_url( admin_url( 'options-general.php' ) ); ?>"></form>

            <form method="post" action="options.php">
                <?php settings_fields( 'wldelay_option_group' ); ?>

                <div class="wldelay-card">
                    <h2 class="wldelay-card-header" role="button" tabindex="0" aria-expanded="true" aria-controls="wldelay-delay-body">
                        <span class="dashicons dashicons-clock" aria-hidden="true"></span>
                        <?php esc_html_e( 'Delay Settings', 'login-delay-shield' ); ?>
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
                            <?php esc_html_e( 'Email Notifications', 'login-delay-shield' ); ?>
                            <?php echo $this->get_status_badge( 'wldelay_email_enabled', __( 'Email Notifications', 'login-delay-shield' ) ); ?>
                            <span class="dashicons dashicons-arrow-down-alt2 wldelay-toggle" aria-hidden="true"></span>
                        </h2>
                        <div id="wldelay-email-body" class="wldelay-card-body">
                            <p class="description"><?php esc_html_e( 'Receive email alerts when multiple failed login attempts are detected from the same IP address.', 'login-delay-shield' ); ?></p>
                            <?php $this->do_settings_section_fields( 'wldelay_email_section_id' ); ?>
                        </div>
                    </div>

                    <div class="wldelay-card">
                        <h2 class="wldelay-card-header" role="button" tabindex="0" aria-expanded="true" aria-controls="wldelay-lockout-body">
                            <span class="dashicons dashicons-lock" aria-hidden="true"></span>
                            <?php esc_html_e( 'IP Lockout', 'login-delay-shield' ); ?>
                            <?php echo $this->get_status_badge( 'wldelay_lockout_enabled', __( 'IP Lockout', 'login-delay-shield' ) ); ?>
                            <span class="dashicons dashicons-arrow-down-alt2 wldelay-toggle" aria-hidden="true"></span>
                        </h2>
                        <div id="wldelay-lockout-body" class="wldelay-card-body">
                            <p class="description"><?php esc_html_e( 'Temporarily block repeated failed login attempts by IP address or by IP + username.', 'login-delay-shield' ); ?></p>
                            <?php $this->do_settings_section_fields( 'wldelay_lockout_section_id' ); ?>
                            <p>
                                <a class="button button-secondary" href="<?php echo esc_url( wldelay_get_unlock_current_ip_url() ); ?>">
                                    <?php esc_html_e( 'Unlock Current IP', 'login-delay-shield' ); ?>
                                </a>
                            </p>
                            <p class="description" id="wldelay_unlock_current_ip_desc">
                                <?php esc_html_e( 'Emergency recovery: remove lockout for your current IP address.', 'login-delay-shield' ); ?>
                            </p>
                        </div>
                    </div>

                    <div class="wldelay-card">
                        <h2 class="wldelay-card-header" role="button" tabindex="0" aria-expanded="true" aria-controls="wldelay-whitelist-body">
                            <span class="dashicons dashicons-shield-alt" aria-hidden="true"></span>
                            <?php esc_html_e( 'IP Whitelist', 'login-delay-shield' ); ?>
                            <?php echo $this->get_status_badge( 'wldelay_whitelist_enabled', __( 'IP Whitelist', 'login-delay-shield' ) ); ?>
                            <span class="dashicons dashicons-arrow-down-alt2 wldelay-toggle" aria-hidden="true"></span>
                        </h2>
                        <div id="wldelay-whitelist-body" class="wldelay-card-body">
                            <p class="description"><?php esc_html_e( 'Skip delay and lockout for trusted IP addresses (e.g., office, VPN).', 'login-delay-shield' ); ?></p>
                            <?php $this->do_settings_section_fields( 'wldelay_whitelist_section_id' ); ?>
                        </div>
                    </div>

                    <div class="wldelay-card">
                        <h2 class="wldelay-card-header" role="button" tabindex="0" aria-expanded="true" aria-controls="wldelay-log-body">
                            <span class="dashicons dashicons-list-view" aria-hidden="true"></span>
                            <?php esc_html_e( 'Login Log', 'login-delay-shield' ); ?>
                            <?php echo $this->get_status_badge( 'wldelay_fail2ban_enabled', __( 'fail2ban Logging', 'login-delay-shield' ) ); ?>
                            <span class="dashicons dashicons-arrow-down-alt2 wldelay-toggle" aria-hidden="true"></span>
                        </h2>
                        <div id="wldelay-log-body" class="wldelay-card-body">
                            <p class="description"><?php esc_html_e( 'Failed login attempts are logged and displayed in the dashboard widget.', 'login-delay-shield' ); ?></p>
                            <?php $this->do_settings_section_fields( 'wldelay_log_section_id' ); ?>
                            <?php $this->render_login_log_telemetry(); ?>
                        </div>
                    </div>

                    <div class="wldelay-card">
                        <h2 class="wldelay-card-header" role="button" tabindex="0" aria-expanded="true" aria-controls="wldelay-xmlrpc-body">
                            <span class="dashicons dashicons-rss" aria-hidden="true"></span>
                            <?php esc_html_e( 'XML-RPC Protection', 'login-delay-shield' ); ?>
                            <?php echo $this->get_status_badge( 'wldelay_xmlrpc_enabled', __( 'XML-RPC Protection', 'login-delay-shield' ) ); ?>
                            <span class="dashicons dashicons-arrow-down-alt2 wldelay-toggle" aria-hidden="true"></span>
                        </h2>
                        <div id="wldelay-xmlrpc-body" class="wldelay-card-body">
                            <p class="description"><?php esc_html_e( 'Protect against brute-force attacks via XML-RPC (used by the WordPress mobile app and remote publishing).', 'login-delay-shield' ); ?></p>
                            <?php $this->do_settings_section_fields( 'wldelay_xmlrpc_section_id' ); ?>
                        </div>
                    </div>

                    <div class="wldelay-card">
                        <h2 class="wldelay-card-header" role="button" tabindex="0" aria-expanded="true" aria-controls="wldelay-custom-login-body">
                            <span class="dashicons dashicons-admin-links" aria-hidden="true"></span>
                            <?php esc_html_e( 'Custom Login URL', 'login-delay-shield' ); ?>
                            <?php echo $this->get_status_badge( 'wldelay_custom_login_enabled', __( 'Custom Login URL', 'login-delay-shield' ) ); ?>
                            <span class="dashicons dashicons-arrow-down-alt2 wldelay-toggle" aria-hidden="true"></span>
                        </h2>
                        <div id="wldelay-custom-login-body" class="wldelay-card-body">
                            <p class="description"><?php esc_html_e( 'Hide wp-login.php behind a custom URL slug to reduce automated attacks targeting the default login path.', 'login-delay-shield' ); ?></p>
                            <?php $this->do_settings_section_fields( 'wldelay_custom_login_section_id' ); ?>
                        </div>
                    </div>
                </div>

                <?php submit_button(); ?>
            </form>
        </div>
        <?php
    }

    /**
     * Render the summary box at the top of the page
     */
    private function render_summary_box() {
        $features = array(
            'wldelay_email_enabled' => __( 'Email Alerts', 'login-delay-shield' ),
            'wldelay_lockout_enabled' => __( 'IP Lockout', 'login-delay-shield' ),
            'wldelay_whitelist_enabled' => __( 'IP Whitelist', 'login-delay-shield' ),
            'wldelay_progressive_enabled' => __( 'Progressive Delay', 'login-delay-shield' ),
            'wldelay_xmlrpc_enabled' => __( 'XML-RPC Protection', 'login-delay-shield' ),
            'wldelay_rest_enabled' => __( 'REST API Protection', 'login-delay-shield' ),
            'wldelay_application_password_enabled' => __( 'Application Password Protection', 'login-delay-shield' ),
            'wldelay_password_reset_enabled' => __( 'Password Reset Protection', 'login-delay-shield' ),
            'wldelay_custom_login_enabled' => __( 'Custom Login URL', 'login-delay-shield' ),
            'wldelay_fail2ban_enabled' => __( 'fail2ban Logging', 'login-delay-shield' ),
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
            $status = $is_enabled ? __( 'enabled', 'login-delay-shield' ) : __( 'disabled', 'login-delay-shield' );
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
                    esc_html__( 'Next recommended: enable %1$s (+%2$d points)', 'login-delay-shield' ),
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
            esc_attr__( 'Protection status summary', 'login-delay-shield' ),
            $pct,
            $pct,
            esc_html__( 'Security Score', 'login-delay-shield' ),
            esc_html__( 'Protection Features Enabled', 'login-delay-shield' ),
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
                        <strong><?php esc_html_e( '2FA plugin check:', 'login-delay-shield' ); ?></strong>
                        <?php
                        echo esc_html(
                            sprintf(
                                /* translators: 1: detected 2FA provider, 2: number of privileged accounts */
                                _n(
                                    '%1$s is active and the detected administrator account appears to have 2FA enabled.',
                                    '%1$s is active and all %2$d detected administrator accounts appear to have 2FA enabled.',
                                    $privileged,
                                    'login-delay-shield'
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
                        <strong><?php esc_html_e( '2FA plugin check:', 'login-delay-shield' ); ?></strong>
                        <?php
                        echo esc_html(
                            sprintf(
                                /* translators: 1: detected 2FA provider, 2: number of unprotected privileged accounts, 3: total privileged accounts */
                                _n(
                                    '%1$s is active, but %2$d administrator account out of %3$d detected does not appear to have 2FA enabled yet.',
                                    '%1$s is active, but %2$d administrator accounts out of %3$d detected do not appear to have 2FA enabled yet.',
                                    $unprotected,
                                    'login-delay-shield'
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
                    <strong><?php esc_html_e( '2FA plugin check:', 'login-delay-shield' ); ?></strong>
                    <?php
                    printf(
                        /* translators: %s: detected plugin with 2FA capability */
                        esc_html__( 'Detected installed plugin with 2FA capability: %s. Verify 2FA is configured for your administrator accounts.', 'login-delay-shield' ),
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
                <strong><?php esc_html_e( '2FA plugin check:', 'login-delay-shield' ); ?></strong>
                <?php esc_html_e( 'No detected common 2FA plugin. If you use a custom or must-use solution, verify administrator 2FA coverage manually.', 'login-delay-shield' ); ?>
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
                <strong><?php esc_html_e( 'Performance tip:', 'login-delay-shield' ); ?></strong>
                <?php esc_html_e( 'For high-traffic sites, consider using a persistent object cache (Redis, Memcached) to reduce database load during attacks.', 'login-delay-shield' ); ?>
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
        $total        = wldelay_count_login_log_attempts( $filters );
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
                <?php esc_html_e( 'New login attempts were recorded since you started browsing. Totals and page numbers may have shifted.', 'login-delay-shield' ); ?>
                <a href="<?php echo esc_url( add_query_arg( array_merge( array( 'page' => 'login-delay-shield-admin' ), wldelay_login_log_filters_to_query_args( $filters ) ), admin_url( 'options-general.php' ) ) ); ?>"><?php esc_html_e( 'Refresh', 'login-delay-shield' ); ?></a>
            </p></div>
        <?php endif; ?>
        <div class="wldelay-telemetry" aria-labelledby="wldelay-telemetry-title">
            <h3 id="wldelay-telemetry-title"><?php esc_html_e( 'Failed Login Telemetry', 'login-delay-shield' ); ?></h3>
            <p class="description"><?php esc_html_e( 'Filter failed login attempts, inspect recent patterns, and export the matching rows as CSV.', 'login-delay-shield' ); ?></p>

            <div class="wldelay-telemetry-filters">
                <input form="wldelay-telemetry-filter-form" type="hidden" name="page" value="login-delay-shield-admin" />
                <div class="wldelay-filter-grid">
                    <label for="wldelay_log_source">
                        <?php esc_html_e( 'Source', 'login-delay-shield' ); ?>
                        <select id="wldelay_log_source" name="wldelay_log_source" form="wldelay-telemetry-filter-form">
                            <option value=""><?php esc_html_e( 'All sources', 'login-delay-shield' ); ?></option>
                            <?php foreach ( $this->get_login_log_source_options( $summary, $filters ) as $source ) : ?>
                                <option value="<?php echo esc_attr( $source ); ?>" <?php selected( $filters['source'], $source ); ?>><?php echo esc_html( wldelay_get_login_source_label( $source ) ); ?></option>
                            <?php endforeach; ?>
                        </select>
                    </label>
                    <label for="wldelay_log_ip">
                        <?php esc_html_e( 'IP address', 'login-delay-shield' ); ?>
                        <input id="wldelay_log_ip" name="wldelay_log_ip" form="wldelay-telemetry-filter-form" type="text" value="<?php echo esc_attr( $filters['ip'] ); ?>" placeholder="<?php echo esc_attr__( 'Any IP', 'login-delay-shield' ); ?>" />
                    </label>
                    <label for="wldelay_log_username">
                        <?php esc_html_e( 'Username', 'login-delay-shield' ); ?>
                        <input id="wldelay_log_username" name="wldelay_log_username" form="wldelay-telemetry-filter-form" type="text" value="<?php echo esc_attr( $filters['username'] ); ?>" placeholder="<?php echo esc_attr__( 'Partial match', 'login-delay-shield' ); ?>" />
                    </label>
                    <label for="wldelay_log_from">
                        <?php esc_html_e( 'From', 'login-delay-shield' ); ?>
                        <input id="wldelay_log_from" name="wldelay_log_from" form="wldelay-telemetry-filter-form" type="date" value="<?php echo esc_attr( $filters['from'] ); ?>" />
                    </label>
                    <label for="wldelay_log_to">
                        <?php esc_html_e( 'To', 'login-delay-shield' ); ?>
                        <input id="wldelay_log_to" name="wldelay_log_to" form="wldelay-telemetry-filter-form" type="date" value="<?php echo esc_attr( $filters['to'] ); ?>" />
                    </label>
                </div>
                <p class="wldelay-telemetry-actions">
                    <button type="submit" form="wldelay-telemetry-filter-form" class="button button-primary"><?php esc_html_e( 'Apply filters', 'login-delay-shield' ); ?></button>
                    <a class="button button-secondary" href="<?php echo esc_url( admin_url( 'options-general.php?page=login-delay-shield-admin' ) ); ?>"><?php esc_html_e( 'Reset', 'login-delay-shield' ); ?></a>
                    <a class="button button-secondary" href="<?php echo esc_url( wldelay_get_export_login_log_url( $filters ) ); ?>"><?php esc_html_e( 'Export filtered CSV', 'login-delay-shield' ); ?></a>
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
                <h4><?php esc_html_e( 'Total attempts', 'login-delay-shield' ); ?></h4>
                <p class="wldelay-telemetry-total"><?php echo esc_html( number_format_i18n( (int) $summary['total_attempts'] ) ); ?></p>
            </section>
            <section class="wldelay-trend-card">
                <h4><?php esc_html_e( 'Daily activity', 'login-delay-shield' ); ?></h4>
                <?php $this->render_count_list( $summary['daily_counts'], 'date' ); ?>
            </section>
            <section class="wldelay-trend-card">
                <h4><?php esc_html_e( 'Top sources', 'login-delay-shield' ); ?></h4>
                <?php $this->render_count_list( $summary['source_counts'], 'source' ); ?>
            </section>
            <section class="wldelay-trend-card">
                <h4><?php esc_html_e( 'Top IPs', 'login-delay-shield' ); ?></h4>
                <?php $this->render_count_list( $summary['top_ips'], 'ip_address' ); ?>
            </section>
            <section class="wldelay-trend-card">
                <h4><?php esc_html_e( 'Top usernames', 'login-delay-shield' ); ?></h4>
                <p class="description"><?php esc_html_e( 'Usernames most targeted by failed login attempts.', 'login-delay-shield' ); ?></p>
                <?php $this->render_count_list( $summary['top_usernames'], 'username' ); ?>
            </section>
            <section class="wldelay-trend-card">
                <h4><?php esc_html_e( 'Top target pairs', 'login-delay-shield' ); ?></h4>
                <p class="description"><?php esc_html_e( 'Most common IP and username combinations from failed login attempts.', 'login-delay-shield' ); ?></p>
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
            echo '<li><span>' . esc_html__( 'No matching data', 'login-delay-shield' ) . '</span><strong>0</strong></li>';
            echo '</ul>';
            return;
        }

        foreach ( $rows as $row ) {
            $label = isset( $row[ $label_key ] ) ? (string) $row[ $label_key ] : '';
            if ( $label_key === 'source' ) {
                $label = wldelay_get_login_source_label( $label );
            } elseif ( $label_key === 'date' ) {
                $label = date_i18n( _x( 'M j, Y', 'date format for login log telemetry', 'login-delay-shield' ), strtotime( $label . ' 00:00:00' ) );
            } elseif ( $label_key === 'target_pair' ) {
                $label = sprintf(
                    /* translators: 1: IP address, 2: username. */
                    __( '%1$s / %2$s', 'login-delay-shield' ),
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
            <h4><?php esc_html_e( 'Matching attempts', 'login-delay-shield' ); ?></h4>
            <p class="description">
                <?php
                printf(
                    /* translators: %s: number of matching failed login attempts */
                    esc_html__( '%s matching failed login attempts.', 'login-delay-shield' ),
                    esc_html( number_format_i18n( $total ) )
                );
                ?>
            </p>
            <?php if ( empty( $attempts ) ) : ?>
                <p class="wldelay-empty-state"><?php esc_html_e( 'No failed login attempts match the current filters.', 'login-delay-shield' ); ?></p>
            <?php else : ?>
                <table class="widefat striped wldelay-telemetry-table">
                    <caption class="screen-reader-text"><?php esc_html_e( 'Filtered failed login attempts', 'login-delay-shield' ); ?></caption>
                    <thead>
                        <tr>
                            <th scope="col"><?php esc_html_e( 'Time', 'login-delay-shield' ); ?></th>
                            <th scope="col"><?php esc_html_e( 'Username', 'login-delay-shield' ); ?></th>
                            <th scope="col"><?php esc_html_e( 'IP address', 'login-delay-shield' ); ?></th>
                            <th scope="col"><?php esc_html_e( 'Source', 'login-delay-shield' ); ?></th>
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

        echo '<nav class="wldelay-pagination" aria-label="' . esc_attr__( 'Login log pagination', 'login-delay-shield' ) . '">';
        if ( $current_page > 1 ) {
            echo '<a class="button button-secondary" href="' . esc_url( add_query_arg( array_merge( $base_args, array( 'wldelay_log_page' => $current_page - 1 ) ), admin_url( 'options-general.php' ) ) ) . '">' . esc_html__( 'Previous', 'login-delay-shield' ) . '</a> ';
        }
        printf(
            '<span class="wldelay-pagination-status">%s</span>',
            esc_html(
                sprintf(
                    /* translators: 1: current page, 2: total pages */
                    __( 'Page %1$d of %2$d', 'login-delay-shield' ),
                    $current_page,
                    $total_pages
                )
            )
        );
        if ( $current_page < $total_pages ) {
            echo ' <a class="button button-secondary" href="' . esc_url( add_query_arg( array_merge( $base_args, array( 'wldelay_log_page' => $current_page + 1 ) ), admin_url( 'options-general.php' ) ) ) . '">' . esc_html__( 'Next', 'login-delay-shield' ) . '</a>';
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
        $text = $is_enabled ? __( 'Enabled', 'login-delay-shield' ) : __( 'Disabled', 'login-delay-shield' );

        // Screen reader text provides context
        $sr_text = $feature_name
            ? sprintf(
                /* translators: 1: feature name, 2: enabled or disabled */
                __( '%1$s: %2$s', 'login-delay-shield' ),
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
        echo $this->tooltip( __( 'A fixed delay applied to every login attempt. Higher values slow down brute-force attacks but may slightly delay legitimate users.', 'login-delay-shield' ) );
    }

    /**
     * Random delay checkbox callback
     */
    public function delay_callback_random() {
        printf(
            '<input type="checkbox" id="wldelay_delay_random" name="wldelay_options[wldelay_delay_random]" value="1" %s />',
            ! empty( $this->options['wldelay_delay_random'] ) ? 'checked="checked"' : ''
        );
        echo $this->tooltip( __( 'Randomized delays make it harder for attackers to detect patterns or time their attempts. Recommended for better security.', 'login-delay-shield' ) );
    }

    /**
     * Random delay minimum callback
     */
    public function delay_callback_random_min() {
        printf(
            '<input type="number" id="wldelay_delay_random_min" name="wldelay_options[wldelay_delay_random_min]" value="%d" min="1" max="10" />',
            isset( $this->options['wldelay_delay_random_min'] ) ? esc_attr( $this->options['wldelay_delay_random_min'] ) : esc_attr( LDS_Settings::_DEFAULT_RANDOM_MIN )
        );
        echo $this->tooltip( __( 'The shortest possible delay. Each login attempt will wait at least this many seconds.', 'login-delay-shield' ) );
    }

    /**
     * Random delay maximum callback
     */
    public function delay_callback_random_max() {
        printf(
            '<input type="number" id="wldelay_delay_random_max" name="wldelay_options[wldelay_delay_random_max]" value="%d" min="1" max="10" />',
            isset( $this->options['wldelay_delay_random_max'] ) ? esc_attr( $this->options['wldelay_delay_random_max'] ) : esc_attr( LDS_Settings::_DEFAULT_RANDOM_MAX )
        );
        echo $this->tooltip( __( 'The longest possible delay. Each login attempt will wait up to this many seconds.', 'login-delay-shield' ) );
    }

    /**
     * Email enabled callback
     */
    public function email_enabled_callback() {
        printf(
            '<input type="checkbox" id="wldelay_email_enabled" name="wldelay_options[wldelay_email_enabled]" value="1" %s />',
            ! empty( $this->options['wldelay_email_enabled'] ) ? 'checked="checked"' : ''
        );
        echo $this->tooltip( __( 'Get notified when someone is trying to break into your site. Alerts are sent once per IP until the attack stops.', 'login-delay-shield' ) );
    }

    /**
     * Email threshold callback
     */
    public function email_threshold_callback() {
        printf(
            '<input type="number" id="wldelay_email_threshold" name="wldelay_options[wldelay_email_threshold]" value="%d" min="1" max="100" />',
            isset( $this->options['wldelay_email_threshold'] ) ? esc_attr( $this->options['wldelay_email_threshold'] ) : esc_attr( LDS_Settings::_DEFAULT_EMAIL_THRESHOLD )
        );
        echo $this->tooltip( __( 'Number of failed attempts from one IP before sending an alert. Lower values mean earlier warnings but more emails.', 'login-delay-shield' ) );
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
        echo $this->tooltip( __( 'Where to send security alerts. If left blank, emails go to the WordPress admin address.', 'login-delay-shield' ) );
        echo '<p id="wldelay_email_address_desc" class="description">' . esc_html__( 'Leave empty to use the site admin email.', 'login-delay-shield' ) . '</p>';
    }

    /**
     * Email cooldown callback
     */
    public function email_cooldown_callback() {
        printf(
            '<input type="number" id="wldelay_email_cooldown" name="wldelay_options[wldelay_email_cooldown]" value="%d" min="0" max="60" aria-describedby="wldelay_email_cooldown_desc" />',
            isset( $this->options['wldelay_email_cooldown'] ) ? esc_attr( $this->options['wldelay_email_cooldown'] ) : esc_attr( LDS_Settings::_DEFAULT_EMAIL_COOLDOWN )
        );
        echo ' <span class="description">' . esc_html__( 'minutes', 'login-delay-shield' ) . '</span>';
        echo $this->tooltip( __( 'Minimum time between alert emails site-wide. Prevents inbox flooding during coordinated attacks from multiple IPs. Set to 0 to disable.', 'login-delay-shield' ) );
        echo '<p id="wldelay_email_cooldown_desc" class="description">' . esc_html__( 'Set to 0 to send an email for every IP that hits the threshold.', 'login-delay-shield' ) . '</p>';
    }

    /**
     * Lockout enabled callback
     */
    public function lockout_enabled_callback() {
        printf(
            '<input type="checkbox" id="wldelay_lockout_enabled" name="wldelay_options[wldelay_lockout_enabled]" value="1" %s />',
            ! empty( $this->options['wldelay_lockout_enabled'] ) ? 'checked="checked"' : ''
        );
        echo $this->tooltip( __( 'Temporarily block IPs after too many failures. Effective at stopping automated attacks cold.', 'login-delay-shield' ) );
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
        echo $this->tooltip( __( 'How many failed attempts before lockout is triggered for the selected strategy.', 'login-delay-shield' ) );
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
            esc_html__( 'IP only', 'login-delay-shield' ),
            $pair_selected,
            esc_html__( 'IP + username', 'login-delay-shield' )
        );

        echo $this->tooltip( __( 'Choose how failed attempts are grouped for progressive delay and lockout. "IP + username" is better for shared networks.', 'login-delay-shield' ) );
        echo '<p id="wldelay_lockout_attempt_strategy_desc" class="description">' . esc_html__( 'IP only = one counter per IP. IP + username = separate counters per username on the same IP.', 'login-delay-shield' ) . '</p>';
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
        echo $this->tooltip( __( 'How long to block an IP. Longer durations discourage persistent attackers but may inconvenience legitimate users who forgot their password.', 'login-delay-shield' ) );
        echo '<p id="wldelay_lockout_duration_desc" class="description">' . esc_html__( 'Maximum: 1440 minutes (24 hours)', 'login-delay-shield' ) . '</p>';
    }

    /**
     * Trust proxy headers callback
     */
    public function trust_proxy_headers_callback() {
        printf(
            '<input type="checkbox" id="wldelay_trust_proxy_headers" name="wldelay_options[wldelay_trust_proxy_headers]" value="1" %s aria-describedby="wldelay_trust_proxy_desc" />',
            ! empty( $this->options['wldelay_trust_proxy_headers'] ) ? 'checked="checked"' : ''
        );
        echo $this->tooltip( __( 'Enable this only if your site is behind a reverse proxy or load balancer (e.g., Cloudflare, nginx proxy, AWS ELB). When disabled, only the direct connection IP is used, preventing attackers from spoofing their IP address.', 'login-delay-shield' ) );
        echo '<p id="wldelay_trust_proxy_desc" class="description">' . esc_html__( 'Leave disabled unless behind a trusted proxy. Enabling this on a non-proxied site allows IP spoofing.', 'login-delay-shield' ) . '</p>';
    }

    /**
     * Progressive enabled callback
     */
    public function progressive_enabled_callback() {
        printf(
            '<input type="checkbox" id="wldelay_progressive_enabled" name="wldelay_options[wldelay_progressive_enabled]" value="1" %s aria-describedby="wldelay_progressive_enabled_desc" />',
            ! empty( $this->options['wldelay_progressive_enabled'] ) ? 'checked="checked"' : ''
        );
        echo $this->tooltip( __( 'Delays grow longer with each failed attempt. First try might be 1s, second 2s, third 3s, etc. Very effective against automated attacks.', 'login-delay-shield' ) );
        echo '<p id="wldelay_progressive_enabled_desc" class="description">' . esc_html__( 'Increase delay with each consecutive failed attempt from the same IP.', 'login-delay-shield' ) . '</p>';
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
        echo $this->tooltip( __( 'How much to increase the delay after each failed attempt. Higher values penalize repeat offenders more aggressively.', 'login-delay-shield' ) );
        echo '<p id="wldelay_progressive_increment_desc" class="description">' . esc_html__( 'Additional seconds added per failed attempt (1-10).', 'login-delay-shield' ) . '</p>';
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
        echo $this->tooltip( __( 'The delay stops increasing at this value. Prevents excessively long waits that could tie up server resources.', 'login-delay-shield' ) );
        echo '<p id="wldelay_progressive_max_desc" class="description">' . esc_html__( 'Maximum total delay in seconds (5-60).', 'login-delay-shield' ) . '</p>';
    }

    /**
     * Whitelist enabled callback
     */
    public function whitelist_enabled_callback() {
        printf(
            '<input type="checkbox" id="wldelay_whitelist_enabled" name="wldelay_options[wldelay_whitelist_enabled]" value="1" %s />',
            ! empty( $this->options['wldelay_whitelist_enabled'] ) ? 'checked="checked"' : ''
        );
        echo $this->tooltip( __( 'Bypass all protection for trusted IPs. Useful for office networks or VPNs where delays would be annoying.', 'login-delay-shield' ) );
    }

    /**
     * Whitelist IPs callback
     */
    public function whitelist_ips_callback() {
        printf(
            '<textarea id="wldelay_whitelist_ips" name="wldelay_options[wldelay_whitelist_ips]" rows="5" cols="40" class="large-text code" aria-describedby="wldelay_whitelist_ips_desc">%s</textarea>',
            isset( $this->options['wldelay_whitelist_ips'] ) ? esc_textarea( $this->options['wldelay_whitelist_ips'] ) : ''
        );
        echo $this->tooltip( __( 'Enter trusted IP addresses. CIDR notation (e.g., 192.168.1.0/24) allows whitelisting entire networks.', 'login-delay-shield' ) );
        echo '<p id="wldelay_whitelist_ips_desc" class="description">' . esc_html__( 'One IP address or CIDR range per line (e.g., 192.168.1.1 or 10.0.0.0/8).', 'login-delay-shield' ) . '</p>';
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
        echo $this->tooltip( __( 'Old logs are automatically cleaned up to save database space. Shorter retention = smaller database.', 'login-delay-shield' ) );
        echo '<p id="wldelay_log_retention_desc" class="description">' . esc_html__( 'Automatically delete log entries older than this many days. Set to 0 to keep logs forever.', 'login-delay-shield' ) . '</p>';
    }

    /**
     * fail2ban logging enabled callback.
     */
    public function fail2ban_enabled_callback() {
        printf(
            '<input type="checkbox" id="wldelay_fail2ban_enabled" name="wldelay_options[wldelay_fail2ban_enabled]" value="1" %s aria-describedby="wldelay_fail2ban_enabled_desc" />',
            ! empty( $this->options['wldelay_fail2ban_enabled'] ) ? 'checked="checked"' : ''
        );
        echo $this->tooltip( __( 'Write a fail2ban-compatible line when Login Delay Shield records an authentication failure.', 'login-delay-shield' ) );
        echo '<p id="wldelay_fail2ban_enabled_desc" class="description">' . esc_html__( 'Disabled by default. Enable only after configuring a fail2ban jail to watch the selected log file.', 'login-delay-shield' ) . '</p>';
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
        echo $this->tooltip( __( 'Leave empty to use the protected default log directory. Custom paths are restricted to the protected default directory by default; use the filter only for server-protected directories.', 'login-delay-shield' ) );
        printf(
            '<p id="wldelay_fail2ban_log_path_desc" class="description">%s <code>%s</code></p>',
            esc_html__( 'Leave empty to write to the protected default path:', 'login-delay-shield' ),
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
        echo $this->tooltip( __( 'Also write a line when Login Delay Shield creates a temporary lockout.', 'login-delay-shield' ) );
        echo '<p id="wldelay_fail2ban_include_lockouts_desc" class="description">' . esc_html__( 'Useful when your jail should ban on plugin lockouts as well as individual failed-login lines.', 'login-delay-shield' ) . '</p>';
    }

    /**
     * XMLRPC enabled callback
     */
    public function xmlrpc_enabled_callback() {
        printf(
            '<input type="checkbox" id="wldelay_xmlrpc_enabled" name="wldelay_options[wldelay_xmlrpc_enabled]" value="1" %s aria-describedby="wldelay_xmlrpc_enabled_desc" />',
            ! empty( $this->options['wldelay_xmlrpc_enabled'] ) ? 'checked="checked"' : ''
        );
        echo $this->tooltip( __( 'XML-RPC is often targeted by attackers because it allows multiple login attempts in a single request. Protecting it is strongly recommended.', 'login-delay-shield' ) );
        echo '<p id="wldelay_xmlrpc_enabled_desc" class="description">' . esc_html__( 'Apply delay and lockout protection to XML-RPC authentication requests.', 'login-delay-shield' ) . '</p>';
    }

    /**
     * XMLRPC block callback
     */
    public function xmlrpc_block_callback() {
        printf(
            '<input type="checkbox" id="wldelay_xmlrpc_block" name="wldelay_options[wldelay_xmlrpc_block]" value="1" %s aria-describedby="wldelay_xmlrpc_block_desc" />',
            ! empty( $this->options['wldelay_xmlrpc_block'] ) ? 'checked="checked"' : ''
        );
        echo $this->tooltip( __( 'Completely disables XML-RPC login. Enable this if you manage your site only via the web interface and don\'t use Jetpack or the WP mobile app.', 'login-delay-shield' ) );
        echo '<p id="wldelay_xmlrpc_block_desc" class="description">' . esc_html__( 'Completely block XML-RPC authentication. Use this if you don\'t need remote publishing or the WordPress mobile app.', 'login-delay-shield' ) . '</p>';
    }

    /**
     * REST protection callback.
     */
    public function rest_enabled_callback() {
        printf(
            '<input type="checkbox" id="wldelay_rest_enabled" name="wldelay_options[wldelay_rest_enabled]" value="1" %s aria-describedby="wldelay_rest_enabled_desc" />',
            ! empty( $this->options['wldelay_rest_enabled'] ) ? 'checked="checked"' : ''
        );
        echo $this->tooltip( __( 'Apply delay and lockout checks to failed REST API authentication requests.', 'login-delay-shield' ) );
        echo '<p id="wldelay_rest_enabled_desc" class="description">' . esc_html__( 'Protect failed REST authentication attempts with the same delay/lockout behavior.', 'login-delay-shield' ) . '</p>';
    }

    /**
     * Print custom login section info
     */
    public function print_custom_login_section_info() {
        // Description is now in card structure
    }

    /**
     * Custom login enabled callback
     */
    public function custom_login_enabled_callback() {
        printf(
            '<input type="checkbox" id="wldelay_custom_login_enabled" name="wldelay_options[wldelay_custom_login_enabled]" value="1" %s aria-describedby="wldelay_custom_login_enabled_desc" />',
            ! empty( $this->options['wldelay_custom_login_enabled'] ) ? 'checked="checked"' : ''
        );
        echo $this->tooltip( __( 'When enabled, the default wp-login.php URL will return a 404, and only the custom slug will load the login page.', 'login-delay-shield' ) );
        echo '<p id="wldelay_custom_login_enabled_desc" class="description">' . esc_html__( 'Replace wp-login.php with a custom URL slug.', 'login-delay-shield' ) . '</p>';
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
        echo $this->tooltip( __( 'Choose a unique, hard-to-guess slug. Only lowercase letters, numbers, and hyphens are allowed.', 'login-delay-shield' ) );
        echo '<p id="wldelay_custom_login_slug_desc" class="description">' . esc_html__( 'Lowercase letters, numbers, and hyphens only. Reserved slugs (wp-admin, login, etc.) are rejected.', 'login-delay-shield' ) . '</p>';
    }

    /**
     * Application password protection callback.
     */
    public function application_password_enabled_callback() {
        printf(
            '<input type="checkbox" id="wldelay_application_password_enabled" name="wldelay_options[wldelay_application_password_enabled]" value="1" %s aria-describedby="wldelay_application_password_enabled_desc" />',
            ! empty( $this->options['wldelay_application_password_enabled'] ) ? 'checked="checked"' : ''
        );
        echo $this->tooltip( __( 'Apply delay and lockout checks to application-password authentication attempts.', 'login-delay-shield' ) );
        echo '<p id="wldelay_application_password_enabled_desc" class="description">' . esc_html__( 'Protect failed application-password attempts and log them separately.', 'login-delay-shield' ) . '</p>';
    }

    /**
     * Password reset protection callback.
     */
    public function password_reset_enabled_callback() {
        printf(
            '<input type="checkbox" id="wldelay_password_reset_enabled" name="wldelay_options[wldelay_password_reset_enabled]" value="1" %s aria-describedby="wldelay_password_reset_enabled_desc" />',
            ! empty( $this->options['wldelay_password_reset_enabled'] ) ? 'checked="checked"' : ''
        );
        echo $this->tooltip( __( 'Apply delay, lockout checks, and logging to password reset submissions without revealing whether an account exists.', 'login-delay-shield' ) );
        echo '<p id="wldelay_password_reset_enabled_desc" class="description">' . esc_html__( 'Protect password reset requests with the same delay and lockout behavior.', 'login-delay-shield' ) . '</p>';
    }
}
