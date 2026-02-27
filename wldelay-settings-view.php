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
    private function tooltip( $text ) {
        self::$tooltip_counter++;
        $tooltip_id = 'wldelay-tooltip-' . self::$tooltip_counter;

        return sprintf(
            '<span class="wldelay-tooltip" tabindex="0" aria-describedby="%s">' .
            '<span class="dashicons dashicons-editor-help" aria-hidden="true"></span>' .
            '<span class="screen-reader-text">%s</span>' .
            '<span id="%s" class="wldelay-tooltip-text" role="tooltip">%s</span>' .
            '</span>',
            esc_attr( $tooltip_id ),
            esc_html__( 'Help', 'login-delay-shield' ),
            esc_attr( $tooltip_id ),
            esc_html( $text )
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
            <?php $this->render_object_cache_notice(); ?>

            <form method="post" action="options.php">
                <?php settings_fields( 'wldelay_option_group' ); ?>

                <div class="wldelay-card" data-section="delay">
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
                    <div class="wldelay-card" data-section="email">
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

                    <div class="wldelay-card" data-section="lockout">
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

                    <div class="wldelay-card" data-section="whitelist">
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

                    <div class="wldelay-card" data-section="log">
                        <h2 class="wldelay-card-header" role="button" tabindex="0" aria-expanded="true" aria-controls="wldelay-log-body">
                            <span class="dashicons dashicons-list-view" aria-hidden="true"></span>
                            <?php esc_html_e( 'Login Log', 'login-delay-shield' ); ?>
                            <span class="dashicons dashicons-arrow-down-alt2 wldelay-toggle" aria-hidden="true"></span>
                        </h2>
                        <div id="wldelay-log-body" class="wldelay-card-body">
                            <p class="description"><?php esc_html_e( 'Failed login attempts are logged and displayed in the dashboard widget.', 'login-delay-shield' ); ?></p>
                            <?php $this->do_settings_section_fields( 'wldelay_log_section_id' ); ?>
                        </div>
                    </div>

                    <div class="wldelay-card" data-section="xmlrpc">
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
                </div>

                <?php submit_button(); ?>
            </form>
            <?php $this->output_admin_scripts(); ?>
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

        return sprintf(
            '<div class="wldelay-summary" role="status" aria-label="%s">
                <div class="wldelay-summary-count" aria-hidden="true"><span id="wldelay-enabled-count">%d</span>/%d</div>
                <div class="wldelay-summary-text">
                    <div class="wldelay-summary-title">%s</div>
                    <div class="wldelay-summary-features" aria-live="polite">%s</div>
                </div>
            </div>',
            esc_attr__( 'Protection status summary', 'login-delay-shield' ),
            $enabled_count,
            $total,
            esc_html__( 'Protection Features Enabled', 'login-delay-shield' ),
            $feature_html
        );
    }

    /**
     * Render object cache notice if no persistent cache is detected
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
     * Output admin JavaScript for field toggling
     */
    public function output_admin_scripts() {
        ?>
        <script>
            jQuery(document).ready( function($) {
                // Badge update helper
                function updateBadge( toggleKey, isEnabled ) {
                    var $badge = $( '.wldelay-badge[data-toggle="' + toggleKey + '"]' );
                    if ( isEnabled ) {
                        $badge.removeClass( 'wldelay-badge-disabled' ).addClass( 'wldelay-badge-enabled' ).text( 'Enabled' );
                    } else {
                        $badge.removeClass( 'wldelay-badge-enabled' ).addClass( 'wldelay-badge-disabled' ).text( 'Disabled' );
                    }
                }

                // Summary box update helper
                function updateSummary( toggleKey, isEnabled ) {
                    var $feature = $( '.wldelay-summary-features span[data-feature="' + toggleKey + '"]' );
                    var $icon = $feature.find( '.dashicons' );

                    if ( isEnabled ) {
                        $feature.removeClass( 'wldelay-feature-off' ).addClass( 'wldelay-feature-on' );
                        $icon.removeClass( 'dashicons-no-alt' ).addClass( 'dashicons-yes' );
                    } else {
                        $feature.removeClass( 'wldelay-feature-on' ).addClass( 'wldelay-feature-off' );
                        $icon.removeClass( 'dashicons-yes' ).addClass( 'dashicons-no-alt' );
                    }

                    // Update count
                    var count = $( '.wldelay-summary-features .wldelay-feature-on' ).length;
                    $( '#wldelay-enabled-count' ).text( count );
                }

                // Random delay toggle
                function toggleRandomDelay() {
                    var isRandomChecked = $( '#wldelay_delay_random' ).prop( 'checked' );
                    $( '#wldelay_delay' ).closest( 'tr' ).toggle( ! isRandomChecked );
                    $( '#wldelay_delay_random_min' ).closest( 'tr' ).toggle( isRandomChecked );
                    $( '#wldelay_delay_random_max' ).closest( 'tr' ).toggle( isRandomChecked );
                }
                toggleRandomDelay();
                $( '#wldelay_delay_random' ).on( 'change', toggleRandomDelay );

                // Progressive delay toggle
                function toggleProgressiveDelay() {
                    var isProgressiveChecked = $( '#wldelay_progressive_enabled' ).prop( 'checked' );
                    $( '#wldelay_progressive_increment' ).closest( 'tr' ).toggle( isProgressiveChecked );
                    $( '#wldelay_progressive_max' ).closest( 'tr' ).toggle( isProgressiveChecked );
                    updateSummary( 'wldelay_progressive_enabled', isProgressiveChecked );
                }
                toggleProgressiveDelay();
                $( '#wldelay_progressive_enabled' ).on( 'change', toggleProgressiveDelay );

                // IP Whitelist toggle
                function toggleWhitelist() {
                    var isWhitelistChecked = $( '#wldelay_whitelist_enabled' ).prop( 'checked' );
                    $( '#wldelay_whitelist_ips' ).closest( 'tr' ).toggle( isWhitelistChecked );
                    updateBadge( 'wldelay_whitelist_enabled', isWhitelistChecked );
                    updateSummary( 'wldelay_whitelist_enabled', isWhitelistChecked );
                }
                toggleWhitelist();
                $( '#wldelay_whitelist_enabled' ).on( 'change', toggleWhitelist );

                // Email notifications toggle
                $( '#wldelay_email_enabled' ).on( 'change', function() {
                    var isChecked = $(this).prop( 'checked' );
                    updateBadge( 'wldelay_email_enabled', isChecked );
                    updateSummary( 'wldelay_email_enabled', isChecked );
                });

                // IP Lockout toggle
                $( '#wldelay_lockout_enabled' ).on( 'change', function() {
                    var isChecked = $(this).prop( 'checked' );
                    updateBadge( 'wldelay_lockout_enabled', isChecked );
                    updateSummary( 'wldelay_lockout_enabled', isChecked );
                });

                // XMLRPC Protection toggle
                function toggleXmlrpc() {
                    var isXmlrpcChecked = $( '#wldelay_xmlrpc_enabled' ).prop( 'checked' );
                    $( '#wldelay_xmlrpc_block' ).closest( 'tr' ).toggle( isXmlrpcChecked );
                    updateBadge( 'wldelay_xmlrpc_enabled', isXmlrpcChecked );
                    updateSummary( 'wldelay_xmlrpc_enabled', isXmlrpcChecked );
                }
                toggleXmlrpc();
                $( '#wldelay_xmlrpc_enabled' ).on( 'change', toggleXmlrpc );

                // REST protection toggle
                $( '#wldelay_rest_enabled' ).on( 'change', function() {
                    updateSummary( 'wldelay_rest_enabled', $(this).prop( 'checked' ) );
                });

                // Application password protection toggle
                $( '#wldelay_application_password_enabled' ).on( 'change', function() {
                    updateSummary( 'wldelay_application_password_enabled', $(this).prop( 'checked' ) );
                });

                // Collapsible sections with keyboard support
                function toggleCard( $header ) {
                    var $card = $header.closest( '.wldelay-card' );
                    var isCollapsed = $card.hasClass( 'collapsed' );
                    $card.toggleClass( 'collapsed' );
                    $header.attr( 'aria-expanded', isCollapsed ? 'true' : 'false' );
                }

                $( '.wldelay-card-header' ).on( 'click', function( e ) {
                    // Don't collapse if clicking on a form element
                    if ( $( e.target ).is( 'input, label' ) ) {
                        return;
                    }
                    toggleCard( $( this ) );
                });

                // Keyboard support: Enter and Space to toggle
                $( '.wldelay-card-header' ).on( 'keydown', function( e ) {
                    if ( e.key === 'Enter' || e.key === ' ' ) {
                        e.preventDefault();
                        toggleCard( $( this ) );
                    }
                });
            });
        </script>
        <?php
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
            '<label><input type="checkbox" id="wldelay_trust_proxy_headers" name="wldelay_options[wldelay_trust_proxy_headers]" value="1" %s /> %s</label>',
            ! empty( $this->options['wldelay_trust_proxy_headers'] ) ? 'checked="checked"' : '',
            esc_html__( 'Trust X-Forwarded-For and HTTP_CLIENT_IP headers for IP detection.', 'login-delay-shield' )
        );
        echo $this->tooltip( __( 'Enable this only if your site is behind a reverse proxy or load balancer (e.g., Cloudflare, nginx proxy, AWS ELB). When disabled, only the direct connection IP is used, preventing attackers from spoofing their IP address.', 'login-delay-shield' ) );
        echo '<p id="wldelay_trust_proxy_desc" class="description">' . esc_html__( 'Leave disabled unless behind a trusted proxy. Enabling this on a non-proxied site allows IP spoofing.', 'login-delay-shield' ) . '</p>';
    }

    /**
     * Progressive enabled callback
     */
    public function progressive_enabled_callback() {
        printf(
            '<label><input type="checkbox" id="wldelay_progressive_enabled" name="wldelay_options[wldelay_progressive_enabled]" value="1" %s /> %s</label>',
            ! empty( $this->options['wldelay_progressive_enabled'] ) ? 'checked="checked"' : '',
            esc_html__( 'Increase delay with each consecutive failed attempt from the same IP.', 'login-delay-shield' )
        );
        echo $this->tooltip( __( 'Delays grow longer with each failed attempt. First try might be 1s, second 2s, third 3s, etc. Very effective against automated attacks.', 'login-delay-shield' ) );
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
}
