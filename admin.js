jQuery(document).ready(function ($) {
    'use strict';

    function getAdminConfig() {
        return window.wldelayAdmin || {};
    }

    function updateBadge(toggleKey, isEnabled) {
        var config = getAdminConfig();
        var $badge = $('.wldelay-badge[data-toggle="' + toggleKey + '"]');

        if (!$badge.length) {
            return;
        }

        if (isEnabled) {
            $badge
                .removeClass('wldelay-badge-disabled')
                .addClass('wldelay-badge-enabled')
                .text(config.badgeEnabled || 'Enabled');
        } else {
            $badge
                .removeClass('wldelay-badge-enabled')
                .addClass('wldelay-badge-disabled')
                .text(config.badgeDisabled || 'Disabled');
        }
    }

    function updateSummary(toggleKey, isEnabled) {
        var $feature = $('.wldelay-summary-features span[data-feature="' + toggleKey + '"]');
        var $icon = $feature.find('.dashicons');

        if (!$feature.length) {
            return;
        }

        if (isEnabled) {
            $feature.removeClass('wldelay-feature-off').addClass('wldelay-feature-on');
            $icon.removeClass('dashicons-no-alt').addClass('dashicons-yes');
        } else {
            $feature.removeClass('wldelay-feature-on').addClass('wldelay-feature-off');
            $icon.removeClass('dashicons-yes').addClass('dashicons-no-alt');
        }

        var enabledCount = $('.wldelay-summary-features .wldelay-feature-on').length;
        var totalCount = $('.wldelay-summary-features span[data-feature]').length;
        $('.wldelay-summary-fraction').text('(' + enabledCount + '/' + totalCount + ')');

        var config = getAdminConfig();
        var weights = config.scoreWeights || {};
        var score = 0;
        var max = 0;
        var bestRec = null;

        $.each(weights, function (key, w) {
            max += w.points;
            var on = $('.wldelay-summary-features span[data-feature="' + key + '"]').hasClass('wldelay-feature-on');
            if (on) {
                score += w.points;
            } else if (!bestRec || w.points > bestRec.points) {
                bestRec = { label: w.label, points: w.points };
            }
        });

        var pct = max > 0 ? Math.round((score / max) * 100) : 0;
        $('.wldelay-score-value').text(pct);
        $('.wldelay-score-circle').css('--score-pct', pct);

        var $rec = $('.wldelay-summary-recommendation');
        if (bestRec && config.recommendPrefix) {
            if (!$rec.length) {
                $rec = $('<div class="wldelay-summary-recommendation"></div>');
                $('.wldelay-summary-features').after($rec);
            }
            $rec.empty()
                .append($('<span class="dashicons dashicons-lightbulb" aria-hidden="true"></span>'))
                .append(' ')
                .append(document.createTextNode(config.recommendPrefix + ' '))
                .append($('<strong></strong>').text(bestRec.label))
                .append(' ')
                .append(document.createTextNode(config.recommendSuffix.replace('%d', bestRec.points)));
        } else {
            $rec.remove();
        }
    }

    function toggleRandomDelay() {
        var isRandomChecked = $('#wldelay_delay_random').prop('checked');
        $('#wldelay_delay').closest('tr').toggle(!isRandomChecked);
        $('#wldelay_delay_random_min').closest('tr').toggle(isRandomChecked);
        $('#wldelay_delay_random_max').closest('tr').toggle(isRandomChecked);
    }

    function toggleProgressiveDelay() {
        var isProgressiveChecked = $('#wldelay_progressive_enabled').prop('checked');
        $('#wldelay_progressive_increment').closest('tr').toggle(isProgressiveChecked);
        $('#wldelay_progressive_max').closest('tr').toggle(isProgressiveChecked);
        updateSummary('wldelay_progressive_enabled', isProgressiveChecked);
    }

    function toggleWhitelist() {
        var isWhitelistChecked = $('#wldelay_whitelist_enabled').prop('checked');
        $('#wldelay_whitelist_ips').closest('tr').toggle(isWhitelistChecked);
        updateBadge('wldelay_whitelist_enabled', isWhitelistChecked);
        updateSummary('wldelay_whitelist_enabled', isWhitelistChecked);
    }

    function toggleXmlrpc() {
        var isXmlrpcChecked = $('#wldelay_xmlrpc_enabled').prop('checked');
        $('#wldelay_xmlrpc_block').closest('tr').toggle(isXmlrpcChecked);
        updateBadge('wldelay_xmlrpc_enabled', isXmlrpcChecked);
        updateSummary('wldelay_xmlrpc_enabled', isXmlrpcChecked);
    }

    function toggleFail2ban() {
        var isFail2banChecked = $('#wldelay_fail2ban_enabled').prop('checked');
        $('#wldelay_fail2ban_log_path').closest('tr').toggle(isFail2banChecked);
        $('#wldelay_fail2ban_include_lockouts').closest('tr').toggle(isFail2banChecked);
        updateBadge('wldelay_fail2ban_enabled', isFail2banChecked);
        updateSummary('wldelay_fail2ban_enabled', isFail2banChecked);
    }

    function toggleCard($header) {
        var $card = $header.closest('.wldelay-card');
        var isCollapsed = $card.hasClass('collapsed');
        $card.toggleClass('collapsed');
        $header.attr('aria-expanded', isCollapsed ? 'true' : 'false');
    }

    if ($('#wldelay_delay_random').length) {
        toggleRandomDelay();
        $('#wldelay_delay_random').on('change', toggleRandomDelay);
    }

    if ($('#wldelay_progressive_enabled').length) {
        toggleProgressiveDelay();
        $('#wldelay_progressive_enabled').on('change', toggleProgressiveDelay);
    }

    if ($('#wldelay_whitelist_enabled').length) {
        toggleWhitelist();
        $('#wldelay_whitelist_enabled').on('change', toggleWhitelist);
    }

    $('#wldelay_custom_login_enabled').on('change', function () {
        var isChecked = $(this).prop('checked');
        $('#wldelay_custom_login_slug').closest('tr').toggle(isChecked);
        updateBadge('wldelay_custom_login_enabled', isChecked);
        updateSummary('wldelay_custom_login_enabled', isChecked);
    });

    $('#wldelay_email_enabled').on('change', function () {
        var isChecked = $(this).prop('checked');
        updateBadge('wldelay_email_enabled', isChecked);
        updateSummary('wldelay_email_enabled', isChecked);
    });

    $('#wldelay_lockout_enabled').on('change', function () {
        var isChecked = $(this).prop('checked');
        updateBadge('wldelay_lockout_enabled', isChecked);
        updateSummary('wldelay_lockout_enabled', isChecked);
    });

    if ($('#wldelay_xmlrpc_enabled').length) {
        toggleXmlrpc();
        $('#wldelay_xmlrpc_enabled').on('change', toggleXmlrpc);
    }

    if ($('#wldelay_fail2ban_enabled').length) {
        toggleFail2ban();
        $('#wldelay_fail2ban_enabled').on('change', toggleFail2ban);
    }

    $('#wldelay_rest_enabled').on('change', function () {
        updateSummary('wldelay_rest_enabled', $(this).prop('checked'));
    });

    $('#wldelay_application_password_enabled').on('change', function () {
        updateSummary('wldelay_application_password_enabled', $(this).prop('checked'));
    });

    $('.wldelay-card-header').on('click', function (e) {
        if ($(e.target).is('input, label')) {
            return;
        }
        toggleCard($(this));
    });

    $('.wldelay-card-header').on('keydown', function (e) {
        if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            toggleCard($(this));
        }
    });

    $(document).on('click', '.wldelay-name-change-notice .notice-dismiss', function () {
        var config = getAdminConfig();

        if (!config.ajaxUrl || !config.dismissNoticeNonce) {
            return;
        }

        $.post(config.ajaxUrl, {
            action: 'wldelay_dismiss_name_change_notice',
            _wpnonce: config.dismissNoticeNonce
        });
    });

    $(document).on('click', '.wldelay-whats-new-notice .notice-dismiss', function () {
        var config = getAdminConfig();
        var version = $(this).closest('.wldelay-whats-new-notice').data('version');

        if (!config.ajaxUrl || !config.dismissNoticeNonce) {
            return;
        }

        $.post(config.ajaxUrl, {
            action: 'wldelay_dismiss_whats_new_notice',
            version: version,
            _wpnonce: config.dismissNoticeNonce
        });
    });
});
