<?php
/**
 * In-product changelog / release-notes page (F-5-5).
 *
 * Renders the plugin's release notes inside wp-admin, parsed entirely from the
 * LOCAL shipped readme.txt — there is no wp.org API call and no network access.
 * The goal is to surface dormant / recently shipped features to existing users
 * who upgrade in place and never revisit the wp.org listing.
 *
 * The parser (wldelay_parse_changelog) takes the readme CONTENTS as a string so
 * it is unit-testable against a fixture without touching the filesystem. The
 * loader (wldelay_get_changelog_entries) is the thin filesystem/cache wrapper
 * around it, and the admin page renders the parsed structure with every piece
 * of text escaped — the readme is plugin-authored but is treated as untrusted
 * text and never echoed raw.
 *
 * @package login-delay-shield
 */

defined( 'ABSPATH' ) || exit;

/**
 * Admin page slug for the changelog / "What's New" page.
 */
if ( ! defined( 'WLDELAY_CHANGELOG_SLUG' ) ) {
    define( 'WLDELAY_CHANGELOG_SLUG', 'login-delay-shield-changelog' );
}

/**
 * Maximum number of recent versions rendered on the page. Older entries are
 * still parsed (so the parser stays a faithful representation of the file) but
 * are not rendered; the page notes that older entries exist.
 */
if ( ! defined( 'WLDELAY_CHANGELOG_MAX_ENTRIES' ) ) {
    define( 'WLDELAY_CHANGELOG_MAX_ENTRIES', 15 );
}

/**
 * Parse the == Changelog == section of a readme.txt into an ordered structure.
 *
 * Pure function: no WordPress calls, no filesystem, no warnings on malformed
 * input. It returns whatever it can extract and an empty array when there is no
 * changelog section.
 *
 * Output shape (preserving file order, newest first as written in the readme):
 *   array(
 *     array(
 *       'version'  => '2.3.4',
 *       'summary'  => 'fail2ban logging hardening.',   // '' when absent
 *       'sections' => array(
 *         array(
 *           'heading' => 'Improvements',               // '' for un-headed bullets
 *           'items'   => array( 'bullet one', 'bullet two' ),
 *         ),
 *         ...
 *       ),
 *     ),
 *     ...
 *   )
 *
 * @param string $readme_contents Raw readme.txt contents.
 * @return array<int,array{version:string,summary:string,sections:array<int,array{heading:string,items:array<int,string>}>}>
 */
function wldelay_parse_changelog( $readme_contents ) {
    if ( ! is_string( $readme_contents ) || '' === $readme_contents ) {
        return array();
    }

    // Normalise line endings so the line-based parser is robust to CRLF files.
    $normalized = str_replace( array( "\r\n", "\r" ), "\n", $readme_contents );
    $lines      = explode( "\n", $normalized );

    // Locate the == Changelog == heading and slice until the next == ... ==
    // top-level heading (or EOF). Headings are matched on a trimmed line so
    // trailing whitespace never hides the boundary.
    $in_changelog = false;
    $section      = array();
    foreach ( $lines as $line ) {
        $trimmed = trim( $line );

        // A top-level section heading looks like "== Something ==".
        $is_heading = ( '' !== $trimmed )
            && ( 0 === strpos( $trimmed, '==' ) )
            && ( '==' === substr( $trimmed, -2 ) );

        if ( $is_heading ) {
            $title = trim( trim( $trimmed, '=' ) );
            if ( 0 === strcasecmp( $title, 'Changelog' ) ) {
                $in_changelog = true;
                continue;
            }
            if ( $in_changelog ) {
                // Reached the section after the changelog — stop.
                break;
            }
            // A heading before the changelog — ignore.
            continue;
        }

        if ( $in_changelog ) {
            $section[] = $line;
        }
    }

    if ( empty( $section ) ) {
        return array();
    }

    return wldelay_parse_changelog_section( $section );
}

/**
 * Parse the already-isolated changelog body (the lines between == Changelog ==
 * and the next top-level heading) into the entry structure.
 *
 * Split out from wldelay_parse_changelog so the boundary logic and the
 * version/section logic stay independently readable.
 *
 * @param string[] $lines Lines belonging to the changelog section only.
 * @return array<int,array<string,mixed>>
 */
function wldelay_parse_changelog_section( array $lines ) {
    $entries        = array();
    $current        = null; // current version entry being assembled
    $current_section = null; // current '**Heading:**' subsection within the entry

    foreach ( $lines as $line ) {
        $trimmed = trim( $line );

        // Version marker: "= X.Y.Z =" (the version token is whatever sits
        // between the single '=' delimiters; we do not constrain it to a strict
        // semver so pre-release suffixes survive).
        if ( '' !== $trimmed
            && '=' === $trimmed[0]
            && '=' === substr( $trimmed, -1 )
            && 0 !== strpos( $trimmed, '==' ) ) {

            $version = trim( trim( $trimmed, '=' ) );
            if ( '' === $version ) {
                continue;
            }

            // Flush the section in progress, then the entry.
            if ( null !== $current ) {
                $current = wldelay_changelog_flush_section( $current, $current_section );
                $current_section = null;
                $entries[] = $current;
            }

            $current = array(
                'version'  => $version,
                'summary'  => '',
                'sections' => array(),
            );
            $current_section = null;
            continue;
        }

        // Malformed version marker: a line that opens like a version header
        // ("= ...", single '=') but never closes with a matching '='. The
        // parser is lenient by design and would otherwise swallow a truncated
        // readme line with no trace — log it so the dropped entry is
        // debuggable. Behaviour is unchanged: we fall through to the prose /
        // pre-first-marker path exactly as before, only now it is observable.
        if ( '' !== $trimmed
            && '=' === $trimmed[0]
            && 0 !== strpos( $trimmed, '==' )
            && '=' !== substr( $trimmed, -1 ) ) {
            error_log( 'wldelay changelog parser: skipping malformed version marker (missing closing "="): ' . $trimmed ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
        }

        // Anything before the first version marker is ignored.
        if ( null === $current ) {
            continue;
        }

        // Subsection heading: "**Improvements:**" (markdown bold, optional
        // trailing colon).
        if ( '' !== $trimmed
            && 0 === strpos( $trimmed, '**' )
            && '**' === substr( $trimmed, -2 )
            && strlen( $trimmed ) > 4 ) {

            $current = wldelay_changelog_flush_section( $current, $current_section );

            $heading = trim( $trimmed, '*' );
            $heading = rtrim( trim( $heading ), ':' );

            $current_section = array(
                'heading' => trim( $heading ),
                'items'   => array(),
            );
            continue;
        }

        // Bullet item: "* something" or "- something".
        if ( '' !== $trimmed
            && ( '*' === $trimmed[0] || '-' === $trimmed[0] )
            && isset( $trimmed[1] ) ) {

            $item = trim( ltrim( $trimmed, '*- ' ) );
            if ( '' === $item ) {
                continue;
            }

            if ( null === $current_section ) {
                // Bullets directly under a version with no preceding heading —
                // collect them under an empty-heading section.
                $current_section = array(
                    'heading' => '',
                    'items'   => array(),
                );
            }
            $current_section['items'][] = $item;
            continue;
        }

        // Blank line: ends the current bullet group but does not necessarily
        // end the entry. Flush any in-progress un-headed bullet section so a
        // following heading starts cleanly; headed sections are flushed by the
        // next heading/version instead.
        if ( '' === $trimmed ) {
            continue;
        }

        // Plain prose line. The first such line for an entry that has no summary
        // and no sections yet is the one-line summary; later prose is appended
        // to the summary so multi-line summaries are not silently dropped.
        if ( null === $current_section && empty( $current['sections'] ) ) {
            if ( '' === $current['summary'] ) {
                $current['summary'] = $trimmed;
            } else {
                $current['summary'] .= ' ' . $trimmed;
            }
            continue;
        }

        // Prose appearing inside/after a subsection: append to the current
        // section's last item if any, otherwise treat as a standalone item so
        // nothing is lost.
        if ( null !== $current_section ) {
            $current_section['items'][] = $trimmed;
        }
    }

    // Flush the trailing entry.
    if ( null !== $current ) {
        $current = wldelay_changelog_flush_section( $current, $current_section );
        $entries[] = $current;
    }

    return $entries;
}

/**
 * Append the in-progress subsection (if it has any items) to the entry.
 *
 * @param array      $entry   The version entry being assembled.
 * @param array|null $section The subsection in progress, or null.
 * @return array The entry with the section appended when non-empty.
 */
function wldelay_changelog_flush_section( array $entry, $section ) {
    if ( is_array( $section ) && ! empty( $section['items'] ) ) {
        $entry['sections'][] = $section;
    }

    return $entry;
}

/**
 * Read the shipped readme.txt, parse it, and cache the result.
 *
 * Guards file_exists/is_readable and returns array() when the file is absent or
 * unreadable. The parsed result is cached in a short transient keyed by the
 * installed plugin version so a release automatically invalidates the cache,
 * with a request-static layer on top so repeated calls in one request are free.
 *
 * @return array<int,array<string,mixed>> Parsed changelog entries (file order).
 */
function wldelay_get_changelog_entries() {
    static $request_cache = null;
    if ( null !== $request_cache ) {
        return $request_cache;
    }

    $transient_key = 'wldelay_changelog_' . WLDELAY_VERSION;

    if ( function_exists( 'get_transient' ) ) {
        $cached = get_transient( $transient_key );
        if ( is_array( $cached ) ) {
            $request_cache = $cached;
            return $request_cache;
        }
    }

    $readme_path = plugin_dir_path( WLDELAY_PLUGIN_FILE ) . 'readme.txt';

    if ( ! file_exists( $readme_path ) || ! is_readable( $readme_path ) ) {
        $request_cache = array();
        return $request_cache;
    }

    $contents = file_get_contents( $readme_path );
    if ( false === $contents ) {
        $request_cache = array();
        return $request_cache;
    }

    $entries = wldelay_parse_changelog( $contents );

    if ( function_exists( 'set_transient' ) ) {
        set_transient( $transient_key, $entries, DAY_IN_SECONDS );
    }

    $request_cache = $entries;
    return $request_cache;
}

/**
 * Register the "What's New" page as a Settings submenu.
 */
function wldelay_register_changelog_page() {
    add_options_page(
        esc_html__( 'Login Delay Shield — What\'s New', 'wp-login-delay' ),
        esc_html__( 'Login Delay Shield — What\'s New', 'wp-login-delay' ),
        'manage_options',
        WLDELAY_CHANGELOG_SLUG,
        'wldelay_render_changelog_page'
    );
}

/**
 * Render the changelog / release-notes admin page.
 *
 * Every piece of parsed text is escaped with esc_html; the current installed
 * version is marked both with text ("Installed version") and a CSS class so the
 * meaning is never carried by colour alone (WCAG 1.4.1). Headings follow a
 * single h1 → h2 → h3 hierarchy and bullet lists are real <ul>/<li>.
 *
 * @param array<int,array<string,mixed>>|null $entries Optional pre-parsed
 *        entries. Defaults to the loader; an explicit value lets tests render
 *        crafted (e.g. malicious) entries deterministically without depending on
 *        the request-static / transient cache state.
 */
function wldelay_render_changelog_page( $entries = null ) {
    if ( function_exists( 'current_user_can' ) && ! current_user_can( 'manage_options' ) ) {
        return;
    }

    if ( null === $entries || ! is_array( $entries ) ) {
        $entries = wldelay_get_changelog_entries();
    }
    $total        = count( $entries );
    $shown        = array_slice( $entries, 0, WLDELAY_CHANGELOG_MAX_ENTRIES );
    $has_older    = $total > count( $shown );
    $current_ver  = defined( 'WLDELAY_VERSION' ) ? WLDELAY_VERSION : '';

    $settings_url = admin_url( 'options-general.php?page=login-delay-shield-admin' );

    echo '<div class="wrap wldelay-changelog">';
    echo '<h1>' . esc_html__( 'Login Delay Shield — What\'s New', 'wp-login-delay' ) . '</h1>';

    // Link back to the settings screen so the page is not a dead end (R1-8).
    echo '<p class="wldelay-changelog-actions"><a href="' . esc_url( $settings_url ) . '">'
        . '&larr; ' . esc_html__( 'Back to Login Delay Shield settings', 'wp-login-delay' )
        . '</a></p>';

    if ( empty( $entries ) ) {
        echo '<p>' . esc_html__( 'No release notes are available.', 'wp-login-delay' ) . '</p>';
        echo '</div>';
        return;
    }

    echo '<p>' . esc_html__( 'Release notes for Login Delay Shield, newest first.', 'wp-login-delay' ) . '</p>';

    foreach ( $shown as $entry ) {
        $version    = isset( $entry['version'] ) ? $entry['version'] : '';
        $is_current = ( '' !== $current_ver && $version === $current_ver );

        $entry_class = 'wldelay-changelog-entry';
        if ( $is_current ) {
            $entry_class .= ' wldelay-changelog-entry--current';
        }

        echo '<div class="' . esc_attr( $entry_class ) . '">';

        // Version heading. The version token may contain digits/dots only in
        // practice, but escape it regardless and set lang="en" on the version
        // number which is locale-independent.
        echo '<h2>';
        /* translators: %s: plugin version number. */
        echo esc_html( sprintf( __( 'Version %s', 'wp-login-delay' ), $version ) );
        if ( $is_current ) {
            // <mark> carries the "highlighted for reference" semantic so the
            // installed version is conveyed without relying on colour alone;
            // it sits inside the <h2> so heading navigation surfaces it.
            echo ' <mark class="wldelay-changelog-current-badge">'
                . esc_html__( '(Installed version)', 'wp-login-delay' )
                . '</mark>';
        }
        echo '</h2>';

        if ( ! empty( $entry['summary'] ) ) {
            echo '<p class="wldelay-changelog-summary">' . esc_html( $entry['summary'] ) . '</p>';
        }

        if ( ! empty( $entry['sections'] ) && is_array( $entry['sections'] ) ) {
            foreach ( $entry['sections'] as $sub ) {
                $heading = isset( $sub['heading'] ) ? $sub['heading'] : '';
                $items   = ( isset( $sub['items'] ) && is_array( $sub['items'] ) ) ? $sub['items'] : array();

                if ( empty( $items ) ) {
                    continue;
                }

                if ( '' !== $heading ) {
                    echo '<h3>' . esc_html( $heading ) . '</h3>';
                }

                echo '<ul class="wldelay-changelog-items">';
                foreach ( $items as $item ) {
                    echo '<li>' . esc_html( $item ) . '</li>';
                }
                echo '</ul>';
            }
        }

        echo '</div>';
    }

    if ( $has_older ) {
        echo '<p class="wldelay-changelog-older">'
            . esc_html(
                sprintf(
                    /* translators: %d: number of older versions not shown. */
                    _n(
                        '%d older version is not shown.',
                        '%d older versions are not shown.',
                        $total - count( $shown ),
                        'wp-login-delay'
                    ),
                    $total - count( $shown )
                )
            )
            . '</p>';
    }

    // Funnel the reader to the settings screen to turn on any feature the notes
    // mention, instead of leaving them to hunt for it in the admin menu (R1-8).
    echo '<p class="wldelay-changelog-footer"><a href="' . esc_url( $settings_url ) . '">'
        . esc_html__( 'Open Login Delay Shield settings to enable any features mentioned above.', 'wp-login-delay' )
        . '</a></p>';

    echo '</div>';
}

if ( function_exists( 'add_action' ) ) {
    add_action( 'admin_menu', 'wldelay_register_changelog_page' );
}
