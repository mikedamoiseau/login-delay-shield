<?php
/**
 * Unit tests for the in-plugin documentation link builder (F-5-6).
 *
 * wldelay_get_doc_url() maps a feature key to its public user-guide anchor,
 * with a filterable base URL that can also disable links entirely.
 */

use Brain\Monkey\Functions;

class HelpLinksTest extends LDS_Unit_Test_Case {

    protected function setUp(): void {
        parent::setUp();

        // Default: apply_filters returns the supplied default unchanged.
        Functions\when( 'apply_filters' )->alias( function ( $tag, $value ) {
            return $value;
        } );

        // trailingslashit: collapse trailing slashes to exactly one.
        Functions\when( 'trailingslashit' )->alias( function ( $string ) {
            return rtrim( $string, '/' ) . '/';
        } );
    }

    /**
     * A known feature key returns the default base URL plus its anchor.
     */
    public function test_known_section_returns_full_doc_url() {
        $this->assertSame(
            'https://damoiseau.xyz/docs/login-delay-shield/user-guide/#email-notifications',
            wldelay_get_doc_url( 'email-notifications' )
        );
    }

    /**
     * Every wired feature key resolves to a non-empty URL ending in its anchor.
     */
    public function test_all_wired_sections_resolve() {
        $sections = array(
            'delay-settings',
            'email-notifications',
            'ip-lockout',
            'ip-whitelist',
            'login-log',
            'xmlrpc-protection',
            'custom-login-url',
            'distributed-attack',
            'country-blocking',
            'challenge-mode',
            'progressive-delay',
            'lockout-strategy',
            'fail2ban',
            'rest-api-protection',
            'recovery-url',
            'audit-log',
        );
        foreach ( $sections as $section ) {
            $url = wldelay_get_doc_url( $section );
            $this->assertStringEndsWith( '#' . $section, $url, "Section '{$section}' must resolve." );
            $this->assertStringStartsWith( 'https://', $url );
        }
    }

    /**
     * An unknown / mistyped key returns '' rather than a broken anchor.
     */
    public function test_unknown_section_returns_empty_string() {
        $this->assertSame( '', wldelay_get_doc_url( 'not-a-real-section' ) );
        $this->assertSame( '', wldelay_get_doc_url( '' ) );
    }

    /**
     * The filter can disable all doc links by returning an empty base URL.
     */
    public function test_empty_base_url_filter_disables_links() {
        Functions\when( 'apply_filters' )->alias( function ( $tag, $value ) {
            return ( 'wldelay_help_base_url' === $tag ) ? '' : $value;
        } );

        $this->assertSame( '', wldelay_get_doc_url( 'email-notifications' ) );
    }

    /**
     * The filter can repoint the base URL (self-hosted / white-label docs).
     */
    public function test_filter_can_override_base_url() {
        Functions\when( 'apply_filters' )->alias( function ( $tag, $value ) {
            return ( 'wldelay_help_base_url' === $tag ) ? 'https://example.test/help' : $value;
        } );

        $this->assertSame(
            'https://example.test/help/#ip-lockout',
            wldelay_get_doc_url( 'ip-lockout' )
        );
    }
}
