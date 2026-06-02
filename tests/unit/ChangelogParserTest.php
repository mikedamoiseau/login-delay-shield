<?php
/**
 * Unit tests for the pure changelog parser (F-5-5).
 *
 * No WordPress runtime and no filesystem: wldelay_parse_changelog() takes the
 * readme CONTENTS as a string, so every case here is fed a fixture string.
 */

class ChangelogParserTest extends LDS_Unit_Test_Case {

    /**
     * A representative changelog with the boundary section that must NOT bleed
     * into the parsed entries.
     *
     * @return string
     */
    private function fixture() {
        return <<<README
=== Login Delay Shield ===
Stable tag: 2.3.4

== Description ==
This text precedes the changelog and must be ignored.

= Some FAQ entry that looks like a version =
Not a changelog version.

== Changelog ==

= 2.3.4 =
fail2ban logging hardening.

**Improvements:**
* Log rotation to a single backup file.
* Web-server protection files written everywhere.

**Maintenance:**
* Added an uninstall routine.

= 2.3.3 =
Security Setup Wizard.

**New Features:**
* Added a Security Setup Wizard.

== Upgrade Notice ==

= 2.3.4 =
THIS LINE MUST NOT APPEAR IN PARSED ENTRIES.
README;
    }

    public function test_returns_entries_in_file_order() {
        $entries  = wldelay_parse_changelog( $this->fixture() );
        $versions = array_column( $entries, 'version' );

        $this->assertSame( array( '2.3.4', '2.3.3' ), $versions );
    }

    public function test_parses_summary() {
        $entries = wldelay_parse_changelog( $this->fixture() );

        $this->assertSame( 'fail2ban logging hardening.', $entries[0]['summary'] );
        $this->assertSame( 'Security Setup Wizard.', $entries[1]['summary'] );
    }

    public function test_parses_section_headings_and_items() {
        $entries  = wldelay_parse_changelog( $this->fixture() );
        $sections = $entries[0]['sections'];

        $this->assertCount( 2, $sections );
        $this->assertSame( 'Improvements', $sections[0]['heading'] );
        $this->assertSame(
            array(
                'Log rotation to a single backup file.',
                'Web-server protection files written everywhere.',
            ),
            $sections[0]['items']
        );
        $this->assertSame( 'Maintenance', $sections[1]['heading'] );
        $this->assertSame( array( 'Added an uninstall routine.' ), $sections[1]['items'] );
    }

    public function test_respects_changelog_boundary() {
        $entries = wldelay_parse_changelog( $this->fixture() );

        // The == Upgrade Notice == section reuses "= 2.3.4 =" but must not be
        // parsed: there are exactly two entries and none carries the sentinel.
        $this->assertCount( 2, $entries );
        foreach ( $entries as $entry ) {
            foreach ( $entry['sections'] as $section ) {
                foreach ( $section['items'] as $item ) {
                    $this->assertStringNotContainsString( 'MUST NOT APPEAR', $item );
                }
            }
            $this->assertStringNotContainsString( 'MUST NOT APPEAR', $entry['summary'] );
        }
    }

    public function test_ignores_content_before_changelog() {
        $entries  = wldelay_parse_changelog( $this->fixture() );
        $versions = array_column( $entries, 'version' );

        // The FAQ-style "= Some FAQ entry =" lives before == Changelog == and
        // must never become an entry.
        $this->assertNotContains( 'Some FAQ entry that looks like a version', $versions );
    }

    public function test_empty_input_returns_empty_array() {
        $this->assertSame( array(), wldelay_parse_changelog( '' ) );
        $this->assertSame( array(), wldelay_parse_changelog( 'no changelog heading here' ) );
    }

    public function test_non_string_input_returns_empty_array() {
        $this->assertSame( array(), wldelay_parse_changelog( null ) );
        $this->assertSame( array(), wldelay_parse_changelog( array() ) );
    }

    public function test_missing_summary_does_not_fatal() {
        $readme = "== Changelog ==\n\n= 9.9.9 =\n\n**Fixes:**\n* A fix with no summary line.\n";

        $entries = wldelay_parse_changelog( $readme );

        $this->assertCount( 1, $entries );
        $this->assertSame( '9.9.9', $entries[0]['version'] );
        $this->assertSame( '', $entries[0]['summary'] );
        $this->assertSame( 'Fixes', $entries[0]['sections'][0]['heading'] );
        $this->assertSame( array( 'A fix with no summary line.' ), $entries[0]['sections'][0]['items'] );
    }

    public function test_version_with_no_subsection_groups_bullets_under_empty_heading() {
        $readme = "== Changelog ==\n\n= 1.0.0 =\nFirst release.\n* Loose bullet one.\n* Loose bullet two.\n";

        $entries = wldelay_parse_changelog( $readme );

        $this->assertCount( 1, $entries );
        $this->assertSame( 'First release.', $entries[0]['summary'] );
        $this->assertCount( 1, $entries[0]['sections'] );
        $this->assertSame( '', $entries[0]['sections'][0]['heading'] );
        $this->assertSame(
            array( 'Loose bullet one.', 'Loose bullet two.' ),
            $entries[0]['sections'][0]['items']
        );
    }

    public function test_version_with_no_body_yields_no_sections() {
        $readme = "== Changelog ==\n\n= 2.0.0 =\nJust a summary, nothing else.\n\n= 1.0.0 =\nOlder.\n";

        $entries = wldelay_parse_changelog( $readme );

        $this->assertCount( 2, $entries );
        $this->assertSame( array(), $entries[0]['sections'] );
        $this->assertSame( 'Just a summary, nothing else.', $entries[0]['summary'] );
    }

    public function test_trailing_whitespace_and_crlf_are_tolerated() {
        $readme = "== Changelog ==   \r\n\r\n= 3.0.0 =  \r\nSummary with trailing space.   \r\n\r\n**Notes:**  \r\n* Item with CRLF.  \r\n";

        $entries = wldelay_parse_changelog( $readme );

        $this->assertCount( 1, $entries );
        $this->assertSame( '3.0.0', $entries[0]['version'] );
        $this->assertSame( 'Summary with trailing space.', $entries[0]['summary'] );
        $this->assertSame( 'Notes', $entries[0]['sections'][0]['heading'] );
        $this->assertSame( array( 'Item with CRLF.' ), $entries[0]['sections'][0]['items'] );
    }

    public function test_changelog_at_eof_without_following_section() {
        $readme = "Intro\n\n== Changelog ==\n\n= 5.0.0 =\nLatest.\n\n**Improvements:**\n* Only entry.\n";

        $entries = wldelay_parse_changelog( $readme );

        $this->assertCount( 1, $entries );
        $this->assertSame( '5.0.0', $entries[0]['version'] );
        $this->assertSame( array( 'Only entry.' ), $entries[0]['sections'][0]['items'] );
    }
}
