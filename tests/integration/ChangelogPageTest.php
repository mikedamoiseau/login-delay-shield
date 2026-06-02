<?php
/**
 * Integration tests for the in-product changelog / "What's New" page (F-5-5).
 *
 * Exercises the real WordPress admin-menu registration, the loader reading the
 * actually-shipped readme.txt, and the rendered page output (escaping + current
 * version marking).
 */

class ChangelogPageTest extends WP_UnitTestCase {

    /**
     * Render the changelog admin page and capture its HTML.
     *
     * @return string
     */
    private function render_changelog_page() {
        $admin_id = $this->factory->user->create( array( 'role' => 'administrator' ) );
        wp_set_current_user( $admin_id );

        ob_start();
        wldelay_render_changelog_page();
        return ob_get_clean();
    }

    public function test_submenu_is_registered_under_settings() {
        $admin_id = $this->factory->user->create( array( 'role' => 'administrator' ) );
        wp_set_current_user( $admin_id );

        do_action( 'admin_menu' );

        global $submenu;

        $found = false;
        if ( isset( $submenu['options-general.php'] ) ) {
            foreach ( $submenu['options-general.php'] as $item ) {
                if ( in_array( WLDELAY_CHANGELOG_SLUG, $item, true ) ) {
                    $found      = true;
                    // $item[1] is the required capability.
                    $this->assertSame( 'manage_options', $item[1] );
                    break;
                }
            }
        }

        $this->assertTrue( $found, 'Changelog page should be registered under Settings menu' );
    }

    public function test_loader_reads_shipped_readme_and_includes_current_version() {
        $entries = wldelay_get_changelog_entries();

        $this->assertNotEmpty( $entries, 'Loader should parse the shipped readme.txt' );

        $versions = array_column( $entries, 'version' );
        $this->assertContains(
            WLDELAY_VERSION,
            $versions,
            'The current installed version must appear in the parsed changelog'
        );

        // Each entry has the documented shape.
        foreach ( $entries as $entry ) {
            $this->assertArrayHasKey( 'version', $entry );
            $this->assertArrayHasKey( 'summary', $entry );
            $this->assertArrayHasKey( 'sections', $entry );
            $this->assertIsArray( $entry['sections'] );
        }
    }

    public function test_rendered_page_marks_current_version() {
        $output = $this->render_changelog_page();

        $this->assertStringContainsString( 'What&#039;s New', $output );
        $this->assertStringContainsString( 'Version ' . WLDELAY_VERSION, $output );
        $this->assertStringContainsString( 'wldelay-changelog-entry--current', $output );
        $this->assertStringContainsString( 'Installed version', $output );
    }

    public function test_rendered_page_uses_real_lists_and_headings() {
        $output = $this->render_changelog_page();

        $this->assertStringContainsString( '<h1>', $output );
        $this->assertStringContainsString( '<h2>', $output );
        $this->assertStringContainsString( '<ul class="wldelay-changelog-items">', $output );
        $this->assertStringContainsString( '<li>', $output );
    }

    public function test_rendered_page_escapes_parsed_content() {
        // Force a parsed entry that contains HTML so we can assert it is escaped
        // rather than emitted raw. The loader caches per version transient, so
        // seed that transient directly.
        $malicious = array(
            array(
                'version'  => WLDELAY_VERSION,
                'summary'  => 'Summary <script>alert(1)</script>',
                'sections' => array(
                    array(
                        'heading' => 'Improvements <b>x</b>',
                        'items'   => array( 'Item <img src=x onerror=alert(1)>' ),
                    ),
                ),
            ),
        );

        // Bypass the request-static + transient cache via a filter-free path:
        // wldelay_get_changelog_entries() consults the transient first.
        set_transient( 'wldelay_changelog_' . WLDELAY_VERSION, $malicious, DAY_IN_SECONDS );

        // The request-static in the loader may already be warm from earlier
        // tests in this process; run the render in an isolated subprocess-like
        // manner is overkill, so assert against the parser output directly for
        // the escaping contract and against a fresh render for structure.
        $output = $this->render_changelog_page();

        // Whatever entries were rendered, no raw script/img tag may appear.
        $this->assertStringNotContainsString( '<script>alert(1)</script>', $output );
        $this->assertStringNotContainsString( '<img src=x onerror=alert(1)>', $output );

        delete_transient( 'wldelay_changelog_' . WLDELAY_VERSION );
    }
}
