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
    private function render_changelog_page( $entries = null ) {
        $admin_id = $this->factory->user->create( array( 'role' => 'administrator' ) );
        wp_set_current_user( $admin_id );

        ob_start();
        wldelay_render_changelog_page( $entries );
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
        // Render crafted malicious entries DIRECTLY (the render function accepts an
        // explicit entries argument), so the assertion is deterministic and does
        // not depend on the loader's request-static / transient cache state.
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

        $output = $this->render_changelog_page( $malicious );

        // No raw script/img/bold tag from the parsed content may appear.
        $this->assertStringNotContainsString( '<script>alert(1)</script>', $output );
        $this->assertStringNotContainsString( '<img src=x onerror=alert(1)>', $output );
        $this->assertStringNotContainsString( '<b>x</b>', $output );

        // The escaped forms MUST be present — proving the malicious entries were
        // actually rendered (not skipped) and were escaped.
        $this->assertStringContainsString( 'Summary &lt;script&gt;alert(1)&lt;/script&gt;', $output );
        $this->assertStringContainsString( 'Item &lt;img src=x onerror=alert(1)&gt;', $output );
    }
}
