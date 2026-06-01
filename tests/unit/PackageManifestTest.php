<?php
/**
 * Guards the packaging allowlist against the "required module not shipped"
 * regression: every local PHP file the bootstrap require_once's MUST appear in
 * bin/package.sh, or the wordpress.org release fatals on load (F-2-2 review).
 *
 * Pure file inspection — no WordPress runtime, no zip — so it runs in the fast
 * unit suite.
 */

class PackageManifestTest extends LDS_Unit_Test_Case {

    /**
     * @return string Repo root (the plugin directory / SVN trunk).
     */
    private function repo_root() {
        return dirname( dirname( __DIR__ ) );
    }

    /**
     * Local PHP files pulled in by the main plugin file via require_once
     * dirname( __FILE__ ) . '/<file>.php'.
     *
     * @return string[]
     */
    private function required_local_php_files() {
        $bootstrap = file_get_contents( $this->repo_root() . '/wp-login-delay.php' );

        preg_match_all(
            "#require_once\\s+dirname\\(\\s*__FILE__\\s*\\)\\s*\\.\\s*'/([A-Za-z0-9_-]+\\.php)'#",
            $bootstrap,
            $matches
        );

        return array_unique( $matches[1] );
    }

    public function test_every_required_module_is_in_package_allowlist() {
        $package = file_get_contents( $this->repo_root() . '/bin/package.sh' );
        $required = $this->required_local_php_files();

        // Sanity: the bootstrap must require at least its known modules so a
        // broken regex cannot make this test vacuously pass.
        $this->assertNotEmpty( $required, 'No require_once modules parsed from wp-login-delay.php' );

        foreach ( $required as $file ) {
            $this->assertStringContainsString(
                $file,
                $package,
                "bin/package.sh does not ship required module {$file} — packaged release would fatal on load"
            );
        }
    }
}
