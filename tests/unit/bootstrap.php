<?php
/**
 * PHPUnit bootstrap file for unit tests.
 *
 * Uses Brain Monkey to mock WordPress functions - no WordPress dependency.
 */

// Composer autoloader
$composer_autoload = dirname( dirname( __DIR__ ) ) . '/vendor/autoload.php';
if ( ! file_exists( $composer_autoload ) ) {
    echo "Composer autoloader not found. Run 'composer install' first." . PHP_EOL;
    exit( 1 );
}
require_once $composer_autoload;

// Define ABSPATH to allow including plugin files
if ( ! defined( 'ABSPATH' ) ) {
    define( 'ABSPATH', '/tmp/wordpress/' );
}

// Load Brain Monkey
use Brain\Monkey;

/**
 * Base test case for unit tests using Brain Monkey.
 */
abstract class LDS_Unit_Test_Case extends \PHPUnit\Framework\TestCase {

    /**
     * Set up Brain Monkey before each test.
     */
    protected function setUp(): void {
        parent::setUp();
        Monkey\setUp();
    }

    /**
     * Tear down Brain Monkey after each test.
     */
    protected function tearDown(): void {
        Monkey\tearDown();
        parent::tearDown();
    }
}

// Load the settings classes for constants
require_once dirname( dirname( __DIR__ ) ) . '/wldelay-settings-view.php';
require_once dirname( dirname( __DIR__ ) ) . '/wldelay-settings.php';

// Load the persistence contract for pure-logic unit tests (key derivation).
require_once dirname( dirname( __DIR__ ) ) . '/wldelay-persistence.php';

// Load the declarative feature/defaults registry (F-2-2).
require_once dirname( dirname( __DIR__ ) ) . '/wldelay-features.php';

// Load the audit module for pure-logic unit tests (settings-diff builder).
// Its top-level hook registration is guarded by function_exists/defined so it
// stays inert without a WP runtime.
require_once dirname( dirname( __DIR__ ) ) . '/wldelay-audit.php';

// Load the privacy module for pure-logic unit tests (row→item mapping,
// email→login resolution). Its filter registration is guarded by
// function_exists so it stays inert without a WP runtime.
require_once dirname( dirname( __DIR__ ) ) . '/wldelay-privacy.php';

// Load the changelog module so the pure parser (wldelay_parse_changelog) is
// available to unit tests. Its admin_menu hook registration is guarded by
// function_exists( 'add_action' ) so it stays inert without a WP runtime.
require_once dirname( dirname( __DIR__ ) ) . '/wldelay-changelog.php';

// Load the shared failed-auth pipeline (F-2-4). Pure logic — all of its
// collaborators are stubbed via Brain Monkey in the tests.
require_once dirname( dirname( __DIR__ ) ) . '/wldelay-pipeline.php';

// WordPress time constants used by the botnet module (and available globally
// in a real WP runtime). Define them here so unit tests run without WP.
if ( ! defined( 'MINUTE_IN_SECONDS' ) ) {
    define( 'MINUTE_IN_SECONDS', 60 );
}
if ( ! defined( 'HOUR_IN_SECONDS' ) ) {
    define( 'HOUR_IN_SECONDS', 3600 );
}
if ( ! defined( 'DAY_IN_SECONDS' ) ) {
    define( 'DAY_IN_SECONDS', 86400 );
}

// Load the botnet / credential-stuffing detection module (F-1-9). Its
// wldelay_register_task_handler() and wldelay_on_event() calls at the bottom
// are guarded or no-ops in the unit suite (function_exists is true for Brain
// Monkey stubs, but the registrations are just array writes — harmless).
require_once dirname( dirname( __DIR__ ) ) . '/wldelay-botnet.php';
