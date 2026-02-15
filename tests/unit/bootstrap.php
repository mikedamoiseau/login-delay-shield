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
