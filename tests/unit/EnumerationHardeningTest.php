<?php
/**
 * Unit tests for username-enumeration hardening (F-3-5).
 *
 * Covers the sanitization of the new toggle and the pure
 * generic-error-message logic that does not require a WordPress runtime.
 */

use Brain\Monkey\Functions;

class EnumerationHardeningTest extends LDS_Unit_Test_Case {

    /**
     * @var LDS_Settings
     */
    private $settings;

    protected function setUp(): void {
        parent::setUp();

        Functions\when( 'absint' )->alias( function( $value ) {
            return abs( (int) $value );
        } );
        Functions\when( 'sanitize_email' )->alias( function( $email ) {
            return filter_var( $email, FILTER_SANITIZE_EMAIL );
        } );
        Functions\when( 'get_option' )->justReturn( false );
        Functions\when( 'update_option' )->justReturn( true );
        Functions\when( 'wp_generate_password' )->alias( function( $length = 12 ) {
            return substr( str_repeat( 'abcdefghijklmnop', 2 ), 0, $length );
        } );

        // The generic-message helper lives in the main plugin file; load only
        // the function under test without booting WordPress.
        if ( ! function_exists( 'wldelay_get_generic_login_error_message' ) ) {
            require_once dirname( dirname( __DIR__ ) ) . '/wldelay-enumeration.php';
        }

        $this->settings = new LDS_Settings();
    }

    /**
     * The new toggle sanitizes to a strict boolean (truthy values -> true).
     */
    public function test_enumeration_hardening_truthy_cast_to_true() {
        $input = [ 'wldelay_enumeration_hardening_enabled' => '1' ];
        $result = $this->settings->sanitize( $input );
        $this->assertTrue( $result['wldelay_enumeration_hardening_enabled'] );
    }

    /**
     * Falsy/missing values sanitize to false (default-off behavior).
     */
    public function test_enumeration_hardening_falsy_cast_to_false() {
        $input = [ 'wldelay_enumeration_hardening_enabled' => '' ];
        $result = $this->settings->sanitize( $input );
        $this->assertFalse( $result['wldelay_enumeration_hardening_enabled'] );
    }

    /**
     * A missing key sanitizes to false so the feature stays opt-in.
     */
    public function test_enumeration_hardening_missing_defaults_false() {
        $input = [];
        $result = $this->settings->sanitize( $input );
        $this->assertFalse( $result['wldelay_enumeration_hardening_enabled'] );
    }

    /**
     * The generic message is a non-empty string and does not reveal which
     * field (username vs password) was wrong.
     */
    public function test_generic_login_error_message_is_neutral() {
        Functions\when( '__' )->alias( function( $text ) {
            return $text;
        } );

        $message = wldelay_get_generic_login_error_message();

        $this->assertIsString( $message );
        $this->assertNotEmpty( $message );
        $this->assertStringNotContainsStringIgnoringCase( 'username', $message );
        $this->assertStringNotContainsStringIgnoringCase( 'password', $message );
    }
}
