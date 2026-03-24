<?php
/**
 * Integration tests for username normalization helpers.
 */

class UsernameNormalizationTest extends WP_UnitTestCase {

    /**
     * Test normalized usernames are unslashed before sanitization.
     */
    public function test_normalize_username_unslashes_before_sanitizing() {
        $this->assertSame( 'oconnor admin', wldelay_normalize_username( "O\\'Connor Admin" ) );
    }

    /**
     * Test requested login username is normalized consistently.
     */
    public function test_requested_login_username_is_unslashed_and_normalized() {
        $_POST['log'] = "Mike\\'s Admin";

        $this->assertSame( 'mikes admin', wldelay_get_requested_login_username() );

        unset( $_POST['log'] );
    }
}
