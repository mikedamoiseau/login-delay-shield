<?php
/**
 * Unit tests for the audit settings-diff builder (F-2-7).
 *
 * Pure logic — exercises wldelay_build_settings_diff() and its helpers with
 * wp_json_encode stubbed via Brain Monkey.
 */

use Brain\Monkey\Functions;

class AuditDiffTest extends LDS_Unit_Test_Case {

    protected function setUp(): void {
        parent::setUp();

        Functions\when( 'wp_json_encode' )->alias( function ( $value ) {
            return json_encode( $value );
        } );
    }

    /**
     * Only changed keys appear in the diff; unchanged keys are omitted.
     */
    public function test_diff_includes_only_changed_keys() {
        $old = array(
            'wldelay_delay'           => 3,
            'wldelay_lockout_enabled' => true,
        );
        $new = array(
            'wldelay_delay'           => 5,
            'wldelay_lockout_enabled' => true,
        );

        $diff = wldelay_build_settings_diff( $old, $new );

        $this->assertArrayHasKey( 'wldelay_delay', $diff );
        $this->assertArrayNotHasKey( 'wldelay_lockout_enabled', $diff );
        $this->assertSame( 3, $diff['wldelay_delay']['old'] );
        $this->assertSame( 5, $diff['wldelay_delay']['new'] );
    }

    /**
     * Bool<->int toggles register as a change; identical values do not.
     */
    public function test_bool_toggle_registers() {
        $diff = wldelay_build_settings_diff(
            array( 'wldelay_lockout_enabled' => false ),
            array( 'wldelay_lockout_enabled' => true )
        );

        $this->assertArrayHasKey( 'wldelay_lockout_enabled', $diff );
    }

    /**
     * A true/1 representation difference must NOT register as a change.
     */
    public function test_equivalent_bool_int_not_changed() {
        $diff = wldelay_build_settings_diff(
            array( 'wldelay_lockout_enabled' => true ),
            array( 'wldelay_lockout_enabled' => 1 )
        );

        $this->assertArrayNotHasKey( 'wldelay_lockout_enabled', $diff );
    }

    /**
     * Added and removed keys both appear in the diff.
     */
    public function test_added_and_removed_keys() {
        $diff = wldelay_build_settings_diff(
            array( 'removed_key' => 'gone' ),
            array( 'added_key' => 'new' )
        );

        $this->assertArrayHasKey( 'removed_key', $diff );
        $this->assertArrayHasKey( 'added_key', $diff );
        $this->assertNull( $diff['removed_key']['new'] );
        $this->assertNull( $diff['added_key']['old'] );
    }

    /**
     * Token-like values are masked, never written verbatim.
     */
    public function test_secret_values_are_masked() {
        $diff = wldelay_build_settings_diff(
            array( 'wldelay_api_token' => 'old-secret' ),
            array( 'wldelay_api_token' => 'new-secret' )
        );

        $this->assertArrayHasKey( 'wldelay_api_token', $diff );
        $this->assertSame( '***', $diff['wldelay_api_token']['old'] );
        $this->assertSame( '***', $diff['wldelay_api_token']['new'] );
    }

    /**
     * The explicit secret-key allowlist is masked too.
     */
    public function test_known_secret_option_key_masked() {
        $diff = wldelay_build_settings_diff(
            array( 'wldelay_fail2ban_default_token' => 'abc' ),
            array( 'wldelay_fail2ban_default_token' => 'xyz' )
        );

        $this->assertSame( '***', $diff['wldelay_fail2ban_default_token']['new'] );
    }

    /**
     * Whitelist change appears in the diff (covered by settings, not double-logged).
     */
    public function test_whitelist_change_in_diff() {
        $diff = wldelay_build_settings_diff(
            array( 'wldelay_whitelist_ips' => "1.1.1.1" ),
            array( 'wldelay_whitelist_ips' => "1.1.1.1\n2.2.2.2" )
        );

        $this->assertArrayHasKey( 'wldelay_whitelist_ips', $diff );
    }

    /**
     * Array values compare by encoding; identical arrays are unchanged.
     */
    public function test_identical_array_unchanged() {
        $diff = wldelay_build_settings_diff(
            array( 'k' => array( 'a', 'b' ) ),
            array( 'k' => array( 'a', 'b' ) )
        );

        $this->assertArrayNotHasKey( 'k', $diff );
    }
}
