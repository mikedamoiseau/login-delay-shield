<?php
/**
 * Unit tests for the settings coherence validator (F-1-3).
 *
 * The validator is a pure file-level function: wldelay_settings_coherence_warnings().
 * Each test mutates exactly one setting into a contradictory state and verifies
 * that precisely one warning is returned with the expected keyword.
 */

use Brain\Monkey\Functions;

class CoherenceValidatorTest extends LDS_Unit_Test_Case {

    protected function setUp(): void {
        parent::setUp();

        // Pass translation wrappers through unchanged.
        Functions\when( '__' )->alias( function ( $text ) { return $text; } );

        // Stub WordPress functions called by wldelay_fail2ban helpers so the
        // path-resolution logic works without a real WP runtime.
        //
        // NOTE: do NOT stub wp_upload_dir here. The coherence-validator's
        // fail2ban tests use paths that short-circuit before
        // wldelay_fail2ban_get_uploads_basedir() is ever reached:
        //   - '/etc/passwd' fails the .log extension check and returns '' early.
        //   - '' (empty) resolves via WP_CONTENT_DIR without touching wp_upload_dir.
        // Stubbing wp_upload_dir via Functions\when() would register the function
        // with Brain Monkey's intercept layer; after tearDown, any subsequent test
        // that calls wp_upload_dir without re-stubbing it would receive a
        // MissingFunctionExpectations error — poisoning Fail2BanTest and others.
        //
        // get_option is called by wldelay_fail2ban_get_default_dir_token().
        Functions\when( 'get_option' )->justReturn( false );
        // apply_filters is called by wldelay_fail2ban_get_allowed_log_dirs().
        Functions\when( 'apply_filters' )->alias( function ( $tag, $value ) { return $value; } );
    }

    /**
     * Coherent baseline: every rule's guard is satisfied (no warnings expected).
     *
     * @return array
     */
    private function clean_options() {
        return array(
            'wldelay_fail2ban_enabled'    => false,
            'wldelay_fail2ban_log_path'   => '',
            'wldelay_whitelist_enabled'   => true,
            'wldelay_whitelist_ips'       => '203.0.113.0/24',
            'wldelay_xmlrpc_enabled'      => false,
            'wldelay_xmlrpc_block'        => false,
            'wldelay_progressive_enabled' => true,
            'wldelay_delay'               => 3,
            'wldelay_progressive_max'     => 30,
            'wldelay_email_enabled'       => true,
            'wldelay_email_threshold'     => 3,
            'wldelay_lockout_enabled'     => true,
            'wldelay_lockout_threshold'   => 5,
            'wldelay_botnet_enabled'      => true,
        );
    }

    // =========================================================================
    // Baseline: clean config → no warnings
    // =========================================================================

    /**
     * A coherent configuration produces zero warnings.
     */
    public function test_clean_config_produces_no_warnings() {
        $this->assertSame( array(), wldelay_settings_coherence_warnings( $this->clean_options() ) );
    }

    // =========================================================================
    // Rule: whitelist enabled + empty list
    // =========================================================================

    /**
     * Whitelist on but no IP entries → warning containing 'whitelist'.
     */
    public function test_warns_whitelist_enabled_with_no_entries() {
        $o = array_merge( $this->clean_options(), array( 'wldelay_whitelist_ips' => '  ' ) );
        $w = wldelay_settings_coherence_warnings( $o );
        $this->assertCount( 1, $w );
        $this->assertStringContainsString( 'whitelist', $w[0] );
    }

    /**
     * Whitelist disabled + empty IPs → no warning (guard not met).
     */
    public function test_no_warning_when_whitelist_disabled_with_no_entries() {
        $o = array_merge( $this->clean_options(), array(
            'wldelay_whitelist_enabled' => false,
            'wldelay_whitelist_ips'     => '',
        ) );
        $this->assertSame( array(), wldelay_settings_coherence_warnings( $o ) );
    }

    // =========================================================================
    // Rule: email threshold above lockout threshold
    // =========================================================================

    /**
     * Email threshold above lockout threshold → warning containing 'never be sent'.
     */
    public function test_warns_email_threshold_above_lockout_threshold() {
        $o = array_merge( $this->clean_options(), array( 'wldelay_email_threshold' => 9 ) );
        $w = wldelay_settings_coherence_warnings( $o );
        $this->assertCount( 1, $w );
        $this->assertStringContainsString( 'never be sent', $w[0] );
    }

    /**
     * Email threshold equal to lockout threshold → no warning (not above).
     */
    public function test_no_warning_when_email_threshold_equals_lockout_threshold() {
        $o = array_merge( $this->clean_options(), array(
            'wldelay_email_threshold'   => 5,
            'wldelay_lockout_threshold' => 5,
        ) );
        $this->assertSame( array(), wldelay_settings_coherence_warnings( $o ) );
    }

    /**
     * Email threshold above lockout but lockout disabled → no warning (guard not met).
     */
    public function test_no_warning_when_lockout_disabled_even_if_thresholds_inverted() {
        $o = array_merge( $this->clean_options(), array(
            'wldelay_email_threshold'  => 9,
            'wldelay_lockout_enabled'  => false,
        ) );
        $this->assertSame( array(), wldelay_settings_coherence_warnings( $o ) );
    }

    // =========================================================================
    // Rule: fail2ban enabled + unresolvable/unwritable path
    //
    // wldelay_fail2ban_resolve_log_path() is a user-defined function loaded
    // before Patchwork's code transformer; Brain Monkey cannot stub it.
    // PHP native filesystem functions (is_dir, is_writable) cannot be stubbed
    // by Patchwork in this suite even with redefinable-internals, because the
    // code transformer has no opportunity to rewrite calls already compiled.
    //
    // Unit tests therefore cover only the observable branches that DON'T rely
    // on native filesystem stubs:
    //
    //   a) Stored log_path value that resolve_log_path() will reject (not in the
    //      allowed-dirs list) → returns '' → rule fires.  ← covered here
    //
    //   b) Default path ('' → allowed) with the log dir NOT YET created on disk
    //      → is_dir() returns false natively → condition false → no warning. ← covered here
    //
    // The "dir exists but not writable" branch is NOT separately tested: it
    // produces the identical warning as branch (a), and reliably forcing an
    // unwritable dir in the Docker test environment (which often runs as root,
    // where file-mode permissions are ignored) is not dependable. The rule's
    // observable behavior is fully covered by (a).
    // =========================================================================

    /**
     * fail2ban on + stored log_path that resolve_log_path rejects (not in allowed dirs)
     * → resolve_log_path returns '' → warning containing 'fail2ban'.
     */
    public function test_warns_fail2ban_enabled_with_disallowed_log_path() {
        $o = array_merge( $this->clean_options(), array(
            'wldelay_fail2ban_enabled'  => true,
            // An absolute path outside the allowed-dirs list is always rejected.
            'wldelay_fail2ban_log_path' => '/etc/passwd',
        ) );
        $w = wldelay_settings_coherence_warnings( $o );
        $this->assertCount( 1, $w );
        $this->assertStringContainsString( 'fail2ban', $w[0] );
    }

    /**
     * fail2ban on + default path (resolves to a non-empty path) + log dir does not
     * yet exist on disk (is_dir returns false natively) → no warning from the
     * is_dir+is_writable branch, and path is non-empty → no warning at all.
     */
    public function test_no_warning_when_fail2ban_enabled_and_default_path_used_and_dir_absent() {
        $o = array_merge( $this->clean_options(), array(
            'wldelay_fail2ban_enabled'  => true,
            'wldelay_fail2ban_log_path' => '',
        ) );
        // The default resolved path dir does not exist in the test container
        // → is_dir() returns false → the unwritable-dir branch doesn't fire.
        $this->assertSame( array(), wldelay_settings_coherence_warnings( $o ) );
    }

    /**
     * fail2ban disabled → rule skipped entirely.
     */
    public function test_no_warning_when_fail2ban_disabled() {
        $o = array_merge( $this->clean_options(), array( 'wldelay_fail2ban_enabled' => false ) );
        $this->assertSame( array(), wldelay_settings_coherence_warnings( $o ) );
    }

    // =========================================================================
    // Rule: xmlrpc_block + xmlrpc_enabled both true
    // =========================================================================

    /**
     * XML-RPC fully blocked AND delay enabled → warning containing 'XML-RPC'.
     */
    public function test_warns_xmlrpc_block_and_enabled_both_true() {
        $o = array_merge( $this->clean_options(), array(
            'wldelay_xmlrpc_enabled' => true,
            'wldelay_xmlrpc_block'   => true,
        ) );
        $w = wldelay_settings_coherence_warnings( $o );
        $this->assertCount( 1, $w );
        $this->assertStringContainsString( 'XML-RPC', $w[0] );
    }

    /**
     * XML-RPC blocked but delay disabled → no warning (delay setting irrelevant).
     */
    public function test_no_warning_when_xmlrpc_block_true_but_delay_disabled() {
        $o = array_merge( $this->clean_options(), array(
            'wldelay_xmlrpc_enabled' => false,
            'wldelay_xmlrpc_block'   => true,
        ) );
        $this->assertSame( array(), wldelay_settings_coherence_warnings( $o ) );
    }

    // =========================================================================
    // Rule: progressive max < base delay
    // =========================================================================

    /**
     * Progressive max below base delay → warning containing 'progressive'.
     */
    public function test_warns_progressive_max_below_base_delay() {
        $o = array_merge( $this->clean_options(), array(
            'wldelay_delay'           => 3,
            'wldelay_progressive_max' => 2,
        ) );
        $w = wldelay_settings_coherence_warnings( $o );
        $this->assertCount( 1, $w );
        $this->assertStringContainsString( 'progressive', $w[0] );
    }

    /**
     * Progressive max equal to base delay → no warning (equal is fine).
     */
    public function test_no_warning_when_progressive_max_equals_base_delay() {
        $o = array_merge( $this->clean_options(), array(
            'wldelay_delay'           => 3,
            'wldelay_progressive_max' => 3,
        ) );
        $this->assertSame( array(), wldelay_settings_coherence_warnings( $o ) );
    }

    /**
     * Progressive disabled + max below base → no warning (guard not met).
     */
    public function test_no_warning_when_progressive_disabled_even_if_max_below_base() {
        $o = array_merge( $this->clean_options(), array(
            'wldelay_progressive_enabled' => false,
            'wldelay_delay'               => 10,
            'wldelay_progressive_max'     => 2,
        ) );
        $this->assertSame( array(), wldelay_settings_coherence_warnings( $o ) );
    }

    // =========================================================================
    // Rule: botnet on + email alerts off
    // =========================================================================

    /**
     * Botnet detection on but email disabled → warning containing 'dashboard only'.
     */
    public function test_warns_botnet_enabled_with_email_disabled() {
        $o = array_merge( $this->clean_options(), array( 'wldelay_email_enabled' => false ) );
        $w = wldelay_settings_coherence_warnings( $o );
        $this->assertCount( 1, $w );
        $this->assertStringContainsString( 'dashboard only', $w[0] );
    }

    /**
     * Botnet disabled + email off → no warning (guard not met).
     */
    public function test_no_warning_when_botnet_disabled_even_if_email_off() {
        $o = array_merge( $this->clean_options(), array(
            'wldelay_botnet_enabled' => false,
            'wldelay_email_enabled'  => false,
        ) );
        $this->assertSame( array(), wldelay_settings_coherence_warnings( $o ) );
    }
}
