<?php
/**
 * Integration tests for the settings migration registry (F-2-6).
 *
 * Exercises WLDelay_Migration::run() against the real get_option()/update_option()
 * so the version tracking, ordering, idempotency, and fresh-install fast path are
 * verified end to end rather than mocked.
 */

class MigrationTest extends WP_UnitTestCase {

    /**
     * Start every test from a clean slate: no stored options and no recorded
     * settings version, so each scenario controls the starting state itself.
     */
    public function setUp(): void {
        parent::setUp();
        delete_option( WLDELAY_OPTION_NAME );
        delete_option( WLDELAY_SETTINGS_VERSION_OPTION );
        wldelay_clear_options_cache();
    }

    /**
     * A behind install runs the registered steps in order and ends stamped at
     * the latest settings version.
     */
    public function test_behind_install_runs_steps_and_advances_to_latest() {
        // Existing install with stored options but no recorded version (= 0).
        update_option( WLDELAY_OPTION_NAME, array( 'wldelay_delay' => 5 ) );
        $this->assertSame( 0, WLDelay_Migration::stored_version() );

        $ran = WLDelay_Migration::run();

        $this->assertTrue( $ran, 'A behind install should report that a migration ran.' );
        $this->assertSame(
            WLDELAY_SETTINGS_VERSION,
            WLDelay_Migration::stored_version(),
            'After running, the stored version should equal the latest.'
        );
    }

    /**
     * Running the migration twice is idempotent: the second invocation is a
     * cheap no-op that neither rewrites options nor re-stamps the version.
     */
    public function test_running_twice_is_idempotent() {
        update_option( WLDELAY_OPTION_NAME, array( 'wldelay_delay' => 5 ) );

        $first  = WLDelay_Migration::run();
        $second = WLDelay_Migration::run();

        $this->assertTrue( $first, 'First run should migrate.' );
        $this->assertFalse( $second, 'Second run should be a no-op once current.' );
        $this->assertSame( WLDELAY_SETTINGS_VERSION, WLDelay_Migration::stored_version() );
    }

    /**
     * The v1 step backfills every default key missing from an existing install
     * while preserving the user's already-set values.
     */
    public function test_v1_backfills_missing_default_keys() {
        // Existing install that predates most keys; one key is user-customised.
        update_option( WLDELAY_OPTION_NAME, array( 'wldelay_delay' => 7 ) );

        WLDelay_Migration::run();

        $options  = get_option( WLDELAY_OPTION_NAME );
        $defaults = WLDelay_Features::defaults();

        // The user's value is preserved, not overwritten by the default.
        $this->assertSame( 7, $options['wldelay_delay'] );

        // Every other default key is now present with its default value.
        foreach ( $defaults as $key => $default ) {
            $this->assertArrayHasKey(
                $key,
                $options,
                "Migration should backfill missing key {$key}."
            );
        }
        $this->assertSame(
            $defaults['wldelay_lockout_threshold'],
            $options['wldelay_lockout_threshold'],
            'A previously-absent key should be seeded with its registry default.'
        );
    }

    /**
     * A fresh install (no stored options, no version) jumps straight to the
     * latest version and does NOT fabricate a stored options array — it has
     * nothing to migrate, and wldelay_get_options() materialises defaults on read.
     */
    public function test_fresh_install_jumps_to_latest_without_corrupting_options() {
        $this->assertFalse( get_option( WLDELAY_OPTION_NAME, false ) );
        $this->assertFalse( get_option( WLDELAY_SETTINGS_VERSION_OPTION, false ) );

        $ran = WLDelay_Migration::run();

        $this->assertFalse( $ran, 'A fresh install should report no migration work.' );
        $this->assertSame(
            WLDELAY_SETTINGS_VERSION,
            WLDelay_Migration::stored_version(),
            'A fresh install should be stamped at the latest version.'
        );
        $this->assertFalse(
            get_option( WLDELAY_OPTION_NAME, false ),
            'A fresh install should not have a stored options array written by the runner.'
        );
    }
}
