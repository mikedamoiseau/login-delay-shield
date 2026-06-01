<?php
/**
 * Ordered, versioned settings migration registry (F-2-6).
 *
 * This is OPTIONS migration, deliberately distinct from the DB schema migration
 * handled by wldelay_maybe_upgrade_db() / wldelay_create_tables(). Schema
 * migration evolves custom tables via dbDelta; this registry transforms the
 * stored wldelay_options array — backfilling new keys, renaming/retyping
 * values, or seeding defaults into installs that predate a feature.
 *
 * The version is tracked in its own option, wldelay_settings_version (an
 * integer), separate from wldelay_db_version (schema) and WLDELAY_VERSION (the
 * user-facing plugin version used by the "What's New" banner). Each migration
 * step is keyed by the settings-version integer it produces and is an
 * idempotent callable that receives the current options array and returns the
 * migrated array. The runner applies every step with a key greater than the
 * stored version, in ascending order, persists the result with a single
 * update_option(), then records the latest applied version.
 *
 * Fresh installs are detected (no stored options AND no stored settings
 * version) and jumped straight to the latest version without replaying history,
 * because wldelay_get_options() already materialises the current defaults for a
 * fresh site — there is nothing to backfill.
 *
 * @package login-delay-shield
 */

defined( 'ABSPATH' ) || exit;

/**
 * Latest settings-schema version. Bump this and add a matching step to
 * WLDelay_Migration::steps() whenever the stored options array needs a
 * one-time transformation on existing installs.
 */
define( 'WLDELAY_SETTINGS_VERSION', 1 );

/**
 * Option name tracking the applied settings-migration version. Distinct from
 * 'wldelay_db_version' (schema) and the 'wldelay_plugin_version' banner option.
 */
define( 'WLDELAY_SETTINGS_VERSION_OPTION', 'wldelay_settings_version' );

/**
 * Ordered registry and runner for settings (options-array) migrations.
 *
 * The registry is intentionally free of side effects: steps() returns pure
 * callables and run() owns all the persistence, so the transformation logic is
 * unit-testable in isolation and the runner can be exercised against real
 * get_option()/update_option() in integration tests.
 */
class WLDelay_Migration {

    /**
     * Ordered map of settings-migration steps.
     *
     * Each entry is keyed by the integer settings-version it produces and is a
     * callable( array $options ) : array. Steps MUST be idempotent — they may
     * be re-applied if a later run is interrupted — and must never assume a key
     * is present.
     *
     * @return array<int,callable> Steps keyed by target version, ascending.
     */
    public static function steps() {
        return array(
            // v1: backfill any option key missing from an existing install with
            // its declared default from the M1 feature registry. This makes the
            // declarative defaults actually seed already-installed sites, not
            // just fresh ones. Idempotent: only absent keys are written.
            1 => function ( $options ) {
                foreach ( WLDelay_Features::defaults() as $key => $default ) {
                    if ( ! array_key_exists( $key, $options ) ) {
                        $options[ $key ] = $default;
                    }
                }

                return $options;
            },
        );
    }

    /**
     * Read the stored settings-migration version.
     *
     * @return int Stored version, or 0 when never recorded (fresh / pre-F-2-6).
     */
    public static function stored_version() {
        return (int) get_option( WLDELAY_SETTINGS_VERSION_OPTION, 0 );
    }

    /**
     * Whether the current install is brand new with respect to settings.
     *
     * Fresh = no settings version recorded AND no stored options at all. Such a
     * site has nothing to migrate (wldelay_get_options() materialises current
     * defaults on read), so the runner jumps it straight to the latest version
     * rather than replaying historical steps.
     *
     * @return bool
     */
    private static function is_fresh_install() {
        if ( false !== get_option( WLDELAY_SETTINGS_VERSION_OPTION, false ) ) {
            return false;
        }

        return false === get_option( WLDELAY_OPTION_NAME, false );
    }

    /**
     * Apply every pending settings migration, exactly once, in order.
     *
     * Safe to call on every load: when the stored version already equals the
     * latest, this returns immediately without touching the options array. When
     * behind, it applies each step with key > stored version in ascending
     * order, persists the resulting options array with a single update_option(),
     * clears the options cache, and records the latest applied version.
     *
     * @return bool True when a migration ran and wrote, false on a no-op.
     */
    public static function run() {
        $latest = WLDELAY_SETTINGS_VERSION;
        $stored = self::stored_version();

        // Already current — the common path on every request.
        if ( $stored >= $latest ) {
            return false;
        }

        // A brand-new install has nothing to migrate: stamp it at the latest
        // version so it never replays historical steps.
        if ( self::is_fresh_install() ) {
            update_option( WLDELAY_SETTINGS_VERSION_OPTION, $latest );

            return false;
        }

        $options = get_option( WLDELAY_OPTION_NAME );
        if ( ! is_array( $options ) ) {
            $options = array();
        }

        $steps = self::steps();
        ksort( $steps );

        foreach ( $steps as $version => $step ) {
            if ( $version <= $stored ) {
                continue;
            }

            $options = call_user_func( $step, $options );

            if ( ! is_array( $options ) ) {
                // A misbehaving step must not corrupt the stored options or
                // advance the version — leave the install untouched so the next
                // request retries from the recorded version.
                return false;
            }
        }

        // Persist the fully-migrated array in a single write, then advance the
        // recorded version. Clear the in-request cache so the freshly migrated
        // options are read on the next wldelay_get_options() call this request.
        update_option( WLDELAY_OPTION_NAME, $options );

        if ( function_exists( 'wldelay_clear_options_cache' ) ) {
            wldelay_clear_options_cache();
        }

        update_option( WLDELAY_SETTINGS_VERSION_OPTION, $latest );

        return true;
    }
}
