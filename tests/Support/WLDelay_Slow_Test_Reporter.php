<?php declare(strict_types=1);
/**
 * PHPUnit 9.6 AfterTestHook extension that tracks per-test runtimes and prints
 * a "SLOW TESTS" summary at the end of a run (F-4-7).
 *
 * Why: surfaces slow/flaky tests so they don't quietly creep into CI runtime.
 * It is a companion to the `enforceTimeLimit` / `defaultTimeLimit` settings in
 * the phpunit configs (the hard backstop that aborts a hung test); this hook is
 * the soft signal that flags tests which are merely slow.
 *
 * The decision/format logic is exposed as pure static methods (`is_slow`,
 * `format_summary`, `resolve_threshold`) so it can be unit-tested without a
 * real PHPUnit run.
 *
 * This file is test-infra only and is excluded from the wordpress.org package.
 */

namespace LoginDelayShield\Tests\Support;

use PHPUnit\Runner\AfterLastTestHook;
use PHPUnit\Runner\AfterTestHook;

if ( ! \defined( 'ABSPATH' ) ) {
	// Allow inclusion from the integration bootstrap without tripping any
	// `defined( 'ABSPATH' ) || exit;` guard style checks elsewhere.
	\define( 'ABSPATH', \sys_get_temp_dir() . '/wordpress/' );
}

/**
 * Records each test's runtime and reports the slow ones.
 */
final class WLDelay_Slow_Test_Reporter implements AfterTestHook, AfterLastTestHook {

	/**
	 * Default slow-test threshold in seconds.
	 */
	public const DEFAULT_THRESHOLD = 1.0;

	/**
	 * Environment variable used to override the threshold.
	 */
	public const THRESHOLD_ENV = 'WLDELAY_SLOW_TEST_THRESHOLD';

	/**
	 * Collected runtimes keyed by test identifier.
	 *
	 * @var array<string, float>
	 */
	private $runtimes = array();

	/**
	 * AfterTestHook: capture the runtime of each finished test.
	 *
	 * @param string $test PHPUnit test identifier (e.g. "Class::method").
	 * @param float  $time Wall-clock seconds the test took.
	 */
	public function executeAfterTest( string $test, float $time ): void {
		$this->runtimes[ $test ] = $time;
	}

	/**
	 * AfterLastTestHook: emit the slow-test summary to STDERR.
	 */
	public function executeAfterLastTest(): void {
		$threshold = self::resolve_threshold( \getenv( self::THRESHOLD_ENV ) );
		$summary   = self::format_summary( $this->runtimes, $threshold );

		\fwrite( \STDERR, "\n" . $summary . "\n" );
	}

	/**
	 * Pure predicate: is a runtime slow relative to the threshold?
	 *
	 * Boundary rule: a runtime exactly equal to the threshold is NOT slow;
	 * only strictly greater runtimes are flagged.
	 *
	 * @param float $seconds   Measured runtime.
	 * @param float $threshold Slow-test threshold.
	 * @return bool True when $seconds is strictly greater than $threshold.
	 */
	public static function is_slow( float $seconds, float $threshold ): bool {
		return $seconds > $threshold;
	}

	/**
	 * Resolve the effective threshold from a raw (env) value.
	 *
	 * Falls back to DEFAULT_THRESHOLD when the input is missing, non-numeric,
	 * or not strictly positive.
	 *
	 * @param string|false|null $raw Raw value, typically from getenv().
	 * @return float Effective threshold in seconds.
	 */
	public static function resolve_threshold( $raw ): float {
		if ( ! \is_string( $raw ) || '' === \trim( $raw ) || ! \is_numeric( $raw ) ) {
			return self::DEFAULT_THRESHOLD;
		}

		$value = (float) $raw;

		return $value > 0.0 ? $value : self::DEFAULT_THRESHOLD;
	}

	/**
	 * Pure formatter: build the slow-test summary text.
	 *
	 * @param array<string, float> $runtimes  Map of test id => seconds.
	 * @param float                $threshold Slow-test threshold.
	 * @return string Human-readable summary (no trailing newline).
	 */
	public static function format_summary( array $runtimes, float $threshold ): string {
		$slow = array();
		foreach ( $runtimes as $test => $seconds ) {
			if ( self::is_slow( (float) $seconds, $threshold ) ) {
				$slow[ $test ] = (float) $seconds;
			}
		}

		if ( empty( $slow ) ) {
			return \sprintf( 'No slow tests (> %ss).', self::format_seconds( $threshold ) );
		}

		// Slowest first.
		\arsort( $slow, \SORT_NUMERIC );

		$lines   = array();
		$lines[] = \sprintf( 'SLOW TESTS (> %ss):', self::format_seconds( $threshold ) );
		foreach ( $slow as $test => $seconds ) {
			$lines[] = \sprintf( '  %8ss  %s', self::format_seconds( $seconds ), $test );
		}

		return \implode( "\n", $lines );
	}

	/**
	 * Format a duration with a stable, locale-independent representation.
	 *
	 * @param float $seconds Duration in seconds.
	 * @return string Seconds rendered to 3 decimal places.
	 */
	public static function format_seconds( float $seconds ): string {
		return \number_format( $seconds, 3, '.', '' );
	}
}
