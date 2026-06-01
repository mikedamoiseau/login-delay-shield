<?php
/**
 * Unit tests for the slow-test reporter's pure threshold/formatting logic (F-4-7).
 *
 * The reporter is a PHPUnit AfterTestHook, but its decision and formatting
 * logic is exposed as pure static methods so it can be asserted here without a
 * real PHPUnit run. These cover the threshold boundary (exactly at, just under,
 * just over), env-override resolution, and summary formatting (empty vs
 * populated, ordering).
 */

use LoginDelayShield\Tests\Support\WLDelay_Slow_Test_Reporter as Reporter;

class SlowTestReporterTest extends LDS_Unit_Test_Case {

	public function test_exactly_at_threshold_is_not_slow() {
		$this->assertFalse( Reporter::is_slow( 1.0, 1.0 ) );
	}

	public function test_just_under_threshold_is_not_slow() {
		$this->assertFalse( Reporter::is_slow( 0.999, 1.0 ) );
	}

	public function test_just_over_threshold_is_slow() {
		$this->assertTrue( Reporter::is_slow( 1.001, 1.0 ) );
	}

	public function test_resolve_threshold_falls_back_when_missing() {
		$this->assertSame( Reporter::DEFAULT_THRESHOLD, Reporter::resolve_threshold( false ) );
		$this->assertSame( Reporter::DEFAULT_THRESHOLD, Reporter::resolve_threshold( null ) );
		$this->assertSame( Reporter::DEFAULT_THRESHOLD, Reporter::resolve_threshold( '' ) );
		$this->assertSame( Reporter::DEFAULT_THRESHOLD, Reporter::resolve_threshold( '  ' ) );
	}

	public function test_resolve_threshold_falls_back_when_non_numeric() {
		$this->assertSame( Reporter::DEFAULT_THRESHOLD, Reporter::resolve_threshold( 'slow' ) );
	}

	public function test_resolve_threshold_falls_back_when_not_positive() {
		$this->assertSame( Reporter::DEFAULT_THRESHOLD, Reporter::resolve_threshold( '0' ) );
		$this->assertSame( Reporter::DEFAULT_THRESHOLD, Reporter::resolve_threshold( '-2.5' ) );
	}

	public function test_resolve_threshold_accepts_positive_numeric() {
		$this->assertSame( 2.5, Reporter::resolve_threshold( '2.5' ) );
		$this->assertSame( 0.25, Reporter::resolve_threshold( '0.25' ) );
	}

	public function test_format_summary_empty_when_no_runtimes() {
		$out = Reporter::format_summary( array(), 1.0 );

		$this->assertStringContainsString( 'No slow tests', $out );
		$this->assertStringContainsString( '1.000', $out );
		$this->assertStringNotContainsString( 'SLOW TESTS', $out );
	}

	public function test_format_summary_empty_when_all_under_threshold() {
		$out = Reporter::format_summary(
			array(
				'Foo::test_a' => 0.1,
				'Bar::test_b' => 1.0, // exactly at threshold -> not slow.
			),
			1.0
		);

		$this->assertStringContainsString( 'No slow tests', $out );
		$this->assertStringNotContainsString( 'Foo::test_a', $out );
		$this->assertStringNotContainsString( 'Bar::test_b', $out );
	}

	public function test_format_summary_lists_only_slow_tests_slowest_first() {
		$out = Reporter::format_summary(
			array(
				'Fast::test'   => 0.2,
				'Slow::test'   => 1.5,
				'Slower::test' => 3.0,
			),
			1.0
		);

		$this->assertStringContainsString( 'SLOW TESTS (> 1.000s):', $out );
		$this->assertStringContainsString( 'Slow::test', $out );
		$this->assertStringContainsString( 'Slower::test', $out );
		$this->assertStringNotContainsString( 'Fast::test', $out );

		// Slowest test must be listed before the less-slow one.
		$this->assertLessThan(
			strpos( $out, 'Slow::test' ),
			strpos( $out, 'Slower::test' ),
			'Summary should be ordered slowest-first.'
		);
	}

	public function test_format_seconds_is_locale_independent_three_decimals() {
		$this->assertSame( '1.500', Reporter::format_seconds( 1.5 ) );
		$this->assertSame( '0.001', Reporter::format_seconds( 0.001 ) );
	}
}
