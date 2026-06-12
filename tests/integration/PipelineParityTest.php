<?php
/**
 * Integration tests for the shared failed-attempt pipeline (F-2-4): event
 * emission and gating. Entry-point parity itself is proven by the existing
 * suites passing unmodified after the conversion.
 */

class PipelineParityTest extends WP_UnitTestCase {
    public function setUp(): void {
        parent::setUp();
        $_SERVER['REMOTE_ADDR'] = '203.0.113.50';
        delete_option( 'wldelay_options' );
        wldelay_clear_options_cache();
    }

    public function tearDown(): void {
        unset( $_SERVER['REMOTE_ADDR'] );
        delete_option( 'wldelay_options' );
        wldelay_clear_options_cache();
        parent::tearDown();
    }

    public function test_failed_attempt_event_fires_on_logged_failure() {
        $captured = array();
        wldelay_on_event( 'failed_attempt', function ( $payload ) use ( &$captured ) {
            $captured[] = $payload;
        } );

        wldelay_process_failed_attempt( 'eventuser', 'rest' );

        $this->assertCount( 1, $captured );
        $this->assertSame( 'eventuser', $captured[0]['username'] );
        $this->assertSame( 'rest', $captured[0]['source'] );
        $this->assertSame( '203.0.113.50', $captured[0]['ip'] );
    }

    public function test_no_event_when_whitelisted() {
        $fired = 0;
        wldelay_on_event( 'failed_attempt', function () use ( &$fired ) {
            $fired++;
        } );
        update_option( 'wldelay_options', array_merge(
            get_option( 'wldelay_options', array() ),
            array(
                'wldelay_whitelist_enabled' => 1,
                'wldelay_whitelist_ips'     => '203.0.113.50',
            )
        ) );
        wldelay_clear_options_cache();

        $r = wldelay_process_failed_attempt( 'eventuser', 'rest' );

        $this->assertFalse( $r['processed'] );
        $this->assertSame( 0, $fired );
    }
}
