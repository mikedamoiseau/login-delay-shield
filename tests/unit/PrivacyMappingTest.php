<?php
/**
 * Unit tests for the pure privacy helpers (F-3-1): the row→export-item mapping
 * and the email→login resolution. No WordPress runtime — Brain Monkey stubs the
 * handful of WP functions the helpers touch.
 *
 * @package login-delay-shield
 */

use Brain\Monkey\Functions;

class PrivacyMappingTest extends LDS_Unit_Test_Case {

    protected function setUp(): void {
        parent::setUp();

        // Translation wrappers pass the string through unchanged.
        Functions\when( '__' )->alias( function ( $text ) {
            return $text;
        } );
    }

    public function test_login_log_row_to_data_maps_all_columns() {
        $row = array(
            'ip_address'   => '203.0.113.7',
            'username'     => 'alice',
            'attempted_at' => '2026-06-01 12:00:00',
            'source'       => 'wp-login',
        );

        $data = wldelay_privacy_login_log_row_to_data( $row );

        $values = wp_list_pluck_assoc( $data );

        $this->assertSame( '203.0.113.7', $values['IP address'] );
        $this->assertSame( 'alice', $values['Username'] );
        $this->assertSame( '2026-06-01 12:00:00', $values['Attempted at'] );
        $this->assertSame( 'wp-login', $values['Source'] );
    }

    public function test_login_log_row_to_data_accepts_objects_and_missing_keys() {
        $row = (object) array( 'ip_address' => '203.0.113.7' );

        $data   = wldelay_privacy_login_log_row_to_data( $row );
        $values = wp_list_pluck_assoc( $data );

        $this->assertSame( '203.0.113.7', $values['IP address'] );
        // Missing columns degrade to empty strings rather than notices.
        $this->assertSame( '', $values['Username'] );
        $this->assertSame( '', $values['Source'] );
    }

    public function test_audit_log_row_to_data_maps_action_and_ip() {
        $row = array(
            'action'     => 'settings_changed',
            'object'     => 'wldelay_lockout_enabled',
            'ip_address' => '198.51.100.4',
            'created_at' => '2026-06-02 09:30:00',
        );

        $values = wp_list_pluck_assoc( wldelay_privacy_audit_log_row_to_data( $row ) );

        $this->assertSame( 'settings_changed', $values['Action'] );
        $this->assertSame( 'wldelay_lockout_enabled', $values['Object'] );
        $this->assertSame( '198.51.100.4', $values['IP address'] );
        $this->assertSame( '2026-06-02 09:30:00', $values['Recorded at'] );
    }

    public function test_lockout_row_to_data_formats_expiry_timestamp() {
        $expires = 1893456000; // Fixed UNIX timestamp.
        $row     = array(
            'ip_address'   => '192.0.2.10',
            'lockout_type' => 'login',
            'expires_at'   => $expires,
        );

        $values = wp_list_pluck_assoc( wldelay_privacy_lockout_row_to_data( $row ) );

        $this->assertSame( '192.0.2.10', $values['IP address'] );
        $this->assertSame( 'login', $values['Lockout type'] );
        $this->assertSame( gmdate( 'Y-m-d H:i:s', $expires ), $values['Expires at'] );
    }

    public function test_resolve_login_returns_user_login_for_known_email() {
        Functions\when( 'get_user_by' )->alias( function ( $field, $value ) {
            $this->assertSame( 'email', $field );
            $this->assertSame( 'alice@example.com', $value );

            return (object) array( 'user_login' => 'alice' );
        } );

        $this->assertSame(
            'alice',
            wldelay_privacy_resolve_login_from_email( 'alice@example.com' )
        );
    }

    public function test_resolve_login_returns_empty_for_unknown_email() {
        Functions\when( 'get_user_by' )->justReturn( false );

        $this->assertSame( '', wldelay_privacy_resolve_login_from_email( 'nobody@example.com' ) );
    }

    public function test_resolve_login_returns_empty_for_blank_email() {
        // No get_user_by stub needed: a blank email short-circuits before the call.
        $this->assertSame( '', wldelay_privacy_resolve_login_from_email( '' ) );
    }
}

/**
 * Helper: collapse a list of { name, value } items into a name => value map.
 *
 * Declared at file scope (not a method) so it stays a plain function the test
 * methods can call without $this gymnastics.
 *
 * @param array $items Exporter data items.
 * @return array<string,mixed>
 */
function wp_list_pluck_assoc( array $items ) {
    $out = array();
    foreach ( $items as $item ) {
        $out[ $item['name'] ] = $item['value'];
    }

    return $out;
}
