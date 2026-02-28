<?php
/**
 * Integration tests for CSV export endpoint.
 */

if ( ! class_exists( 'WLD_WPDieException' ) ) {
    class WLD_WPDieException extends Exception {}
}

class ExportCsvTest extends WP_UnitTestCase {

    /**
     * @var array
     */
    private $old_request = array();

    /**
     * @var array
     */
    private $old_get = array();

    public function setUp(): void {
        parent::setUp();

        wldelay_create_log_table();

        $this->old_request = $_REQUEST;
        $this->old_get     = $_GET;

        global $wpdb;
        $table_name = wldelay_get_log_table_name();
        $wpdb->query( "TRUNCATE TABLE $table_name" );
    }

    public function tearDown(): void {
        $_REQUEST = $this->old_request;
        $_GET     = $this->old_get;

        remove_all_filters( 'wldelay_export_login_log_should_exit' );
        remove_all_filters( 'wp_die_handler' );

        parent::tearDown();
    }

    public function test_export_endpoint_action_registered() {
        $this->assertNotFalse(
            has_action( 'admin_post_wldelay_export_login_log', 'wldelay_handle_export_login_log' ),
            'wldelay_handle_export_login_log should be hooked to admin_post_wldelay_export_login_log'
        );
    }

    public function test_export_csv_outputs_expected_columns_and_rows() {
        global $wpdb;
        $table_name = wldelay_get_log_table_name();

        $wpdb->insert( $table_name, array(
            'ip_address'   => '192.168.1.10',
            'username'     => 'alice',
            'attempted_at' => '2025-01-01 10:00:00',
            'source'       => 'wp-login',
        ) );
        $wpdb->insert( $table_name, array(
            'ip_address'   => '192.168.1.11',
            'username'     => 'bob',
            'attempted_at' => '2025-01-01 11:00:00',
            'source'       => 'xmlrpc',
        ) );

        $admin_id = $this->factory->user->create( array( 'role' => 'administrator' ) );
        wp_set_current_user( $admin_id );

        $nonce = wp_create_nonce( 'wldelay_export_login_log' );
        $_GET['_wpnonce'] = $nonce;
        $_REQUEST['_wpnonce'] = $nonce;

        add_filter( 'wldelay_export_login_log_should_exit', '__return_false' );

        ob_start();
        do_action( 'admin_post_wldelay_export_login_log' );
        $csv = ob_get_clean();

        $this->assertNotEmpty( $csv );

        $lines = preg_split( "/\\r\\n|\\n|\\r/", trim( $csv ) );
        $this->assertGreaterThanOrEqual( 3, count( $lines ) );

        $header = str_getcsv( $lines[0] );
        $this->assertSame( array( 'source', 'ip', 'username', 'timestamp' ), $header );

        $row1 = str_getcsv( $lines[1] );
        $row2 = str_getcsv( $lines[2] );

        // Export is ordered by attempted_at DESC; bob should be first.
        $this->assertSame( 'xmlrpc', $row1[0] );
        $this->assertSame( '192.168.1.11', $row1[1] );
        $this->assertSame( 'bob', $row1[2] );
        $this->assertSame( '2025-01-01 11:00:00', $row1[3] );

        $this->assertSame( 'wp-login', $row2[0] );
        $this->assertSame( '192.168.1.10', $row2[1] );
        $this->assertSame( 'alice', $row2[2] );
        $this->assertSame( '2025-01-01 10:00:00', $row2[3] );
    }

    public function test_export_csv_sanitizes_leading_space_formula_payload() {
        global $wpdb;
        $table_name = wldelay_get_log_table_name();

        $payload = ' =1+1';

        $wpdb->insert( $table_name, array(
            'ip_address'   => '192.168.1.12',
            'username'     => $payload,
            'attempted_at' => '2025-01-01 12:00:00',
            'source'       => 'wp-login',
        ) );

        $admin_id = $this->factory->user->create( array( 'role' => 'administrator' ) );
        wp_set_current_user( $admin_id );

        $nonce = wp_create_nonce( 'wldelay_export_login_log' );
        $_GET['_wpnonce']     = $nonce;
        $_REQUEST['_wpnonce'] = $nonce;

        add_filter( 'wldelay_export_login_log_should_exit', '__return_false' );

        ob_start();
        do_action( 'admin_post_wldelay_export_login_log' );
        $csv = ob_get_clean();

        $lines = preg_split( "/\\r\\n|\\n|\\r/", trim( $csv ) );
        $row   = str_getcsv( $lines[1] );

        $this->assertSame( "'" . $payload, $row[2] );
    }

    public function test_export_csv_sanitizes_leading_tab_formula_payload() {
        global $wpdb;
        $table_name = wldelay_get_log_table_name();

        $payload = "\t=1+1";

        $wpdb->insert( $table_name, array(
            'ip_address'   => '192.168.1.13',
            'username'     => $payload,
            'attempted_at' => '2025-01-01 12:01:00',
            'source'       => 'wp-login',
        ) );

        $admin_id = $this->factory->user->create( array( 'role' => 'administrator' ) );
        wp_set_current_user( $admin_id );

        $nonce = wp_create_nonce( 'wldelay_export_login_log' );
        $_GET['_wpnonce']     = $nonce;
        $_REQUEST['_wpnonce'] = $nonce;

        add_filter( 'wldelay_export_login_log_should_exit', '__return_false' );

        ob_start();
        do_action( 'admin_post_wldelay_export_login_log' );
        $csv = ob_get_clean();

        $lines = preg_split( "/\\r\\n|\\n|\\r/", trim( $csv ) );
        $row   = str_getcsv( $lines[1] );

        $this->assertSame( "'" . $payload, $row[2] );
    }

    public function test_export_csv_requires_manage_options() {
        $user_id = $this->factory->user->create( array( 'role' => 'subscriber' ) );
        wp_set_current_user( $user_id );

        $nonce = wp_create_nonce( 'wldelay_export_login_log' );
        $_GET['_wpnonce'] = $nonce;
        $_REQUEST['_wpnonce'] = $nonce;

        add_filter( 'wp_die_handler', array( __CLASS__, 'filter_wp_die_handler' ) );

        $this->expectException( WLD_WPDieException::class );
        do_action( 'admin_post_wldelay_export_login_log' );
    }

    public function test_export_csv_requires_nonce() {
        $admin_id = $this->factory->user->create( array( 'role' => 'administrator' ) );
        wp_set_current_user( $admin_id );

        unset( $_GET['_wpnonce'], $_REQUEST['_wpnonce'] );

        add_filter( 'wp_die_handler', array( __CLASS__, 'filter_wp_die_handler' ) );

        $this->expectException( WLD_WPDieException::class );
        do_action( 'admin_post_wldelay_export_login_log' );
    }

    public static function filter_wp_die_handler( $handler ) {
        return array( __CLASS__, 'throw_wp_die' );
    }

    public static function throw_wp_die( $message, $title = '', $args = array() ) {
        if ( is_wp_error( $message ) ) {
            $message = $message->get_error_message();
        } elseif ( is_array( $message ) ) {
            $message = implode( ' ', $message );
        }

        throw new WLD_WPDieException( (string) $message );
    }
}
