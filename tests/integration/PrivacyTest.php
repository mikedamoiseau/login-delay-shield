<?php
/**
 * Integration tests for the GDPR export & erasure hooks (F-3-1).
 *
 * Exercises the registered WP Privacy Tools exporter and eraser against real
 * plugin tables and the durable lockout store, using WLDelay_Test_Fixture for
 * lockout state so the materialised rows are production-faithful.
 *
 * @package login-delay-shield
 */

class PrivacyTest extends WP_UnitTestCase {

    /**
     * @var int Registered subject user id.
     */
    private $user_id;

    /**
     * @var string Subject login.
     */
    private $login = 'privacy_subject';

    /**
     * @var string Subject email.
     */
    private $email = 'subject@example.com';

    public function setUp(): void {
        parent::setUp();

        WLDelay_Test_Fixture::reset();

        // Ensure plugin tables exist for this test (login log, audit, lockouts).
        wldelay_create_log_table();
        wldelay_create_audit_table();
        wldelay_create_lockout_table();

        $this->user_id = self::factory()->user->create(
            array(
                'user_login' => $this->login,
                'user_email' => $this->email,
            )
        );
    }

    public function tearDown(): void {
        WLDelay_Test_Fixture::reset();
        $this->truncate_plugin_tables();
        parent::tearDown();
    }

    private function truncate_plugin_tables() {
        global $wpdb;
        foreach (
            array(
                wldelay_get_log_table_name(),
                wldelay_get_audit_table_name(),
                wldelay_get_lockout_table_name(),
            ) as $table
        ) {
            $wpdb->query( "DELETE FROM $table" ); // phpcs:ignore WordPress.DB
        }
    }

    /**
     * Insert a login-log row for a username.
     */
    private function seed_login_log( $username, $ip = '203.0.113.9', $source = 'wp-login' ) {
        global $wpdb;
        $wpdb->insert(
            wldelay_get_log_table_name(),
            array(
                'ip_address'   => $ip,
                'username'     => $username,
                'attempted_at' => current_time( 'mysql' ),
                'source'       => $source,
            )
        );
    }

    /**
     * Insert an audit-log row for an actor_login.
     */
    private function seed_audit_log( $actor_login, $action = 'settings_changed' ) {
        wldelay_audit_write_row(
            array(
                'actor_id'    => $this->user_id,
                'actor_login' => $actor_login,
                'action'      => $action,
                'object'      => 'wldelay_lockout_enabled',
                'ip_address'  => '198.51.100.5',
                'created_at'  => current_time( 'mysql', true ),
            )
        );
    }

    // ----------------------------------------------------------------------
    // (d) Registration
    // ----------------------------------------------------------------------

    public function test_exporter_is_registered_on_filter() {
        $exporters = apply_filters( 'wp_privacy_personal_data_exporters', array() );

        $this->assertArrayHasKey( 'login-delay-shield', $exporters );
        $this->assertSame( 'wldelay_privacy_exporter', $exporters['login-delay-shield']['callback'] );
    }

    public function test_eraser_is_registered_on_filter() {
        $erasers = apply_filters( 'wp_privacy_personal_data_erasers', array() );

        $this->assertArrayHasKey( 'login-delay-shield', $erasers );
        $this->assertSame( 'wldelay_privacy_eraser', $erasers['login-delay-shield']['callback'] );
    }

    // ----------------------------------------------------------------------
    // (a) Exporter returns the subject's data in correct shape
    // ----------------------------------------------------------------------

    public function test_exporter_returns_login_audit_and_lockout_data() {
        $this->seed_login_log( $this->login );
        $this->seed_login_log( $this->login, '203.0.113.10' );
        $this->seed_audit_log( $this->login );

        // A real lockout for the subject via production paths.
        WLDelay_Test_Fixture::make()
            ->with_option( 'wldelay_lockout_enabled', true )
            ->with_option( 'wldelay_lockout_attempt_strategy', 'ip_username' )
            ->with_lockout( '192.0.2.20', $this->login )
            ->apply();

        $result = wldelay_privacy_exporter( $this->email, 1 );

        $this->assertTrue( $result['done'], 'Single small page should be complete.' );
        $this->assertNotEmpty( $result['data'] );

        $groups = array();
        foreach ( $result['data'] as $item ) {
            $groups[ $item['group_id'] ][] = $item;
            // Shape: each item has group_label, item_id, and a data array.
            $this->assertArrayHasKey( 'group_label', $item );
            $this->assertArrayHasKey( 'item_id', $item );
            $this->assertIsArray( $item['data'] );
        }

        $this->assertArrayHasKey( 'wldelay-login-log', $groups );
        $this->assertCount( 2, $groups['wldelay-login-log'] );

        $this->assertArrayHasKey( 'wldelay-audit-log', $groups );
        $this->assertCount( 1, $groups['wldelay-audit-log'] );

        $this->assertArrayHasKey( 'wldelay-lockouts', $groups );
        $this->assertCount( 1, $groups['wldelay-lockouts'] );
    }

    public function test_exporter_paginates_login_log_and_reports_done() {
        // Seed more login-log rows than one page so pagination is exercised.
        $page_size = (int) WLDELAY_PRIVACY_PAGE_SIZE;
        $total     = $page_size + 5;
        for ( $i = 0; $i < $total; $i++ ) {
            $this->seed_login_log( $this->login, '203.0.113.' . ( $i % 250 ) );
        }

        $page1 = wldelay_privacy_exporter( $this->email, 1 );
        $this->assertCount( $page_size, $page1['data'] );
        $this->assertFalse( $page1['done'], 'More rows remain after page 1.' );

        $page2 = wldelay_privacy_exporter( $this->email, 2 );
        $this->assertCount( 5, $page2['data'] );
        $this->assertTrue( $page2['done'], 'No more data after the final page.' );

        // item_ids are stable and unique across pages.
        $ids = array();
        foreach ( array_merge( $page1['data'], $page2['data'] ) as $item ) {
            $ids[] = $item['item_id'];
        }
        $this->assertCount( $total, array_unique( $ids ) );
    }

    public function test_exporter_does_not_export_other_users_login_rows() {
        $this->seed_login_log( $this->login );
        $this->seed_login_log( 'someone_else' );          // unrelated account
        $this->seed_login_log( 'admin-probe-username' );  // arbitrary non-account

        $result = wldelay_privacy_exporter( $this->email, 1 );

        $login_items = array_filter(
            $result['data'],
            static function ( $item ) {
                return 'wldelay-login-log' === $item['group_id'];
            }
        );

        $this->assertCount( 1, $login_items, 'Only the subject\'s own login rows are exported.' );
    }

    // ----------------------------------------------------------------------
    // (b) Unknown email
    // ----------------------------------------------------------------------

    public function test_exporter_returns_empty_done_for_unknown_email() {
        // Seed data that must NOT leak on an email with no registered user.
        $this->seed_login_log( 'ghost' );

        $result = wldelay_privacy_exporter( 'nobody@example.com', 1 );

        $this->assertSame( array(), $result['data'] );
        $this->assertTrue( $result['done'] );
    }

    // ----------------------------------------------------------------------
    // (c) Eraser removes data and clears the lockout
    // ----------------------------------------------------------------------

    public function test_eraser_removes_login_audit_and_lockout() {
        global $wpdb;

        $this->seed_login_log( $this->login );
        $this->seed_login_log( $this->login, '203.0.113.11' );
        $this->seed_audit_log( $this->login );
        // An unrelated account's rows that must survive erasure.
        $this->seed_login_log( 'someone_else' );
        $this->seed_audit_log( 'someone_else' );

        WLDelay_Test_Fixture::make()
            ->with_option( 'wldelay_lockout_enabled', true )
            ->with_option( 'wldelay_lockout_attempt_strategy', 'ip_username' )
            ->with_current_ip( '192.0.2.21' )
            ->with_lockout( '192.0.2.21', $this->login )
            ->apply();

        // Lockout is in force before erasure.
        $this->assertTrue(
            wldelay_is_ip_locked( '192.0.2.21', $this->login ),
            'Subject should be locked before erasure.'
        );

        $result = wldelay_privacy_eraser( $this->email, 1 );

        $this->assertTrue( $result['items_removed'] );
        $this->assertTrue( $result['done'] );

        // Subject's login-log rows gone; other account retained.
        $log_table = wldelay_get_log_table_name();
        $this->assertSame(
            0,
            (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM $log_table WHERE username = %s", $this->login ) ) // phpcs:ignore WordPress.DB
        );
        $this->assertSame(
            1,
            (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM $log_table WHERE username = %s", 'someone_else' ) ) // phpcs:ignore WordPress.DB
        );

        // Subject's audit rows gone; other account retained.
        $audit_table = wldelay_get_audit_table_name();
        $this->assertSame(
            0,
            (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM $audit_table WHERE actor_login = %s", $this->login ) ) // phpcs:ignore WordPress.DB
        );
        $this->assertSame(
            1,
            (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM $audit_table WHERE actor_login = %s", 'someone_else' ) ) // phpcs:ignore WordPress.DB
        );

        // Lockout cleared on both fast-path and durable store.
        wldelay_reset_persistence_runtime_cache();
        $this->assertFalse(
            wldelay_is_ip_locked( '192.0.2.21', $this->login ),
            'Subject lockout should be cleared after erasure.'
        );
        $this->assertSame( array(), wldelay_privacy_get_lockouts_for_login( $this->login ) );
    }

    public function test_eraser_returns_done_no_removal_for_unknown_email() {
        $this->seed_login_log( 'ghost' );

        $result = wldelay_privacy_eraser( 'nobody@example.com', 1 );

        $this->assertFalse( $result['items_removed'] );
        $this->assertTrue( $result['done'] );
    }
}
