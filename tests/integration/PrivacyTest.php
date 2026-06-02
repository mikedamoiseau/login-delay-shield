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

        // The exporter scopes its per-run state to the privacy REQUEST id, which
        // WordPress exposes as $_POST['id'] during the AJAX handler. Tests call the
        // callback directly, so simulate that superglobal. A non-user_request id
        // exercises the option-fallback state store; tests that need the post-meta
        // path set a real user_request post id explicitly.
        $_POST['id'] = 4242;
    }

    public function tearDown(): void {
        unset( $_POST['id'] );
        // Clear any per-run export state / processing lock the option-fallback
        // path may have left behind so tests do not leak state into each other.
        wldelay_privacy_clear_run_state( 4242 );
        wldelay_privacy_release_lock( 4242 );
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

    /**
     * Finding 1: a substring LIKE export would also return rows whose username
     * merely CONTAINS the subject's login (decoys joann / ann-admin), disclosing
     * unrelated users' IPs and timestamps. The exact-match path must return only
     * the subject `ann`.
     */
    public function test_exporter_uses_exact_username_match_not_substring() {
        $subject       = 'ann';
        $subject_email = 'ann@example.com';
        self::factory()->user->create(
            array(
                'user_login' => $subject,
                'user_email' => $subject_email,
            )
        );

        $this->seed_login_log( $subject, '203.0.113.40' );
        $this->seed_login_log( 'joann', '203.0.113.41' );      // contains "ann"
        $this->seed_login_log( 'ann-admin', '203.0.113.42' );  // contains "ann"
        // Audit decoys that a LIKE would also pull.
        $this->seed_audit_log( $subject );
        $this->seed_audit_log( 'joann' );
        $this->seed_audit_log( 'ann-admin' );

        $result = wldelay_privacy_exporter( $subject_email, 1 );

        $login_items = array_filter(
            $result['data'],
            static function ( $item ) {
                return 'wldelay-login-log' === $item['group_id'];
            }
        );
        $this->assertCount( 1, $login_items, 'Only the exact subject login rows are exported.' );

        $audit_items = array_filter(
            $result['data'],
            static function ( $item ) {
                return 'wldelay-audit-log' === $item['group_id'];
            }
        );
        $this->assertCount( 1, $audit_items, 'Only the exact subject audit rows are exported.' );
    }

    /**
     * Finding 5: pagination must be deterministic across a page boundary with no
     * duplicates and no skips, including when the audit group straddles the
     * boundary after the login group.
     */
    public function test_exporter_pagination_is_stable_across_group_boundary() {
        $page_size = (int) WLDELAY_PRIVACY_PAGE_SIZE;

        // Fill login-log to exactly one page, then add audit rows so group 2
        // begins on page 2 — exercising the cross-group window math.
        for ( $i = 0; $i < $page_size; $i++ ) {
            $this->seed_login_log( $this->login, '203.0.113.' . ( $i % 250 ) );
        }
        $audit_count = 7;
        for ( $i = 0; $i < $audit_count; $i++ ) {
            $this->seed_audit_log( $this->login );
        }

        $page1 = wldelay_privacy_exporter( $this->email, 1 );
        $this->assertCount( $page_size, $page1['data'] );
        $this->assertFalse( $page1['done'], 'Audit rows still pending after page 1.' );

        $page2 = wldelay_privacy_exporter( $this->email, 2 );
        $this->assertCount( $audit_count, $page2['data'] );
        $this->assertTrue( $page2['done'], 'No more data after the final page.' );

        // No dup/skip: every item_id is unique and the totals add up.
        $ids = array();
        foreach ( array_merge( $page1['data'], $page2['data'] ) as $item ) {
            $ids[] = $item['item_id'];
        }
        $this->assertCount( $page_size + $audit_count, $ids );
        $this->assertCount( $page_size + $audit_count, array_unique( $ids ), 'No duplicate item_ids across pages.' );

        // Page 1 is all login-log; page 2 is all audit-log.
        foreach ( $page1['data'] as $item ) {
            $this->assertSame( 'wldelay-login-log', $item['group_id'] );
        }
        foreach ( $page2['data'] as $item ) {
            $this->assertSame( 'wldelay-audit-log', $item['group_id'] );
        }
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

    /**
     * Finding 2: erasing one user must not clear an unrelated account's lockout
     * that originates from the SAME IP (shared NAT). The former IP-wide delete
     * cleared both; the username-scoped path must leave the other user locked.
     */
    public function test_eraser_preserves_other_users_lockout_on_shared_ip() {
        $other_login = 'cohabitant';
        self::factory()->user->create(
            array(
                'user_login' => $other_login,
                'user_email' => 'cohabitant@example.com',
            )
        );

        $shared_ip = '192.0.2.55';

        WLDelay_Test_Fixture::make()
            ->with_option( 'wldelay_lockout_enabled', true )
            ->with_option( 'wldelay_lockout_attempt_strategy', 'ip_username' )
            ->with_current_ip( $shared_ip )
            ->with_lockout( $shared_ip, $this->login )
            ->with_lockout( $shared_ip, $other_login )
            ->apply();

        $this->assertTrue( wldelay_is_ip_locked( $shared_ip, $this->login ) );
        $this->assertTrue( wldelay_is_ip_locked( $shared_ip, $other_login ) );

        $result = wldelay_privacy_eraser( $this->email, 1 );
        $this->assertTrue( $result['items_removed'] );

        wldelay_reset_persistence_runtime_cache();

        // Subject is unlocked; the cohabitant on the same IP stays locked.
        $this->assertFalse(
            wldelay_is_ip_locked( $shared_ip, $this->login ),
            'Subject lockout cleared.'
        );
        $this->assertTrue(
            wldelay_is_ip_locked( $shared_ip, $other_login ),
            'Unrelated account on the same IP must remain locked.'
        );
        $this->assertSame( array(), wldelay_privacy_get_lockouts_for_login( $this->login ) );
        $this->assertNotEmpty( wldelay_privacy_get_lockouts_for_login( $other_login ) );
    }

    /**
     * Finding 3: an EXPIRED lockout row still bears the subject's username + IP
     * (personal data). get_active_lockouts() filters it out, so the eraser must
     * reach it through the username-scoped (active + expired) enumeration.
     */
    public function test_eraser_removes_expired_lockout_rows() {
        global $wpdb;

        $table = wldelay_get_lockout_table_name();
        $ip    = '192.0.2.66';

        // Seed a durable lockout row that has already expired.
        $past_created = gmdate( 'Y-m-d H:i:s', time() - 7200 );
        $past_expires = gmdate( 'Y-m-d H:i:s', time() - 3600 );
        $wpdb->insert(
            $table,
            array(
                'lockout_key'   => wldelay_get_lockout_storage_key( $ip, $this->login, 'login' ),
                'ip_address'    => $ip,
                'username'      => $this->login,
                'lockout_type'  => 'login',
                'source'        => 'wp-login',
                'transient_key' => '',
                'generation'    => '',
                'created_at'    => $past_created,
                'expires_at'    => $past_expires,
            )
        );

        // Precondition: the row exists for the subject.
        $this->assertSame(
            1,
            (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM $table WHERE username = %s", $this->login ) ) // phpcs:ignore WordPress.DB
        );

        $result = wldelay_privacy_eraser( $this->email, 1 );
        $this->assertTrue( $result['items_removed'] );

        // The expired row is gone after erasure.
        $this->assertSame(
            0,
            (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM $table WHERE username = %s", $this->login ) ) // phpcs:ignore WordPress.DB
        );
    }

    /**
     * Finding 4: a failed DELETE ($wpdb->query() returning FALSE, distinct from
     * "0 rows deleted") must NOT be reported as a clean erasure. items_retained
     * must be true with an actionable message.
     */
    public function test_eraser_reports_retained_on_db_delete_failure() {
        $this->seed_login_log( $this->login );

        $log_table = wldelay_get_log_table_name();

        // Force the login-log DELETE to fail deterministically by mangling it
        // into invalid SQL via the `query` filter (mirrors AuditLogTest).
        $break = static function ( $query ) use ( $log_table ) {
            if ( 0 === stripos( ltrim( $query ), 'DELETE' ) && false !== strpos( $query, $log_table ) ) {
                return 'DELETE FROM'; // Syntax error -> $wpdb->query returns false.
            }
            return $query;
        };
        add_filter( 'query', $break );

        global $wpdb;
        $suppress = $wpdb->suppress_errors( true );
        $result   = wldelay_privacy_eraser( $this->email, 1 );
        $wpdb->suppress_errors( $suppress );

        remove_filter( 'query', $break );

        $this->assertTrue( $result['items_retained'], 'A failed delete must flag items_retained.' );
        $this->assertNotEmpty( $result['messages'], 'A failed delete must surface an actionable message.' );

        // The subject's row must still be on disk (delete genuinely failed).
        $this->assertSame(
            1,
            (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM $log_table WHERE username = %s", $this->login ) ) // phpcs:ignore WordPress.DB
        );
    }

    // ----------------------------------------------------------------------
    // Finding A: keyset (snapshot) export pagination is stable under concurrent
    // insert AND delete between page calls — no duplicate, no skipped row.
    // ----------------------------------------------------------------------

    /**
     * Finding A: with offset pagination, a row inserted at the top between
     * page-1 and page-2 would shift the window so the page-1 boundary row is
     * re-emitted on page 2 (duplicate) and an older row is skipped; a delete
     * causes the inverse. The keyset model snapshots a max_id ceiling on page 1
     * and pages by id < cursor under it, so an insert after the run started is
     * excluded and a delete can only shrink the set — never duplicate or skip.
     */
    public function test_exporter_pagination_is_stable_across_insert_and_delete() {
        global $wpdb;

        $log_table = wldelay_get_log_table_name();
        $page_size = (int) WLDELAY_PRIVACY_PAGE_SIZE;

        // Seed two full pages' worth so page 2 has rows of its own.
        $total = $page_size + 10;
        for ( $i = 0; $i < $total; $i++ ) {
            $this->seed_login_log( $this->login, '203.0.113.' . ( $i % 250 ) );
        }

        // Capture the ids that EXIST when the run starts; the export must emit
        // exactly these (minus any deleted below), with no dup and no extra.
        $ids_at_start = array_map(
            'intval',
            (array) $wpdb->get_col( $wpdb->prepare( "SELECT id FROM $log_table WHERE username = %s ORDER BY id DESC", $this->login ) ) // phpcs:ignore WordPress.DB
        );
        $this->assertCount( $total, $ids_at_start );

        // ---- Page 1 (snapshots the ceiling) ----
        $page1 = wldelay_privacy_exporter( $this->email, 1 );
        $this->assertCount( $page_size, $page1['data'] );
        $this->assertFalse( $page1['done'] );

        // ---- Concurrent activity BETWEEN page 1 and page 2 ----
        // (1) An attacker hammers the subject again: new rows land at the TOP
        //     (highest ids). Offset pagination would re-window and duplicate.
        for ( $i = 0; $i < 5; $i++ ) {
            $this->seed_login_log( $this->login, '203.0.113.200' );
        }
        // (2) A retention purge deletes an OLD row that has NOT yet been emitted
        //     (one of the lowest ids, which belongs on page 2).
        $oldest_id = min( $ids_at_start );
        $wpdb->delete( $log_table, array( 'id' => $oldest_id ), array( '%d' ) );

        // ---- Page 2 ----
        $page2 = wldelay_privacy_exporter( $this->email, 2 );
        $this->assertTrue( $page2['done'] );

        // Collect emitted login-log item_ids across both pages.
        $emitted = array();
        foreach ( array_merge( $page1['data'], $page2['data'] ) as $item ) {
            if ( 'wldelay-login-log' === $item['group_id'] ) {
                $emitted[] = $item['item_id'];
            }
        }

        // No duplicates across the page boundary.
        $this->assertCount( count( $emitted ), array_unique( $emitted ), 'No duplicate rows across pages.' );

        // The emitted set is exactly the start-of-run rows minus the one deleted
        // before it was emitted: no row inserted after the run leaks in, and the
        // deleted (not-yet-emitted) row is simply absent — never skipping a
        // DIFFERENT row in its place.
        $expected = array();
        foreach ( $ids_at_start as $id ) {
            if ( $id === $oldest_id ) {
                continue; // Legitimately deleted before emission.
            }
            $expected[] = 'wldelay-login-log-' . $id;
        }
        sort( $expected );
        sort( $emitted );
        $this->assertSame( $expected, $emitted, 'Exactly the snapshot rows (minus the deleted one) are emitted — no skip, no dup, no post-run row.' );
    }

    // ----------------------------------------------------------------------
    // Finding B: lockout export is scoped at SQL by username, so the subject's
    // lockout is exported even when it sits outside the global active window.
    // ----------------------------------------------------------------------

    /**
     * Finding B: the old exporter fetched the GLOBAL top-N active lockouts and
     * filtered by username in PHP, so on a busy site the subject's own lockout
     * could sit outside that window and never be exported. The username-scoped
     * SQL read fetches the subject's lockout regardless of how many unrelated
     * lockouts the site holds.
     */
    public function test_exporter_lockout_scoped_by_username_outside_global_window() {
        global $wpdb;

        $table = wldelay_get_lockout_table_name();
        $now   = time();

        // Seed many unrelated active lockouts, each with a LATER expiry than the
        // subject's so a global "ORDER BY expires_at DESC LIMIT n" prefix would
        // never reach the subject's row. The username-scoped keyset read ignores
        // global ordering entirely, so the count only needs to comfortably exceed
        // one export page to prove the scoping (the old hard scan cap is gone).
        $decoys = ( (int) WLDELAY_PRIVACY_PAGE_SIZE ) + 25;
        for ( $i = 0; $i < $decoys; $i++ ) {
            $ip = '10.0.' . intdiv( $i, 250 ) . '.' . ( $i % 250 );
            $wpdb->insert(
                $table,
                array(
                    'lockout_key'   => wldelay_get_lockout_storage_key( $ip, 'decoy_' . $i, 'login' ),
                    'ip_address'    => $ip,
                    'username'      => 'decoy_' . $i,
                    'lockout_type'  => 'login',
                    'source'        => 'wp-login',
                    'transient_key' => '',
                    'generation'    => '',
                    'created_at'    => gmdate( 'Y-m-d H:i:s', $now ),
                    // Far-future expiry so these dominate a global expires_at DESC sort.
                    'expires_at'    => gmdate( 'Y-m-d H:i:s', $now + 86400 ),
                )
            );
        }

        // The subject's own active lockout, with a NEARER expiry so it would be
        // pushed past the end of a global window.
        $subject_ip = '192.0.2.77';
        $wpdb->insert(
            $table,
            array(
                'lockout_key'   => wldelay_get_lockout_storage_key( $subject_ip, $this->login, 'login' ),
                'ip_address'    => $subject_ip,
                'username'      => $this->login,
                'lockout_type'  => 'login',
                'source'        => 'wp-login',
                'transient_key' => '',
                'generation'    => '',
                'created_at'    => gmdate( 'Y-m-d H:i:s', $now ),
                'expires_at'    => gmdate( 'Y-m-d H:i:s', $now + 600 ),
            )
        );

        $result = wldelay_privacy_exporter( $this->email, 1 );

        $lockout_items = array_filter(
            $result['data'],
            static function ( $item ) {
                return 'wldelay-lockouts' === $item['group_id'];
            }
        );

        $this->assertCount( 1, $lockout_items, 'The subject\'s lockout is exported despite the global window being saturated by decoys.' );

        $item = array_shift( $lockout_items );
        $this->assertSame(
            'wldelay-lockout-' . wldelay_get_lockout_storage_key( $subject_ip, $this->login, 'login' ),
            $item['item_id']
        );
    }

    // ----------------------------------------------------------------------
    // Finding C: a failed lockout SELECT or DELETE must surface items_retained
    // + a message, not a clean completion while the subject's PII remains.
    // ----------------------------------------------------------------------

    /**
     * Finding C (read): get_lockouts_for_username() returning FALSE on a failed
     * SELECT must propagate to the eraser as items_retained, not collapse to an
     * empty "nothing to erase" result.
     */
    public function test_eraser_reports_retained_on_lockout_select_failure() {
        $lockout_table = wldelay_get_lockout_table_name();

        // Break ONLY the username-scoped SELECT against the lockout table. The
        // table-existence SHOW TABLES check is left intact so the read reaches
        // the failing SELECT.
        $break = static function ( $query ) use ( $lockout_table ) {
            if (
                0 === stripos( ltrim( $query ), 'SELECT' )
                && false !== strpos( $query, $lockout_table )
                && false !== strpos( $query, 'WHERE username' )
            ) {
                return 'SELECT * FROM'; // Syntax error -> get_results errors out.
            }
            return $query;
        };
        add_filter( 'query', $break );

        global $wpdb;
        $suppress = $wpdb->suppress_errors( true );
        $result   = wldelay_privacy_eraser( $this->email, 1 );
        $wpdb->suppress_errors( $suppress );

        remove_filter( 'query', $break );

        $this->assertTrue( $result['items_retained'], 'A failed lockout SELECT must flag items_retained.' );
        $this->assertNotEmpty( $result['messages'], 'A failed lockout SELECT must surface an actionable message.' );
    }

    /**
     * Finding C (delete): remove_lockouts_matching_generation() returning FALSE
     * on a failed DELETE (distinct from 0 rows) must propagate to the eraser as
     * items_retained while the subject's lockout row stays on disk.
     */
    public function test_eraser_reports_retained_on_lockout_delete_failure() {
        global $wpdb;

        $lockout_table = wldelay_get_lockout_table_name();
        $ip            = '192.0.2.88';

        // Seed a real durable lockout row for the subject so there is something
        // to delete (and the SELECT returns a non-empty snapshot).
        $wpdb->insert(
            $lockout_table,
            array(
                'lockout_key'   => wldelay_get_lockout_storage_key( $ip, $this->login, 'login' ),
                'ip_address'    => $ip,
                'username'      => $this->login,
                'lockout_type'  => 'login',
                'source'        => 'wp-login',
                'transient_key' => '',
                'generation'    => '',
                'created_at'    => gmdate( 'Y-m-d H:i:s', time() ),
                'expires_at'    => gmdate( 'Y-m-d H:i:s', time() + 600 ),
            )
        );

        // Break ONLY the DELETE against the lockout table; the SELECT snapshot
        // must succeed so we exercise the DELETE-failure branch specifically.
        $break = static function ( $query ) use ( $lockout_table ) {
            if ( 0 === stripos( ltrim( $query ), 'DELETE' ) && false !== strpos( $query, $lockout_table ) ) {
                return 'DELETE FROM'; // Syntax error -> $wpdb->delete returns false.
            }
            return $query;
        };
        add_filter( 'query', $break );

        $suppress = $wpdb->suppress_errors( true );
        $result   = wldelay_privacy_eraser( $this->email, 1 );
        $wpdb->suppress_errors( $suppress );

        remove_filter( 'query', $break );

        $this->assertTrue( $result['items_retained'], 'A failed lockout DELETE must flag items_retained.' );
        $this->assertNotEmpty( $result['messages'], 'A failed lockout DELETE must surface an actionable message.' );

        // The subject's lockout row must still be on disk (delete genuinely failed).
        $this->assertSame(
            1,
            (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM $lockout_table WHERE username = %s", $this->login ) ) // phpcs:ignore WordPress.DB
        );
    }

    // ----------------------------------------------------------------------
    // M6 point 1+2: durable run state lost mid-run -> WP_Error abort, no
    // dup / no infinite loop. The persisted run state is deleted between
    // page 1 and page 2; the exporter must return a WP_Error (the supported
    // hard-failure channel) rather than silently restarting the cursor.
    // ----------------------------------------------------------------------

    public function test_exporter_returns_wp_error_when_run_state_lost_between_pages() {
        $request_id = (int) $_POST['id'];

        // Seed more than one page so a page 2 is genuinely expected.
        $page_size = (int) WLDELAY_PRIVACY_PAGE_SIZE;
        $total     = $page_size + 5;
        for ( $i = 0; $i < $total; $i++ ) {
            $this->seed_login_log( $this->login, '203.0.113.' . ( $i % 250 ) );
        }

        $page1 = wldelay_privacy_exporter( $this->email, 1 );
        $this->assertIsArray( $page1 );
        $this->assertFalse( $page1['done'], 'More rows remain after page 1.' );

        // Simulate the durable state being lost (object-cache eviction / manual
        // clear) between page calls.
        wldelay_privacy_clear_run_state( $request_id );

        $page2 = wldelay_privacy_exporter( $this->email, 2 );

        $this->assertWPError( $page2, 'A lost run state on a later page must abort with a WP_Error.' );
        $this->assertSame( 'wldelay_privacy_export_state', $page2->get_error_code() );
    }

    /**
     * M6 point 1+2: a later page with NO valid request id (the $_POST['id']
     * superglobal absent, e.g. a programmatic call that cannot resume the
     * cursor) must also abort with a WP_Error rather than restart.
     */
    public function test_exporter_returns_wp_error_on_later_page_without_request_id() {
        $this->seed_login_log( $this->login );

        unset( $_POST['id'] );

        $page2 = wldelay_privacy_exporter( $this->email, 2 );

        $this->assertWPError( $page2 );
        $this->assertSame( 'wldelay_privacy_export_state', $page2->get_error_code() );
    }

    // ----------------------------------------------------------------------
    // M6 point 3: a broken SHOW TABLES probe is a FAILED read, not "table
    // absent". get_lockouts_for_username() returns FALSE and the eraser
    // reports items_retained + a message (no silent "nothing to erase").
    // ----------------------------------------------------------------------

    public function test_eraser_reports_retained_on_table_probe_failure() {
        global $wpdb;

        $lockout_table = wldelay_get_lockout_table_name();

        // Break ONLY the SHOW TABLES existence probe for the lockout table.
        $break = static function ( $query ) use ( $lockout_table ) {
            if ( 0 === stripos( ltrim( $query ), 'SHOW TABLES' ) && false !== strpos( $query, $lockout_table ) ) {
                return 'SHOW TABLES LIKE'; // Syntax error -> probe errors out.
            }
            return $query;
        };
        add_filter( 'query', $break );

        // Force a fresh probe so the broken SHOW TABLES is actually run.
        wldelay_reset_persistence_runtime_cache();

        $suppress = $wpdb->suppress_errors( true );

        // Confirm the store distinguishes a failed probe from "no rows".
        $store = wldelay_get_persistence_store();
        $this->assertFalse(
            $store->get_lockouts_for_username( $this->login ),
            'A failed existence probe must return FALSE, not array().'
        );

        wldelay_reset_persistence_runtime_cache();
        $result = wldelay_privacy_eraser( $this->email, 1 );

        $wpdb->suppress_errors( $suppress );
        remove_filter( 'query', $break );
        wldelay_reset_persistence_runtime_cache();

        $this->assertTrue( $result['items_retained'], 'A failed table probe must flag items_retained.' );
        $this->assertNotEmpty( $result['messages'], 'A failed table probe must surface an actionable message.' );
    }

    // ----------------------------------------------------------------------
    // M6 point 2: a failed ceiling (MAX id) read must abort the export with a
    // WP_Error, not coerce to a 0 ceiling and emit a spurious empty done group.
    // ----------------------------------------------------------------------

    public function test_exporter_returns_wp_error_on_failed_ceiling_read() {
        global $wpdb;

        $this->seed_login_log( $this->login );

        $log_table = wldelay_get_log_table_name();

        // Break ONLY the MAX(id) ceiling read against the login-log table.
        $break = static function ( $query ) use ( $log_table ) {
            if ( false !== stripos( $query, 'SELECT MAX(id)' ) && false !== strpos( $query, $log_table ) ) {
                return 'SELECT MAX(id) FROM'; // Syntax error -> get_var errors out.
            }
            return $query;
        };
        add_filter( 'query', $break );

        $suppress = $wpdb->suppress_errors( true );
        $result   = wldelay_privacy_exporter( $this->email, 1 );
        $wpdb->suppress_errors( $suppress );

        remove_filter( 'query', $break );

        $this->assertWPError( $result, 'A failed ceiling read must abort with a WP_Error.' );
        $this->assertSame( 'wldelay_privacy_export_state', $result->get_error_code() );
    }

    // ----------------------------------------------------------------------
    // M6 point 4: a forced durable DELETE failure in the IP-recovery / unlock
    // path must be SURFACED (false), not coerced to 0 and reported as success.
    // ----------------------------------------------------------------------

    public function test_unlock_ip_propagates_durable_delete_failure() {
        global $wpdb;

        $lockout_table = wldelay_get_lockout_table_name();
        $ip            = '192.0.2.99';

        // A real durable lockout row so the snapshot is non-empty and a DELETE
        // is attempted.
        $wpdb->insert(
            $lockout_table,
            array(
                'lockout_key'   => wldelay_get_lockout_storage_key( $ip, $this->login, 'login' ),
                'ip_address'    => $ip,
                'username'      => $this->login,
                'lockout_type'  => 'login',
                'source'        => 'wp-login',
                'transient_key' => '',
                'generation'    => '',
                'created_at'    => gmdate( 'Y-m-d H:i:s', time() ),
                'expires_at'    => gmdate( 'Y-m-d H:i:s', time() + 600 ),
            )
        );

        // Break ONLY the DELETE against the lockout table; the snapshot SELECT
        // must succeed so we hit the DELETE-failure branch.
        $break = static function ( $query ) use ( $lockout_table ) {
            if ( 0 === stripos( ltrim( $query ), 'DELETE' ) && false !== strpos( $query, $lockout_table ) ) {
                return 'DELETE FROM'; // Syntax error -> $wpdb->delete returns false.
            }
            return $query;
        };
        add_filter( 'query', $break );

        $suppress = $wpdb->suppress_errors( true );
        $result   = wldelay_delete_lockout_for_ip( $ip, $this->login );
        $wpdb->suppress_errors( $suppress );

        remove_filter( 'query', $break );

        $this->assertFalse(
            $result,
            'A failed durable delete must propagate as FALSE, not coerce to a success count.'
        );

        // The row genuinely remains on disk (delete failed).
        $this->assertSame(
            1,
            (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM $lockout_table WHERE username = %s", $this->login ) ) // phpcs:ignore WordPress.DB
        );
    }

    /**
     * M6 point 4: the same forced failure through the flush path must propagate
     * as FALSE so the CLI flush surfaces it rather than reporting a clean flush.
     */
    public function test_flush_propagates_durable_delete_failure() {
        global $wpdb;

        $lockout_table = wldelay_get_lockout_table_name();
        $ip            = '192.0.2.111';

        $wpdb->insert(
            $lockout_table,
            array(
                'lockout_key'   => wldelay_get_lockout_storage_key( $ip, $this->login, 'login' ),
                'ip_address'    => $ip,
                'username'      => $this->login,
                'lockout_type'  => 'login',
                'source'        => 'wp-login',
                'transient_key' => '',
                'generation'    => '',
                'created_at'    => gmdate( 'Y-m-d H:i:s', time() ),
                'expires_at'    => gmdate( 'Y-m-d H:i:s', time() + 600 ),
            )
        );

        $break = static function ( $query ) use ( $lockout_table ) {
            if ( 0 === stripos( ltrim( $query ), 'DELETE' ) && false !== strpos( $query, $lockout_table ) ) {
                return 'DELETE FROM';
            }
            return $query;
        };
        add_filter( 'query', $break );

        $suppress = $wpdb->suppress_errors( true );
        $result   = wldelay_flush_lockout_transients();
        $wpdb->suppress_errors( $suppress );

        remove_filter( 'query', $break );

        $this->assertFalse(
            $result,
            'A failed durable delete during flush must propagate as FALSE.'
        );
    }

    // ----------------------------------------------------------------------
    // M6 point 1: interleaved same-subject runs (two distinct request ids for
    // one email) must NOT share a cursor. page1(A), page1(B), page2(A) must
    // continue A's OWN cursor — no cross-run corruption.
    // ----------------------------------------------------------------------

    public function test_interleaved_same_subject_runs_keep_independent_cursors() {
        $page_size = (int) WLDELAY_PRIVACY_PAGE_SIZE;
        $total     = $page_size + 7;
        for ( $i = 0; $i < $total; $i++ ) {
            $this->seed_login_log( $this->login, '203.0.113.' . ( $i % 250 ) );
        }

        $req_a = 5001;
        $req_b = 5002;

        // --- Run A, page 1 ---
        $_POST['id'] = $req_a;
        $a1          = wldelay_privacy_exporter( $this->email, 1 );
        $this->assertCount( $page_size, $a1['data'] );
        $this->assertFalse( $a1['done'] );

        // --- Run B, page 1 (a DIFFERENT export of the SAME email) ---
        $_POST['id'] = $req_b;
        $b1          = wldelay_privacy_exporter( $this->email, 1 );
        $this->assertCount( $page_size, $b1['data'] );
        $this->assertFalse( $b1['done'] );

        // --- Run A, page 2 — must resume A's cursor, not B's ---
        $_POST['id'] = $req_a;
        $a2          = wldelay_privacy_exporter( $this->email, 2 );
        $this->assertTrue( $a2['done'], 'Run A completes on its own page 2.' );

        // Run A across both pages emitted exactly the subject's rows, no dup.
        $a_ids = array();
        foreach ( array_merge( $a1['data'], $a2['data'] ) as $item ) {
            if ( 'wldelay-login-log' === $item['group_id'] ) {
                $a_ids[] = $item['item_id'];
            }
        }
        $this->assertCount( $total, $a_ids, 'Run A emitted every subject login row across its pages.' );
        $this->assertCount( $total, array_unique( $a_ids ), 'Run A emitted no duplicate rows — B did not steal A\'s cursor.' );

        // Cleanup the two extra runs' option-fallback state.
        wldelay_privacy_clear_run_state( $req_a );
        wldelay_privacy_clear_run_state( $req_b );
        wldelay_privacy_release_lock( $req_a );
        wldelay_privacy_release_lock( $req_b );
    }

    // ----------------------------------------------------------------------
    // M6 point 5: more active lockouts for the subject than the OLD scan cap
    // (1000) — all are exported across pages, no truncation.
    // ----------------------------------------------------------------------

    public function test_exporter_paginates_all_active_lockouts_no_cap() {
        global $wpdb;

        $table     = wldelay_get_lockout_table_name();
        $now       = time();
        $page_size = (int) WLDELAY_PRIVACY_PAGE_SIZE;

        // Seed more active lockouts than fit on a single page so pagination of
        // the lockout group is genuinely exercised (and well clear of any single
        // cap). Each row is the subject's, on a distinct IP/type-key.
        $lockout_total = $page_size + 13;
        for ( $i = 0; $i < $lockout_total; $i++ ) {
            $ip = '198.51.' . intdiv( $i, 250 ) . '.' . ( $i % 250 );
            $wpdb->insert(
                $table,
                array(
                    'lockout_key'   => wldelay_get_lockout_storage_key( $ip, $this->login, 'login' ),
                    'ip_address'    => $ip,
                    'username'      => $this->login,
                    'lockout_type'  => 'login',
                    'source'        => 'wp-login',
                    'transient_key' => '',
                    'generation'    => '',
                    'created_at'    => gmdate( 'Y-m-d H:i:s', $now ),
                    'expires_at'    => gmdate( 'Y-m-d H:i:s', $now + 3600 ),
                )
            );
        }

        // Drain every page until done, collecting lockout item_ids.
        $lockout_ids = array();
        $page        = 1;
        $guard       = 0;
        do {
            $result = wldelay_privacy_exporter( $this->email, $page );
            $this->assertIsArray( $result, 'Export pages must not error in the happy path.' );
            foreach ( $result['data'] as $item ) {
                if ( 'wldelay-lockouts' === $item['group_id'] ) {
                    $lockout_ids[] = $item['item_id'];
                }
            }
            $page++;
            $guard++;
        } while ( empty( $result['done'] ) && $guard < 1000 );

        $this->assertTrue( $result['done'], 'Pagination terminated.' );
        $this->assertCount( $lockout_total, $lockout_ids, 'Every active lockout was exported across pages — no truncation.' );
        $this->assertCount( $lockout_total, array_unique( $lockout_ids ), 'No duplicate lockout item_ids across pages.' );
    }

    // ----------------------------------------------------------------------
    // M6 point 6: a STALE processing lock (older than the timeout) is reclaimed
    // so a crashed prior page does not wedge the run forever.
    // ----------------------------------------------------------------------

    public function test_stale_processing_lock_is_reclaimed() {
        $request_id = 6001;

        // Plant a stale lock: a timestamp older than the timeout, as a crashed
        // prior page would have left behind.
        $stale = time() - ( (int) WLDELAY_PRIVACY_LOCK_TIMEOUT ) - 10;
        update_option( wldelay_privacy_lock_option_name( $request_id ), $stale, false );

        // A fresh-but-live lock for a DIFFERENT request must NOT be acquirable.
        $live_id = 6002;
        update_option( wldelay_privacy_lock_option_name( $live_id ), time(), false );

        $this->assertTrue(
            wldelay_privacy_acquire_lock( $request_id ),
            'A stale lock must be reclaimable.'
        );
        $this->assertFalse(
            wldelay_privacy_acquire_lock( $live_id ),
            'A live (non-stale) lock must NOT be acquirable by a second caller.'
        );

        wldelay_privacy_release_lock( $request_id );
        wldelay_privacy_release_lock( $live_id );
    }
}
