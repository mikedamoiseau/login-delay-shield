<?php
/**
 * Unit tests for the persistent lockout store key derivation (F-2-1).
 *
 * The storage key is the stable identifier the DB store uses for upsert and
 * lookup. It must be deterministic, isolate username and lockout type, and be
 * short enough to fit the indexed column. These are pure-logic assertions that
 * run without a WordPress runtime.
 */

class PersistenceKeyTest extends LDS_Unit_Test_Case {

    public function test_key_is_deterministic() {
        $a = wldelay_get_lockout_storage_key( '203.0.113.5', 'alice', 'login' );
        $b = wldelay_get_lockout_storage_key( '203.0.113.5', 'alice', 'login' );

        $this->assertSame( $a, $b );
    }

    public function test_key_isolates_username() {
        $alice = wldelay_get_lockout_storage_key( '203.0.113.5', 'alice', 'login' );
        $bob   = wldelay_get_lockout_storage_key( '203.0.113.5', 'bob', 'login' );

        $this->assertNotSame( $alice, $bob );
    }

    public function test_key_isolates_ip() {
        $one = wldelay_get_lockout_storage_key( '203.0.113.5', 'alice', 'login' );
        $two = wldelay_get_lockout_storage_key( '203.0.113.6', 'alice', 'login' );

        $this->assertNotSame( $one, $two );
    }

    public function test_key_isolates_lockout_type() {
        $login = wldelay_get_lockout_storage_key( '203.0.113.5', 'alice', 'login' );
        $reset = wldelay_get_lockout_storage_key( '203.0.113.5', 'alice', 'password-reset' );

        $this->assertNotSame( $login, $reset );
    }

    public function test_key_fits_indexed_column() {
        $key = wldelay_get_lockout_storage_key( '203.0.113.5', 'alice', 'login' );

        // Stored in a varchar(64) column.
        $this->assertLessThanOrEqual( 64, strlen( $key ) );
        $this->assertNotSame( '', $key );
    }
}
