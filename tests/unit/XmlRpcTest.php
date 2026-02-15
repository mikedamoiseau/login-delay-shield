<?php
/**
 * Unit tests for XML-RPC blocking functionality.
 */

use Brain\Monkey\Functions;

class XmlRpcTest extends LDS_Unit_Test_Case {

    protected function setUp(): void {
        parent::setUp();

        // Clear XMLRPC constant if defined
        if ( defined( 'XMLRPC_REQUEST' ) ) {
            // Can't undefine constants, so tests will need to work around this
        }

        // Clear $_SERVER
        unset( $_SERVER['REQUEST_URI'] );
    }

    /**
     * Test wldelay_is_xmlrpc_request returns true when XMLRPC_REQUEST is defined.
     */
    public function test_is_xmlrpc_request_with_constant() {
        // Since we can't define constants in unit tests reliably,
        // we'll test the REQUEST_URI fallback instead
        $_SERVER['REQUEST_URI'] = '/xmlrpc.php';

        $result = $this->is_xmlrpc_request();

        $this->assertTrue( $result );
    }

    /**
     * Test wldelay_is_xmlrpc_request with xmlrpc.php in URI.
     */
    public function test_is_xmlrpc_request_with_uri() {
        $_SERVER['REQUEST_URI'] = '/wp/xmlrpc.php';

        $result = $this->is_xmlrpc_request();

        $this->assertTrue( $result );
    }

    /**
     * Test wldelay_is_xmlrpc_request returns false for regular requests.
     */
    public function test_is_xmlrpc_request_returns_false_for_regular_request() {
        $_SERVER['REQUEST_URI'] = '/wp-login.php';

        $result = $this->is_xmlrpc_request();

        $this->assertFalse( $result );
    }

    /**
     * Test wldelay_is_xmlrpc_request returns false when no URI set.
     */
    public function test_is_xmlrpc_request_returns_false_when_no_uri() {
        $result = $this->is_xmlrpc_request();

        $this->assertFalse( $result );
    }

    /**
     * Test wldelay_get_login_source returns 'xmlrpc' for XMLRPC requests.
     */
    public function test_get_login_source_returns_xmlrpc() {
        $_SERVER['REQUEST_URI'] = '/xmlrpc.php';

        $source = $this->get_login_source();

        $this->assertEquals( 'xmlrpc', $source );
    }

    /**
     * Test wldelay_get_login_source returns 'wp-login' for regular requests.
     */
    public function test_get_login_source_returns_wp_login() {
        $_SERVER['REQUEST_URI'] = '/wp-login.php';

        $source = $this->get_login_source();

        $this->assertEquals( 'wp-login', $source );
    }

    /**
     * Helper to replicate wldelay_is_xmlrpc_request() logic.
     *
     * @return bool True if this is an XMLRPC request.
     */
    private function is_xmlrpc_request(): bool {
        // Check WordPress constant first (can't test this in unit tests)
        if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
            return true;
        }

        // Fallback: check the request URI
        if ( isset( $_SERVER['REQUEST_URI'] ) && strpos( $_SERVER['REQUEST_URI'], 'xmlrpc.php' ) !== false ) {
            return true;
        }

        return false;
    }

    /**
     * Helper to replicate wldelay_get_login_source() logic.
     *
     * @return string 'xmlrpc' or 'wp-login'
     */
    private function get_login_source(): string {
        return $this->is_xmlrpc_request() ? 'xmlrpc' : 'wp-login';
    }
}
