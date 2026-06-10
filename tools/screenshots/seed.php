<?php
/**
 * Seed demo data for wordpress.org screenshot generation.
 *
 * Dev-only — executed inside the dev container via `wp eval-file` by
 * bin/screenshots.sh. Never shipped (bin/package.sh uses an allowlist).
 *
 * Populates the failed-login log with a realistic week of attack traffic
 * so the dashboard widget (screenshot 4) renders daily trends, top
 * sources, top IPs and top usernames, and switches on the settings
 * (email notifications, lockout, whitelist, XML-RPC protection) that
 * screenshots 2 and 3 are supposed to show populated.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit( "seed.php must run via wp eval-file inside WordPress.\n" );
}

global $wpdb;

wldelay_create_log_table();
$table_name = wldelay_get_log_table_name();
$wpdb->query( "TRUNCATE TABLE $table_name" ); // phpcs:ignore WordPress.DB

// A believable week of brute-force traffic: a couple of persistent IPs
// hammering common usernames, plus background noise.
$ips       = array( '203.0.113.42', '198.51.100.7', '192.0.2.118', '203.0.113.9', '198.51.100.23' );
$usernames = array( 'admin', 'administrator', 'editor', 'webmaster', 'test' );
$sources   = array( 'wp-login', 'wp-login', 'wp-login', 'xmlrpc', 'password-reset' );

$now  = current_time( 'timestamp' );
$rows = 0;

for ( $day = 6; $day >= 0; $day-- ) {
	// Heavier traffic on recent days so the trend chart slopes up.
	$attempts_today = 3 + ( 6 - $day ) * 2;

	for ( $i = 0; $i < $attempts_today; $i++ ) {
		$ts = $now - ( $day * DAY_IN_SECONDS ) - wp_rand( 0, DAY_IN_SECONDS - HOUR_IN_SECONDS );

		$wpdb->insert( // phpcs:ignore WordPress.DB
			$table_name,
			array(
				'ip_address'   => $ips[ wp_rand( 0, $i % 3 === 0 ? 4 : 1 ) ],
				'username'     => $usernames[ wp_rand( 0, $i % 4 === 0 ? 4 : 0 ) ],
				'attempted_at' => gmdate( 'Y-m-d H:i:s', $ts ),
				'source'       => $sources[ wp_rand( 0, 4 ) ],
			)
		);
		$rows++;
	}
}

// Turn on the features the screenshot captions promise, on top of the
// plugin's existing defaults so unknown keys keep their default values.
$options = wldelay_get_options();

$options['wldelay_email_enabled']      = 1;
$options['wldelay_email_address']      = 'admin@example.com';
$options['wldelay_email_threshold']    = 5;
$options['wldelay_lockout_enabled']    = 1;
$options['wldelay_lockout_threshold']  = 10;
$options['wldelay_lockout_duration']   = 60;
$options['wldelay_whitelist_enabled']  = 1;
$options['wldelay_whitelist_ips']      = "203.0.113.200\n198.51.100.0/24";
$options['wldelay_xmlrpc_enabled']     = 1;
$options['wldelay_progressive_enabled'] = 1;

update_option( WLDELAY_OPTION_NAME, $options );

// Drop dashboard sub-caches so the widget rebuilds from the seeded table.
delete_transient( WLDELAY_DASH_RECENT_CACHE );
delete_transient( WLDELAY_DASH_TRENDS_CACHE );

echo "Seeded {$rows} failed-login rows and enabled showcase settings.\n";
