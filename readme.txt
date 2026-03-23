=== Login Delay Shield ===
Contributors: michael.damoiseau
Donate link: http://damoiseau.me/
Tags: security,login,brute-force,lockout,xmlrpc
Requires PHP: 5.4
Requires at least: 3.5.1
Tested up to: 6.9
Version: 2.1.5
Stable tag: 2.1.5
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

Login Delay Shield slows down brute-force attacks by adding a configurable delay to failed login attempts while keeping successful logins instant.

== Description ==

WordPress is one of the most widely used content management systems on the internet, making it a frequent target for bots and hackers attempting brute-force attacks.

A brute-force attack works by systematically trying passwords until finding the correct one. Login Delay Shield defends against this by adding a configurable delay after each failed login attempt. Since successful logins are never delayed, legitimate users experience no slowdown. This approach is particularly effective against bots that send thousands of login requests, as each failed attempt forces the attacker to wait before trying the next password.

**Features:**

* **Login delay** — Fixed or random delay on failed login attempts (1-10 seconds)
* **Progressive delay** — Delay increases with each consecutive failed attempt from the same IP
* **IP lockout** — Temporarily block IP addresses after too many failed attempts
* **Username-aware lockout strategy** — Choose `IP only` or `IP + username` to reduce false positives on shared networks
* **Login feedback** — Shows remaining attempts before lockout and a lockout countdown when blocked
* **IP whitelist** — Bypass all security measures for trusted IPs (supports CIDR notation)
* **Email notifications** — Receive alerts when failed login thresholds are reached
* **Failed login log** — Track all failed attempts with a dashboard widget showing recent activity and 7-day trends
* **XML-RPC protection** — Apply delays to XML-RPC authentication or block it entirely
* **Log retention** — Automatic cleanup of old log entries (configurable retention period)
* **Accessible admin interface** — WCAG 2.1 compliant with keyboard navigation and screen reader support
* **Multilingual** — Translated into 18 languages including French, German, Spanish, Japanese, Chinese, Arabic, and more
* Lightweight and compatible with other security plugins

*This plugin is not a complete security solution — dedicated security plugins offer more comprehensive protection.* However, Login Delay Shield adds an effective layer of defense that works alongside your existing security measures without conflict.

*Note: This plugin was formerly known as "WP Login Delay".*

== Installation ==

1. Upload the `wp-login-delay` folder to the `/wp-content/plugins/` directory
1. Activate the plugin through the 'Plugins' menu in WordPress
1. That's it, Login Delay Shield is installed and working

== Frequently Asked Questions ==

= How does this plugin protect my site? =

When a bot attempts a brute-force attack, it tries thousands of passwords as fast as possible. By adding a delay (even just 1 second) after each failed attempt, the attack becomes impractical. A one-second delay is barely noticeable to legitimate users but makes a huge difference when multiplied across thousands of attempts.

= Where are the plugin settings? =

Go to `Settings` > `Login Delay Shield`

= What is progressive delay? =

Progressive delay increases the wait time with each consecutive failed attempt from the same IP address. For example, the first failure might delay 1 second, the second failure 2 seconds, and so on. This makes repeated attacks increasingly slow.

= How does IP lockout work? =

After a configurable number of failed attempts (default: 10), login attempts are temporarily blocked. You can choose whether attempts are counted by `IP only` or by `IP + username` (recommended for shared office/mobile IPs). Lockout duration is configurable (default: 60 minutes).

= What are the "attempts remaining" and countdown messages? =

When lockout is enabled, failed logins show how many attempts remain before temporary lockout. If lockout is triggered, the error message includes a countdown (for example, "try again in 2 minutes") so users know when to retry.

= How do I whitelist my own IP? =

Enable the IP whitelist feature and add your IP address (or a range using CIDR notation like `192.168.1.0/24`). Whitelisted IPs bypass all delays and lockouts, ensuring you never lock yourself out.

= Should I block XML-RPC? =

If you don't use the WordPress mobile app or remote publishing tools like Windows Live Writer, blocking XML-RPC authentication removes a common attack vector. You can also choose to just apply delays without blocking it entirely.

= How do email notifications work? =

When enabled, the plugin tracks failed login attempts per IP address. Once the threshold is reached (default: 5 attempts), an email is sent to alert you. The counter resets after one hour of no failed attempts from that IP.

= Where can I see failed login attempts? =

A dashboard widget shows the 10 most recent failed login attempts, including the time, username attempted, IP address, and source. It also includes a lightweight 7-day trends panel with daily totals, top sources, and top IPs.

= Is the admin interface accessible? =

Yes! Login Delay Shield follows WCAG 2.1 accessibility guidelines. All settings are fully keyboard navigable, screen reader compatible, and include proper ARIA attributes. Collapsible sections can be toggled with Enter or Space keys, tooltips appear on focus (not just hover), and all dynamic changes are announced to assistive technologies.

= Does this plugin work better with an object cache? =

For high-traffic sites or sites experiencing frequent attacks, we recommend using a persistent object cache like Redis or Memcached.

The plugin uses WordPress transients to track failed login attempts and lockouts per IP address. By default, transients are stored in the database. During a distributed brute-force attack (many IPs), this can create additional database queries.

With an object cache installed:

* Transient reads/writes go to memory instead of the database
* Much faster performance under attack conditions
* Reduced database load

Popular object cache plugins: Redis Object Cache, W3 Total Cache, LiteSpeed Cache.

Most managed WordPress hosts (WP Engine, Kinsta, Flywheel) include object caching by default.

= What languages are supported? =

Login Delay Shield is translated into 18 languages:

* English (default)
* Arabic (العربية)
* Chinese Simplified (简体中文)
* Czech (Čeština)
* Dutch (Nederlands)
* French (Français)
* German (Deutsch)
* Indonesian (Bahasa Indonesia)
* Italian (Italiano)
* Japanese (日本語)
* Korean (한국어)
* Polish (Polski)
* Portuguese - Brazil (Português do Brasil)
* Russian (Русский)
* Spanish (Español)
* Swedish (Svenska)
* Thai (ไทย)
* Turkish (Türkçe)
* Vietnamese (Tiếng Việt)

The plugin automatically uses your site's language setting. Want to help translate into another language? Visit [translate.wordpress.org](https://translate.wordpress.org/).

== Screenshots ==

1. Settings page with delay configuration options.
2. Email notification and IP lockout settings.
3. IP whitelist and XML-RPC protection settings.
4. Dashboard widget showing recent failed login attempts.

== Changelog ==

= Unreleased =
Adds a lightweight observability panel to the failed-login dashboard widget.

**New Features:**
* Dashboard telemetry trends for failed login logs over the last 7 days, including daily totals, top sources, and top IPs.

**Improvements:**
* Dashboard widget cache now stores both recent attempts and the trends snapshot, while staying backward-compatible with the previous cache shape.

= 2.1.5 =
Patch release focused on safer defaults for migrated/legacy installs.

**Improvements:**
* Hardened REST and application-password protection toggles when related option keys are missing.
* Preserves behavior for sites with explicitly saved toggle values while avoiding unintended strict defaults on legacy option states.

= 2.1.4 =
Adds 2FA health check notice and code quality improvements.

**New Features:**
* 2FA health check notice on the settings page — detects common 2FA plugins (Two-Factor, WP 2FA, miniOrange, Google Authenticator) and reminds administrators to verify coverage.
* Extensible `wldelay_2fa_providers` filter hook for adding custom 2FA provider detection.

**Improvements:**
* CSV export now uses the dedicated request filter reader for consistency and safer parameter handling.
* Renamed 2FA notice CSS class to `wldelay-health-notice` for clearer semantics.
* Removed `1=1` WHERE sentinel from query builder in favour of conditional clause construction.
* Hardened `wldelay_2fa_providers` filter callback with type validation to guard against malformed return values.

= 2.1.3 =
Adds telemetry log filters and hardens the CSV export.

**New Features:**
* Telemetry log filters — filter failed login attempts by source, IP, username, and date range.
* Filtered CSV export — export only the subset of log entries matching the active filters.

**Improvements:**
* CSV export now streams results in batches to prevent memory exhaustion on large log tables.
* Added database index on the `source` column for faster filtered queries.
* Hardened query builder to always use `$wpdb->prepare()` for defense-in-depth.
* Restricted request parameter reading to expected `wldelay_log_*` keys only.

= 2.1.2 =
Feature and bugfix release.

**New Features:**
* CSV export for the failed login log — download attempts as a CSV file directly from the dashboard widget.
* Optional REST API and application-password authentication protection toggles.

**Bug Fixes:**
* Fixed REST protection staying active even when application passwords are unavailable.
* Lockout flush recovery now correctly clears failure counters alongside lockout transients.

**Improvements:**
* Stabilized integration test suite and improved CSV export test reliability.

= 2.1.1 =
Patch release focused on lockout recovery tooling.

**New Features:**
* Added an admin recovery action: **Unlock Current IP** button in settings (nonce + capability protected).
* Added WP-CLI recovery commands:
  * `wp login-delay-shield unlock-ip <ip>`
  * `wp login-delay-shield flush-lockouts`
* Added optional protection toggles for REST API and application-password authentication paths.

**Improvements:**
* Added integration tests covering lockout recovery helpers and unlock URL generation.
* Failed-attempt logs now include dedicated source values for REST (`rest`) and application-password (`application-password`) auth failures.

= 2.1.0 =
Minor release focused on smarter throttling and lockout behavior.

**New Security Feature:**
* Username-aware throttling and lockout strategy — choose between `IP only` and `IP + username` to reduce false positives on shared networks.
* Login feedback messages — show remaining attempts before lockout and a lockout countdown when blocked.

**Improvements:**
* Added lockout strategy control to the admin settings UI.
* Progressive delay now continues tracking failed attempts when enabled, even if email notifications and lockout are disabled.
* Expanded test coverage for strategy sanitization and username-isolated lockout behavior.

= 2.0.0 =
Major release with comprehensive security features and modern admin interface.

**New Security Features:**
* Progressive delay — increases wait time with each consecutive failed attempt from the same IP
* IP lockout — temporarily blocks IP addresses after configurable number of failures
* IP whitelist — bypass all security for trusted IPs with CIDR notation support (e.g., 192.168.1.0/24)
* XML-RPC protection — apply delays to XML-RPC authentication or block it entirely
* Email notifications — alerts when failed login thresholds are reached, with rate limiting to prevent inbox flooding
* Failed login log — database-backed logging with dashboard widget showing recent activity
* Configurable log retention — automatic cleanup of old entries (1-365 days or keep forever)

**Improved Delay System:**
* Delays now only apply to failed logins — successful logins are always instant
* Configurable random delay range — set custom min/max values (1-10 seconds)
* Smart delay — successful logins bypass all delays for seamless user experience

**Admin Interface:**
* Completely redesigned settings page with collapsible sections
* Real-time status badges showing which features are active
* Protection summary box for quick security overview
* WCAG 2.1 Level AA accessible — full keyboard navigation and screen reader support

**Internationalization:**
* Translated into 18 languages: Arabic, Chinese (Simplified), Czech, Dutch, French, German, Indonesian, Italian, Japanese, Korean, Polish, Portuguese (Brazil), Russian, Spanish, Swedish, Thai, Turkish, and Vietnamese

**Performance & Reliability:**
* Batched log cleanup for large tables — prevents database locks
* Improved proxy header handling with proper whitespace trimming
* Options caching for reduced database queries
* Compatible with object caches (Redis, Memcached) for high-traffic sites

**Other Improvements:**
* Renamed from "WP Login Delay" to "Login Delay Shield"
* WordPress 6.9 compatibility
* PHP 8.x compatibility
* Comprehensive test suite

= 1.5 =
* Added support until WordPress  5.7.2
* Remove the word WordPress from the plugin name

= 1.4 =
* Added setting to use a random delay between 1 and 5 seconds

= 1.3.1 =
* Added support until WordPress 4.8.2

= 1.3 =
* Wrong SVN commands to push plugin update to WordPress repository

= 1.2 =
* Fixed the invalid header issue after installation

= 1.1 =
* Updated the readme file for Wordpress 3.8
* Renamed a function of the plugin to avoid conflict with WooCommerce plugin
* Added a setting under "Settings > Login Delay Shield" to set the delay time in seconds (the default value is one second)

= 1.0 =
* First version of the plugin

== Upgrade Notice ==

= 2.1.5 =
Hardens default handling for missing REST/application-password option keys on migrated or legacy installs.

= 2.1.4 =
Adds 2FA health check notice on the settings page and extensible provider detection via filter hook.

= 2.1.3 =
Adds telemetry log filters, filtered CSV export, and batched streaming for large exports.

= 2.1.2 =
Adds CSV export for the failed login log, REST API and application-password auth protection, and fixes lockout recovery clearing failure counters.

= 2.1.1 =
Adds emergency lockout recovery tools: admin **Unlock Current IP** action and WP-CLI commands to unlock a specific IP or flush all lockouts.

= 2.1.0 =
Adds username-aware throttling/lockout (`IP + username`), login feedback messages (remaining attempts + lockout countdown), and improves failed-attempt tracking for progressive delay mode.

= 2.0.0 =
Major update with progressive delays, IP lockout, whitelist, XML-RPC protection, email alerts, failed login logging, and 18 language translations. Fully accessible admin interface.

= 1.3.1 =
Code is still the same, only the supported version of WordPress has been updated in the documentation.
