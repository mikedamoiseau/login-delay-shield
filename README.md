# Login Delay Shield

[![WordPress Plugin Version](https://img.shields.io/wordpress/plugin/v/wp-login-delay)](https://wordpress.org/plugins/wp-login-delay/)
[![WordPress Plugin: Tested WP Version](https://img.shields.io/wordpress/plugin/tested/wp-login-delay)](https://wordpress.org/plugins/wp-login-delay/)
[![License: GPL v2+](https://img.shields.io/badge/License-GPLv2+-blue.svg)](https://www.gnu.org/licenses/gpl-2.0.html)

Login Delay Shield slows down brute-force attacks by adding a configurable delay to failed login attempts while keeping successful logins instant.

## Description

WordPress is one of the most widely used content management systems on the internet, making it a frequent target for bots and hackers attempting brute-force attacks.

A brute-force attack works by systematically trying passwords until finding the correct one. Login Delay Shield defends against this by adding a configurable delay after each failed login attempt. Since successful logins are never delayed, legitimate users experience no slowdown. This approach is particularly effective against bots that send thousands of login requests, as each failed attempt forces the attacker to wait before trying the next password.

### Features

- **Security Setup Wizard** — Choose Conservative, Balanced, or Aggressive protection profiles from the settings page
- **Login delay** — Fixed or random delay on failed login attempts (1-10 seconds)
- **Progressive delay** — Delay increases with each consecutive failed attempt from the same IP
- **IP lockout** — Temporarily block IP addresses after too many failed attempts
- **Username-aware lockout strategy** — Choose `IP only` or `IP + username` to reduce false positives on shared networks
- **Login feedback** — Shows remaining attempts before lockout and a lockout countdown when blocked
- **IP whitelist** — Bypass all security measures for trusted IPs (supports CIDR notation)
- **Email notifications** — Receive alerts when failed login thresholds are reached
- **Failed login log** — Track all failed attempts with a dashboard widget showing recent activity and 7-day trends
- **fail2ban logging (optional)** — Write fail2ban-compatible failed-login and lockout lines to a safe log file
- **XML-RPC protection** — Apply delays to XML-RPC authentication or block it entirely
- **REST/API auth protection (optional)** — Apply delay/lockout checks to REST and application-password authentication paths
- **Password reset protection** — Apply delays, lockouts, and logging to password reset submissions without revealing account existence
- **Country blocking (optional)** — Block login authentication from selected country codes. Ships no GeoIP database; reads the country your server or CDN already determined (`GEOIP_COUNTRY_CODE`, Cloudflare's `CF-IPCountry`, or an `X-Country-Code` proxy header), or one supplied through the `wldelay_resolve_country_code` filter
- **Challenge mode (optional)** — After a set number of failed sign-ins, require a self-hosted challenge (math question, emailed one-time code, or in-browser proof-of-work) before credentials are checked. No third-party CAPTCHA; extensible via the `wldelay_challenge_providers` filter
- **Log retention** — Automatic cleanup of old log entries (configurable retention period)
- **Recovery tools** — Admin unlock action and WP-CLI commands to flush lockouts
- **Emergency recovery URL (optional)** — A secret link that clears the lockout for your own IP, so you can get back in even with no admin, shell, or file access
- **Accessible admin interface** — WCAG 2.1 compliant with keyboard navigation and screen reader support
- **Multilingual** — Translated into 18 languages including French, German, Spanish, Japanese, Chinese, Arabic, and more
- Lightweight and compatible with other security plugins

> *This plugin is not a complete security solution — dedicated security plugins offer more comprehensive protection.* However, Login Delay Shield adds an effective layer of defense that works alongside your existing security measures without conflict.

## Installation

1. Upload the `wp-login-delay` folder to the `/wp-content/plugins/` directory
2. Activate the plugin through the 'Plugins' menu in WordPress
3. That's it, Login Delay Shield is installed and working

Settings are available under **Settings > Login Delay Shield**.

The Security Setup Wizard at the top of the settings page lets you apply a protection profile quickly:

- **Conservative** — Core throttling with gentler thresholds for low-friction sites
- **Balanced** — Recommended defaults for most WordPress sites
- **Aggressive** — Stricter lockouts and XML-RPC authentication blocking for sites under frequent attack

## FAQ

### How does this plugin protect my site?

When a bot attempts a brute-force attack, it tries thousands of passwords as fast as possible. By adding a delay (even just 1 second) after each failed attempt, the attack becomes impractical. A one-second delay is barely noticeable to legitimate users but makes a huge difference when multiplied across thousands of attempts.

### What is progressive delay?

Progressive delay increases the wait time with each consecutive failed attempt from the same IP address. For example, the first failure might delay 1 second, the second failure 2 seconds, and so on. This makes repeated attacks increasingly slow.

### How does IP lockout work?

After a configurable number of failed attempts (default: 10), login attempts are temporarily blocked. You can choose whether attempts are counted by `IP only` or by `IP + username` (recommended for shared office/mobile IPs). Lockout duration is configurable (default: 60 minutes).

### What are protection profiles?

Protection profiles are guided presets in the Security Setup Wizard. Applying a profile updates the main delay, progressive delay, lockout, email alert, and authentication endpoint settings, while still leaving every individual control editable.

### How do I whitelist my own IP?

Enable the IP whitelist feature and add your IP address (or a range using CIDR notation like `192.168.1.0/24`). Whitelisted IPs bypass all delays and lockouts, ensuring you never lock yourself out.

### Should I block XML-RPC?

If you don't use the WordPress mobile app or remote publishing tools like Windows Live Writer, blocking XML-RPC authentication removes a common attack vector. You can also choose to just apply delays without blocking it entirely.

### Should I protect password reset requests?

Yes, for most sites. Password reset protection applies the same delay and lockout behavior used for login attempts, logs the source as `password-reset`, and keeps messages generic so the form does not reveal whether a username or email exists.

### How do I use fail2ban logging?

Enable fail2ban logging under **Settings > Login Delay Shield > Login Log**. If the log path is empty, Login Delay Shield writes to `login-delay-shield-fail2ban/login-delay-shield-fail2ban.log` in a plugin-owned temporary directory outside the WordPress uploads tree and adds basic `.htaccess`/`index.html` protections. Custom paths are restricted to the protected default directory by default; use the `wldelay_fail2ban_allowed_log_dirs` filter only for server-protected directories. If a custom path is rejected, logging is disabled instead of silently writing somewhere else. If lockout-event logging is enabled, an attempt that triggers a lockout may produce both a `failed login` line and a `lockout` line, so tune your jail's `maxretry` accordingly. The log is rotated to a single `.log.1` backup once it reaches 5 MB so it cannot grow without bound; adjust or disable this with the `wldelay_fail2ban_max_log_bytes` filter (return `0` to rely on system logrotate instead).

Log lines include an ISO-8601 timestamp, stable prefix, and fields such as:

```text
2026-05-04T12:00:00+00:00 Login Delay Shield: failed login source=wp-login ip=203.0.113.10 username=admin
```

A fail2ban filter can match the IP with:

```text
failregex = Login Delay Shield: (?:failed login|lockout) .* ip=<HOST>
```

### What happens if I lock myself out?

You can always get back in. Lockouts are temporary by design (24 hours maximum — there are no permanent bans), so waiting always works. To recover immediately:

- If another administrator can log in, use the Active Lockouts manager on the settings page (one-click Unlock per lockout, plus "Unlock Current IP").
- If you set up the Emergency Recovery URL in advance, open that saved link and confirm (see below).
- With shell access, use WP-CLI (see WP-CLI Commands below).
- With only FTP access, add `define( 'WLDELAY_SAFE_MODE', true );` to `wp-config.php` to disable all delays and lockouts until you remove the line.
- To avoid lockouts entirely, whitelist your own IP.

### What is the Emergency Recovery URL?

An optional, off-by-default secret link you generate in advance from **Settings > Login Delay Shield**. Save it somewhere safe and off your site — it is shown once on screen, emailed to your admin address, and offered as a `.txt` download. If you are ever locked out with no admin login, no shell, and no file access, open the link and confirm: it clears the login lockout for your current IP only. It never logs you in (you still sign in normally afterwards) and never disables protection.

Treat the link like a password. The plugin stores only a hash in its long-term settings, but the freshly generated URL may exist briefly in transient storage so it can be shown and downloaded once. Opening it requires a confirmation click, attempts are rate-limited and recorded in the audit log, and the plugin reminds you to regenerate it after 90 days (regenerating invalidates the previous link immediately).

### WP-CLI Commands

```bash
# Unlock a specific IP address
wp login-delay-shield unlock-ip <ip>

# Flush all lockouts
wp login-delay-shield flush-lockouts
```

### Does this plugin work better with an object cache?

For high-traffic sites or sites experiencing frequent attacks, we recommend using a persistent object cache like Redis or Memcached. The plugin uses WordPress transients to track failed login attempts and lockouts per IP address — with an object cache, these go to memory instead of the database.

### Supported Languages

English, Arabic, Chinese (Simplified), Czech, Dutch, French, German, Indonesian, Italian, Japanese, Korean, Polish, Portuguese (Brazil), Russian, Spanish, Swedish, Thai, Turkish, and Vietnamese.

## Screenshots

1. Settings page with delay configuration options
2. Email notification and IP lockout settings
3. IP whitelist and XML-RPC protection settings
4. Dashboard widget showing recent failed login attempts

## Changelog

### 2.3.3

- Added a Security Setup Wizard with Conservative, Balanced, and Aggressive protection profiles that configure delay, lockout, alerts, and authentication endpoints in one step while keeping every control editable.
- Protection profiles no longer overwrite the log retention period, preventing unintended deletion of existing failed-login logs.
- The current-profile badge now reflects the actual stored configuration and shows "Custom" after manual edits.
- The Aggressive profile counts lockouts by IP rather than IP + username, closing a password-spray gap.
- Pressing Enter in a settings field no longer applies a profile over manual edits.

### 2.1.6

- Added a lightweight 7-day failed-login trends panel to the dashboard widget.
- Updated the widget cache to snapshot both recent attempts and trend data while remaining compatible with the previous cache format.
- Updated the WordPress.org listing metadata, including a more accurate minimum PHP version and refreshed tags.
- Extracted admin inline JavaScript into a dedicated file for easier maintenance.
- Standardized settings checkbox rendering and added a small username unslashing hardening improvement.

See [readme.txt](readme.txt) for the full changelog.

## License

This project is licensed under the GPL v2 or later — see the [LICENSE](https://www.gnu.org/licenses/gpl-2.0.html) for details.
