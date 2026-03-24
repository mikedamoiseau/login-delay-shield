# Login Delay Shield

[![WordPress Plugin Version](https://img.shields.io/wordpress/plugin/v/wp-login-delay)](https://wordpress.org/plugins/wp-login-delay/)
[![WordPress Plugin: Tested WP Version](https://img.shields.io/wordpress/plugin/tested/wp-login-delay)](https://wordpress.org/plugins/wp-login-delay/)
[![License: GPL v2+](https://img.shields.io/badge/License-GPLv2+-blue.svg)](https://www.gnu.org/licenses/gpl-2.0.html)

Login Delay Shield slows down brute-force attacks by adding a configurable delay to failed login attempts while keeping successful logins instant.

## Description

WordPress is one of the most widely used content management systems on the internet, making it a frequent target for bots and hackers attempting brute-force attacks.

A brute-force attack works by systematically trying passwords until finding the correct one. Login Delay Shield defends against this by adding a configurable delay after each failed login attempt. Since successful logins are never delayed, legitimate users experience no slowdown. This approach is particularly effective against bots that send thousands of login requests, as each failed attempt forces the attacker to wait before trying the next password.

### Features

- **Login delay** — Fixed or random delay on failed login attempts (1-10 seconds)
- **Progressive delay** — Delay increases with each consecutive failed attempt from the same IP
- **IP lockout** — Temporarily block IP addresses after too many failed attempts
- **Username-aware lockout strategy** — Choose `IP only` or `IP + username` to reduce false positives on shared networks
- **Login feedback** — Shows remaining attempts before lockout and a lockout countdown when blocked
- **IP whitelist** — Bypass all security measures for trusted IPs (supports CIDR notation)
- **Email notifications** — Receive alerts when failed login thresholds are reached
- **Failed login log** — Track all failed attempts with a dashboard widget showing recent activity and 7-day trends
- **XML-RPC protection** — Apply delays to XML-RPC authentication or block it entirely
- **REST/API auth protection (optional)** — Apply delay/lockout checks to REST and application-password authentication paths
- **Log retention** — Automatic cleanup of old log entries (configurable retention period)
- **Recovery tools** — Admin unlock action and WP-CLI commands to flush lockouts
- **Accessible admin interface** — WCAG 2.1 compliant with keyboard navigation and screen reader support
- **Multilingual** — Translated into 18 languages including French, German, Spanish, Japanese, Chinese, Arabic, and more
- Lightweight and compatible with other security plugins

> *This plugin is not a complete security solution — dedicated security plugins offer more comprehensive protection.* However, Login Delay Shield adds an effective layer of defense that works alongside your existing security measures without conflict.

## Installation

1. Upload the `wp-login-delay` folder to the `/wp-content/plugins/` directory
2. Activate the plugin through the 'Plugins' menu in WordPress
3. That's it, Login Delay Shield is installed and working

Settings are available under **Settings > Login Delay Shield**.

## FAQ

### How does this plugin protect my site?

When a bot attempts a brute-force attack, it tries thousands of passwords as fast as possible. By adding a delay (even just 1 second) after each failed attempt, the attack becomes impractical. A one-second delay is barely noticeable to legitimate users but makes a huge difference when multiplied across thousands of attempts.

### What is progressive delay?

Progressive delay increases the wait time with each consecutive failed attempt from the same IP address. For example, the first failure might delay 1 second, the second failure 2 seconds, and so on. This makes repeated attacks increasingly slow.

### How does IP lockout work?

After a configurable number of failed attempts (default: 10), login attempts are temporarily blocked. You can choose whether attempts are counted by `IP only` or by `IP + username` (recommended for shared office/mobile IPs). Lockout duration is configurable (default: 60 minutes).

### How do I whitelist my own IP?

Enable the IP whitelist feature and add your IP address (or a range using CIDR notation like `192.168.1.0/24`). Whitelisted IPs bypass all delays and lockouts, ensuring you never lock yourself out.

### Should I block XML-RPC?

If you don't use the WordPress mobile app or remote publishing tools like Windows Live Writer, blocking XML-RPC authentication removes a common attack vector. You can also choose to just apply delays without blocking it entirely.

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

### Unreleased

- Updated the WordPress.org listing metadata, including a more accurate minimum PHP version and refreshed tags.
- Extracted admin inline JavaScript into a dedicated file for easier maintenance.
- Standardized settings checkbox rendering and added a small username unslashing hardening improvement.

See [readme.txt](readme.txt) for the full changelog.

## License

This project is licensed under the GPL v2 or later — see the [LICENSE](https://www.gnu.org/licenses/gpl-2.0.html) for details.
