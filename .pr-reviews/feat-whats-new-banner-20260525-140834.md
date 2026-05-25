# PR Review: feat-whats-new-banner
**Date:** 2026-05-25 14:08
**Mode:** review + fix (3-agent voting)
**Agents:** Codex (reviewer) + Gemini (reviewer) + Claude (implementer)
**Base:** main
**Diff lines:** 116
**Approval rule:** 2/3 majority vote
**Description source:** --description flag

---

## Feature description

F-5-1: Release notes in-plugin banner. Dismissible What's New notice after upgrade showing curated feature highlights (no security details). AJAX dismiss per version. Follows existing name-change notice pattern.

---


## [Codex — Reviewer] Round 1

NEEDS_FIX: The banner is shown after downgrades as though the installed older version were a new upgrade.

**Finding 1: Rollbacks incorrectly trigger the "What's New" upgrade banner**

- **File:** [wp-login-delay.php](/Users/mike/Documents/www/login-delay-shield/trunk/wp-login-delay.php:1470), [wp-login-delay.php](/Users/mike/Documents/www/login-delay-shield/trunk/wp-login-delay.php:1536)
- **Line(s):** 1470-1477, 1536-1543
- **What:** If a site rolls back from a newer plugin version to `2.2.4`, administrators receive a banner saying "What's new in Login Delay Shield 2.2.4" and listing `2.2.4` features, even though they have just installed an older version.
- **Why:** `wldelay_track_version()` records any differing installed version as `wldelay_previous_version`, regardless of whether it is older or newer than `WLDELAY_VERSION`. `wldelay_show_whats_new_notice()` only checks that this option is non-empty; it never verifies that `$previous_version < WLDELAY_VERSION`.
- **Impact:** The feature violates its stated after-upgrade behavior and gives misleading release information during a legitimate rollback/recovery workflow.
- **Fix:** Gate notice display on an actual upgrade, for example:
  ```php
  if ( empty( $previous_version ) || version_compare( $previous_version, WLDELAY_VERSION, '>=' ) ) {
      return;
  }
  ```
  Add a test that sets `wldelay_plugin_version` to a higher version than `WLDELAY_VERSION`, runs version tracking, and asserts that `wldelay_show_whats_new_notice()` renders no banner.
- **Severity:** BLOCKING
- **Fixable:** YES

---

## [Gemini — Reviewer] Round 1

NEEDS_FIX: The "What's New" banner is non-functional due to incorrect nonce verification and failure to track previous plugin versions.

### Detailed Findings

**1. Correctness: Nonce Verification Failure for "What's New" Dismissal**
*   **File:** `admin.js` (lines 217-219), `wp-login-delay.php` (line 1489)
*   **What can go wrong:** The "What's New" notice, once displayed, cannot be dismissed by users clicking the dismiss button. The AJAX request to dismiss the notice will consistently fail due to an invalid security nonce.
*   **Why the code is vulnerable to this:** The JavaScript in `admin.js` sends `_wpnonce: config.dismissNoticeNonce` for the `wldelay_dismiss_whats_new_notice` AJAX action. However, the PHP handler `wldelay_dismiss_whats_new_notice` calls `check_ajax_referer( 'wldelay_dismiss_notice', '_wpnonce' );`. The `config.dismissNoticeNonce` appears to be a global nonce, and based on existing code (`wldelay_dismiss_name_change_notice` using `check_ajax_referer( 'wldelay_dismiss_name_change_notice', '_wpnonce' );` and also sending `config.dismissNoticeNonce`), it is highly likely that `config.dismissNoticeNonce` is generated for the `'wldelay_dismiss_name_change_notice'` action. This mismatch in nonce action strings will cause `check_ajax_referer` to fail.
*   **Impact:** The user experience is significantly degraded as the "What's New" banner will persistently remain visible, even after the user attempts to dismiss it. The intended functionality of dismissing per version will not work.
*   **Fix recommendation:** A dedicated nonce for the "What's New" dismissal action needs to be generated in the PHP backend (e.g., `wp_create_nonce( 'wldelay_dismiss_notice' )`) and passed to the frontend JavaScript via `wp_localize_script` with a unique key (e.g., `config.dismissWhatsNewNoticeNonce`). The `admin.js` code should then use this new, specific nonce in its AJAX post request.
*   **Severity:** BLOCKING
*   **Fixable:** YES

**2. Correctness: "What's New" Banner Will Never Display Due to Missing Previous Version Tracking**
*   **File:** `wp-login-delay.php` (lines 1461-1463)
*   **What can go wrong:** The "What's New" banner, intended to inform users after a plugin upgrade, will never be displayed because a critical condition for its display (`$previous_version` being non-empty) is never met.
*   **Why the code is vulnerable to this:** The `wldelay_show_whats_new_notice()` function includes the conditional `if ( empty( $previous_version ) ) { return; }`, where `$previous_version` is obtained from `get_option( 'wldelay_previous_version', '' )`. The provided diff, and by extension the current plugin's update mechanism (as inferred from `wldelay_track_version` which only updates `wldelay_plugin_version`), does not include any logic to set or update the `wldelay_previous_version` option. Therefore, this option will always remain empty, causing the `wldelay_show_whats_new_notice` function to return prematurely.
*   **Impact:** The core purpose of the "What's New" feature—to announce new features post-upgrade—is completely undermined, as the banner will never appear for any user.
*   **Fix recommendation:** The plugin's version tracking logic, specifically `wldelay_track_version()`, needs to be updated. Before `update_option( 'wldelay_plugin_version', WLDELAY_VERSION );` is called, the current value of `wldelay_plugin_version` (which represents the *previous* version) should be saved to `wldelay_previous_version`.
*   **Severity:** BLOCKING
*   **Fixable:** YES

---


## [Claude — Implementer] Round 1

217 tests pass, 570 assertions. Fix is clean.

---

## Summary

| Issue | Raised by | Action | Reason |
|-------|-----------|--------|--------|
| Rollbacks trigger "What's New" banner | Codex only | **Fixed (agree)** | Added `version_compare($previous_version, WLDELAY_VERSION, '>=')` guard so banner only shows on actual upgrades, not downgrades. |
| Nonce verification failure for dismiss | Gemini only | **Pushback (disagree)** | Both dismiss handlers use same action string `'wldelay_dismiss_notice'`, matching the nonce generated at line 98. No mismatch exists. |
| Missing previous version tracking | Gemini only | **Pushback (disagree)** | `wldelay_track_version()` at lines 1539-1541 already saves `wldelay_previous_version` before updating. Gemini analyzed truncated diff context, missed existing code. |

---

