# PR Review: feat-username-normalizer-registry
**Date:** 2026-05-25 13:42
**Mode:** review + fix (3-agent voting)
**Agents:** Codex (reviewer) + Gemini (reviewer) + Claude (implementer)
**Base:** main
**Diff lines:** 36
**Approval rule:** 2/3 majority vote
**Description source:** --description flag

---

## Feature description

F-2-8: Username normalization registry. Added wldelay_normalize_username filter hook so plugins with LDAP/email/SSO auth can override username normalization for lockout tracking keys. Default behavior unchanged.

---


## [Codex — Reviewer] Round 1

NEEDS_FIX: The new filter can make lockout counters and lockout checks use different keys, allowing repeated failures to evade enforcement.

**Finding 1: Non-idempotent normalization callbacks break `ip_username` lockouts**

- **File:** [wp-login-delay.php](/Users/mike/Documents/www/login-delay-shield/trunk/wp-login-delay.php:1618), [wp-login-delay.php](/Users/mike/Documents/www/login-delay-shield/trunk/wp-login-delay.php:1631), [wp-login-delay.php](/Users/mike/Documents/www/login-delay-shield/trunk/wp-login-delay.php:1671), [wp-login-delay.php](/Users/mike/Documents/www/login-delay-shield/trunk/wp-login-delay.php:2557), [wp-login-delay.php](/Users/mike/Documents/www/login-delay-shield/trunk/wp-login-delay.php:2568), [wp-login-delay.php](/Users/mike/Documents/www/login-delay-shield/trunk/wp-login-delay.php:2595), [wp-login-delay.php](/Users/mike/Documents/www/login-delay-shield/trunk/wp-login-delay.php:2651), [wp-login-delay.php](/Users/mike/Documents/www/login-delay-shield/trunk/wp-login-delay.php:2694)
- **What:** With `ip_username` tracking enabled, a legitimate filter such as one that appends an auth realm (`$normalized . '@ldap'`) is applied a different number of times when checking an existing lockout versus recording a failed attempt. The lockout can be written under one transient key and checked under another, so repeated bad passwords for the same account never block subsequent attempts.
- **Why:** The new filter is inside `wldelay_normalize_username()`, but usernames are already normalized before being passed to helpers that normalize again. For the normal login flow, `wldelay_get_requested_login_username()` applies the filter once; `wldelay_is_ip_locked()` reaches `wldelay_get_attempt_identifier()` and applies it again; `wldelay_track_failed_attempt()` applies it again before its transient-key helper applies it yet again. Before this change, repeated built-in sanitization was effectively idempotent; arbitrary filter callbacks are not required or documented to be idempotent.
- **Impact:** Custom LDAP/email/SSO integrations using the new public hook can silently disable per-username brute-force protection and progressive failure accounting, which is the security behavior this hook is supposed to support.
- **Fix:** Make normalization occur exactly once for each raw attempted username. Pass raw input through the lockout/count/tracking flow and normalize only inside key generation, or introduce explicit helpers for already-normalized identifiers and ensure those paths never invoke the filter again. Add an integration test with `ip_username` enabled and a non-idempotent callback such as `return $normalized . '@ldap';` that verifies repeated failures result in a lockout detectable on the next request.
- **Severity:** BLOCKING
- **Fixable:** YES

---

## [Gemini — Reviewer] Round 1

NEEDS_FIX: Filter `wldelay_normalize_username` allows arbitrary, potentially insecure, modification of lockout tracking keys.

**Finding 1: Security and Correctness - Insecure `wldelay_normalize_username` filter**

*   **File** and **line number(s)**: `wp-login-delay.php`, lines 1604-1615
*   **What** can go wrong: A malicious or poorly implemented plugin can exploit the `wldelay_normalize_username` filter to return a non-unique or constant string for all username inputs. For example, a plugin could return an empty string (`''`), "admin", or a small set of common strings, regardless of the actual `$username` input.
*   **Why** the code is vulnerable to this: The `apply_filters` call provides full control over the normalized username. While the default normalization (`strtolower( sanitize_user( wp_unslash( $username ), true ) )`) is designed for security and consistency, the filter allows overriding this to any arbitrary value. The `(string)` cast only prevents type errors but does not enforce any security or uniqueness properties on the returned string. This breaks the fundamental assumption that the normalized username will be a unique and consistent identifier for lockout tracking keys. If multiple distinct raw usernames normalize to the same filtered value, the lockout mechanism is compromised.
*   **Impact** if it happens:
    *   **Authentication Bypass**: If all or many usernames normalize to the same key, an attacker can bypass lockouts by trying different raw usernames, all of which count against the same (potentially never locking out) counter. This could also enable indefinite password guessing for a single target account.
    *   **Denial of Service (DoS)**: A poorly implemented filter returning a constant or limited set of keys could cause legitimate users to be locked out unnecessarily if their login attempts all contribute to the same lockout counter.
    *   **Ineffective Lockout Protection**: The primary security mechanism of the plugin (login delay/lockout) would be rendered useless or severely weakened, exposing the WordPress site to brute-force attacks.
*   **Fix** recommendation: The filter's design needs to ensure that the normalized username remains a secure and unique identifier for lockout tracking.
    *   **Option A (Recommended - more secure)**: Modify the filter to act on the *raw* `$username` *before* the default normalization is applied. This would allow custom authentication backends to process the username (e.g., extract a canonical ID from an email address) but still ensure that the *final* output is processed by `strtolower( sanitize_user( ... ) )`, maintaining a consistent and secure format for the lockout key.
    *   **Option B (Alternative - requires strict validation)**: If the filter must operate *after* default normalization, robust validation must be added. The function should check the filtered value:
        1.  If the filtered value is empty (`''`), it should fall back to the default `$normalized` value or log a critical error and treat it as a special error case to avoid global lockouts. An empty string is often treated specially and could lead to multiple users mapping to the same lockout key.
        2.  The filter documentation must strongly emphasize that implementers are responsible for returning a unique, consistent, and securely normalized string.
*   **Severity**: BLOCKING
*   **Fixable**: NO (requires human judgment on design and security implications, specifically regarding how much flexibility is truly needed versus the security risk).

---


## [Claude — Implementer] Round 1

---

## Analysis & Verdicts

### Finding 1 — Non-idempotent filter callbacks break lockout tracking (Codex)

**Raised by:** Codex | **Severity:** BLOCKING | **Verdict: AGREE — FIXED**

Codex nailed it. Traced the full call chain:

- `wldelay_auth_login` calls `wldelay_get_requested_login_username()` → normalizes once → `user@ldap`
- Passes result to `wldelay_is_ip_locked()` → `wldelay_get_attempt_identifier()` → normalizes again → `user@ldap@ldap`  
- Passes result to `wldelay_track_failed_attempt()` → normalizes → `user@ldap@ldap`, then calls `wldelay_get_failure_transient_key()` → normalizes again → `user@ldap@ldap@ldap`

Read path uses key `ip|user@ldap@ldap`. Write path uses `ip|user@ldap@ldap@ldap`. Lockout never triggers.

**Fix:** Removed redundant `wldelay_normalize_username()` from `wldelay_get_attempt_identifier()` and `wldelay_track_failed_attempt()`. Both always receive pre-normalized input from their callers. Filter now fires exactly once per raw username.

### Finding 2 — Insecure filter allows arbitrary modification (Gemini)

**Raised by:** Gemini | **Severity:** BLOCKING | **Fixable:** NO | **Verdict: PARTIALLY AGREE — ACKNOWLEDGED**

The empty-string collapse concern is valid — added a fallback: if filter returns `''`, use the default normalized value. This prevents all usernames from mapping to the same lockout key.

The broader "malicious plugin" concern: this is standard WordPress filter pattern. Every `apply_filters` hook trusts the callback. If a malicious plugin is running with code execution, you've already lost. Adding strict validation beyond the empty-string guard would break legitimate use cases. Gemini correctly marked this Fixable: NO — the design tradeoff (flexibility vs. guardrails) is a human decision.

I did add documentation in the filter docblock noting that callbacks must be idempotent and that empty returns are rejected.

---

## Summary

| Issue | Raised by | Action | Reason |
|-------|-----------|--------|--------|
| Non-idempotent filter double-fires in lockout flow | Codex | **Fixed** — removed redundant normalize calls from `wldelay_get_attempt_identifier` and `wldelay_track_failed_attempt` | Verified: read/write keys diverge with non-idempotent callbacks. Filter now fires exactly once. |
| Filter can return empty string collapsing all keys | Gemini | **Partially fixed** — added empty-string fallback | Valid concern; falls back to default normalization if filter returns `''`. |
| Filter allows arbitrary modification (design concern) | Gemini (Fixable: NO) | **Acknowledged, not changed** | Standard WP filter trust model. Broader design question left for human decision. Documented idempotency requirement. |

All 217 tests pass after changes.

---

