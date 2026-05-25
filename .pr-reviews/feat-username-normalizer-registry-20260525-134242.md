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


## [Codex — Reviewer] Round 2

NEEDS_FIX: The attempted fix makes XML-RPC lockout checks use raw usernames while other authentication paths write normalized keys, allowing `ip_username` lockouts to be bypassed.

**Finding 1: XML-RPC can bypass an existing per-username lockout by changing username casing or formatting**

- **File and lines:** [wp-login-delay.php](/Users/mike/Documents/www/login-delay-shield/trunk/wp-login-delay.php:1635), [wp-login-delay.php](/Users/mike/Documents/www/login-delay-shield/trunk/wp-login-delay.php:1638), [wp-login-delay.php](/Users/mike/Documents/www/login-delay-shield/trunk/wp-login-delay.php:2407), [wp-login-delay.php](/Users/mike/Documents/www/login-delay-shield/trunk/wp-login-delay.php:2448), [wp-login-delay.php](/Users/mike/Documents/www/login-delay-shield/trunk/wp-login-delay.php:2598)
- **What:** With `wldelay_lockout_attempt_strategy = ip_username`, an account locked through REST or normal login under normalized username `admin` is not blocked through XML-RPC when the request supplies an equivalent raw login such as `Admin`. The XML-RPC request checks the transient key for `IP|Admin`, while the lockout was written under `IP|admin`.
- **Why:** `wldelay_get_attempt_identifier()` no longer normalizes its `$username` parameter, but `wldelay_block_xmlrpc_auth()` passes WordPress's raw `$username` argument directly into `wldelay_is_ip_locked()`. In contrast, REST obtains its identifier through `wldelay_get_php_auth_username()`, which calls `wldelay_normalize_username()` before failed attempts create a lockout. The claimed invariant that all callers already pass normalized usernames is false for the XML-RPC path.
- **Impact:** An attacker can evade an existing per-account lockout on the XML-RPC authentication surface using a case or normalization variant of the same username, weakening brute-force enforcement across authentication backends even without any custom filter installed.
- **Fix:** Normalize the XML-RPC `$username` once before every lockout lookup, for example at entry to `wldelay_block_xmlrpc_auth()`, and audit other callers that pass attempted usernames directly, including recovery deletion paths. Prefer introducing separate clearly named raw-input and canonical-identifier APIs so key helpers cannot silently receive inconsistent representations. Add an integration test that creates an `ip_username` lockout for normalized `admin` and verifies an XML-RPC request using `Admin` is still rejected.
- **Severity:** BLOCKING
- **Fixable:** YES

---

## [Gemini — Reviewer] Round 2

LGTM: The critical issues regarding redundant normalization and empty filter returns have been addressed, and the architectural design trade-offs are acknowledged.

---

## [Claude — Implementer] Round 2

### Finding 1 — XML-RPC passes raw username, bypassing ip_username lockouts (Codex)

**Raised by:** Codex only | **Severity:** BLOCKING | **Verdict: AGREE — FIXED**

Codex is correct. Traced all four auth entry points:

| Entry point | Normalizes before lockout? |
|---|---|
| `wldelay_auth_login` | Yes — via `wldelay_get_requested_login_username()` |
| `wldelay_handle_rest_authentication` | Yes — via `wldelay_get_php_auth_username()` |
| `wldelay_handle_application_password_auth` | Yes — explicit `wldelay_normalize_username()` at line 2507 |
| `wldelay_block_xmlrpc_auth` | **No** — raw `$username` from WP `authenticate` filter |

With `ip_username` strategy, lockout written under `IP|admin` but XML-RPC checks `IP|Admin`. Case variant bypasses lockout.

**Fix:** Added `$username = wldelay_normalize_username( $username );` at entry to `wldelay_block_xmlrpc_auth()`, after early returns for disabled/whitelisted but before any lockout check or logging. All four auth paths now normalize before touching lockout keys.

---

## Round 2 Summary

| Issue | Raised by | Action | Reason |
|-------|-----------|--------|--------|
| XML-RPC raw username bypasses ip_username lockout | Codex | **Fixed** — normalize at entry to `wldelay_block_xmlrpc_auth` | Verified: only auth path missing normalization. Case variants produce different transient keys. |

All 217 tests pass after changes.

---

