# PR Review: feat-security-health-score
**Date:** 2026-05-25 13:58
**Mode:** review + fix (3-agent voting)
**Agents:** Codex (reviewer) + Gemini (reviewer) + Claude (implementer)
**Base:** main
**Diff lines:** 209
**Approval rule:** 2/3 majority vote
**Description source:** --description flag

---

## Feature description

F-1-4: Security health score card. Weighted 0-100 score with donut chart in summary box. Shows next recommended feature to enable. Replaces plain X/N counter with actionable guidance.

---


## [Codex — Reviewer] Round 1

NEEDS_FIX: The new health card reports stale and incorrectly prioritized guidance, so its central actionable-status behavior is not reliable.

**Finding 1: The score card becomes internally inconsistent as soon as an admin toggles a feature**

- **File:** [wldelay-settings-view.php](/Users/mike/Documents/www/login-delay-shield/trunk/wldelay-settings-view.php:238) lines 238-247; [admin.js](/Users/mike/Documents/www/login-delay-shield/trunk/admin.js:29) lines 29-46
- **What:** When an admin enables or disables a feature before submitting the form, the feature indicators update immediately, but the displayed score, enabled fraction, and recommendation remain based on the old saved state. For example, enabling `IP Lockout` can leave the card showing the old score and still recommending that `IP Lockout` be enabled.
- **Why:** The patch removes `#wldelay-enabled-count`, which `updateSummary()` still attempts to update at `admin.js:45`, and adds new server-rendered score/recommendation elements without any client-side update path.
- **Impact:** The new security-health UI provides contradictory security guidance during normal settings interaction. An admin can be told that an already-selected protection remains disabled or see an incorrect health score before saving.
- **Fix:** Add stable DOM targets/data for the fraction, score circle/value, and recommendation; update them in `updateSummary()` using the same feature weights as PHP, including recalculating the highest-priority disabled recommendation. Alternatively, remove live summary mutation entirely so the card consistently reflects only saved settings.
- **Severity:** BLOCKING
- **Fixable:** YES

**Finding 2: “Next recommended” does not select the highest-value disabled feature**

- **File:** [wp-login-delay.php](/Users/mike/Documents/www/login-delay-shield/trunk/wp-login-delay.php:1468) lines 1468-1502
- **What:** If `IP Lockout`, `Progressive Delay`, `Custom Login URL`, `XML-RPC Protection`, and `Email Alerts` are enabled, while `IP Whitelist` and `fail2ban Logging` are disabled, the card recommends `IP Whitelist (+5 points)` instead of `fail2ban Logging (+10 points)`.
- **Why:** `$recommendation` is assigned to the first disabled item encountered, but the feature list is not ordered descending by points: the three 5-point features precede 10-point `fail2ban Logging`.
- **Impact:** The card’s actionable recommendation contradicts its weighted scoring model and the function contract stating it returns the “top disabled feature.” Users are directed to a lower-impact action.
- **Fix:** Select the disabled feature with the greatest `points` during iteration, or sort the feature definitions by descending weight and enforce that order with a test.
- **Severity:** BLOCKING
- **Fixable:** YES

---

## [Gemini — Reviewer] Round 1

NEEDS_FIX: Recommendation logic selects the first disabled feature instead of the most impactful.

**File:** `wp-login-delay.php`
**Line number(s):** 1475-1483
**What can go wrong:** The "next recommended feature" is determined by its arbitrary order in the `$features` array, not by its security impact or points value. This can lead to recommending a low-impact feature when a higher-impact one is also disabled.
**Why the code is vulnerable to this:** The `elseif ( $recommendation === null )` condition ensures that `recommendation` is assigned to the first disabled feature encountered during the `foreach` loop iteration. This prioritizes features earlier in the array over potentially more critical or higher-scoring ones listed later.
**Impact if it happens:** Users might receive suboptimal recommendations for improving their security posture. This could reduce the effectiveness of the "actionable guidance" intended by the feature, potentially leading to a less secure system or user frustration if a minor recommendation is given when a more significant one is available.
**Fix recommendation:** Implement a logic that selects the disabled feature with the highest `points` value as the recommendation. This would involve collecting all disabled features and then sorting them to find the most impactful one, or iterating to find the maximum.

Example of how to change the recommendation logic to pick the highest scoring disabled feature:
```php
    $score          = 0;
    $max            = 0;
    $recommendation = null;
    $scored         = array();
    $disabled_features = array(); // Store all disabled features

    foreach ( $features as $key => $feature ) {
        $enabled       = ! empty( $options[ $key ] );
        $max          += $feature['points'];
        $scored[ $key ] = array(
            'label'   => $feature['label'],
            'points'  => $feature['points'],
            'enabled' => $enabled,
        );

        if ( $enabled ) {
            $score += $feature['points'];
        } else {
            // Store disabled features for later recommendation selection
            $disabled_features[] = array(
                'key'    => $key,
                'label'  => $feature['label'],
                'points' => $feature['points'],
            );
        }
    }

    // Now, determine the recommendation from the disabled features
    if ( ! empty( $disabled_features ) ) {
        // Sort by points in descending order
        usort( $disabled_features, function( $a, $b ) {
            return $b['points'] <=> $a['points'];
        });
        // Pick the first one (highest points)
        $recommendation = $disabled_features[0];
    }
```
**Severity:** BLOCKING (due to misleading actionable guidance as described in the feature description)
**Fixable:** YES

---


## [Claude — Implementer] Round 1

---

## Summary

| Issue | Raised by | Action | Reason |
|-------|-----------|--------|--------|
| Recommendation picks first disabled feature, not highest-value | Both (Codex + Gemini) | **Fixed** | Must fix — 2/3 majority. Changed `elseif ($recommendation === null)` to also compare `$feature['points'] > $recommendation['points']`, so the highest-scoring disabled feature wins. |
| Score card goes stale on client-side toggle | Codex only | **Fixed (agree)** | `#wldelay-enabled-count` was removed but `updateSummary()` still targeted it. New score circle, fraction, and recommendation had no JS update path. Added feature weights to `wldelayAdmin` config and rewrote `updateSummary()` to recalculate score, update `--score-pct`, fraction text, and recommendation on every toggle. |

---


## [Codex — Reviewer] Round 2

NEEDS_FIX: The live security score fix omits the Custom Login URL toggle, leaving the card stale for a 15-point feature.

**Finding 1: Toggling Custom Login URL does not recalculate the security health card**

- **File:** [admin.js](/Users/mike/Documents/www/login-delay-shield/trunk/admin.js:142) lines 142-170; [wldelay-settings-view.php](/Users/mike/Documents/www/login-delay-shield/trunk/wldelay-settings-view.php:1088) lines 1088-1092; [wp-login-delay.php](/Users/mike/Documents/www/login-delay-shield/trunk/wp-login-delay.php:1483) line 1483
- **What:** If an admin checks or unchecks `Custom Login URL`, the summary feature status, score circle, enabled fraction, and recommendation do not update before saving. For example, when `Custom Login URL` is the recommended disabled 15-point feature, enabling it leaves the card still recommending it.
- **Why:** `wldelay_custom_login_enabled` is included in the scored features and is rendered as a checkbox, but `admin.js` registers live `updateSummary()` handlers only for the other scored toggles. There is no change handler for `#wldelay_custom_login_enabled`.
- **Impact:** The primary guidance added by this feature remains incorrect during a normal settings change, and can understate the displayed score by 15 points.
- **Fix:** Add a `change` handler for `#wldelay_custom_login_enabled` that calls `updateSummary('wldelay_custom_login_enabled', $(this).prop('checked'))` and updates its status badge consistently with the other badge-bearing features.
- **Severity:** BLOCKING
- **Fixable:** YES

---

## [Gemini — Reviewer] Round 2

LGTM: All previously identified blocking issues have been addressed. Both the server-side and client-side logic for security score calculation and recommendation are now consistent and correctly prioritize the highest-value disabled features.

---


## [Claude — Implementer] Round 2

---

## Summary

| Issue | Raised by | Action | Reason |
|-------|-----------|--------|--------|
| Custom Login URL toggle missing JS change handler | Codex only | **Fixed (agree)** | All 8 other scored features had change handlers calling `updateSummary()` + `updateBadge()`. Custom Login URL (15 pts) was the only one missing. Added handler that toggles slug sub-field visibility, updates badge, and recalculates score. |

---


## [Claude — Implementer] Round 2

All 217 tests pass (1 skipped — pre-existing).

---

## Round 2 Summary

| Issue | Raised by | Action | Reason |
|-------|-----------|--------|--------|
| Custom Login URL toggle missing JS change handler | Codex only | **Fixed (agree)** | All 8 other scored features had change handlers calling `updateSummary()` + `updateBadge()`. Custom Login URL (15 pts) was the only one missing. Added handler at `admin.js:142` that toggles slug sub-field visibility, updates badge, and recalculates score card on every toggle. |

---


## [Codex — Reviewer] Round 3

NEEDS_FIX: The live recommendation update introduces a stored XSS path through translated text inserted with `.html()`.

**Finding 1: A translation can inject markup or script into the settings page during any toggle update**

- **File:** `admin.js`, lines 62-72 of the diff; `wp-login-delay.php`, lines 98-100 of the diff
- **What:** If the localized `recommendTpl` string contains HTML, such as a malicious translation value supplied through a compromised/custom language pack, changing any protection checkbox inserts that HTML into the admin settings page. For example, an injected `<img src=x onerror=...>` payload in the translated recommendation template executes when the recommendation is redrawn.
- **Why:** PHP localizes `__( 'Next recommended: enable %1$s (+%2$d points)', ... )` directly into `wldelayAdmin.recommendTpl`, and `admin.js` concatenates that value into `$rec.html(...)` without escaping it. Server-rendered output uses `esc_html__()`, but the new client-side rendering path bypasses that protection.
- **Impact:** A malicious or compromised translation package can execute JavaScript in an administrator's browser, potentially enabling account/session compromise or unauthorized plugin-setting changes.
- **Fix:** Do not construct the localized sentence through `.html()`. Build the recommendation using DOM text nodes and a separately created `<strong>` element, assigning translated strings through `.text()`; alternatively, localize escaped/non-HTML sentence fragments and insert only the explicitly created markup node.
- **Severity:** BLOCKING
- **Fixable:** YES

---

## [Gemini — Reviewer] Round 3

LGTM: All previously identified blocking issues have been addressed by Claude's changes in both server-side and client-side logic. The security score calculation and recommendation now correctly prioritize the highest-value disabled features and update dynamically on the client-side.

---


## [Claude — Implementer] Round 3

217 tests pass (1 skipped — pre-existing).

---

## Round 3 Analysis

**Finding: XSS via `.html()` on translated recommendation template** — Codex only, Gemini LGTM.

**My verdict: Agree with Codex. Fixed.**

Codex is correct. `__()` returns raw translation text — a compromised/malicious language pack could inject `<img src=x onerror=...>` into `recommendTpl`. The server-side path correctly uses `esc_html__()`, but the JS path dumped the unescaped translation directly into `.html()`. Classic asymmetric escaping bug.

**What changed:**
- **`wp-login-delay.php`**: Split single `recommendTpl` into `recommendPrefix` ("Next recommended: enable") and `recommendSuffix` ("(+%d points)") — both still `__()` but no longer concatenated with HTML
- **`admin.js`**: Replaced `.html()` string concatenation with DOM construction — `document.createTextNode()` for translated strings, explicit `$('<strong></strong>').text()` for feature name. No path from translation → innerHTML now.

| Issue | Raised by | Action | Reason |
|-------|-----------|--------|--------|
| XSS via `.html()` on translated recommendation template | Codex only | **Fixed (agree)** | Real vector — compromised language packs are documented WordPress attack surface. Server-side used `esc_html__()` but client-side `.html()` bypassed escaping. Rebuilt with DOM text nodes so translated strings never parse as HTML. |

---

