# PR Review: feat-contextual-help-links
**Date:** 2026-05-25 14:14
**Mode:** review + fix (3-agent voting)
**Agents:** Codex (reviewer) + Gemini (reviewer) + Claude (implementer)
**Base:** main
**Diff lines:** 71
**Approval rule:** 2/3 majority vote
**Description source:** --description flag

---

## Feature description

F-5-6: Contextual help & video links. Extended tooltip() with optional help_url parameter. Renders Learn more link inside tooltip popup. Styled to match tooltip theme. No existing tooltips changed.

---


## [Codex — Reviewer] Round 1

NEEDS_FIX: The new “Learn more” link disappears as soon as a keyboard user tries to focus it.

**Finding 1: Keyboard users cannot reliably access the new tooltip link**

- **File:** `admin.css:445-449`; `wldelay-settings-view.php:41`
- **Severity:** BLOCKING
- **Fixable:** YES
- **What:** When a keyboard user tabs to the tooltip trigger, the popup becomes visible. Pressing `Tab` to reach the newly added “Learn more” anchor moves focus off `.wldelay-tooltip`; since the popup is only shown for `:hover` or `:focus`, it immediately becomes hidden while the link is being entered.
- **Why:** The anchor is a focusable descendant inside `.wldelay-tooltip-text`, but the visibility selector does not preserve the popup while focus is anywhere inside the tooltip component:
  ```css
  .wldelay-tooltip:hover .wldelay-tooltip-text,
  .wldelay-tooltip:focus .wldelay-tooltip-text
  ```
  The new `<a>` introduces a second focus target without adding `:focus-within` handling.
- **Impact:** The feature is unusable or visually lost for keyboard-only users. This directly regresses the component’s documented keyboard accessibility once any tooltip supplies a help URL.
- **Fix:** Keep the popup visible whenever the wrapper or any descendant has focus, for example:
  ```css
  .wldelay-tooltip:hover .wldelay-tooltip-text,
  .wldelay-tooltip:focus-within .wldelay-tooltip-text {
      visibility: visible;
      opacity: 1;
  }
  ```
  Also test tabbing from the trigger onto the link and back out of the tooltip.

---

## [Gemini — Reviewer] Round 1

LGTM: The changes correctly implement the feature with appropriate security sanitization and styling.

No specific issues found that would block this PR. The use of `esc_url()` for the `$help_url` parameter and `esc_html()` for the `$text` parameter correctly prevents XSS vulnerabilities. The `target="_blank" rel="noopener noreferrer"` attributes are good security practice for external links. The CSS changes are consistent with the new UI element.

---


## [Claude — Implementer] Round 1

Fix applied. Here's the analysis:

---

**Finding 1 (Codex): Keyboard users cannot reach "Learn more" link**
- **Raised by:** Codex only
- **My verdict:** Agree. `:focus` on the wrapper doesn't cover focus on child elements. Tabbing to the `<a>` inside the tooltip moves focus away from `.wldelay-tooltip`, hiding the popup before the link can be activated. `:focus-within` is the correct fix — supported in all modern browsers and already used elsewhere in this file's focus management pattern.
- **Action:** Fixed. Added `.wldelay-tooltip:focus-within .wldelay-tooltip-text` selector alongside existing `:hover` and `:focus` rules.

**Gemini's LGTM:** Agree with their assessment — escaping is correct (`esc_url`, `esc_html`, `esc_attr`), `rel="noopener noreferrer"` is proper, CSS is consistent.

---

| Issue | Raised by | Action | Reason |
|-------|-----------|--------|--------|
| Tooltip hides when tabbing to "Learn more" link | Codex | **Fixed** — added `:focus-within` selector | Real a11y bug: `:focus` only matches the element itself, not descendants. Child `<a>` gets focus but parent loses it, hiding tooltip. |

---

