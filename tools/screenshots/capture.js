/**
 * Capture wordpress.org listing screenshots from a running WP instance.
 *
 * Dev-only — runs inside a Playwright container, driven by
 * bin/screenshots.sh. Never shipped (bin/package.sh uses an allowlist).
 *
 * Captures the four screenshots described in readme.txt "== Screenshots ==":
 *   1. Settings page with Security Setup Wizard and delay configuration.
 *   2. Email notification and IP lockout settings.
 *   3. IP whitelist and XML-RPC protection settings.
 *   4. Dashboard widget showing recent failed login attempts.
 *
 * Env:
 *   WP_BASE_URL  base URL of the WordPress site (default http://wp:8080)
 *   OUTPUT_DIR   where screenshot-N.png files are written (default /output)
 */

'use strict';

const { chromium } = require('playwright-core');

const BASE = process.env.WP_BASE_URL || 'http://wp:8080';
const OUT = process.env.OUTPUT_DIR || '/output';

// Match the dimensions of the existing wordpress.org screenshots.
const VIEWPORT = { width: 1200, height: 900 };

async function login(page) {
    await page.goto(`${BASE}/wp-login.php`, { waitUntil: 'domcontentloaded' });
    await page.fill('#user_login', 'admin');
    await page.fill('#user_pass', 'admin');
    await Promise.all([
        page.waitForURL(/wp-admin/, { timeout: 30000 }),
        page.click('#wp-submit'),
    ]);
}

// Scroll a settings section into view by heading text; fall back to a
// fractional page scroll so a markup change degrades the framing, not
// the whole run.
async function scrollToSection(page, headingTexts, fallbackFraction) {
    for (const text of headingTexts) {
        const heading = page
            .locator('h1, h2, h3, h4')
            .filter({ hasText: text })
            .first();
        if (await heading.count()) {
            await heading.scrollIntoViewIfNeeded();
            // Nudge up slightly so the heading isn't glued to the viewport top.
            await page.mouse.wheel(0, -60);
            await page.waitForTimeout(250);
            return true;
        }
    }
    await page.evaluate((fraction) => {
        window.scrollTo(0, document.body.scrollHeight * fraction);
    }, fallbackFraction);
    await page.waitForTimeout(250);
    return false;
}

async function hideAdminNoise(page) {
    // Core update nags and unrelated notices churn the screenshots between
    // WP releases; the plugin's own UI is what the listing should show.
    await page.addStyleTag({
        content:
            '.update-nag, .notice:not([class*="wldelay"]), #wp-admin-bar-updates { display: none !important; }',
    });
}

(async () => {
    const browser = await chromium.launch();
    const page = await browser.newPage({ viewport: VIEWPORT, deviceScaleFactor: 2 });

    await login(page);

    // --- Screenshots 1-3: the settings page at three scroll positions ---
    await page.goto(
        `${BASE}/wp-admin/options-general.php?page=login-delay-shield-admin`,
        { waitUntil: 'networkidle' }
    );
    await hideAdminNoise(page);

    await page.evaluate(() => window.scrollTo(0, 0));
    await page.waitForTimeout(250);
    await page.screenshot({ path: `${OUT}/screenshot-1.png` });
    console.log('captured screenshot-1.png (setup wizard + delay config)');

    const found2 = await scrollToSection(
        page,
        ['Email Notification', 'Email notification', 'IP Lockout', 'IP lockout'],
        0.35
    );
    await page.screenshot({ path: `${OUT}/screenshot-2.png` });
    console.log(`captured screenshot-2.png (email + lockout)${found2 ? '' : ' [fallback scroll]'}`);

    // The whitelist and XML-RPC cards are not adjacent in the card grid, so
    // a single anchor can't frame both. Compute the union of their bounding
    // boxes, scroll its top into view, and grow the viewport if it doesn't
    // fit 900px — wordpress.org accepts varying screenshot heights.
    const card3a = page
        .locator('.wldelay-card', { hasText: 'IP Whitelist' })
        .first();
    const card3b = page
        .locator('.wldelay-card', { hasText: 'XML-RPC Protection' })
        .first();
    if ((await card3a.count()) && (await card3b.count())) {
        // Element-shoot each card, then place the two PNGs side by side at
        // their natural widths on a synthetic page — no image library needed.
        // Hide the fixed admin bar so it can't bleed into the element shots.
        await page.evaluate(() => {
            const bar = document.getElementById('wpadminbar');
            if (bar) bar.style.display = 'none';
        });
        await card3a.scrollIntoViewIfNeeded();
        const bufA = await card3a.screenshot();
        await card3b.scrollIntoViewIfNeeded();
        const bufB = await card3b.screenshot();
        await page.evaluate(() => {
            const bar = document.getElementById('wpadminbar');
            if (bar) bar.style.display = '';
        });

        const composite = await browser.newPage({ deviceScaleFactor: 1 });
        await composite.setContent(`
            <body style="margin:0;background:#f0f0f1;">
              <div id="stack" style="display:flex;gap:16px;padding:16px;align-items:flex-start;width:fit-content;">
                <img src="data:image/png;base64,${bufA.toString('base64')}" style="display:block;">
                <img src="data:image/png;base64,${bufB.toString('base64')}" style="display:block;">
              </div>
            </body>`);
        await composite.locator('#stack img').first().waitFor();
        await composite.locator('#stack').screenshot({ path: `${OUT}/screenshot-3.png` });
        await composite.close();
        console.log('captured screenshot-3.png (whitelist + xml-rpc, side-by-side cards)');
    } else {
        await scrollToSection(page, ['IP Whitelist', 'XML-RPC'], 0.6);
        await page.screenshot({ path: `${OUT}/screenshot-3.png` });
        console.log('captured screenshot-3.png (whitelist + xml-rpc) [fallback]');
    }

    // --- Screenshot 4: dashboard widget ---
    await page.goto(`${BASE}/wp-admin/index.php`, { waitUntil: 'networkidle' });
    await hideAdminNoise(page);

    const widget = page.locator('#wldelay_failed_logins_widget');
    if (!(await widget.count())) {
        throw new Error(
            'Dashboard widget #wldelay_failed_logins_widget not found — is the plugin active and the user an admin?'
        );
    }
    await widget.scrollIntoViewIfNeeded();
    await page.waitForTimeout(250);
    await page.screenshot({ path: `${OUT}/screenshot-4.png` });
    console.log('captured screenshot-4.png (dashboard widget)');

    await browser.close();
    console.log('All screenshots written to', OUT);
})().catch((err) => {
    console.error(err);
    process.exit(1);
});
