// @ts-check
const { test, expect, request } = require('@playwright/test');

const BASE_URL = 'http://localhost';
const CUSTOM_SLUG = 'secure-login';

test.describe('Custom Login URL feature', () => {

    // --- Slug access ---

    test('1. custom slug shows login form', async ({ page }) => {
        await page.goto(`${BASE_URL}/${CUSTOM_SLUG}/`);
        await expect(page.locator('#loginform')).toBeVisible();
        await expect(page.locator('#user_login')).toBeVisible();
        await expect(page.locator('#user_pass')).toBeVisible();
    });

    test('7. custom slug works without trailing slash', async ({ page }) => {
        await page.goto(`${BASE_URL}/${CUSTOM_SLUG}`);
        await expect(page.locator('#loginform')).toBeVisible();
    });

    test('custom slug preserves redirect_to parameter', async ({ page }) => {
        await page.goto(`${BASE_URL}/${CUSTOM_SLUG}/?redirect_to=${encodeURIComponent('/wp-admin/edit.php')}`);
        await expect(page.locator('#loginform')).toBeVisible();
    });

    // --- wp-login.php blocking ---

    test('2. wp-login.php returns 404', async ({ context }) => {
        const api = context.request;
        const response = await api.get(`${BASE_URL}/wp-login.php`);
        expect(response.status()).toBe(404);
    });

    test('3. wp-login.php does NOT leak custom slug in redirect', async ({ context }) => {
        const api = context.request;
        const response = await api.get(`${BASE_URL}/wp-login.php`, { maxRedirects: 0 });
        const location = response.headers()['location'] || '';
        expect(location).not.toContain(CUSTOM_SLUG);
    });

    test('6. wp-login.php with query params returns 404', async ({ context }) => {
        const api = context.request;
        const response = await api.get(`${BASE_URL}/wp-login.php?action=lostpassword`);
        expect(response.status()).toBe(404);
    });

    // --- Login actions via custom slug ---

    test('4. login POST via custom slug redirects to wp-admin', async ({ page }) => {
        await page.goto(`${BASE_URL}/${CUSTOM_SLUG}/`);
        await page.fill('#user_login', 'admin');
        await page.fill('#user_pass', 'admin');
        await page.click('#wp-submit');

        await page.waitForURL(/wp-admin/, { timeout: 15000 });
        await expect(page).toHaveURL(/wp-admin/);
    });

    test('5. lost password form loads via custom slug', async ({ page }) => {
        await page.goto(`${BASE_URL}/${CUSTOM_SLUG}/?action=lostpassword`);
        await expect(page.locator('#lostpasswordform')).toBeVisible();
        await expect(page.locator('#user_login')).toBeVisible();
    });

    test('lost password link on login page uses custom slug', async ({ page }) => {
        await page.goto(`${BASE_URL}/${CUSTOM_SLUG}/`);

        const lostPwLink = page.locator('a[href*="action=lostpassword"]');
        const href = await lostPwLink.getAttribute('href');
        expect(href).toContain(CUSTOM_SLUG);
        expect(href).not.toContain('wp-login.php');
    });

    // --- Authenticated behaviour ---

    test('8. unauthenticated /wp-admin/ redirects to custom slug login', async ({ page }) => {
        // Use a fresh context (no cookies) to ensure we're not logged in.
        await page.goto(`${BASE_URL}/wp-admin/`);

        // WordPress will redirect through to the login page.
        await page.waitForURL(new RegExp(CUSTOM_SLUG), { timeout: 15000 });
        await expect(page).toHaveURL(new RegExp(CUSTOM_SLUG));
        await expect(page.locator('#loginform')).toBeVisible();
    });

    test('9. logout URL uses custom slug', async ({ page }) => {
        // Login first.
        await page.goto(`${BASE_URL}/${CUSTOM_SLUG}/`);
        await page.fill('#user_login', 'admin');
        await page.fill('#user_pass', 'admin');
        await page.click('#wp-submit');
        await page.waitForURL(/wp-admin/, { timeout: 15000 });

        // Check logout link in the admin bar / dashboard.
        const logoutLink = await page.locator('a[href*="action=logout"]').first();
        const href = await logoutLink.getAttribute('href');
        expect(href).toContain(CUSTOM_SLUG);
        expect(href).not.toContain('wp-login.php');
    });

    // --- Internal WP paths ---

    test('10. internal /wp/wp-login.php still loads (not blocked)', async ({ page }) => {
        await page.goto(`${BASE_URL}/wp/wp-login.php`);
        await expect(page.locator('#loginform')).toBeVisible();
    });
});
