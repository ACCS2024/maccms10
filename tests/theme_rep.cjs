const {chromium} = require('playwright');
const assert = require('node:assert/strict');
const {execFileSync} = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '..');
const fixtures = JSON.parse(execFileSync('php', [path.join(__dirname, 'theme_rep.php')], {encoding: 'utf8'}));
const css = fs.readFileSync(root + '/template/m1938pc3_v2/assets/v2/theme.css', 'utf8');

(async () => {
  const browser = await chromium.launch({executablePath: process.env.CHROMIUM_PATH || '/usr/bin/chromium', args: ['--no-sandbox']});
  const results = [];
  try {
    for (const width of [1440, 768, 390, 360]) {
      const page = await browser.newPage({viewport: {width, height: 1000}});
      for (const [state, html] of Object.entries(fixtures)) {
        await page.setContent(`<!doctype html><meta charset="utf-8"><style>${css}</style><main class="wrap"><section class="service-board">${html}</section></main>`);
        if (state === 'disabled') {
          assert.equal(await page.locator('.replacement-notice').count(), 0);
          continue;
        }
        assert(await page.locator('.replacement-link').isVisible());
        assert.equal(await page.evaluate(() => document.documentElement.scrollWidth), width);
        if (state === 'published') {
          assert.equal(await page.locator('time').innerText(), '2026-09-09 17:06');
          assert.equal(await page.locator('time').getAttribute('datetime'), '2026-09-09T17:06:00+08:00');
          assert.equal(await page.locator('.replacement-type').innerText(), '图片域名替换 <测试>');
        } else {
          assert.equal(await page.locator('time').count(), 0);
          assert((await page.locator('.replacement-update').innerText()).includes(state === 'empty' ? '暂无公开替换记录' : '时间未记录'));
        }
      }
      if (process.env.THEME_PREVIEW_URL) {
        const base = process.env.THEME_PREVIEW_URL;
        const errors = [];
        page.on('pageerror', error => errors.push(error.message));
        await page.route('**/*', route => {
          const r = route.request();
          if (['image', 'media'].includes(r.resourceType()) || new URL(r.url()).origin !== new URL(base).origin) return route.abort();
          return route.continue();
        });
        assert.equal((await page.goto(base, {waitUntil: 'networkidle'})).status(), 200);
        assert(await page.locator('.replacement-link').isVisible(), 'Notice visible with mobile services collapsed');
        const link = await page.locator('.replacement-link').getAttribute('href');
        assert.equal(new URL(link, base).href, base + '/macrep.html');
        const time = await page.locator('.replacement-update time').count() ? await page.locator('.replacement-update time').getAttribute('datetime') : null;
        const repResponse = await page.goto(new URL(link, base).href, {waitUntil: 'networkidle'});
        assert.equal(repResponse.status(), 200);
        assert.equal(await page.locator('h1').innerText(), '替换记录');
        assert(await page.locator('.masthead').isVisible());
        assert.equal(await page.evaluate(() => document.documentElement.scrollWidth), width, 'Record page overflow');
        if (time) {
          const timestamps = await page.locator('.rep-card').evaluateAll(rows => rows.map(row => Number(row.dataset.ts)));
          assert.equal(Date.parse(time) / 1000, Math.max(...timestamps), 'Homepage date agrees with published records');
        } else {
          assert(await page.locator('.rep-empty').isVisible());
        }
        assert.deepEqual(errors, [], 'Record page JavaScript errors');
      }
      results.push({width, states: Object.keys(fixtures), live: !!process.env.THEME_PREVIEW_URL, status: 'pass'});
      await page.close();
    }
    console.log(JSON.stringify(results, null, 2));
  } finally {
    await browser.close();
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
