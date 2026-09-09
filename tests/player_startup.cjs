// NODE_PATH=<playwright node_modules> node tests/player_startup.cjs
// Optional PLAYER_PAGE_URL checks the deployed shell with an inert parser fixture.
const {chromium} = require('playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '..');
const origin = 'http://player.test';
const read = file => fs.readFileSync(path.join(root, file), 'utf8');

(async () => {
  const browser = await chromium.launch({
    executablePath: process.env.CHROMIUM_PATH || '/usr/bin/chromium',
    args: ['--no-sandbox'],
  });
  const results = [];
  try {
    for (const test of [
      {name: 'malformed triple slash', prestrain: '///html/prestrain.html', buffer: '///html/loading.html'},
      {name: 'empty overlay', prestrain: '', buffer: ''},
      {name: 'backslash malformed URL', prestrain: '\\\\\\html/prestrain.html', buffer: '\\\\\\html/loading.html'},
      {name: 'non HTTP URL', prestrain: 'javascript:alert(1)', buffer: 'data:text/html,error'},
      {name: 'zero duration', prestrain: '/preload.html', buffer: '', second: '0'},
      {name: 'valid local overlays', prestrain: '/preload.html', buffer: '/loading.html', visible: true},
      {name: 'valid external overlays', prestrain: 'https://overlay.test/preload.html', buffer: '//overlay.test/loading.html', visible: true},
      {name: 'unsupported source', prestrain: '', buffer: '', from: 'unknown'},
    ]) {
      const page = await browser.newPage();
      await page.clock.install();
      const navigations = [];
      const config = {width: '100%', height: '100%', widthmob: '100%', heightmob: '100%',
        second: '5', player_list: {}, server_list: {}, ...test};
      const data = {flag: 'play', encrypt: 0, from: test.from || 'iframe', link: '', url: '/parser.html', server: ''};
      await page.route('**/*', route => {
        const url = new URL(route.request().url());
        if (route.request().isNavigationRequest()) navigations.push(url.href);
        const assets = {'/jquery.js': 'static/js/jquery.js', '/player.js': 'static/js/player.js',
          '/static/player/iframe.js': 'static/player/iframe.js'};
        if (url.origin === origin && assets[url.pathname]) {
          return route.fulfill({contentType: 'text/javascript', body: read(assets[url.pathname])});
        }
        const body = url.href === origin + '/' ? `<!doctype html><meta charset="utf-8"><script src="/jquery.js"></script>
          <script>var maccms={path:''},MacPlayerConfig=${JSON.stringify(config)},player_aaaa=${JSON.stringify(data)};</script>
          <script src="/player.js"></script>` : '<p>Inert player/loading fixture</p>';
        return route.fulfill({contentType: 'text/html', body});
      });
      await page.goto(origin, {waitUntil: 'load'});
      const overlay = page.locator('#buffer');
      assert.equal(await overlay.isVisible(), !!test.visible, test.name);
      if (!test.visible) assert.equal(await overlay.getAttribute('src'), 'about:blank', test.name);
      assert(!navigations.some(url => new URL(url).hostname === 'html'), 'Invalid host requested');
      if (test.from) {
        assert((await page.locator('#playleft').innerText()).includes('不支持的播放来源'));
      } else {
        assert(await page.locator('#playleft iframe').isVisible());
      }
      await page.clock.runFor(5100);
      assert.equal(await overlay.isVisible(), false, 'Preload must end');
      await page.evaluate(() => MacPlayer.AdsStart());
      assert.equal(await overlay.isVisible(), !!test.buffer && !!test.visible, 'Buffer validity');
      await page.evaluate(() => MacPlayer.AdsEnd());
      assert.equal(await overlay.isVisible(), false);
      results.push({name: test.name, status: 'pass'});
      await page.close();
    }

    if (process.env.PLAYER_PAGE_URL) {
      const url = process.env.PLAYER_PAGE_URL;
      const site = new URL(url).origin;
      for (const width of [1440, 390]) {
        const page = await browser.newPage({viewport: {width, height: 1000}, isMobile: width < 600});
        const invalid = [], parsers = [];
        await page.route('**/*', route => {
          const request = route.request(), target = new URL(request.url());
          if (target.hostname === 'html') invalid.push(target.href);
          if (target.origin !== site) {
            if (request.isNavigationRequest()) parsers.push(target.origin);
            return route.fulfill({contentType: 'text/html', body: '<p>Parser fixture ready</p>'});
          }
          if (['image', 'media'].includes(request.resourceType())) return route.abort();
          return route.continue();
        });
        assert.equal((await page.goto(url, {waitUntil: 'load'})).status(), 200);
        assert(await page.locator('#playleft iframe').isVisible());
        assert.equal(await page.locator('#buffer').isVisible(), false);
        assert.equal(await page.locator('#buffer').getAttribute('src'), 'about:blank');
        await page.evaluate(() => MacPlayer.AdsStart());
        assert.equal(await page.locator('#buffer').isVisible(), false);
        assert.deepEqual(invalid, []);
        assert(parsers.length > 0, 'Parser iframe must be requested');
        results.push({name: 'deployed startup', width, status: 'pass', parser: 'stubbed; media decoding not tested'});
        await page.close();
      }
    }
    console.log(JSON.stringify(results, null, 2));
  } finally {
    await browser.close();
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
