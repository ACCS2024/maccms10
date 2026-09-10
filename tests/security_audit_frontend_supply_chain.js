#!/usr/bin/env node
'use strict';

// Offline regression: Node.js, Chromium and ffmpeg; no npm packages or external services.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const vm = require('node:vm');
const http = require('node:http');
const crypto = require('node:crypto');
const { spawn, spawnSync } = require('node:child_process');
const root = path.resolve(__dirname, '..');
const read = name => fs.readFileSync(path.join(root, name), 'utf8');
const homes = [
    'static/js/home.js', 'static_new/js/home.js',
    'template/default/asset/js/public-home-stack.js', 'template/default/asset/js/user-home-stack.js',
    'template/m1938pc3_v2/js/home.js', 'template/vozy/tuo/assets/home.js.download',
];

for (const file of homes) {
    const source = read(file);
    new vm.Script(source, { filename: file });
    const begin = source.indexOf("'Qrcode':");
    const end = source.indexOf("'Image':", begin);
    for (const base of ['', '/', '/video', '/video/']) {
        const share = 'https://site.example/vod?id=2&title=电影#chapter';
        const values = {};
        const element = {
            length: 1,
            attr(name, value) { values[name] = value; return this; },
            val(value) { values.value = value; return this; },
            text(value) { values.text = value; return this; },
            html() { throw new Error('Share URL must never become HTML'); },
        };
        const sandbox = {
            MAC: { Url: share, Ajax() { throw new Error('No network allowed for share helpers'); } },
            maccms: { path: base }, location: { href: share }, $: () => element,
        };
        vm.runInNewContext('Object.assign(MAC, {' + source.slice(begin, end) + '});', sandbox);
        sandbox.MAC.Qrcode.Init();
        const qr = new URL(values.src, share);
        assert.equal(qr.origin, 'https://site.example');
        assert.equal(qr.pathname, base.replace(/\/+$/, '') + '/index.php/qrcode/index.html');
        assert.equal(qr.searchParams.get('url'), share);
        assert.equal(qr.hash, '');
        sandbox.MAC.Shorten.Init();
        assert.equal(values.value, share);
        let callback;
        const url = 'https://site.example/?q=<img src=x onerror=alert(1)>';
        const result = sandbox.MAC.Shorten.Get(url, value => { callback = value; });
        assert.equal(result.code, 1);
        assert.equal(callback.data.url_short, url);
        assert.equal(values.text, url);
    }
}
console.log('PASS: 6 share bundles preserve QR URLs and callback payloads without JSONP or HTML injection');

const legacyProvenance = JSON.parse(read('template/m1938pc3_v2/js/SOURCE.json'));
for (const [name, info] of Object.entries(legacyProvenance.files)) {
    const file = 'template/m1938pc3_v2/js/' + name;
    assert.equal(crypto.createHash('sha256').update(fs.readFileSync(path.join(root, file))).digest('hex'), info.sha256);
}
assert.equal(legacyProvenance.files['jquery.js'].commit, 'f79d5f1a337528940ab7029d4f8bbba72326f269');

const mathjaxDir = 'static_new/ueditor/third-party/mathjax/';
const provenance = JSON.parse(read(mathjaxDir + 'SOURCE.json'));
assert.equal(provenance.commit, '600692ad9d3552cc25f85510d5797bc942ecc9f7');
for (const [name, info] of Object.entries(provenance.files)) {
    const hash = crypto.createHash('sha256').update(fs.readFileSync(path.join(root, mathjaxDir, name))).digest('hex');
    assert.equal(hash, info.sha256, 'Official pinned MathJax asset changed: ' + name);
}

class ChromiumPipe {
    constructor(profile) {
        this.id = 0;
        this.pending = new Map();
        this.listeners = [];
        this.buffer = '';
        this.process = spawn(process.env.CHROMIUM_BIN || 'chromium', [
            '--headless=new', '--no-sandbox', '--disable-dev-shm-usage', '--remote-debugging-pipe',
            '--disable-background-networking', '--disable-component-update', '--no-first-run',
            '--no-default-browser-check', '--disable-sync', '--disable-extensions',
            '--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1',
            '--autoplay-policy=no-user-gesture-required', '--user-data-dir=' + profile, 'about:blank',
        ], { stdio: ['ignore', 'ignore', 'ignore', 'pipe', 'pipe'] });
        this.closed = new Promise(resolve => this.process.once('close', resolve));
        this.process.on('error', error => { for (const entry of this.pending.values()) { entry.reject(error); } });
        this.process.stdio[4].on('data', chunk => {
            this.buffer += chunk.toString();
            let end;
            while ((end = this.buffer.indexOf('\0')) !== -1) {
                const message = JSON.parse(this.buffer.slice(0, end));
                this.buffer = this.buffer.slice(end + 1);
                if (message.id) {
                    const entry = this.pending.get(message.id);
                    if (!entry) { continue; }
                    clearTimeout(entry.timer);
                    this.pending.delete(message.id);
                    message.error ? entry.reject(new Error(JSON.stringify(message.error))) : entry.resolve(message.result);
                } else {
                    for (const listener of this.listeners) { listener(message); }
                }
            }
        });
    }
    send(method, params = {}, sessionId) {
        const id = ++this.id;
        return new Promise((resolve, reject) => {
            const timer = setTimeout(() => { this.pending.delete(id); reject(new Error('CDP timeout: ' + method)); }, 20000);
            this.pending.set(id, { resolve, reject, timer });
            this.process.stdio[3].write(JSON.stringify({ id, method, params, sessionId }) + '\0');
        });
    }
    async close() {
        const forceClose = setTimeout(() => this.process.kill('SIGKILL'), 5000);
        try {
            if (this.process.exitCode === null && this.process.signalCode === null) {
                // The CDP acknowledgement arrives before Chromium finishes writing its profile.
                this.send('Browser.close').catch(() => this.process.kill());
            }
            await this.closed;
        } finally {
            clearTimeout(forceClose);
            for (const entry of this.pending.values()) { clearTimeout(entry.timer); }
            this.pending.clear();
        }
    }
}

async function browserChecks() {
    const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'maccms-supply-browser-'));
    const video = spawnSync('ffmpeg', [
        '-hide_banner', '-loglevel', 'error', '-f', 'lavfi', '-i', 'color=c=black:s=64x64:d=1:r=5',
        '-an', '-c:v', 'libvpx', '-f', 'webm', 'pipe:1',
    ], { maxBuffer: 1024 * 1024 });
    assert.equal(video.status, 0, 'ffmpeg must be installed for the local playback regression');
    const editorBundle = read('static_new/ueditor/ueditor.all.min.js');
    const imageStart = editorBundle.indexOf('UE.image=function()');
    const imageEnd = editorBundle.indexOf('UE.dialog=', imageStart);
    const stub = `<script>
        window.auditCommands = [];
        window.utils = { domReady: function (fn) { document.addEventListener('DOMContentLoaded', fn); } };
        window.editor = { options: {}, selection: { getRange: function () { return { getClosedNode: function () { return null; } }; } },
            execCommand: function () { auditCommands.push(Array.from(arguments)); }, fireEvent: function () {} };
        window.dialog = { close: function () {}, popup: { hide: function () {} },
            getDom: function () { return { style: {}, parentNode: { parentNode: { style: {} } } }; } };
        </script>`;
    const cspProcess = spawnSync('php', ['-r', 'require "application/middleware/SecurityHeaders.php"; echo \\app\\middleware\\SecurityHeaders::scriptCspPolicy([]);'], { cwd: root, encoding: 'utf8' });
    assert.equal(cspProcess.status, 0, 'Read the actual application CSP baseline');
    const csp = cspProcess.stdout;
    assert.ok(csp.includes("script-src 'self'"));
    const requests = [];
    const server = http.createServer((req, res) => {
        res.setHeader('Content-Security-Policy', csp);
        const url = new URL(req.url, 'http://127.0.0.1');
        requests.push(url.pathname);
        if (url.pathname === '/__supply_test__/sample.webm') {
            res.writeHead(200, { 'Content-Type': 'video/webm', 'Content-Length': video.stdout.length });
            return res.end(video.stdout);
        }
        if (url.pathname === '/__supply_test__/compression.html') {
            res.setHeader('Content-Type', 'text/html');
            return res.end('<!doctype html><script>window.UE={};</script><script src="image.js"></script>');
        }
        if (url.pathname === '/__supply_test__/image.js') {
            res.setHeader('Content-Type', 'application/javascript');
            return res.end(editorBundle.slice(imageStart, imageEnd));
        }
        if (url.pathname === '/__supply_test__/local-ui.html') {
            res.setHeader('Content-Type', 'text/html');
            return res.end('<!doctype html><body><button id="localButton" onclick="this.dataset.clicked=1">Test</button>'
                + '<script src="/static_new/js/jquery.js"></script><script src="/static_new/layui/layui.js"></script>'
                + '<script>document.body.dataset.inline="ok";</script></body>');
        }
        if (url.pathname === '/__supply_test__/legacy-theme.html') {
            res.setHeader('Content-Type', 'text/html');
            return res.end('<!doctype html><body>'
                + '<input id="fixtureAutocomplete"><input id="m3u8But" type="checkbox">'
                + '<input name="selectedM" type="checkbox" value="1"><input name="selectedM" type="checkbox" value="2">'
                + '<img class="lazy" width="32" height="32" data-original="/static/ueditor/themes/default/images/spacer.gif">'
                + '<button id="m3u8Copy">Copy</button><button id="playCopy">Copy</button>'
                + '<script>Object.defineProperty(navigator,"platform",{value:"Linux armv8l"});'
                + 'Object.defineProperty(document,"referrer",{value:location.origin+"/incoming"});'
                + 'window.maccms={path:"",mid:1,aid:1,mob_status:0,url:location.host,wapurl:location.host};</script>'
                + ['jquery.js','jquery.autocomplete.js','jquery.lazyload.js','clipboard.min.js','home.js','main.js']
                    .map(name => '<script src="/template/m1938pc3_v2/js/' + name + '"></script>').join('') + '</body>');
        }
        if (url.pathname === '/__supply_test__/ajax.json') {
            res.setHeader('Content-Type', 'application/json');
            return res.end('{"local":true}');
        }
        const filename = path.resolve(root, '.' + decodeURIComponent(url.pathname));
        if (!filename.startsWith(root + path.sep) || !fs.existsSync(filename) || !fs.statSync(filename).isFile()) {
            res.writeHead(404); return res.end();
        }
        let body = fs.readFileSync(filename);
        if (url.searchParams.has('audit')) {
            body = body.toString().replace(/<script[^>]+src="\.\.\/internal\.js[^"<]*"[^>]*><\/script>/, stub);
        }
        const type = { '.js': 'application/javascript', '.html': 'text/html', '.css': 'text/css', '.gif': 'image/gif', '.svg': 'image/svg+xml' }[path.extname(filename)];
        if (type) { res.setHeader('Content-Type', type); }
        res.end(body);
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const origin = 'http://127.0.0.1:' + server.address().port;
    const cdp = new ChromiumPipe(profile);
    const external = [];
    const errors = [];
    const expectedScriptDenials = [];
    try {
        const target = await cdp.send('Target.createTarget', { url: 'about:blank' });
        const { sessionId } = await cdp.send('Target.attachToTarget', { targetId: target.targetId, flatten: true });
        const command = (method, params) => cdp.send(method, params, sessionId);
        cdp.listeners.push(message => {
            if (message.sessionId !== sessionId) { return; }
            if (message.method === 'Fetch.requestPaused') {
                const { request, requestId } = message.params;
                const local = request.url.startsWith(origin + '/') || /^(data|blob):/.test(request.url);
                if (!local) { external.push(request.url); }
                command(local ? 'Fetch.continueRequest' : 'Fetch.failRequest', local ? { requestId } : { requestId, errorReason: 'BlockedByClient' }).catch(error => {
                    // A completed-page navigation may cancel a paused favicon/worker request
                    // before Chromium consumes our reply. This is not a page exception.
                    if (!error.message.includes('"code":-32602,"message":"Invalid InterceptionId."')) {
                        errors.push(error.message);
                    }
                });
            }
            if (message.method === 'Log.entryAdded' && message.params.entry.source === 'security') {
                const text = message.params.entry.text;
                if (text.includes('https://unapproved.invalid/csp-boundary.js') && text.includes('script-src')) {
                    expectedScriptDenials.push(text);
                } else {
                    errors.push(text);
                }
            }
            if (message.method === 'Runtime.exceptionThrown') {
                const details = message.params.exceptionDetails;
                errors.push(details.exception && details.exception.description || details.text);
            }
        });
        await command('Page.enable');
        await command('Runtime.enable');
        await command('Log.enable');
        await command('Fetch.enable', { patterns: [{ urlPattern: '*' }] });
        const evaluate = async expression => {
            const result = await command('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true });
            if (result.exceptionDetails) { throw new Error(result.exceptionDetails.exception.description); }
            return result.result.value;
        };
        const navigate = async url => {
            await command('Page.navigate', { url: origin + url });
            await evaluate('new Promise(resolve => document.readyState === "complete" ? resolve(true) : window.addEventListener("load", () => resolve(true), {once:true}))');
        };

        await navigate('/__supply_test__/local-ui.html');
        const localUi = await evaluate(`(async function () {
            document.getElementById('localButton').click();
            var ajax = await new Promise((resolve, reject) => $.getJSON('/__supply_test__/ajax.json').done(resolve).fail(reject));
            var formReady = await new Promise(resolve => layui.use(['form', 'layer'], function () { layui.form.render(); resolve(true); }));
            var workerUrl = URL.createObjectURL(new Blob(['postMessage("worker-ok")'], { type: 'application/javascript' }));
            var worker = new Worker(workerUrl);
            var workerResult = await new Promise((resolve, reject) => {
                var timer = setTimeout(() => reject(new Error('Local worker did not start')), 2000);
                worker.onmessage = event => { clearTimeout(timer); resolve(event.data); };
                worker.onerror = reject;
            });
            worker.terminate(); URL.revokeObjectURL(workerUrl);
            return { inline: document.body.dataset.inline, clicked: document.getElementById('localButton').dataset.clicked,
                evaluated: new Function('return 42')(), ajax: ajax.local, formReady, workerResult };
        })()`);
        assert.deepEqual(localUi, { inline: 'ok', clicked: '1', evaluated: 42, ajax: true, formReady: true, workerResult: 'worker-ok' });
        const rejectedScript = await evaluate(`new Promise((resolve, reject) => {
            var timer = setTimeout(() => reject(new Error('Unapproved script was not rejected by CSP')), 2000);
            document.addEventListener('securitypolicyviolation', event => {
                if (event.blockedURI === 'https://unapproved.invalid/csp-boundary.js') {
                    clearTimeout(timer); resolve({ blocked: event.blockedURI, directive: event.effectiveDirective });
                }
            });
            var script = document.createElement('script');
            script.src = 'https://unapproved.invalid/csp-boundary.js'; document.body.appendChild(script);
        })`);
        assert.equal(rejectedScript.blocked, 'https://unapproved.invalid/csp-boundary.js');
        assert.ok(rejectedScript.directive.startsWith('script-src'));
        console.log('PASS: local jQuery/layui, AJAX, inline events, eval and blob workers run; unapproved script is blocked before network');

        await navigate('/__supply_test__/legacy-theme.html');
        const legacy = await evaluate(`(async function () {
            await new Promise(resolve => jQuery(resolve));
            var selected = '';
            var input = $('#fixtureAutocomplete').autocomplete(['Alpha', 'Alpine', 'Beta'], { minChars: 1, delay: 10, matchSubset: true });
            input.result(function (event, data, value) { selected = value; });
            await new Promise(resolve => setTimeout(resolve, 40));
            input.focus().val('Al').trigger($.Event('keydown', { keyCode: 65 }));
            await new Promise(resolve => setTimeout(resolve, 80));
            var suggestions = $('.ac_results li').length;
            input.trigger($.Event('keydown', { keyCode: 40 }));
            input.trigger($.Event('keydown', { keyCode: 38 }));
            input.trigger($.Event('keydown', { keyCode: 13 }));
            document.getElementById('m3u8But').click();
            $('img.lazy').trigger('appear');
            await new Promise(resolve => setTimeout(resolve, 30));
            return { jquery: $.fn.jquery, suggestions, selected: selected || input.val(),
                checked: MAC.CheckBox.Count('selectedM'), image: document.querySelector('img.lazy').getAttribute('src'),
                platform: navigator.platform, referrer: document.referrer };
        })()`);
        assert.equal(legacy.jquery, '3.7.1');
        assert.equal(legacy.suggestions, 2);
        assert.equal(legacy.selected, 'Alpha');
        assert.equal(legacy.checked, 2);
        assert.equal(legacy.image, '/static/ueditor/themes/default/images/spacer.gif');
        assert.equal(legacy.platform, 'Linux armv8l');
        assert.ok(legacy.referrer.includes('.'));
        console.log('PASS: old theme uses jQuery 3.7.1; autocomplete keyboard selection, lazyload and checkboxes work under the former mobile/referrer trigger');

        await navigate('/__supply_test__/compression.html');
        const compressed = await evaluate(`(async function () {
            var workers = 0;
            window.Worker = function () { workers++; throw new Error('worker forbidden'); };
            var canvas = document.createElement('canvas'); canvas.width = 128; canvas.height = 64;
            canvas.getContext('2d').fillRect(0, 0, 128, 64);
            var blob = await new Promise(resolve => canvas.toBlob(resolve, 'image/jpeg'));
            var file = new File([blob], 'photo.jpg', { type: blob.type, lastModified: 1234 });
            var output = await UE.image.compress(file, { maxWidthOrHeight: 32, maxSizeMB: 0.1, useWebWorker: true,
                libURL: 'https://external.invalid/untrusted.js', preserveExif: true });
            var image = await createImageBitmap(output);
            return { workers, width: image.width, height: image.height, size: output.size, type: output.type };
        })()`);
        assert.equal(compressed.workers, 0);
        assert.equal(compressed.width, 32);
        assert.equal(compressed.height, 16);
        assert.equal(compressed.type, 'image/jpeg');
        assert.ok(compressed.size > 0);
        console.log('PASS: real image compression ignores worker and remote libURL options');

        await navigate('/static_new/ueditor/dialogs/formula/formula.html?audit=1');
        const formula = await evaluate(`(async function () {
            document.getElementById('editor').value = String.fromCharCode(92) + 'frac{1}{2} + x^2';
            var src = await Formula.renderPlain();
            if (!src) { return { error: document.getElementById('formulaError').textContent }; }
            await document.getElementById('previewImage').decode();
            return { src: src.slice(0, 26), svg: atob(src.split(',')[1]), width: document.getElementById('previewImage').naturalWidth };
        })()`);
        assert.equal(formula.src, 'data:image/svg+xml;base64,');
        assert.ok(formula.svg.includes('<path') && formula.width > 0, JSON.stringify(formula));
        for (const tex of ['require{https://external.invalid/evil}', 'href{javascript:alert(1)}{test}', 'includegraphics{https://external.invalid/image.svg}']) {
            const activeMarkup = await evaluate(`(async function () {
                document.getElementById('editor').value = String.fromCharCode(92) + ${JSON.stringify(tex)};
                var src = await Formula.renderPlain();
                if (!src) { return false; }
                var svg = new DOMParser().parseFromString(atob(src.split(',')[1]), 'image/svg+xml');
                return Array.from(svg.querySelectorAll('*')).some(function (node) {
                    return /^(script|foreignObject|image|a)$/i.test(node.tagName) || Array.from(node.attributes).some(function (attribute) {
                        return /^on/i.test(attribute.name) || /^(href|xlink:href|src)$/i.test(attribute.name) && !attribute.value.startsWith('#');
                    });
                });
            })()`);
            assert.equal(activeMarkup, false, 'TeX may not emit active SVG markup or external references');
        }
        assert.ok(!requests.some(url => /mathjax\/.+extensions\//.test(url)), 'TeX may not load extension scripts');
        console.log('PASS: formula SVG renders with local MathJax, and TeX cannot import remote extensions');

        await navigate('/static/ueditor/dialogs/map/map.html?audit=1');
        const mapInput = await evaluate(`(function () {
            document.getElementById('address').value = '<script>alert(1)</script>';
            document.getElementById('mapUrl').value = 'https://maps.example/location';
            dialog.onok();
            var saved = auditCommands[0][1];
            document.getElementById('mapUrl').value = 'javascript:alert(1)';
            return { saved, rejected: dialog.onok() === false, commands: auditCommands.length };
        })()`);
        assert.ok(mapInput.saved.includes('&lt;script&gt;'));
        assert.equal(mapInput.rejected, true);
        assert.equal(mapInput.commands, 1);
        await navigate('/static/ueditor/dialogs/map/show.html#center=116.404,39.915');
        const legacyMap = new URL(await evaluate('document.querySelector("a").href'));
        assert.equal(legacyMap.searchParams.get('location'), '39.915,116.404');
        assert.equal(legacyMap.searchParams.get('coord_type'), 'bd09ll');
        console.log('PASS: maps save escaped links and retain historical coordinate systems without loading a map SDK');

        for (const base of ['static', 'static_new']) {
            await navigate('/' + base + '/ueditor/dialogs/emotion/emotion.html?audit=1');
            const emotion = await evaluate(`(async function () {
                document.querySelector('#tab0 td').click();
                for (var i=0; i<100 && !auditCommands.length; i++) { await new Promise(r => setTimeout(r, 20)); }
                var value = auditCommands[0];
                var blob = await (await fetch(value[1].src)).blob();
                var image = await createImageBitmap(blob);
                return { command: value[0], prefix: value[1].src.slice(0, 22), width: image.width, height: image.height };
            })()`);
            assert.equal(emotion.command, 'insertimage');
            assert.equal(emotion.prefix, 'data:image/png;base64,');
            assert.equal(emotion.width, 35);
            assert.equal(emotion.height, 35);
            await navigate('/' + base + '/player/iva.html?u=' + encodeURIComponent(origin + '/__supply_test__/sample.webm'));
            const playback = await evaluate(`(async function () {
                for (var i=0; i<200; i++) {
                    var video = document.querySelector('video');
                    if (video && video.readyState >= 2 && video.currentTime > 0) { return { src: video.currentSrc, time: video.currentTime }; }
                    await new Promise(r => setTimeout(r, 20));
                }
                return { error: 'Video did not play', url: location.href };
            })()`);
            assert.equal(playback.src, origin + '/__supply_test__/sample.webm', JSON.stringify(playback));
            assert.ok(playback.time > 0);
        }
        console.log('PASS: both editor sprite pickers insert local PNGs; legacy IVA URLs play through local DPlayer');
        assert.deepEqual(external, [], 'No browser request may leave the local fixture server');
        assert.deepEqual(errors, [], 'No uncaught browser exceptions');
        assert.equal(expectedScriptDenials.length, 1, 'Exactly the intentional script denial must be reported');
        console.log('PASS: zero external requests and zero uncaught browser exceptions');
    } finally {
        await cdp.close();
        await new Promise(resolve => server.close(resolve));
        fs.rmSync(profile, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    }
}

browserChecks().catch(error => { console.error(error); process.exitCode = 1; });
