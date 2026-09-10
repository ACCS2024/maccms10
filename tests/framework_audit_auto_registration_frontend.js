// Execute the actual login response callbacks with isolated browser and UI state.
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const assert = require('node:assert/strict');
let checks = 0;
function extractFunction(source, start) {
    for (let end = source.indexOf('}', start); end !== -1; end = source.indexOf('}', end + 1)) {
        const candidate = source.slice(start, end + 1);
        try { new vm.Script('(' + candidate + ')'); return candidate; } catch (error) { if (!(error instanceof SyntaxError)) throw error; }
    }
    throw new Error('Actual login callback could not be parsed');
}
const files = ['template/default/html/user/login.html', 'template/default/asset/js/user-home-stack.js', 'template/default/asset/js/public-home-stack.js'];
for (const file of files) {
    const source = fs.readFileSync(path.join(__dirname, '..', file), 'utf8');
    const page = file.endsWith('.html');
    const anchor = source.indexOf(page ? 'url: loginOrRegUrl' : "MAC.Ajax(_loginOrRegUrl, 'post'");
    assert.ok(anchor > 0); checks++;
    const callback = extractFunction(source, source.indexOf(page ? 'function (r)' : 'function (r)', anchor));
    function run(response) {
        const effects = { navigation: [], text: [], alerts: [], refresh: [], values: [], removed: 0, authenticated: 0 };
        const location = { href: 'https://example.invalid/fixture/index.php/user/login', origin: 'https://example.invalid',
            assign(url) { effects.navigation.push(url); }, reload() { effects.navigation.push('reload'); } };
        function jquery(selector) {
            return { text(value) { effects.text.push(value); return this; }, show() { return this; }, hide() { return this; },
                addClass() { return this; }, val(value) { if (arguments.length) { effects.values.push([selector,value]); return this; } return 'fixture-value'; },
                trigger(event) { effects.refresh.push([selector,event]); return this; } };
        }
        jquery.trim = value => String(value).trim();
        const MAC = { alert(message) { effects.alerts.push(message); }, Pop: { Remove() { effects.removed++; } },
            User: { _lastInitIsMobile: false, _postLoginRedirect: '', fetchAuthMe(cb) { effects.authenticated++; cb({is_login:1}); },
                applyAuthMeInfo() {}, emitAuthMe() {}, renderLoggedInChrome() {}, hydrateFromCookiesAndRender() {} }, showRegSuccess() {} };
        const context = vm.createContext({ URL, window: { location }, location, $: jquery, MAC, _pathBase:'/fixture', document:{ querySelector() { return null; } } });
        vm.runInContext('(' + callback + ')', context)(response);
        return { effects, location };
    }
    let result = run({code:1013, registration_required:1, registration_url:'/fixture/index.php/user/reg?invite_code=ABCDE', msg:'Complete registration'});
    assert.deepEqual(result.effects.navigation,['https://example.invalid/fixture/index.php/user/reg?invite_code=ABCDE']); checks++;
    assert.equal(result.effects.authenticated,0); checks++;
    result = run({code:1013,registration_required:1,registration_url:'https://other.invalid/register',msg:'Complete registration'});
    assert.deepEqual(result.effects.navigation,[]); checks++;
    result = run({code:1,pending_approval:1,msg:'Waiting for approval'});
    assert.equal(result.location.href,'https://example.invalid/fixture/index.php/user/login'); checks++;
    assert.equal(result.effects.authenticated,0); checks++;
    assert.ok(result.effects.text.includes('Waiting for approval') || result.effects.alerts.includes('Waiting for approval')); checks++;
    result = run({code:1002,msg:'Invalid verification'});
    assert.equal(result.effects.refresh.length,1); checks++;
    assert.equal(result.effects.values.length,1); checks++;
    result = run({code:1,action:'login',msg:'Signed in'});
    if (page) assert.equal(result.location.href,"{:url('user/index')}");
    else { assert.equal(result.effects.authenticated,1); assert.equal(result.effects.removed,1); }
    checks++;
}
process.stdout.write('Automatic registration frontend audit passed (' + checks + ' checks)\n');
