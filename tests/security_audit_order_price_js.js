// Exercise the actual generated plan-card renderer with unavailable, free and payable prices.
'use strict';
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const source = fs.readFileSync(require('node:path').join(__dirname, '../template/default/asset/js/user-buy-upgrade-ajax.js'), 'utf8');
const match = source.match(/function A\(e,a\)\{[\s\S]*?(?=function w\()/);
assert.ok(match, 'Actual plan-card renderer not found');
const context = vm.createContext({});
vm.runInContext('function v(s){return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");}' + match[0], context);
assert.match(context.A(20, 8.33), /￥8\.33/);
assert.match(context.A(20, '8.33'), /￥8\.33/);
assert.match(context.A(20, null), /仅支持积分兑换/);
assert.doesNotMatch(context.A(20, null), /￥null|￥0|免费开通/);
assert.match(context.A(0, 0), /免费开通/);
assert.match(context.A(0, null), /免费开通/);
console.log('order price JS audit: 7 assertions passed');
