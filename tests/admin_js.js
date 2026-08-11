#!/usr/bin/env node
/*
 * 后台【渲染后】页面的内联 JS 语法门禁。
 *
 * 为什么需要它：commit 7e79ab6 删除「新旧版后台切换」死开关时，只删掉了一个
 * $.ajax({...}) 的函数头，把尾巴留在了 view/index/index.html：
 *
 *         layer.msg(r.msg, { time: 1800 });
 *     },
 *     complete: function () { location.reload(); }
 *     });
 *     }
 *
 * 这是语法错误 → 浏览器解析该 <script> 块直接失败 → 块内【所有】JS 都不执行，
 * 包括顶栏与左侧菜单的点击处理器、标签页系统。表现是「点了没反应 / 像被弹回首页」，
 * 而服务端一切正常：nginx 日志里连请求都没有、mac:selfcheck 全绿、php -l 全过 ——
 * 因为坏的是模板里的 JS，不是 PHP。这一整类缺陷此前没有任何仪器能发现。
 *
 * 为什么只扫渲染后的页面、不扫原始模板：
 * 模板里大量存在【条件发射的 JS】（{if}…{/if} 里各半句、{volist} 拼字符串、
 * 模板标签写在 JS 字符串字面量里且自带引号），这些只有渲染后才是合法 JS。
 * 试过对原始模板做标签剥离，无论宽严都会产生几十处误报 —— 而带误报的门禁
 * 两周内就会被无视，比没有门禁更危险。所以本检查的输入必须是真实渲染产物。
 *
 * 用法：
 *     node tests/admin_js.js <rendered.html> [more.html ...]
 *
 * 配合 tests/admin_smoke.sh 抓页面，例如：
 *     for u in index/index index/welcome vod/data vod/info make/opt admin/info; do
 *         curl -sS -b cookie.jar "$BASE/$u.html" > /tmp/pages/${u//\//_}.html
 *     done
 *     node tests/admin_js.js /tmp/pages/*.html
 *
 * 有语法错误时退出码非 0。
 */
const fs = require('fs');
const path = require('path');

const targets = process.argv.slice(2);
if (!targets.length) {
    console.error('用法: node tests/admin_js.js <渲染后的 html> [...]');
    console.error('注意：输入必须是【渲染后】的页面，不是 application/admin/view 下的原始模板。');
    process.exit(2);
}

let files = 0, blocks = 0, errors = 0, skipped = 0;

for (const f of targets) {
    let html;
    try { html = fs.readFileSync(f, 'utf8'); } catch { console.log(`  ?? 读不到 ${f}`); continue; }

    // 登录页/错误页会被误当成"抓到了"，但它们不含后台外壳，扫了没意义
    if (html.length < 500 || /name="admin_pwd"/.test(html)) {
        skipped++;
        console.log(`  -- 跳过 ${path.basename(f)}（${html.length} 字节，疑似未登录或错误页）`);
        continue;
    }
    files++;

    for (const m of html.matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi)) {
        const raw = m[1];
        if (!raw.trim()) continue;
        // type="text/html" 这类模板容器不是 JS
        const tag = m[0].slice(0, m[0].indexOf('>'));
        if (/type\s*=\s*["'](?!text\/javascript|application\/javascript|module)/i.test(tag)) continue;
        blocks++;
        const line = html.slice(0, m.index).split('\n').length;
        try {
            new Function(raw);
        } catch (e) {
            errors++;
            console.log(`  !! ${path.basename(f)}:${line}  ${e.message}`);
        }
    }
}

console.log(`\nadmin inline JS: ${files} 个页面 / ${blocks} 个内联块，语法错误 ${errors} 处` +
            (skipped ? `（跳过 ${skipped}）` : ''));
if (errors) {
    console.log('提示：括号/逗号不配对多半是删代码时只删了一半 —— 删了函数头，尾巴留在原地。');
    process.exit(1);
}
if (!blocks) {
    console.log('!! 一个内联块都没扫到，检查抓页面那步是不是没带登录 cookie。');
    process.exit(1);
}
console.log('admin JS OK');
