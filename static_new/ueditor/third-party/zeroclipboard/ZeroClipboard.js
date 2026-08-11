/*!
 * ZeroClipboard 兼容垫片 —— 用原生 Clipboard API 取代已死的 Flash 实现
 *
 * 背景：
 * ueditor 的 copy 插件（ueditor.all.min.js 里 E.plugin.register("copy", ...)）在编辑器
 * ready 时会懒加载本文件，然后调用
 *     ZeroClipboard.config({ swfPath: UEDITOR_HOME_URL + "third-party/zeroclipboard/ZeroClipboard.swf" })
 * —— 也就是说，上游那份实现依赖 Flash。Flash 已于 2020 年底被所有浏览器彻底移除，
 * 因此这个复制按钮【早就是坏的】，本文件缺失只是把它从"静默失效"变成了控制台里的 404：
 *     Error: The load .../third-party/zeroclipboard/ZeroClipboard.js fails
 *
 * 本垫片做两件事：
 * 1. 消掉 404 与那条报错；
 * 2. 用 navigator.clipboard.writeText() 把"复制"这个功能真正接回来 ——
 *    它是浏览器原生 API，不需要任何库，也不需要 Flash。
 *
 * 为什么不直接删掉 copy 插件：那要改 ueditor.all.min.js（压缩后的上游文件），
 * 一改就无法再与上游对比校验，也无法用官方文件覆盖升级。加一个垫片是可逆的。
 *
 * 接口按 ueditor 的实际调用面实现，不追求还原完整的 ZeroClipboard API：
 *   ZeroClipboard.config(opts)   吞掉（swfPath 已无意义）
 *   ZeroClipboard.destroy()      吞掉
 *   new ZeroClipboard()          返回带 on/off/setText/clip 的实例
 *   client.on('copy', fn)        记下回调；真正复制时先调它拿到文本
 *   client.on('mouseover'|'mouseout'|'wrongflash noflash', fn)   记下但不触发
 *
 * 注意：navigator.clipboard 只在安全上下文（https 或 localhost）可用。
 * 非安全上下文下回退到 document.execCommand('copy')，再不行就静默放弃 ——
 * 无论哪种情况都不再抛异常，编辑器其余功能不受影响（Ctrl+C 一直是可用的）。
 */
(function (window, document) {
    'use strict';

    function noop() {}

    function writeClipboard(text) {
        if (text == null) { return; }
        text = String(text);
        if (window.navigator && window.navigator.clipboard && window.isSecureContext) {
            window.navigator.clipboard.writeText(text)['catch'](function () {
                legacyCopy(text);
            });
            return;
        }
        legacyCopy(text);
    }

    // 非安全上下文（http 访问后台）下的回退：临时 textarea + execCommand
    function legacyCopy(text) {
        try {
            var ta = document.createElement('textarea');
            ta.value = text;
            ta.setAttribute('readonly', 'readonly');
            ta.style.position = 'fixed';
            ta.style.top = '-9999px';
            ta.style.opacity = '0';
            document.body.appendChild(ta);
            ta.select();
            document.execCommand('copy');
            document.body.removeChild(ta);
        } catch (e) {
            /* 复制失败不应影响编辑器，用户仍可用 Ctrl+C */
        }
    }

    function Client() {
        this._handlers = {};
    }

    Client.prototype.on = function (types, fn) {
        var self = this;
        String(types).split(/\s+/).forEach(function (t) {
            if (!t) { return; }
            (self._handlers[t] = self._handlers[t] || []).push(fn);
        });
        return this;
    };

    Client.prototype.off = function (types) {
        var self = this;
        String(types || '').split(/\s+/).forEach(function (t) { delete self._handlers[t]; });
        return this;
    };

    // ueditor 的 copy 回调里会调 e.client.setText(html) —— 这就是要写进剪贴板的内容
    Client.prototype.setText = function (text) {
        writeClipboard(text);
        return this;
    };

    // 上游用 clip(dom) 把 Flash 影片贴到按钮上；原生 API 不需要，改为绑一次点击
    Client.prototype.clip = function (el) {
        var self = this;
        if (!el || el.__zcBound) { return this; }
        el.__zcBound = true;
        el.addEventListener('click', function () {
            var list = self._handlers['copy'] || [];
            for (var i = 0; i < list.length; i++) {
                try { list[i].call(self, { client: self }); } catch (e) { /* 单个回调出错不阻断 */ }
            }
        }, false);
        return this;
    };

    Client.prototype.glue    = Client.prototype.clip;   // 老版本别名
    Client.prototype.unclip  = noop;
    Client.prototype.destroy = noop;

    function ZeroClipboard() { return new Client(); }
    ZeroClipboard.config  = noop;
    ZeroClipboard.destroy = noop;
    ZeroClipboard.isFlashUnusable = function () { return true; };
    ZeroClipboard.version = 'shim-native-clipboard';

    window.ZeroClipboard = ZeroClipboard;
})(window, document);
