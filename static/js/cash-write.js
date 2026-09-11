(function (window) {
    'use strict';
    // One in-flight financial write per page; an uncertain POST is never retried automatically.
    window.MacCashWrite = function (options) {
        var pending = false, blocked = null;
        function unknown(result) {
            blocked = result || {code: 2004, msg: '提现操作结果暂未确认，请核对提现记录并联系管理员，确认前请勿重复提交。',
                info: {retryable: false, outcome: 'transport_unknown'}};
            return blocked;
        }
        function localUrl(value) {
            var url = new URL(value, window.location.href);
            if (url.origin !== window.location.origin || url.username || url.password || url.hash) {
                throw new Error('Invalid cash endpoint');
            }
            return url.href;
        }
        function request(url, settings) {
            var controller = new AbortController();
            var timer = window.setTimeout(function () { controller.abort(); }, 30000);
            settings.signal = controller.signal;
            settings.credentials = 'same-origin';
            settings.cache = 'no-store';
            settings.redirect = 'error';
            return window.fetch(url, settings).then(function (response) {
                if (!response.ok) { throw new Error('HTTP response unavailable'); }
                return response.json();
            }).finally(function () { window.clearTimeout(timer); });
        }
        return {
            blocked: function () { return blocked !== null; },
            submit: function (url, fields) {
                if (blocked) { return Promise.resolve(blocked); }
                if (pending) { return Promise.resolve({code: 1005, msg: '正在处理，请稍候。'}); }
                pending = true;
                var sent = false;
                return Promise.resolve().then(function () {
                    url = localUrl(url);
                    if (options.token) { return {code: 1, info: {csrf_token: options.token}}; }
                    return request(localUrl(options.tokenUrl), {method: 'GET'});
                }).then(function (result) {
                    if (!result || Number(result.code) !== 1 || !result.info
                        || typeof result.info.csrf_token !== 'string' || !result.info.csrf_token || result.info.csrf_token.length > 128) {
                        return {code: 1403, msg: '无法验证当前会话，请刷新页面或重新登录后再试。'};
                    }
                    var body = new URLSearchParams();
                    Object.keys(fields).forEach(function (key) {
                        if (typeof fields[key] !== 'string' && typeof fields[key] !== 'number') { throw new Error('Invalid cash field'); }
                        body.set(key, fields[key]);
                    });
                    body.set('csrf_token', result.info.csrf_token);
                    sent = true;
                    return request(url, {method: 'POST', headers: {'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'}, body: body.toString()})
                        .then(function (reply) {
                            if (!reply || !Number.isInteger(reply.code) || reply.code < 1 || typeof reply.msg !== 'string') { return unknown(); }
                            if (reply.retryable === false || (reply.info && reply.info.retryable === false)) { return unknown(reply); }
                            return reply;
                        });
                }).catch(function () {
                    return sent ? unknown() : {code: 1006, msg: '暂时无法验证会话，本次操作尚未提交，请稍后重试。'};
                }).finally(function () { pending = false; });
            }
        };
    };
})(window);
