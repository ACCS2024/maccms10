(function () {
    'use strict';
    var root = document.querySelector('[data-art-base]');
    if (!root) { return; }
    var result = root.querySelector('[data-art-result]');
    var base;
    try {
        base = new URL(root.getAttribute('data-art-base'), window.location.href);
        if (base.origin !== window.location.origin || base.username || base.password || base.search || base.hash
            || !base.pathname.endsWith('/')) { return; }
    } catch (error) { return; }
    function integer(value, maximum) {
        return typeof value === 'string' && /^[0-9]{1,10}$/.test(value) && Number(value) > 0 && Number(value) <= maximum;
    }
    function request(path, data) {
        var controller = new AbortController();
        var timeout = window.setTimeout(function () { controller.abort(); }, 15000);
        var options = {credentials: 'same-origin', cache: 'no-store', signal: controller.signal};
        if (data) {
            options.method = 'POST';
            options.headers = {'Content-Type': 'application/x-www-form-urlencoded', 'X-Requested-With': 'XMLHttpRequest'};
            options.body = new URLSearchParams(data).toString();
        }
        return fetch(new URL('index.php/' + path, base).href, options).then(function (response) {
            if (!response.ok) { throw new Error('请求失败，请稍后重试'); }
            return response.json();
        }).finally(function () { window.clearTimeout(timeout); });
    }
    function bind(selector, purchase) {
        var form = root.querySelector(selector);
        if (!form) { return; }
        form.addEventListener('submit', function (event) {
            event.preventDefault();
            var button = form.querySelector('button');
            if (button.disabled) { return; }
            var id = form.getAttribute('data-id');
            var page = form.getAttribute('data-page');
            // A whole-work purchase can name any existing page; the server chooses stored sid=0.
            if (!integer(id, 4294967295) || (purchase && !integer(page, 4294967295))) { return; }
            button.disabled = true;
            result.textContent = '';
            var pending;
            if (purchase) {
                pending = request('user/write_token').then(function (token) {
                    if (!token || Number(token.code) !== 1 || !token.info || typeof token.info.csrf_token !== 'string' || !token.info.csrf_token) {
                        if (token && Number(token.code) !== 1) { return token; }
                        throw new Error('请求失败，请稍后重试');
                    }
                    return request('user/ajax_buy_popedom.html', {mid: '2', type: '1', id: id, sid: page, nid: '0', csrf_token: token.info.csrf_token});
                });
            } else {
                pending = request('ajax/pwd', {mid: '2', type: '1', id: id, pwd: form.querySelector('[name="pwd"]').value});
            }
            pending.then(function (response) {
                result.textContent = response && typeof response.msg === 'string' ? response.msg : '请求失败，请稍后重试';
                if (response && Number(response.code) === 1) { window.location.reload(); }
            }).catch(function () {
                result.textContent = '请求失败，请稍后重试';
            }).finally(function () { button.disabled = false; });
        });
    }
    bind('[data-art-password]', false);
    bind('[data-art-purchase]', true);
}());
