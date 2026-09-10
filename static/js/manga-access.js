(function () {
    'use strict';
    var root = document.querySelector('[data-manga-base]');
    if (!root) { return; }
    var result = root.querySelector('[data-manga-result]');
    var base;
    try {
        base = new URL(root.getAttribute('data-manga-base'), window.location.href);
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
            var sid = form.getAttribute('data-sid');
            var nid = form.getAttribute('data-nid');
            // The displayed purchase entry is a real nonempty chapter; the server selects the final receipt scope.
            if (!integer(id, 4294967295) || (purchase && (!integer(sid, 255) || !integer(nid, 65535)))) { return; }
            button.disabled = true;
            result.textContent = '';
            var pending;
            if (purchase) {
                pending = request('user/write_token').then(function (token) {
                    if (!token || Number(token.code) !== 1 || !token.info || typeof token.info.csrf_token !== 'string' || !token.info.csrf_token) {
                        if (token && Number(token.code) !== 1) { return token; }
                        throw new Error('请求失败，请稍后重试');
                    }
                    return request('user/ajax_buy_popedom.html', {mid: '12', type: '1', id: id, sid: sid, nid: nid, csrf_token: token.info.csrf_token});
                });
            } else {
                pending = request('ajax/pwd', {mid: '12', type: '1', id: id, pwd: form.querySelector('[name="pwd"]').value});
            }
            pending.then(function (response) {
                result.textContent = response && typeof response.msg === 'string' ? response.msg : '请求失败，请稍后重试';
                if (response && Number(response.code) === 1) { window.location.reload(); }
            }).catch(function () {
                result.textContent = '请求失败，请稍后重试';
            }).finally(function () { button.disabled = false; });
        });
    }
    bind('[data-manga-password]', false);
    bind('[data-manga-purchase]', true);
}());
