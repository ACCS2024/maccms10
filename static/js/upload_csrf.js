(function (window, document) {
    'use strict';

    function uploadUrl(value) {
        try {
            var url = new URL(value, document.baseURI);
            return url.origin === window.location.origin &&
                /\/(?:upload\/upload|user\/portrait)(?:\.html?)?\/?$/i.test(url.pathname);
        } catch (error) { return false; }
    }

    function token() {
        var meta = document.querySelector('meta[name="mac-upload-csrf"],meta[name="mac-admin-csrf"]');
        return meta ? meta.getAttribute('content') || '' : '';
    }

    function headers(url) {
        var value = token();
        return uploadUrl(url) && value ? {'X-CSRF-Token': value} : {};
    }

    function prepareForm(form) {
        if (!form || String(form.method).toUpperCase() !== 'POST' || !uploadUrl(form.action)) { return; }
        var value = token();
        if (!value) { return; }
        Array.prototype.forEach.call(form.querySelectorAll('input[name="csrf_token"]'), function (input) { input.remove(); });
        var input = document.createElement('input');
        input.type = 'hidden';
        input.name = 'csrf_token';
        input.value = value;
        form.appendChild(input);
    }

    function hook(jq) {
        if (!jq || !jq.ajaxPrefilter || jq.__macUploadCsrf) { return; }
        jq.__macUploadCsrf = true;
        jq.ajaxPrefilter(function (options) {
            if (!/^(POST|PUT|PATCH|DELETE)$/i.test(options.type || options.method || 'GET') || !uploadUrl(options.url)) { return; }
            options.headers = jq.extend({}, options.headers || {}, headers(options.url));
        });
        // Covers jQuery's synthetic .submit() as well as native submit buttons used by iframe uploaders.
        jq(document).on('submit.macUploadCsrf', 'form', function () { prepareForm(this); });
    }

    window.MacUploadCsrf = {headers: headers, token: token, prepareForm: prepareForm};
    document.addEventListener('submit', function (event) { prepareForm(event.target); }, true);
    hook(window.jQuery);
    if (window.layui) {
        hook(window.layui.jquery);
        window.layui.use(['jquery'], function () { hook(window.layui.jquery); });
    }
}(window, document));
