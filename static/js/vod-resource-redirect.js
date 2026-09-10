(function () {
    'use strict';
    var link = document.getElementById('resource-link');
    if (!link) {
        return;
    }
    function reject() {
        link.removeAttribute('href');
        link.textContent = '链接参数无效，请从详情目录重新选择';
    }
    function positive(value) {
        return typeof value === 'string' && /^[0-9]{1,10}$/.test(value)
            && Number(value) > 0 && Number(value) <= 4294967295;
    }
    var entry = link.getAttribute('data-entry');
    var id = link.getAttribute('data-id');
    var sid = link.getAttribute('data-sid');
    var nid = link.getAttribute('data-nid');
    var operation = link.getAttribute('data-operation');
    var legacy = link.getAttribute('data-legacy-query');
    // Only the explicit local PHP entry may receive public coordinates. No resource URL is stored here.
    if (typeof entry !== 'string' || !/^\/(?:[^/]+\/)*index\.php\/vod\/resource$/.test(entry)
        || /^\/\//.test(entry) || /[\\?#%\x00-\x20\x7f]/.test(entry)
        || /(?:^|\/)\.{1,2}(?:\/|$)/.test(entry)
        || !positive(id) || !positive(sid) || !positive(nid)
        || (operation !== 'play' && operation !== 'down') || (legacy !== '0' && legacy !== '1')) {
        reject();
        return;
    }
    // These existing selectors are shared by view 2 (all sources) and view 4 (one source).
    // The destination resolves the current row and authorizes the selected resource afresh.
    if (legacy === '1' && location.search) {
        var match = /^\?([0-9]{1,10})-([0-9]{1,10})-([0-9]{1,10})$/.exec(location.search);
        if (!match || !positive(match[1]) || !positive(match[2]) || !positive(match[3])) {
            reject();
            return;
        }
        id = match[1];
        sid = match[2];
        nid = match[3];
    }
    var target = entry + '?id=' + Number(id) + '&operation=' + operation
        + '&sid=' + Number(sid) + '&nid=' + Number(nid);
    link.href = target;
    location.replace(target);
}());
