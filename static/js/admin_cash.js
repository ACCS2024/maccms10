(function () {
    'use strict';
    document.addEventListener('DOMContentLoaded', function () {
        var root = document.getElementById('mac-admin-cash');
        var meta = document.querySelector('meta[name="mac-admin-csrf"]');
        if (!root || !meta) { return; }
        var write = window.MacCashWrite({token: meta.getAttribute('content')}), busy = false;
        function lock(value) {
            root.querySelectorAll('.js-cash-action').forEach(function (button) {
                button.setAttribute('aria-disabled', value ? 'true' : 'false');
                button.classList.toggle('layui-btn-disabled', value);
            });
        }
        root.addEventListener('click', function (event) {
            var button = event.target.closest('.js-cash-action');
            if (!button || !root.contains(button)) { return; }
            event.preventDefault();
            if (busy || write.blocked()) { return; }
            var selection = button.getAttribute('data-cash-selection'), fields;
            if (selection === 'all') { fields = {all: '1'}; }
            else {
                var ids = selection === 'checked'
                    ? Array.from(root.querySelectorAll('.checkbox-ids:checked'), function (input) { return input.value; }).join(',')
                    : selection;
                if (!ids) { window.alert('请选择要操作的记录'); return; }
                fields = {ids: ids, all: '0'};
            }
            if (!window.confirm(button.getAttribute('data-confirm') || '确定执行此提现操作吗？')) { return; }
            busy = true; lock(true);
            write.submit(button.getAttribute('data-cash-url'), fields).then(function (result) {
                window.alert(result.msg);
                if (result.code === 1) { window.location.reload(); }
            }).finally(function () { busy = false; lock(write.blocked()); });
        });
    });
})();
