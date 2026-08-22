(function (window, $) {
    'use strict';

    var MAC = window.MAC || {};

    MAC.CheckBox = {
        All: function (name) {
            $(document.getElementsByName(name)).prop('checked', true);
        },
        Other: function (name) {
            $(document.getElementsByName(name)).each(function () {
                this.checked = !this.checked;
            });
        },
        Count: function (name) {
            return $(document.getElementsByName(name)).filter(':checked').length;
        },
        Ids: function (name) {
            return $(document.getElementsByName(name)).filter(':checked').map(function () {
                return this.value;
            }).get().join(',');
        }
    };

    function refreshVerifyImage(image) {
        var source = String(image.getAttribute('src') || '').split('?')[0];
        image.setAttribute('src', source + '?r=' + Date.now());
    }

    function deleteLogs(page, ids, all) {
        var action = page.attr('data-delete-url');
        var type = page.attr('data-log-type');
        var label = all ? '清空' : '删除';

        if (!action || !type || !window.confirm('确定要' + label + '记录吗')) {
            return;
        }

        $.post(action, {ids: ids, type: type, all: all ? 1 : 0}, function (response) {
            if (response && Number(response.code) === 1) {
                window.alert('删除成功');
                window.location.reload();
                return;
            }
            window.alert('删除失败：' + String(response && response.msg ? response.msg : '服务器未返回原因'));
        }, 'json').fail(function () {
            window.alert('删除失败：网络请求异常');
        });
    }

    $(function () {
        $('body')
            .on('click.demoVerify', '.js-verify-refresh', function (event) {
                event.preventDefault();
                refreshVerifyImage(this);
            })
            .on('click.demoCheckAll', '.js-check-all', function (event) {
                event.preventDefault();
                MAC.CheckBox.All('ids[]');
            })
            .on('click.demoCheckOther', '.js-check-other', function (event) {
                event.preventDefault();
                MAC.CheckBox.Other('ids[]');
            })
            .on('click.demoLogDelete', '.js-log-delete', function (event) {
                event.preventDefault();
                deleteLogs($(this).closest('.js-log-page'), $(this).attr('data-id'), false);
            })
            .on('click.demoLogDeleteSelected', '.js-log-delete-selected', function (event) {
                event.preventDefault();
                var page = $(this).closest('.js-log-page');
                var ids = MAC.CheckBox.Ids('ids[]');
                if (ids === '') {
                    window.alert('请至少选择一个数据');
                    return;
                }
                deleteLogs(page, ids, false);
            })
            .on('click.demoLogClear', '.js-log-clear', function (event) {
                event.preventDefault();
                deleteLogs($(this).closest('.js-log-page'), '', true);
            });
    });

    window.MAC = MAC;
}(window, jQuery));
