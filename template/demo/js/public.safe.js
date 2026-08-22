(function (window, $) {
    'use strict';

    var MAC = window.MAC || {};

    function route(path) {
        var base = window.maccms && typeof window.maccms.path === 'string' ? window.maccms.path : '';
        return base.replace(/\/$/, '') + path;
    }

    function request(options) {
        return $.ajax($.extend({
            method: 'GET',
            timeout: 15000,
            headers: {'X-Requested-With': 'XMLHttpRequest'}
        }, options));
    }

    function message(value, fallback) {
        return typeof value === 'string' && value !== '' ? value : fallback;
    }

    function showMessage(value) {
        var backdrop = document.createElement('div');
        var dialog = document.createElement('div');
        var content = document.createElement('div');
        backdrop.className = 'mac_pop_msg_bg';
        dialog.className = 'mac_pop_msg';
        content.className = 'pop-msg';
        content.textContent = message(value, '操作完成');
        dialog.style.width = '260px';
        dialog.style.height = '24px';
        dialog.appendChild(content);
        document.body.appendChild(backdrop);
        document.body.appendChild(dialog);
        $(backdrop).add(dialog).show();
        window.setTimeout(function () {
            backdrop.remove();
            dialog.remove();
        }, 1800);
    }

    function closeReport() {
        $('.mac_pop_bg.demo-report, .mac_pop.demo-report').remove();
    }

    function showReport(value) {
        closeReport();

        var backdrop = document.createElement('div');
        var dialog = document.createElement('div');
        var top = document.createElement('div');
        var title = document.createElement('h2');
        var close = document.createElement('button');
        var form = document.createElement('form');
        var textarea = document.createElement('textarea');
        var submit = document.createElement('button');

        backdrop.className = 'mac_pop_bg demo-report';
        dialog.className = 'mac_pop demo-report';
        top.className = 'pop_top';
        title.textContent = '数据报错';
        close.type = 'button';
        close.className = 'pop_close';
        close.textContent = '关闭';
        form.className = 'gbook_form';
        textarea.className = 'gbook_content';
        textarea.name = 'gbook_content';
        textarea.maxLength = 200;
        textarea.value = typeof value === 'string' ? value : '';
        textarea.style.cssText = 'box-sizing:border-box;width:100%;height:150px;margin-top:16px;padding:10px;';
        submit.type = 'button';
        submit.className = 'gbook_submit submit_btn';
        submit.textContent = '提交留言';
        submit.style.cssText = 'display:block;width:100px;height:32px;margin:12px auto;cursor:pointer;';

        top.appendChild(title);
        top.appendChild(close);
        form.appendChild(textarea);
        form.appendChild(submit);
        dialog.appendChild(top);
        dialog.appendChild(form);
        dialog.style.width = '400px';
        dialog.style.height = '300px';
        document.body.appendChild(backdrop);
        document.body.appendChild(dialog);
        $(backdrop).add(dialog).show();
        close.addEventListener('click', closeReport);
        backdrop.addEventListener('click', closeReport);
        MAC.Gbook.Init();
    }

    function refreshVerify() {
        $('.mac_verify_img').attr('src', route('/index.php/verify/index.html?r=') + Math.random());
    }

    function ensureVerifyImage(input) {
        if ($(input).siblings('.mac_verify_img').length > 0) {
            return;
        }
        var image = document.createElement('img');
        image.className = 'mac_verify_img';
        image.alt = '点击刷新验证码';
        image.title = '看不清楚？换一张';
        image.src = route('/index.php/verify/index.html?r=') + Math.random();
        input.insertAdjacentElement('afterend', image);
    }

    function replaceResponseHtml(target, html) {
        var parsed = new DOMParser().parseFromString(String(html), 'text/html');
        parsed.querySelectorAll('script, iframe, object, embed, base, meta, link').forEach(function (node) {
            node.remove();
        });
        parsed.body.querySelectorAll('*').forEach(function (node) {
            Array.from(node.attributes).forEach(function (attribute) {
                if (/^on/i.test(attribute.name)) {
                    node.removeAttribute(attribute.name);
                }
                if ((attribute.name === 'href' || attribute.name === 'src') && /^\s*javascript:/i.test(attribute.value)) {
                    node.removeAttribute(attribute.name);
                }
            });
        });
        $(target).empty().append($(parsed.body).contents());
    }

    MAC.Pop = MAC.Pop || {};
    MAC.Pop.Msg = function (width, height, value) {
        showMessage(value);
    };

    MAC.Verify = {
        Refresh: refreshVerify,
        Init: function () {
            $('body')
                .off('focus.demoVerify', '.mac_verify')
                .on('focus.demoVerify', '.mac_verify', function () {
                    ensureVerifyImage(this);
                })
                .off('click.demoVerify', '.mac_verify_img')
                .on('click.demoVerify', '.mac_verify_img', refreshVerify);
        }
    };

    MAC.Remaining = function (input, limit, output) {
        var value = String($(input).val() || '');
        if (value.length > limit) {
            value = value.slice(0, limit);
            $(input).val(value);
        }
        $(output).text(limit - value.length);
    };

    MAC.AddEm = function (input, id) {
        $(input).val(String($(input).val() || '') + '[em:' + String(id) + ']');
    };

    MAC.Gbook = $.extend(MAC.Gbook || {}, {
        Login: 0,
        Verify: 0,
        Init: function () {
            $('body')
                .off('keyup.demoGbook', '.gbook_content')
                .on('keyup.demoGbook', '.gbook_content', function () {
                    MAC.Remaining(this, 200, $(this).closest('form').find('.gbook_remaining'));
                })
                .off('click.demoGbook', '.gbook_submit')
                .on('click.demoGbook', '.gbook_submit', function () {
                    MAC.Gbook.Submit($(this));
                })
                .off('click.demoReport', '.bugs')
                .on('click.demoReport', '.bugs', function () {
                    var link = $(this);
                    var report = '编号【' + String(link.attr('data-vod-id') || '') + '】名称【'
                        + String(link.attr('data-vod-name') || '') + '】不能观看请检查修复，页面地址' + window.location.href;
                    MAC.Gbook.Report(report);
                });
            MAC.Verify.Init();
        },
        Submit: function (button) {
            var form = button.closest('form');
            var content = String(form.find('.gbook_content').val() || '').trim();
            if (content === '') {
                showMessage('请输入您的留言！');
                return;
            }
            button.prop('disabled', true);
            request({
                url: route('/index.php/gbook/saveData'),
                method: 'POST',
                dataType: 'json',
                data: form.serialize()
            }).done(function (response) {
                showMessage(response && response.msg);
                if (response && Number(response.code) === 1) {
                    closeReport();
                    window.setTimeout(function () { window.location.reload(); }, 300);
                } else if (MAC.Gbook.Verify === 1) {
                    refreshVerify();
                }
            }).fail(function () {
                showMessage('提交失败，请稍后重试');
            }).always(function () {
                button.prop('disabled', false);
            });
        },
        Report: function (name) {
            showReport(name);
        }
    });

    MAC.Comment = $.extend(MAC.Comment || {}, {
        Login: 0,
        Verify: 0,
        Init: function () {
            $('body')
                .off('click.demoCommentFace', '.comment_face_box img')
                .on('click.demoCommentFace', '.comment_face_box img', function () {
                    MAC.AddEm($(this).closest('form').find('.comment_content'), $(this).attr('data-id'));
                })
                .off('click.demoCommentPanel', '.comment_face_panel')
                .on('click.demoCommentPanel', '.comment_face_panel', function () {
                    $(this).siblings('.comment_face_box').toggle();
                })
                .off('keyup.demoComment', '.comment_content')
                .on('keyup.demoComment', '.comment_content', function () {
                    MAC.Remaining(this, 200, $(this).closest('form').find('.comment_remaining'));
                })
                .off('click.demoCommentReport', '.comment_report')
                .on('click.demoCommentReport', '.comment_report', function () {
                    var button = $(this);
                    request({
                        url: route('/index.php/comment/report.html'),
                        dataType: 'json',
                        data: {id: button.attr('data-id')}
                    }).done(function (response) {
                        showMessage(response && response.msg);
                    }).fail(function () {
                        showMessage('举报失败，请稍后重试');
                    });
                })
                .off('click.demoCommentReply', '.comment_reply')
                .on('click.demoCommentReply', '.comment_reply', function () {
                    var button = $(this);
                    if (button.text().trim() === '取消回复') {
                        button.text('回复');
                        $('.comment_reply_form').remove();
                        return;
                    }
                    $('.comment_reply').text('回复');
                    $('.comment_reply_form').remove();
                    var reply = $('.comment_form').first().clone(false, false).addClass('comment_reply_form');
                    reply.find('[id]').removeAttr('id');
                    reply.find('input[name="comment_pid"]').val(button.attr('data-id'));
                    button.closest('.gw-action').after(reply);
                    button.text('取消回复');
                })
                .off('click.demoCommentSubmit', '.comment_submit')
                .on('click.demoCommentSubmit', '.comment_submit', function () {
                    MAC.Comment.Submit($(this));
                })
                .off('click.demoCommentPage', '.comment_page_link')
                .on('click.demoCommentPage', '.comment_page_link', function () {
                    MAC.Comment.Show($(this).attr('data-page'));
                })
                .off('click.demoCommentGo', '.comment_page_go')
                .on('click.demoCommentGo', '.comment_page_go', function () {
                    MAC.Comment.Show($(this).siblings('.page_input').val());
                })
                .off('click.demoDigg', '.digg_link, .comment_digg')
                .on('click.demoDigg', '.digg_link, .comment_digg', function () {
                    var button = $(this);
                    request({
                        url: route('/index.php/ajax/digg.html'),
                        dataType: 'json',
                        data: {
                            mid: button.attr('data-mid') || 6,
                            id: button.attr('data-id'),
                            type: button.attr('data-type')
                        }
                    }).done(function (response) {
                        if (!response || Number(response.code) !== 1) {
                            showMessage(response && response.msg);
                            return;
                        }
                        var value = button.attr('data-type') === 'up' ? response.data.up : response.data.down;
                        button.find('.digg_num, .comment_digg_num, .icon-num').first().text(value);
                    });
                });
            MAC.Verify.Init();
        },
        Show: function (page) {
            page = parseInt(page, 10);
            if (!Number.isFinite(page) || page < 1 || $('.mac_comment').length === 0) {
                return;
            }
            var box = $('.mac_comment').first();
            request({
                url: route('/index.php/comment/ajax.html'),
                dataType: 'html',
                data: {rid: box.attr('data-id'), mid: box.attr('data-mid'), page: page}
            }).done(function (response) {
                replaceResponseHtml(box, response);
            }).fail(function () {
                showMessage('评论加载失败，请重试');
            });
        },
        Submit: function (button) {
            var form = button.closest('form');
            var box = $('.mac_comment').first();
            if (String(form.find('.comment_content').val() || '').trim() === '') {
                showMessage('请输入您的评论！');
                return;
            }
            if (!box.attr('data-mid') || !box.attr('data-id')) {
                showMessage('评论关联信息缺失');
                return;
            }
            button.prop('disabled', true);
            request({
                url: route('/index.php/comment/saveData'),
                method: 'POST',
                dataType: 'json',
                data: form.serialize() + '&comment_mid=' + encodeURIComponent(box.attr('data-mid')) + '&comment_rid=' + encodeURIComponent(box.attr('data-id'))
            }).done(function (response) {
                showMessage(response && response.msg);
                if (response && Number(response.code) === 1) {
                    MAC.Comment.Show(1);
                } else if (MAC.Comment.Verify === 1) {
                    refreshVerify();
                }
            }).fail(function () {
                showMessage('评论提交失败，请稍后重试');
            }).always(function () {
                button.prop('disabled', false);
            });
        }
    });

    $(function () {
        MAC.Verify.Init();
        MAC.Gbook.Init();
        MAC.Comment.Init();
    });

    window.MAC = MAC;
}(window, jQuery));
