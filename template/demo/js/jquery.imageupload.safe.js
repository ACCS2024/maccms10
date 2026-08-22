(function ($) {
    'use strict';

    var defaults = {
        formAction: '',
        inputFileName: 'file',
        browseButtonValue: '选择图片',
        browseButtonClass: '',
        automaticUpload: true,
        hover: true
    };

    function message(value, fallback) {
        return typeof value === 'string' && value !== '' ? value : fallback;
    }

    function isSafeImageUrl(value) {
        try {
            var url = new URL(value, document.baseURI);
            return url.protocol === 'http:' || url.protocol === 'https:';
        } catch (error) {
            return false;
        }
    }

    $.fn.imageUpload = function (options) {
        var settings = $.extend({}, defaults, options || {});

        return this.each(function () {
            var image = this;
            var $image = $(image);
            var previous = $image.data('imageUpload');
            if (previous && typeof previous.destroy === 'function') {
                previous.destroy();
            }

            var input = document.createElement('input');
            input.type = 'file';
            input.name = settings.inputFileName;
            input.accept = 'image/*';
            input.hidden = true;

            var button = document.createElement('button');
            button.type = 'button';
            button.className = settings.browseButtonClass;
            button.textContent = settings.browseButtonValue;

            function fail(reason) {
                $image.trigger('imageUpload.uploadFailed', [message(reason, '上传失败')]);
            }

            function upload() {
                var file = input.files && input.files[0];
                if (!file || !settings.formAction) {
                    return;
                }

                var body = new FormData();
                body.append(settings.inputFileName, file);
                button.disabled = true;

                fetch(settings.formAction, {
                    method: 'POST',
                    body: body,
                    credentials: 'same-origin',
                    headers: {'X-Requested-With': 'XMLHttpRequest'}
                })
                    .then(function (response) {
                        if (!response.ok) {
                            throw new Error('HTTP ' + response.status);
                        }
                        return response.json();
                    })
                    .then(function (payload) {
                        if (!payload || Number(payload.code) !== 1) {
                            fail(payload && payload.msg);
                            return;
                        }

                        var url = payload.url || (payload.data && payload.data.url);
                        if (typeof url !== 'string' || !isSafeImageUrl(url)) {
                            fail('返回的图片地址无效');
                            return;
                        }

                        image.src = url;
                        $image.trigger('imageUpload.imageChanged', [payload]);
                    })
                    .catch(function (error) {
                        fail(error && error.message);
                    })
                    .finally(function () {
                        button.disabled = false;
                        input.value = '';
                    });
            }

            function choose() {
                input.click();
            }

            button.addEventListener('click', choose);
            input.addEventListener('change', function () {
                if (settings.automaticUpload) {
                    upload();
                }
            });

            image.insertAdjacentElement('afterend', input);
            input.insertAdjacentElement('afterend', button);
            if (settings.hover) {
                image.style.cursor = 'pointer';
                image.addEventListener('click', choose);
            }

            var instance = {
                upload: upload,
                destroy: function () {
                    image.removeEventListener('click', choose);
                    button.removeEventListener('click', choose);
                    input.remove();
                    button.remove();
                    $image.removeData('imageUpload');
                }
            };
            $image.data('imageUpload', instance);
            $image.off('imageUpload.destroy.safe').on('imageUpload.destroy.safe', instance.destroy);
        });
    };
}(jQuery));
