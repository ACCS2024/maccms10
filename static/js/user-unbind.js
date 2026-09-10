(function ($) {
    "use strict";
    if (!$) { return; }
    $(function () {
        var form = $("#userUnbindForm");
        if (!form.length) { return; }
        form.on("submit", function (event) {
            event.preventDefault();
            var button = form.find('button[type="submit"]');
            if (button.prop("disabled")) { return; }
            button.prop("disabled", true);
            $("#userUnbindResult").text("正在确认…");
            $.ajax({
                url: form.attr("action"), type: "POST", dataType: "json", data: form.serialize(),
                success: function (result) {
                    $("#userUnbindResult").text(result.msg || "操作失败，请重试");
                    if (result.code === 1) { window.location.href = form.attr("data-url-login"); }
                },
                error: function () { $("#userUnbindResult").text("网络请求失败，请稍后重试"); },
                complete: function () { button.prop("disabled", false); }
            });
        });
    });
})(window.jQuery);
