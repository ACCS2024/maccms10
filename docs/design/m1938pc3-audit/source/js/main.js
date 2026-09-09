//赖加载
$(document).ready(function () {


    $(".on-window").click(function () {
        $(".window").slideDown("slow");
    });
    $(".window img").click(function () {
        $(".window").slideUp("slow");
    });


    $(".window input").click(function () {
        $(".window").slideUp("slow");
        alert("提交成功!");
        $(".window textarea").val("");
    });

  


    //详情列表
    $("#m3u8But").click(function () {
        if ($("#m3u8But").is(":checked")) {
            $("[name='selectedM']").prop("checked", true);//全选 
        }
        else {

            $("[name='selectedM']").prop("checked", false);//取消全选
        }

    });

    $("#playBut").click(function () {
        if ($("#playBut").is(":checked")) {
            $("[name='selectedP']").prop("checked", true);//全选 
        }
        else {

            $("[name='selectedP']").prop("checked", false);//取消全选
        }

    });



    var clipboard = new Clipboard('#m3u8Copy', {
        text: function () {
            var playNum = $("#playNum").text();
            var content = "";
            for (var i = 1; i <= playNum; i++) {
                if ($("#seleMId" + i).is(":checked")) {
                    if (i != 1) {
                        content += "\n";
                    }
                    content += $("#m3u8Id" + i).val();
                }
            }
            return content;
        }
    });
    clipboard.on('success', function (e) {
        alert("复制成功");
    });

    clipboard.on('error', function (e) {
        console.log(e);
    });

    var clipboard2 = new Clipboard('#playCopy', {
        text: function () {
            var playNum = $("#playNum").text();
            var content = "";
            for (var i = 1; i <= playNum; i++) {
                if ($("#selePId" + i).is(":checked")) {
                    if (i != 1) {
                        content += "\n";
                    }
                    content += $("#playId" + i).val();
                }
            }
            return content;
        }
    });
    clipboard2.on('success', function (e) {
        alert("复制成功");
    });

    clipboard2.on('error', function (e) {
        console.log(e);
    });
});


