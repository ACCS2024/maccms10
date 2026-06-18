/**老大哥copy代码QQ：788 47 023*/
$(function() {
    InitCopy();
});
function copy1(suf)
{
    var copystr = GetCopyStr(suf, 1);
    CopyText(copystr);
}
function copy2(suf)
{
    var copystr = GetCopyStr(suf, 2);
    CopyText(copystr);
}
function copy3(suf)
{
    var copystr = GetCopyStr(suf, 3);
    CopyText(copystr);
}
function checkAll(suf, checked) {
    var a = $("input[name='copy_"+suf+"[]']");
    var n = a.length;
    for (var i = 0; i < n; i++) {
        a[i].checked = checked
    }
}
function GetCopyStr(suf, type) {
    var a = $("input[name='copy_"+suf+"[]']");
    var n = a.length;
    var ldgcopystr = "";
    for (var i = 0; i < n; i++) {
        if (a[i].checked) {
            if (type == 2) {
                ldgcopystr += a[i].value;
            } else if (type == 3) {
                ldgcopystr += a[i].value + "$" + suf;
            } else {
                const strs=a[i].value.split("$");
                if(strs.length>1){
                    ldgcopystr += strs[1];
                }else{
                    ldgcopystr += a[i].value;
                }
            }
            ldgcopystr += "<br/>";
        }
    }
    return ldgcopystr;

}

function InitCopy() {
    var self = this;
    var element = document.body;
    var oDiv = document.createElement('div');
    oDiv.innerHTML = "ldg";
    oDiv.id = 'copyContent';
    oDiv.style.opacity = 0;
    oDiv.style.position = 'fixed';
    oDiv.style.zIndex = '-9999';
    element.appendChild(oDiv);
}

function CopyText(copytext) {
    var self = this;
    var info = "";
    var flag;
    var ua = self.ua;
    try {

        var content = document.getElementById('copyContent');
        content.innerHTML = copytext;
        var selection = window.getSelection();
        var range = document.createRange();
        range.selectNodeContents(content);
        selection.removeAllRanges();
        selection.addRange(range);
        var resultCopy = document.execCommand('Copy', false, null);
        if (resultCopy || ua.indexOf("UCBrowser") > -1) {
            flag = true;
        } else {
            flag = false;
        }

    } catch (e) {
        flag = false;
    }
    if (flag) {
        alert("复制成功");
    } else {
        alert("复制失败,请手动选中复制");
    }
    return flag;
}