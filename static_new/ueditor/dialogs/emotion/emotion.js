/* Local sprite sheets supply both previews and inserted PNGs; no remote emoji files. */
(function () {
    var sprites = { tab0: 'jxface2.gif', tab1: 'tface.gif', tab2: 'wface.gif', tab3: 'bface.gif', tab4: 'cface.gif', tab5: 'fface.gif', tab6: 'yface.gif' };
    var loaded = {};
    function imageFor(tab) {
        if (!loaded[tab]) {
            loaded[tab] = new Promise(function (resolve, reject) {
                var image = new Image();
                image.onload = function () { resolve(image); };
                image.onerror = reject;
                image.src = 'images/' + sprites[tab];
            });
        }
        return loaded[tab];
    }
    function localFace(tab, index) {
        return imageFor(tab).then(function (image) {
            var size = emotion.imageCssOffset[tab];
            var canvas = document.createElement('canvas');
            canvas.width = size;
            canvas.height = size;
            canvas.getContext('2d').drawImage(image, 0, size * index, size, size, 0, 0, size, size);
            return canvas.toDataURL('image/png');
        });
    }
    function buildTab(tab) {
        var host = document.getElementById(tab);
        if (host.firstChild) { return; }
        var table = document.createElement('table');
        table.className = 'smileytable';
        var row;
        for (var index = 0; index < emotion.SmilmgName[tab][1]; index++) {
            if (index % 11 === 0) { row = table.insertRow(); }
            (function (index) {
                var cell = row.insertCell();
                var face = document.createElement('img');
                var size = emotion.imageCssOffset[tab];
                cell.className = emotion.imageCss[tab];
                face.src = 'images/0.gif';
                face.title = emotion.SmileyInfor[tab][index] || '';
                face.style.backgroundPosition = 'left -' + size * index + 'px';
                cell.appendChild(face);
                cell.tabIndex = 0;
                cell.setAttribute('role', 'button');
                cell.setAttribute('aria-label', face.title || '表情');
                function insert(event) {
                    localFace(tab, index).then(function (src) {
                        editor.execCommand('insertimage', { src: src, _src: src, alt: face.title, title: face.title });
                        if (!event.ctrlKey) { dialog.popup.hide(); }
                    }).catch(function () {});
                }
                cell.onclick = insert;
                cell.onkeydown = function (event) {
                    if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); insert(event); }
                };
            })(index);
        }
        host.appendChild(table);
    }
    function switchTab(index) {
        var headers = document.getElementById('tabHeads').getElementsByTagName('span');
        for (var i = 0; i < headers.length; i++) {
            headers[i].className = i === index ? 'focus' : '';
            document.getElementById('tab' + i).style.display = i === index ? 'block' : 'none';
        }
        buildTab('tab' + index);
        var iframe = dialog.getDom('iframe');
        iframe.style.height = '380px';
        iframe.parentNode.parentNode.style.height = '392px';
    }
    window.onload = function () {
        var headers = document.getElementById('tabHeads').getElementsByTagName('span');
        for (var i = 0; i < headers.length; i++) {
            (function (index) { headers[index].onclick = function () { switchTab(index); }; })(i);
        }
        document.getElementById('tabIconReview').style.display = 'none';
        switchTab(0);
    };
})();
