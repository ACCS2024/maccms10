/* UEditorPlus formula dialog: render the bundled MathJax TeX engine locally. */
var Formula = {
    revision: 0,
    imageSrc: '',
    init: function () {
        var input = document.getElementById('editor');
        var selected = editor.selection.getRange().getClosedNode();
        if (selected && selected.getAttribute('data-formula-image')) {
            try { input.value = decodeURIComponent(selected.getAttribute('data-formula-image')); } catch (error) {}
        }
        var timer;
        input.addEventListener('input', function () {
            clearTimeout(timer);
            timer = setTimeout(function () { Formula.renderPlain(); }, 200);
        });
        document.getElementById('inputDemo').addEventListener('click', function () {
            input.value = 'f(a) = \\frac{1}{2\\pi i} \\oint\\frac{f(z)}{z-a}dz';
            Formula.renderPlain();
        });
        dialog.onclose = function (event, confirm) {
            if (!confirm) { return true; }
            Formula.renderPlain().then(function (src) {
                if (!src) { return; }
                editor.execCommand('formula', input.value.trim(), src);
                editor.fireEvent('saveScene');
                dialog.close(false);
            });
            return false;
        };
        Formula.renderPlain();
    },
    renderPlain: function () {
        var latex = document.getElementById('editor').value.trim();
        var preview = document.getElementById('preview');
        var message = document.getElementById('formulaError');
        var revision = ++Formula.revision;
        Formula.imageSrc = '';
        message.textContent = '';
        preview.hidden = true;
        if (!latex) { return Promise.resolve(''); }
        if (latex.length > 10000) {
            message.textContent = '公式过长，请缩短后重试。';
            return Promise.resolve('');
        }
        return MathJax.startup.promise.then(function () {
            var node = MathJax.tex2svg(latex, { display: true });
            if (node.querySelector('[data-mml-node="merror"]')) {
                throw new Error('公式语法有误，请检查 LaTeX。');
            }
            var svg = node.querySelector('svg');
            svg.setAttribute('xmlns', 'http://www.w3.org/2000/svg');
            svg.setAttribute('color', '#111');
            var text = new XMLSerializer().serializeToString(svg);
            var src = 'data:image/svg+xml;base64,' + btoa(unescape(encodeURIComponent(text)));
            if (revision !== Formula.revision) { return ''; }
            Formula.imageSrc = src;
            document.getElementById('previewImage').src = src;
            preview.hidden = false;
            return src;
        }).catch(function (error) {
            if (revision === Formula.revision) {
                message.textContent = error.message || '公式无法渲染，请检查 LaTeX。';
            }
            return '';
        });
    }
};
