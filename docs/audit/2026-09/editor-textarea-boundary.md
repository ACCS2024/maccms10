# 后台正文 textarea 的文本往返与元素边界

日期：2026-09-11。固定复现源 `e8776f8d`。范围：Actor、Art、Manga、Role、Topic、Vod、Website 的正文编辑框和 Vod 分集剧情，共八个实际模板。

## 已观察问题

默认模板过滤器为空，`mac_url_content_img` 只替换图片协议/地址，不承担 HTML 文本转义。实际模板输出中的实体被浏览器解码，文字中的 textarea 结束标记会结束原编辑框。以普通段落作为框外探针，PHP 8.3.33 / 8.4.25 生成的页面在 Chromium 中均出现两个 textarea 和一个额外段落；原本的实体字面量、开头换行也不能原样返回。

这批浏览器验证关闭页面脚本、阻断网络，不使用脚本载荷。早期 libxml DOM 证据用于定位，最终以实际 Chromium 的原生 inputValue 为准；不能把 HTML4 DOM 解析器的全部行为当作浏览器解析结果。

## 修改与验证

八个模板在原有图片/剧情分隔处理之后调用 `mac_escape_textarea`：明确 UTF-8，替代无效编码，对引号和 HTML 特殊字符转义，并保留实体字面量的双重编码。数据库内容不改写。每个起始标签后保留一个模板换行，供 HTML 解析器消费，因此正文自己的开头换行不再丢失。CRLF / CR 按浏览器 textarea 的通常行为成为 LF。

`tests/fixtures/editor_textarea.php` 从真实模板提取实际 textarea，使用项目的真实 Think 模板配置渲染；`tests/browser/editor_textarea.cjs` 验证原生输入值、唯一编辑框、没有额外段落以及无资源请求。每版 PHP 的 89 个用例共 269 项检查全部通过，覆盖普通/富文本、实体字面量、引号、结束标记作为文字、开头和不同形式换行、null、0、无效 UTF-8、图片协议及剧情分隔。原有购买模板 49 项也通过，修改 PHP 在两版 E_ALL 下编译无诊断，CI 工作流通过 actionlint。

```sh
npm ci --prefix tests/browser --ignore-scripts --no-audit --no-fund
CHROMIUM_BINARY=/usr/bin/chromium PHP_BINARY=php node tests/browser/editor_textarea.cjs
php tests/fixtures/editor_textarea.php capacity
```

浏览器命令已加入现有 PHP 8.3 / 8.4 CI 的浏览器步骤。也可提供 `EDITOR_AUDIT_PHP_IMAGE` 使用已安装 vendor 的项目目录运行容器 PHP。

文章实际模板另以 8 MiB 全引号文本渲染，输出 50,331,759 字节，两版峰值 113,258,496 字节（108.01 MiB），在 128M 下完成。这个检查针对单个最坏转义扩张的正文，不是完整管理页、多个分页正文或所有编辑器运行时的组合容量结论。

## 剩余范围

此处处理 HTML textarea 初始输出边界。富文本编辑器将输入值转为编辑文档时的内容策略、公开富文本展示、其它 textarea / input / JavaScript / URL 上下文、编辑器依赖及其上传插件仍须分别审计。它不是通用富文本清洗器，也没有执行完整后台登录、所有编辑器初始化或真实页面提交。
