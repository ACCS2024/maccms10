# 前端供应链本地化（2026-09-10）

本次按奇安信 Xlab 披露的 FUNNULL/RingH23 链路继续清理 fork 中可加载外部代码的前端入口。检查范围包括 `static/`、`static_new/`、所有主题、备份和 `.download` 文件；没有访问文章 IOC 域名，也没有执行混淆载荷。

## 已完成

| 入口 | 最终行为 |
| --- | --- |
| 默认主题两个 `*-home-stack.js`、两套 `static*/js/home.js`、旧主题 `home.js` 和 `.download` 副本 | 二维码统一调用同源 `index.php/qrcode/index.html`，完整编码页面 URL，兼容子目录安装；分享保留原始 URL 和 `{code:1,data:{url_short}}` 回调，不再发 JSONP。输出使用文本，URL 不作为 HTML 插入。 |
| 两套 `playerconfig.js.bak` | 预加载、缓冲页改为本地页面，避免恢复备份时重接联盟站点。 |
| 新版 UEditor 图片压缩 | 删除 worker 创建、`importScripts` 和远程 `libURL` 分支。保留内嵌 browser-image-compression 2.0.2 算法、尺寸和格式选项以及 EXIF 行为；压缩在主线程完成。 |
| 新版 UEditor 公式 | LaTeX 输入、预览和保存均通过本地 MathJax 生成 SVG，作为 data URL 存入文章；不加载远程 iframe、SDK 或图片服务。编辑已有公式时保留 LaTeX 属性。 |
| 两套 UEditor 表情 | 从已有本地 sprite 在浏览器 canvas 中截取静态 PNG；预览和插入不请求远程 GIF。七组表情保留，原远程动图改为 sprite 中的静态图像。 |
| UEditor 模板示例图、列表标记 | 示例图使用内嵌 SVG，列表使用原生 CSS 数字、中文或项目符号，不加载百度列表图标。 |
| 旧 UEditor 地图 | 编辑器保存地址文字或用户填写的 HTTP(S) 地图链接，也可使用图片功能上传截图。历史地图 iframe 保留坐标，显示用户点击后才访问的地图链接，沿用 BD-09 坐标系；页面不加载地图 SDK。 |
| 旧 UEditor 图片搜索 | 去除百度 JSONP 和已无用途的 GB2312 编码表；保留图片上传、本地图库、用户填写图片地址。 |
| IVA 播放器 key 和历史 `iva.html?u=...` | 跳转本地 DPlayer，保留播放 URL。两套 DPlayer 均兼容历史 `u` 参数、独立嵌入和已有父页播放信息。已有用户配置的解析地址和媒体资源地址不变。 |
| 默认静态广告、统计和演示依赖 | 删除 demo 专题页 JuicyAds 代码、两份无引用的 51.la SDK；图标示例页使用本地 jQuery，去除外部高亮代码、样式和装饰字体/图片。 |
| 旧 jQuery 插件 | 对两套 imageupload 和旧 cookie 的 Dean Edwards packer 按文本字典解包。确认都是正常插件，保留原功能，源码不再需要运行 `eval` 解包。 |
| 已退役 Mycj | 删除无控制器入口的 `application/admin/view/mycj/` 和 `static_new/mycj/`；现有本地 ResourceHub、BatchPlayer 提供相关管理功能。 |
| 旧主题 `m1938pc3_v2/js` | 替换被注入的 jQuery 和伪装成 Lazy Load 的远程脚本加载器。使用官方 jQuery 3.7.1、固定提交的 Lazy Load 1.9.7；自动补全插件的五处 `.size()` 改为 `.length`。 |

## 旧主题发现的真实残留

最终对脚本中的编码字符串复扫，确认 `template/m1938pc3_v2/js/jquery.js` 仍含文章域名相关的恶意加载器。原 SHA-256 为 `6ad4fa64e5979085b38af7995979cbe18d0c82f2bf6178b5db761666dc822c1a`。规范化换行后，其前 92,629 字节与官方 jQuery 1.9.1 相同，之后追加自定义 Base64 解码器、十六进制属性名和拼接的 `script` 标签。

载荷目标解码为 `zz.bdustatic.com` 的 `/linksubmit/push.js`，触发条件是 `navigator.platform` 不以 Mac/Win 开头且 `document.referrer` 含点。因此直接按域名搜源码、仅使用桌面直接打开页面，都可能漏检；本次没有运行原载荷。

同目录 `jquery.lazyload.js` 原 SHA-256 为 `9e31b2d470f49e6eae4b1526f892581f9abf00ed12d34d920e63c4cbc030cb34`。该文件不是正常 Lazy Load 插件，而是读取 `www.towoo.net` 的远程脚本，并配置向 `211.162.103.35` 加载 `static/Device/learn.js` 和浮动内容脚本，包含动态脚本标签、XHR 与 `eval` 路径。不能把它只当作无害统计；该文件已整体替换，未访问这些地址。

整个目录六个 JS 已逐一检查外部 URL、Base64 字符串、脚本/iframe 创建和尾部代码；另四个文件未发现同类供应商加载器。正常 Clipboard 文本复制、站内 API、用户配置的业务 URL 与 jQuery 自身通用 DOM/AJAX 能力保留。

替换后的 jQuery 3.7.1 已与[官方固定提交的构建文件](https://github.com/jquery/jquery/blob/f79d5f1a337528940ab7029d4f8bbba72326f269/dist/jquery.min.js)及官方 CDN 发布文件逐字节核对；Lazy Load 1.9.7 取自[官方固定提交](https://github.com/tuupola/jquery_lazyload/blob/218e50eb4999fe59ac94b939a65c8c988d1d420b/jquery.lazyload.min.js)。版本、来源、固定提交、新旧 SHA-256 均记录在 `template/m1938pc3_v2/js/SOURCE.json`。没有把未投毒的 jQuery 1.x 称为安全版本；此目录已经升级现代核心，其他旧主题/编辑器的历史依赖版本不在此次兼容升级结论内。

## Mycj 混淆客户端取证

原 `static_new/mycj/js/Mybase.js` 的 SHA-256 为 `f3648d0bc2daf2a4ac69bb05b6bc9330f342df4df1f117dd93eb50e2c2ef65f9`。文件前部为 CryptoJS，末尾为 jsjiami v7 加密字符串和 packer。

通过静态解析字符串、重排 Base64 字母表、RC4 解密和 62 进制字典替换，还原出自动远程脚本加载器。默认请求 `api.mycj.top` 的 `/collect/v10/data.js?ver=<version>`，错误时切换 `collect.mycj.pro`；`layui.sessionData` 还能覆盖域名及路径。这些域名并非据此认定为文章中的恶意 IOC，但后台自动执行供应商代码的路径不适合保留在本地 fork 中。解包全过程只把载荷当文本处理。

## 本地公式库来源及边界

MathJax 3.2.2 的完整 `tex-svg.js` 与 Apache 2.0 LICENSE 取自[官方仓库固定提交](https://github.com/mathjax/MathJax/tree/600692ad9d3552cc25f85510d5797bc942ecc9f7)，来源 URL 和 SHA-256 记录在 `static_new/ueditor/third-party/mathjax/SOURCE.json`。

采用自带 SVG 字形的整包，仅启用已打包的 `base`、`ams`、`newcommand`、`noundefined`；禁用自动扩展加载、`require`、HTML 链接/图片扩展和菜单，避免公式输入触发脚本、字体或图片下载。此配置依据[MathJax 的 autoload 说明](https://docs.mathjax.org/en/v3.2/input/tex/extensions/autoload.html)。公式仅接受本地渲染得到的 SVG data URL；回归同时检查恶意 `require`、`href`、`includegraphics` 不产生可执行 SVG 或外部引用。

旧地图坐标继续标记 `coord_type=bd09ll`，依据[百度地图 URI 文档](https://lbs.baidu.com/docs/webapi?title=mapadjustment%2Furi%2Fweb)，避免把原始百度坐标误当 GPS 坐标。

## 验证

运行 `node tests/security_audit_frontend_supply_chain.js`（Node.js、Chromium、ffmpeg，无 npm 依赖）。服务仅监听随机本地端口；Chromium 禁止外部 DNS，CDP 在请求发送前拦截非本地 URL。测试服务使用实际 `SecurityHeaders::scriptCspPolicy([])` 生成的强制 CSP。

2026-09-11 整理提交时重新运行通过，记录见 [工作区收尾验证](workspace-cleanup-20260911.md)：

- 六份分享代码在根目录、子目录及带尾斜线的路径下，二维码参数完整、同源，短网址回调兼容，无 AJAX/JSONP 或 HTML 注入。
- 强制使用 Linux ARM 平台标识、包含点的 referrer，加载旧主题全部六个 JS；jQuery 3.7.1 下自动补全上下键/Enter、图片懒加载、复选框全选正常，原载荷触发条件下仍无外部请求。
- 实际 JPEG 从 128×64 压缩至 32×16；即使传入 `useWebWorker:true` 和远程 `libURL`，也不构造 worker。
- 公式真实生成可解码 SVG，危险 TeX 不导入扩展或产生可执行标签、事件属性、外部引用。
- 地图链接文字正确转义，拒绝 `javascript:`，历史坐标类型不变。
- 两套编辑器表情实际插入 35×35 本地 PNG。
- 两套历史 IVA URL 通过本地 DPlayer 播放离线生成的 WebM，视频时间确实推进。
- 全程无外部请求或未捕获浏览器异常；除测试主动触发的未批准脚本拦截外，无意外 CSP 违规。

## 部署与内容数据

部署必须同步更新静态资源、清理浏览器/CDN 缓存，并按退役清单将 Mycj 与旧统计 SDK 迁出 webroot、保留证据；只覆盖 Git 中仍存在的文件不会删除服务器上的旧副本。

本次修改代码和默认资产，没有扫描或改写线上数据库。已有文章中的远程公式图片、历史外链、广告配置、用户自配播放器和主机级持久化，应按各自来源检查；静态默认入口清理不能代替这些检查。主线程压缩较大图片时可能短暂占用界面线程。
