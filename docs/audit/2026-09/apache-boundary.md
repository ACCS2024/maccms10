# Docker Apache 公开访问边界

日期：2026-09-10。范围限 `docker/Dockerfile`、镜像内 Apache 配置和隔离 HTTP 回归。未启动真实站点，未请求仓库中的真实配置、凭证或用户文件。

## 已确认的问题

旧镜像直接以仓库根目录 `/var/www/html` 为 DocumentRoot，只启用 rewrite 和 `AllowOverride All`；当前仓库没有根 `.htaccess`。在旧 PHP 8.4 生产镜像中，用纯临时假站点复现了 8 项行为：假 `.env`、`.git/config`、`composer.lock`、`application/fixture.txt`、`runtime/session/example` 可直接读取；假上传 PHP 可执行；上传目录的 `.htaccess` 可把 `.jpg` 改成 PHP handler；不存在的前台路由返回 404。

以上证据来自人工哨兵文件及无害执行标记，不能据此推断真实站点已被利用。测试容器无外部网络和发布端口，所有 HTTP 请求均发往容器内回环地址。

## 修改后的边界

- Dockerfile 将 `apache/maccms.conf` 安装为默认虚拟主机，保护不依赖仓库中的可写文件。`AllowOverride None`、`AllowOverrideList None` 禁止上传的 `.htaccess` 改写 handler；`Options None` 禁止目录列表、CGI/SSI 和跟随符号链接。
- 拒绝点文件/点目录、内部源码/配置/运行数据/迁移/工具/备份目录、Composer 清单、备份及配置后缀、根目录压缩包和 `security_check.php`。中央 rewrite 拒绝规则同时覆盖双扩展名，避免模板资源的授权规则重新放行 `source.sql.css` 等文件。
- 根目录小写 `.php` 仍作为可信入口执行，保留 `index.php`、`api.php`、`install.php` 和任意合法改名后的后台入口及 PATH_INFO。嵌套路径上的 PHP/CGI 等脚本拒绝访问；公开资产目录另关闭 PHP engine。
- 保留现有 `static/`、`static_new/`、模板样式/脚本/图片/字体、旧模板 `vendor/jquery`、模板 `help/*.html`、插件资源和 `/static/addons/...`。模板/插件 view 和配置默认不公开；仅其 `asset`、`assets`、`static` 子目录允许所需的静态 JSON/HTML。
- 上传目录只公开图片、当前上传契约中的文档/压缩包和媒体扩展。上传 HTML/SVG/脚本拒绝；带 PHP 文本的假 JPG 仅以图片扩展静态传输，不能执行。内容真实性仍由上传业务检查负责。
- 已存在的公开 HTML、robots、sitemap、站点验证文本和规范 ACME challenge 路径保持可访问。缺失资源返回 404；空目录不能靠 DirectoryIndex 子请求误进入应用并返回成功。
- 不存在的业务路径重写至 `index.php`，通过 ThinkPHP 的 `s` 兼容参数传入解码后的路由；转义后追加在查询末尾，保留中文、空格、原查询、POST 和认证头。使用 `NS` 避免目录索引的内部子请求被重写。

后续完整应用联调发现通用 `.properties` 拒绝规则同时拦截了默认模板的中英文语言包。现在仅放行 `/template/<规范目录名>/asset/language/strings_en.properties` 和 `strings_zh.properties`，以纯文本返回；其他 properties、备份/脚本双扩展、PATH_INFO 和链接到私有文件的符号链接仍拒绝。正向 Location 例外与精确 rewrite 规则配套，文件系统的脚本禁用、点路径拒绝和不跟随符号链接继续生效。

Apache 的覆盖范围和段合并顺序参见 [AllowOverride](https://httpd.apache.org/docs/2.4/mod/core.html#allowoverride)、[配置段合并](https://httpd.apache.org/docs/2.4/sections.html)；rewrite 转义及子请求行为参见 [rewrite flags](https://httpd.apache.org/docs/2.4/rewrite/flags.html)。保护文件和资源放行规则必须一起审查，不能只依赖一个后缀拒绝清单。

## 验证

```bash
docker build --build-arg PHP_VERSION=8.3 -t maccms-audit-apache83:20260910 docker
docker build --build-arg PHP_VERSION=8.4 -t maccms-audit-apache84:20260910 docker
python3 tests/run_apache_boundary_audit.py \
  maccms-audit-apache83:20260910 maccms-audit-apache84:20260910
```

两版最终镜像各通过 201 项 HTTP 断言，PHP 分别为 8.3.33、8.4.25；两版 `apache2ctl -t` 和 PHP 测试文件 lint 均通过，Python harness 语法检查通过。最终测试直接使用镜像内的默认配置，不额外挂载配置文件，以验证 Dockerfile 的安装步骤。

假站点入口仅加载仓库的 Composer autoloader 和真实 ThinkPHP 8 `Request`，使用全新临时 `App` 路径，不初始化真实项目。验证根入口、改名后台入口、API/PATH_INFO、安装入口、前台漂亮 URL、插件虚拟路由、中文/空格路由，以及查询参数、POST、Authorization 的保持；同时验证点路径编码、双扩展名、上传 handler 覆盖、目录符号链接和公开资源。

另在可丢弃的真实应用副本中，PHP 8.3/8.4 新镜像各通过 19 条前台/API 内容契约、两个实际语言包、37 项真实会员/管理员账变 HTTP 断言和 32 个后台页面。使用专用 MySQL 与严格 PHP 诊断，未读取或部署实际站点。这层补充验证用于发现人工假站点未覆盖的业务资产。

旧镜像基线可独立复现（镜像必须是修复前构建）：

```bash
python3 tests/run_apache_boundary_audit.py --baseline maccms-audit-production84:20260910
```

## 部署影响与剩余范围

- 升级必须重新构建镜像，旧镜像不会自动获得此配置。已有根/模板/插件 `.htaccess` 不再生效；确有需要的自定义路由或响应头应审查后写入可信 Apache 配置并重建镜像。
- 后台改名必须仍放在仓库根目录并以 `.php` 结尾。所有根 PHP 都被视作部署者授权的入口，因此这不是恶意代码检测器；不要把不可信 PHP 放到根目录。
- 依赖符号链接提供静态资源的外部部署需要改为真实文件或受控挂载；不要重新全局打开 `FollowSymLinks`。新插件若需要额外公开文件类型，应按具体目录增加规则及回归，不能放开整个 `addons`/`template`。
- 本批验证 Apache 到真实框架 Request 的边界，不等于所有页面、插件或数据库业务均已通过端到端测试。外部代理/CDN、HTTPS 终止、其他自建 Apache/Nginx 配置、仓库根新增私有目录不在自动保护覆盖承诺内；新增部署内容仍需评审公开路径。
