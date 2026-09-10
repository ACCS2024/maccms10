# 独立静态 HTML 的脚本策略

PHP 的 `SecurityHeaders` 不会保护直接打开的播放器、编辑器对话框或独立帮助 HTML。仓库新增以下配置补齐这些响应；这是待发布的配置，不能据此判断现网已经启用。

基线为 `script-src 'self' 'unsafe-inline' 'unsafe-eval'; object-src 'none'; base-uri 'self'; worker-src 'self' blob:;`。它保留当前本地 jQuery、layui、编辑器和 Blob Worker 的兼容性，阻止未批准的外站脚本标签。它不替代 XSS 防护，也不证明已有同源文件、内联脚本或数据库内容可信。自定义播放器如确需第三方脚本，应先审查并本地维护依赖。

## Docker / Apache

`docker/Dockerfile` 启用 `headers` 模块，`docker/apache/maccms.conf` 对实际文件名以 `.htm` / `.html` 结尾的响应设置强制 CSP。DirectoryIndex 打开的 `index.html` 也适用。规则没有授予目录或文件访问权限；原有源码、上传和敏感路径拒绝规则继续有效。

该规则按实际文件匹配，不按请求 URL 的 `.html` 后缀匹配。经过重写的前台路由和 `/index.php/...html` 继续由 PHP 设置 CSP，包括 `security_script_sources` 中明确批准的来源。静态 HTML 不会读取 PHP 配置中的额外来源。自建 Apache 环境必须启用 `mod_headers` 并加载相同配置；旧镜像需要重建，新代码卷本身不会更新镜像中的 Apache 配置。

在只含假数据的临时文档根下验证新构建的镜像：

```sh
python3 tests/run_apache_boundary_audit.py maccms-ci:8.4
```

已有审计镜像可以用工作区配置验证，脚本仅在一次性容器中启用模块并挂载配置，不修改运行中的站点：

```sh
python3 tests/run_apache_boundary_audit.py --working-config maccms-audit-image83:20260910 maccms-audit-image84:20260910
```

测试检查真实 HTTP 响应：静态 HTML/HTM、大小写后缀、DirectoryIndex、HEAD 均带强制头；PHP 及伪静态路由只有应用原有的批准来源策略；私有模板、双重后缀和上传 HTML 仍被拒绝。

## Nginx / OpenResty

将两份片段复制到服务器由管理员维护的配置目录，再按下面的层级引用。不要在网站可写目录中加载服务配置。

```nginx
http {
    include /etc/nginx/snippets/maccms-static-html-csp-map.conf;
    server {
        # 保留站点现有的 root、rewrite、PHP、deny 和其他 add_header。
        include /etc/nginx/snippets/maccms-static-html-csp-header.conf;
    }
}
```

`map` 在响应时仅为没有上游处理记录和上游缓存状态的 `text/html` 生成策略，覆盖直接静态文件、目录首页和 Nginx 自己的 HTML 错误页；JS、CSS、下载响应不添加该头。FastCGI、反向代理及其缓存响应保留上游 CSP，不会被第二条静态策略收紧，也不会自动得到本策略。缓存命中时 `$upstream_addr` 可能为空，所以同时检查 `$upstream_cache_status`。保持正确的 `mime.types`，HTML 应返回 `text/html`。机制依据 [Nginx map 文档](https://nginx.org/en/docs/http/ngx_http_map_module.html) 和 [响应头模块文档](https://nginx.org/en/docs/http/ngx_http_headers_module.html)。

配置片段不新增 `location`，因此不会改变现有敏感路径拒绝和 PHP 处理顺序。已核对仓库内 `deploy/nginx/maccms-legacy-noise.conf` 的 favicon/旧后台入口规则，以及 `migration/nei.selangzy.com.nginx.conf` 的拒绝规则、PHP include 和静态资源 location：本片段无需插入新的 HTML 正则 location。迁移配置引用的面板 rewrite 和 `enable-php-83.conf` 不在仓库，实际启用前需检查完整的 `nginx -T` 输出。

Nginx 默认在子 `location` 自己声明任何 `add_header` 时停止继承父级全部 `add_header`。这类会返回静态 HTML 的位置应同时引用 header 片段并保留原有 HSTS、nosniff 等头；同一层级不要重复引用。不要为此创建宽泛的 HTML location，避免改变 deny 优先级。默认继承规则见 [官方 add_header 说明](https://nginx.org/en/docs/http/ngx_http_headers_module.html#add_header)。

`migration/nei-cutover-proxy.nginx.conf` 的 `location ^~ /` 会将请求全部转发。应在最终实际提供 HTML 的上游启用配置；中转代理加载本片段不能补救上游漏头。其他反向代理、CDN 缓存以及上游错误后转成本地文件的特殊回退路径，需要分别核对最终响应。发布时检查配置后按站点既有流程 reload，并更新缓存中的旧 HTML 响应头。

本地真实 Nginx/OpenResty 回归只创建临时假文件和回环 HTTP 上游，不读取现网或业务数据：

```sh
python3 tests/security_audit_nginx_static_csp.py --nginx /usr/local/openresty/nginx/sbin/nginx
```
