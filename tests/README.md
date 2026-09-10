# 测试与 CI

维护目标为 PHP 8.3 / 8.4，生产镜像默认 PHP 8.4。检查分为原生编译、独立行为回归、真实数据库、HTTP 契约及容器集成；通过某一层不能代替其他层，也不代表生产部署已经安全。

## 本地基础检查

```sh
composer install --no-dev --no-plugins --no-scripts --no-interaction
composer check-platform-reqs --no-dev
composer audit --locked --no-dev
composer --working-dir=extend/upyun audit --locked --no-dev
bash tests/lint.sh --json=/tmp/maccms-php-lint.json
php tests/run_audit.php
```

原生 lint 对维护中的业务、扩展、入口和脚本逐个执行 `php -n -d error_reporting=-1 -l`，不加载应用或 php.ini；解析错误、弃用等额外诊断和未完成扫描均失败。`--all` 另外包含依赖、运行目录和旧归档，报告记录范围与排除项。

`run_audit.php` 使用显式文件清单，每项运行在独立进程中，启用 E_ALL，限时 180 秒；缺文件、未知选项、超时及非零退出都会失败。默认执行 unit、models、financial，后两组默认用 SQLite。可以使用 `--suite=unit`、`--suite=models,financial`、`--list` 或 `--suite=all`。install 组的拒绝写入测试必须以普通用户运行，root 无法验证文件权限拒绝。

行为回归覆盖真实业务实现；部分脚本隔离渲染、第三方传输或 App 初始化，隔离点在各脚本头部说明。覆盖支付验签、金额/账变、会话与 CSRF、文件路径、远程请求、上传、ORM、采集、验证器及扩展协议。第三方支付使用测试签名和本地响应，不代表生产商户配置已验证。

## MySQL 与安装

只连接专用测试实例。脚本会创建、清空或删除专用数据库中的测试表，不能指向生产或共享业务数据库。所需库均使用 utf8mb4：

| 测试组 | 环境开关 | 固定数据库 |
| --- | --- | --- |
| models | `FRAMEWORK_AUDIT_MYSQL=1` | `maccms_audit_models`；部分完整安装模型使用 `maccms_audit_http` 的 audit 表 |
| financial / payment schema | `MEMBERSHIP_AUDIT_MYSQL=1` | `maccms_audit_membership` |
| install | `FRAMEWORK_AUDIT_MYSQL=1` | `maccms_audit_install` |
| HTTP | `MAC_AUDIT_FIXTURE=1` | `maccms_audit_http` 的 mac 表 |

前两种数据库开关分别使用 `FRAMEWORK_AUDIT_HOST` / `FRAMEWORK_AUDIT_PASSWORD` 和 `MEMBERSHIP_AUDIT_HOST` / `MEMBERSHIP_AUDIT_PASSWORD`，账号为测试实例 root。MySQL CI 使用 8.0；其他数据库版本尚不能据此认定通过。

```sh
# 设置上述对应环境变量后：
php tests/run_audit.php --suite=models,financial
php tests/security_audit_payment_schema.php
php tests/security_audit_ledger_schema.php
# 以下两次均以普通系统用户运行；第二次启用 MySQL 环境开关。
php tests/run_audit.php --suite=install
```

安装回归覆盖配置原子写入、拒绝写入/失败回滚、扩展检查以及真实 MySQL 的 Web/CLI 安装流程。线上历史表结构的只读预检与人工处理要求见 [支付表结构说明](../docs/audit/2026-09/payment-schema.md) 和 [账变留存说明](../docs/audit/2026-09/ledger-retention.md)；CI 不会对业务库执行迁移。

## HTTP 与生产镜像

HTTP 测试需要全新、可丢弃的 checkout：依次载入 `application/install/sql/install.sql`、`initdata.sql`、`tests/fixtures/http_seed.sql`，然后按 CI 中的环境变量运行 `tests/setup_http_fixture.php`。脚本拒绝覆盖已有 `.env`、站点配置或安装锁；测试账号与数据仅用于该临时实例。

`python3 tests/run_http_smoke.py` 检查实际前台/API action 的状态和固定内容，并运行两个故意失败的对照。后台以改名入口启动 PHP HTTP 服务，`admin_smoke.sh` 检查登录后的页面内容，`admin_write_smoke.py` 验证持久化修改、拒绝未授权写入以及 CSRF。严格诊断模式下的 500、空响应或缺少业务标记都不能通过。`ledger_http_smoke.py` 通过真实会员/管理员登录验证账变隐藏、后台保留、财务字段不变，要求 `MAC_MYSQL` 明确选择专用 HTTP 库；验证后恢复测试记录显示状态。完整启动顺序见 [工作流](../.github/workflows/ci.yml)。

```sh
docker build --build-arg PHP_VERSION=8.4 -t maccms-audit:8.4 docker
python3 tests/run_hits_buffer_audit.py maccms-audit:8.4
python3 tests/run_collection_audit.py maccms-audit:8.4
python3 tests/run_baidu_urlsend_audit.py maccms-audit:8.4
python3 tests/run_sdk_redirect_audit.py maccms-audit:8.4
python3 tests/run_apache_boundary_audit.py maccms-audit:8.4
python3 -m venv /tmp/maccms-qr-venv
/tmp/maccms-qr-venv/bin/pip install -r tests/requirements-qr.txt
/tmp/maccms-qr-venv/bin/python tests/run_qrcode_audit.py maccms-audit:8.4
```

容器回归需要 Docker、Python 3；HitsBuffer 还需要宿主 redis-server，百度 TLS 测试需要 openssl。各运行器创建并清理自己的临时服务。QR 测试独立解码实际 PNG，避免只比较生成器自身结果。Apache 测试用纯假站点验证镜像内默认配置和真实 TP8 Request，不请求仓库秘密文件；完整业务 HTTP 由另一层单独覆盖。

## 工作流与静态分析

push / pull request 工作流分别在 PHP 8.3、8.4 执行编译、锁定依赖检查、独立回归、SQLite/MySQL、安装、前台/API、后台及实际 Docker 镜像集成；ShellCheck 单独检查 deploy/tests 脚本。远程工作流需要提交推送后才会运行，本地等价验证不能表述为 GitHub CI 已通过。

PHPStan / PHPCompatibility 的锁文件、范围、命令及诊断解释见 [审计工具](../tools/audit/README.md)。目前仍有需要分类的静态候选，工具没有忽略基线；报告条数不能作为漏洞数量。审计状态及分项报告见 [当前代码审计](../docs/audit/2026-09/README.md)。
