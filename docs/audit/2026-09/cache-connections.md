# 缓存配置与连接探针（PHP 8.3 / 8.4）

旧 `System::test_cache` 调用 TP8 不存在的 `Cache::connect`，使用固定 `test` 键且没有有效期、读回和删除检查。生产 Redis 配置中的用户名也没有被框架驱动用于 ACL 认证；Memcached 的生产 store 没有传递认证字段。只修测试按钮会出现“测试成功，生产连接仍不可用”的分歧。

本组用 `CacheConnection` 统一生产配置和探针，并通过本地 Redis / Memcache / Memcached 适配器接入实际 native 客户端。没有修改 vendor、Session 配置、缓存清空入口或后台既有身份验证。`System.php` 仅替换 `test_cache`；`config/cache.php` 保留原有站点配置加载部分，只替换 store 构造部分。

## 配置合同

- 固定支持 `file`、`redis`、`memcache`、`memcached`，不把配置值当作任意类名加载。
- 缺省、空或非正 `cache_time` 保持 60 秒；缺省、空或非正 `cache_timeout` 保持 1.5 秒。正超时保留小数，最小 1 毫秒，最大 30 秒；无穷大、错误文本或数组会被拒绝。
- 选择网络 backend 时立即校验它的字段；选择 file 时，无关网络字段不会影响文件缓存。显式使用未选中的命名 store（包括现有 session cache driver）时，才校验该 store 的原始字段。不会把数组转换成字符串或悄悄改连另一地址。
- TCP 端口为 1–65535；未提供时 Redis 为 6379、另两种为 11211。缺省 host 为 `127.0.0.1`，显式空 host / port 视为错误。显式 null 的 host、port、用户名、密码或 Redis db 也属于错误，不能悄悄换成本机默认值或去掉认证；未提供字段仍使用上述默认值。host 不接受 URL、文件路径或用户信息。此配置接口面向单 TCP endpoint，未增加集群、Unix socket 或 TLS 参数配置。
- 用户名、密码必须是字符串，并保持原始字节，不进行 URL 解码、HTML 编码或 trim。Redis 支持用户名加密码 ACL，也保持仅密码认证；Memcached 的用户名和密码必须成对提供，并要求 native SASL 支持。Memcache 不支持认证，因此有认证字段时明确拒绝，不忽略它们。
- 错误配置会使选定 store 明确失败；生产 store 不自动退回 file，也不吞掉连接异常。未安装对应扩展的测试按钮返回受控错误。

Redis 使用非持久连接，并分别设置浮点连接和读取超时。Memcache 关闭 native 默认的持久连接并保留浮点 timeout。Memcached 使用无 persistent ID 的私有实例；连接与 poll 超时使用毫秒，发送与读取超时使用微秒。用户名认证启用 binary protocol。单位与持久连接语义分别依据 [PHP Memcached 选项文档](https://www.php.net/manual/en/memcached.constants.php) 和 [PHP Memcache::addServer 文档](https://www.php.net/manual/en/memcache.addserver.php)，并以真实客户端行为验证。

Memcache / Memcached 将超过 30 天的数值解释为绝对 Unix 时间；原框架直接传相对秒数，会把较长 `cache_time` 变成已过期时间。本地适配器现在将较长 TTL 转成未来时间戳，同时处理默认 TTL、显式整数、DateTimeInterface 和 DateInterval。显式 0 保持永久缓存；负 TTL 立即过期。超过通用 signed 32-bit 时间戳上限的长 TTL 在写入前拒绝，不加法溢出或变成永久缓存。[PHP 过期时间文档](https://www.php.net/manual/en/memcached.expiration.php)

## 实际测试按钮

后台现有 `system/config.html::test_cache()` 已通过 POST 正文发送 `type / host / port / username / password / db`，无需改模板。入口同时要求原始和有效 HTTP 方法均为 POST；query 不能提供或覆盖参数。可选正文 `timeout` 与生产相同单位，未传则使用站点的已保存超时配置。

探针独立创建驱动，不替换共享 cache manager。每次创建随机 `mac_probe_` 前缀键和随机值，TTL 为 30 秒；只有写入成功、完整读回一致、删除成功并确认不存在才返回 `code=1`。失败时再次尽力删除自己的键，无法删除时由短 TTL 兜底。不会覆盖旧固定 `test` 键或清空其他缓存。

配置错误返回 `code=1001`；扩展、连接、认证、数据库选择、实际读写或清理失败返回 `code=1002` 与对应固定消息。错误消息不包含用户名、密码、host 或完整连接字符串。探针暂时把 native 网络警告转成受控异常，结束后恢复原 error handler，避免错误文本污染 JSON。部分延迟连接失败只能在实际读写阶段判定，会报告读写验证失败。

## 回归证据

`tests/framework_audit_cache_connection.php` 使用真实 `app\Request`、真实 `System::test_cache` 方法、真实配置加载和 TP cache/session driver。为隔离既有管理员认证，测试通过反射直接建立控制器；不声称这里覆盖了后台登录构造链。所有凭证均为临时本地 fixture，服务仅监听测试容器 loopback，运行容器禁止外部网络。

覆盖：

- 正常 file 配置、缺省行为、错误类型、固定驱动映射、惰性 named store、POST 正文和方法覆盖、缺扩展/拒绝连接、原 error handler 恢复。
- 真实 Redis ACL 的正确、错误、只有密码及不存在用户名场景；runtime store 和现有 session driver 使用同一真实 named store；实际数据库、序列化、TTL 与 0.2 秒 native read timeout。
- Redis 限制删除权限时返回失败；遗留键保留自身短 TTL，且无关固定键保持不变。
- 真实 Memcache / Memcached 的正常读写删除、Memcached native 超时单位、SASL 正确和错误凭证、生产与探针保持相同原始密码、非持久实例。
- 两种 Memcache 客户端的 30 天边界、31 天、日期、时间间隔、显式永久/已过期 TTL、默认长 TTL，以及上限溢出前拒绝且零写入。
- 三个 native 客户端连接到只接收、不回应命令的隔离服务，验证 0.15 秒读取超时下在 2 秒内失败；不会用 mock 返回值证明超时生效。

测试会自行启动、关闭并清理属于本次运行的 Redis / Memcached / 静默 peer，不连接现有服务。CI 原生驱动步骤设置 `CACHE_AUDIT_REQUIRE_NATIVE=1`，缺任一扩展、daemon 或 SASL 组件即失败。未设置该要求的基础用例在缺少 daemon 或扩展时继续执行，并在输出标明真实集成分支不可用；“基础通过”不能替代完整驱动矩阵。

可在已有 PHP 8.3 / 8.4 测试镜像基础上构造包含真实服务的隔离镜像：

```sh
docker build --build-arg AUDIT_BASE=maccms-audit-image83:20260910 -f tests/fixtures/cache_runtime.Dockerfile -t maccms-audit-cache-integration83:20260910 .
docker run --rm --network none -e CACHE_AUDIT_REQUIRE_NATIVE=1 -v "$PWD:/app:ro" -w /app maccms-audit-cache-integration83:20260910 php tests/framework_audit_cache_connection.php
```

PHP 8.4 使用对应 `84` 镜像。测试也支持 `php tests/framework_audit_cache_connection.php`；是否执行真实服务分支取决于 native 扩展和本地 fixture daemon 是否齐全。扩展测试版本为 php-redis 6.3.0、Memcache 8.2、Memcached 3.3.0（SASL 开启）。

根代理补充显式 null / 非 TCP 地址拒绝与实际零连接验证后的结果：

| PHP | 基础镜像（无 daemon / Memcache 扩展） | 完整 native 集成镜像 | 本组 8 个 PHP 文件 lint |
| --- | --- | --- | --- |
| 8.3 | 105 / 105 | 162 / 162 | 全通过 |
| 8.4 | 105 / 105 | 162 / 162 | 全通过 |

本组未验证公网 DNS 故障时操作系统解析器的最坏阻塞时间、TLS / 集群连接、不同服务器版本或资源耗尽下的持续运行；不据此宣称整个缓存子系统审计完成。
