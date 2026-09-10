# 远端对象生命周期 ③a：结果合同与持久意图基础

本批新增内部 API 和显式迁移，为下一批远端附件与头像接入提供持久证据；**尚未把现有 `Upload::api()`、图片下载或 AI 封面切到新 API**。旧调用的返回值、删除时机及配置读取保持原合同。因此不能把本批描述为远端上传一致性问题已全部修复。

## 已确认的调用链问题与分批边界

隔离的真实 Upload/Image/ORM 调用配合受控存储端，已复现以下行为：远端成功时 `StorageResult::complete()` 可以先删除本地文件，而 Annex/User/Vod 引用还没有可靠提交；远端上传流程仅处理主图及第一张缩略图；远端头像留下本地 `user_portrait`，而实际文件已经删除；SDK 抛错/非规范返回值可能导致异常或伪成功。旧远端路径不登记完整附件。这些问题由下一批接入修复，不在本批更换业务流程。

本批没有删除本地文件或远端对象，没有修改用户头像读取器，没有让历史 `user_portrait` 中任意 URL 生效，没有自动重试未知结果，也没有修改已有数据库数据。`SinaUpload` 的旧传输实现由独立批次处理。

## 新内部合同

`StorageIntent::prepare()` 在独立事务中保存随机意图 ID、供应商、目的配置摘要、用途和拥有者、本地路径、字节数、SHA-256、预期 URL 与初始状态。配置摘要只包含目标识别字段；数据库不保存密钥、口令、SDK 原始异常或签名查询参数。源路径必须在 `upload/` 下、组件合法且没有符号链接，头像必须是该用户已经约定的不可变随机路径。

`StorageTransfer::attempt()` 先把记录从 `prepared` 锁定转为 `attempting` 并得到 COMMIT 成功回执，然后才能调用 SDK。两个进程不能提交同一意图；`attempting`、失败结果和完成记录均不能被此方法重新上传。SDK 接收 `keep_local=1`，本批所有正常/失败结果都保留源文件。

| 供应商返回/本地情况 | 持久状态 | 返回给后续接入层 |
| --- | --- | --- |
| 已确认 SDK 完成且 URL 匹配受信目标 | `remote_confirmed`，引用仍为 `pending` | `remote` 与远端 URL |
| SDK 返回本地路径、false/null/错误对象、抛错或非法 URL | `outcome_unknown`，引用仍为 `pending` | `local_fallback` 与本地路径 |
| 外部调用后源文件改变或丢失 | 保留可确认远端 URL，记录 `source_changed` | `unavailable`，文件为 null，禁止登记引用 |
| 远端结果的数据库写入或 COMMIT 回执失败 | 保留已经独立提交的调用前意图；可能仍为 `attempting` | `unrecorded`，仅可返回仍有效的本地候选，不承诺远端完成 |

`outcome_unknown` 的含义是不能证明远端没有对象。超时、SDK 的本地回退以及错误响应都不会被宣称为远端回滚。

`StorageIntent::recordReferences()` 必须加入调用方现有的主库事务，不独立提交。它锁定并核对实际 Annex 的路径、类型、字节数，头像还要核对实际 User 指针；仅引用完成状态与明确的本地回退可登记。一次最多 32 个对象，整批先校验再更新，并精确读回结果。调用方必须在任何异常后回滚，最终的附件/用户写入、文件清理与响应仍属于接入批次职责。MySQL 的 Intent、Annex，以及涉及头像时的 User 必须全部是 InnoDB。

独立事务方法检查当前 PDO 以及实际主库 PDO 是否已有事务，包括绕过 ORM 计数器直接 `beginTransaction()` 的情况；已有事务时拒绝操作，防止外部上传已经发生但意图随后随业务事务一起回滚。冷连接通过只读查询初始化，不靠应用启动。普通查询仍须显式指向主库，避免从副本把尚未同步的证据看成不存在。

## 四个适配器的显式严格分支

仅新增内部参数 `submit($file_path, bool $verified = false)`。默认单参数调用保持原样，新的 Transfer API 显式传入 true。没有 SDK/vendor 修改或依赖变更。

| 适配器 | 新分支的完成证据 |
| --- | --- |
| S3 | 真实 `Aws\ResultInterface`，`@metadata.statusCode` 为 200/201/204；202 不作为完成 |
| Upyun | 同一已安装 SDK 的 `Uploader::upload(..., [], false)` 返回 PSR Response，状态为 200/201/204 |
| Qiniu | 当前上传 token 自定义 `returnBody` 的 `newName` 等于本次 key，`fsize` 精确等于本地字节数且是规范非负整数，`hash` 为非空字符串 |
| FTP | 实际 `put()` 严格返回 true，其他真值不能冒充成功 |

Upyun 的原 `write()` 会把 HTTP 响应转换为筛选后的响应头，成功上传非图片时可以合法返回空数组；所以没有用“是数组”或“数组非空”判定。新分支没有启用异步处理，也没有改变上传算法；只保留原方法会丢弃的 HTTP 状态。官方 REST 文档规定简单上传成功 200，分块完成为 201/204；实际已安装 SDK 的本地 HTTP 回归覆盖这些响应与 202、307、500。[又拍云 REST API](https://docs.upyun.com/api/rest_api/)

## URL 与头像未来读取边界

`StoragePublicUrl` 仅根据服务器已有存储配置构造目标：S3 使用同一 AWS SDK 的本地 URL 构造器或现有自定义域名规则，保留旧 `basepath` 的精确 key；Upyun/Qiniu/FTP 必须等于配置基址加本次路径。响应不能自行扩大域名或路径白名单。禁止凭据、query、fragment、控制字符、反斜线、路径穿越以及混淆编码。

Alibaba/Uomg/Weibo 在新 API 下需要管理员配置明确的 `public_url_prefix`，并按带尾斜线的路径前缀核对；缺失时在 SDK 调用前拒绝。此要求**尚不改变旧适配器调用**。URL 策略不推断图片服务的动态域名，也不会从首次响应自动建立信任。服务器配置的自建 HTTP 地址仍按现有合同允许，没有在本批强制全站 HTTPS 或发出 URL 探测请求。

后续头像仍保留不超过现有字段长度的本地逻辑路径；只有已核对且与实际引用同事务提交的远端记录，才可被专用 reader 批量解析。尚未实现这一读取接入。历史任意远端 `user_portrait` 不会因新增表而被激活。超过 Annex 255 字符的公共 URL、全部缩略图、Annex 列表 URL 展示及 `keep_local` 删除时机必须在业务接入中一并处理。

## 显式迁移与恢复限制

本批新增 `<prefix>storage_intent`，实际 DDL 见 `migration/lib/StorageIntentMigration.php`：InnoDB、ascii_bin、意图主键、本地不可变路径唯一索引、待核对和拥有者查询索引。URL 上限 2048 字符，字节/拥有者/Annex ID 为 UINT32。没有把积分上限套到 ID 上。

运行 `php migration/create-storage-intents.php` 默认只读取 information_schema 和既有行数，输出计划。必须提供显式选库的 `STORAGE_INTENT_SCHEMA_DSN`、用户、口令和可选表前缀；只有 `--apply` 才创建表。使用运维环境变量/密钥注入，不在命令历史中粘贴实际口令：

```sh
php migration/create-storage-intents.php
php migration/create-storage-intents.php --apply
php migration/create-storage-intents.php
```

支持的变量是 `STORAGE_INTENT_SCHEMA_DSN`、`STORAGE_INTENT_SCHEMA_USER`、`STORAGE_INTENT_SCHEMA_PASSWORD`、`STORAGE_INTENT_SCHEMA_PREFIX`。DSN 必须为 MySQL 且明确含 `dbname`。既有同名表的引擎、排序规则、列类型、可空性、生成属性和必要索引不匹配时受控阻断，不自动修复/截断/删除。重复运行保持已有证据。执行 DDL 时拒绝外层事务，避免 MySQL 隐式提交。当前新 API 尚未接入生产业务，因此没有改安装 SQL；启用下一批调用前，新旧安装均必须具备此迁移。

数据库与远端服务没有分布式原子提交。在“服务已收对象但响应没收到”，或“收到随机图床 URL 后数据库完全不可用/进程死亡”的窗口，记录只能证明曾经调用过，未必知道服务分配的随机对象 ID。四个确定 key 的供应商有持久化预期 URL；动态图床未返回的随机 key 不能凭空恢复。COMMIT 应答丢失也可能出现数据库实际已提交但调用方返回 `unrecorded`。运维核对必须先读取持久记录与存储端事实，不能直接重试、删除或对外宣称已回滚。本批没有自动垃圾回收或归档命令，不会删除任何既有凭证。

## 验证和 CI 接入

两版均使用 `maccms-audit-image83:20260910` / `maccms-audit-image84:20260910`，PHP 8.3.33 / 8.4.25，实际锁定依赖。源代码只读挂载，文件全部在独立临时目录；存储 SDK 仅用受控 fixture、进程内 HTTP handler 或 loopback HTTP，不发送真实外部请求。

| 测试入口 | PHP 8.3 / 8.4 |
| --- | --- |
| `tests/security_audit_storage_intents.php`，SQLite | 各 199 检查 |
| 同上，非严格 MySQL 真实 DDL | 各 218 检查 |
| `tests/security_audit_storage_sdk.php`，实际 AWS/Upyun | 各 25 检查 |
| `tests/extensions_audit_upload_adapters.php`，既有单参数合同 | 各 65 检查 |
| `tests/extensions_audit_upyun.php`，root-first/embedded-first | 每种顺序各 11 检查 |
| 本批 17 个 PHP 文件 | 两版 lint 通过 |

主测试还运行 6 个独立 COMMIT 故障子进程，每个 4 个断言，覆盖 prepare/claim/finish 的提交前故障和实际提交后丢失回执。真实 SQLite/MySQL 双进程测试覆盖一次 claim、外部效果后 SIGKILL 与引用仍 pending；真实数据库触发器覆盖 SDK 成功后的回执写入失败，MySQL 非严格截断必须由精确读回发现并回滚。迁移 CLI 默认只读、显式 apply、保留既有行、错误表和非法输入也由实际进程验证。

独立 `storage` suite 已加入默认回归和 CI，主测试 SQLite 默认运行；MySQL 单独串行设置 `STORAGE_AUDIT_MYSQL=1`，固定测试库 `maccms_audit_storage`，前缀 `storage_audit_` 与临时 CLI 前缀 `storage_cli_`，可选 `STORAGE_AUDIT_HOST` / `STORAGE_AUDIT_PASSWORD`。测试会重建这些专用表，不能指向业务库。SDK 入口需要 loopback 监听、proc_open 和现有 curl/PDO；无需新扩展或包。原 MySQL financial/upload 套件不复用此库。

```sh
php tests/run_audit.php --suite=storage
# 专用测试 MySQL 中先创建 maccms_audit_storage，设置 STORAGE_AUDIT_HOST/PASSWORD。
STORAGE_AUDIT_MYSQL=1 php tests/run_audit.php --suite=storage
```

后续仍分为手工上传/头像接入、下载/AI 封面接入；Annex 手工删除正在使用的引用是独立后续组。以上未完成入口不能算作本批已关闭。
