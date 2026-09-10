# 远端对象生命周期 ③b：手工附件与头像接入

本批把 `Upload::upload()` 的网页、API 头像及后台编辑器上传接入已提交的[持久意图基础](storage-intent-foundation.md)。服务器身份/RBAC、CSRF、受控配置 GET、图片解码和本地不可变头像合同继续适用。本批不修改 `Upload::api()`、图片下载或 AI 封面；不能据此宣称所有远端写入已完成迁移。

## 确认问题与实际流程

旧远端手工流程先让供应商按 `keep_local=0` 删除本地文件，随后才处理未完整检查的附件/用户引用；只上传第一张缩略图，其他缩略图未完整登记；头像继续指向已删除的固定本地文件。图床返回失败、部分文件成功及数据库失败不能被同一个布尔“成功”表示。

新流程复用 `LocalAttachment` 的隔离接收、扫描、全部图片处理与独占随机文件发布，不复制编辑器分支：

1. 在私有临时目录完成校验和主图/全部缩略图；头像明确输出 JPEG。校验 User/Annex 事务能力并排除已有主库事务。MySQL 引擎检查明确查询主库，不能用副本的 InnoDB 结果放行主库 MyISAM。
2. 发布本次不可变本地文件，为**整批**准备持久意图。缺表、表不兼容、无效目标或任一 prepare 失败，在任何 SDK 调用前整批退回本地。部分已 prepare 的记录保留供核对，不能被说成完成远端引用。
3. 逐张调用原供应商的明确严格合同，SDK 始终收到 `keep_local=1`。网络期间没有 User/Annex 事务或行锁。每次外部调用先有独立提交的 `attempting` 记录，主图和每张缩略图分别持有结果。
4. 开始业务事务，重新锁定及检查头像拥有者，保存每张 Annex 并精确读回路径、类型、**字节数**、ID 和时间；头像写本用户不可变逻辑路径。所有意图引用与这些业务记录同事务提交。
5. 收到 COMMIT 成功回执后，`keep_local=0` 才清理已验证远端成功、实际引用仍匹配且源 SHA-256 未变化的本次本地副本。供应商失败的文件保留本地；清理失败保留多余副本，不把已提交上传改报失败。编辑器 echo/exit 在处理、事务和清理完成后执行。

普通 `local`/字面 `remote` 模式继续走本地流程。数字 2/3/4/5 继续分别映射 Upyun/Qiniu/FTP/Weibo。受支持的七种远端供应商逐张成功或失败可混合：返回的主图和每个缩略图各自指向实际远端 URL 或其本地回退文件。

## 持久引用与显示合同

`Annex.annex_file` 保存不超过 255 字符的本地逻辑路径；`User.user_portrait` 保留原有 VARCHAR(100)，新头像路径最长 61 字符；独立意图表保存最长 2048 字符的公共远端 URL。不会把长 URL 截断进旧列，也不会把 Annex 字节数继续写成 KB。附件响应仍以 KB 展示 `size`。

`StorageObjectUrl` 只激活 `remote_confirmed`、`reference_state=committed`、结果确认成功且真实 Annex 路径/类型/字节数吻合的映射。目标摘要必须匹配**当前服务器存储配置**，URL 还须符合其受信前缀/确定 key。头像读取另检查用途、拥有者、受控不可变路径，且从真实 User 指针选择对象。任意历史用户 URL、错误拥有者、待提交记录、伪造响应域名不能变成头像。批量读取最多每 500 个路径一次查询，空列表不访问请求或数据库。

手工上传远端成功现在返回原本已验证的 HTTP(S) URL，不再转成会丢失 TLS 语义的 `mac:`。本地回退保持原有相对路径/安装目录规则。编辑器和会员 response 不会给远端 URL 拼接站点子目录；本人头像 cookie 使用已提交的实际 URL。内部逻辑路径字段不会返回客户端。

Annex 列表使用新增 `annex_url`，只通过上述映射或安全本地路径生成链接。后台用户头像输入仍 readonly、无 name，已有有效 UID 才读取专用 helper；创建新用户时为空。`All::label_user` 只投影模板 `$tpl_user`，`index/User::__construct` 只投影 `obj` 副本；**不改 `$GLOBALS['user']` 身份行**、登录/过期处理、MemberWrite 或跳转。实际 demo 原模板过滤器重载可显示已移至远端的头像，无须批量修改旧主题。

目标配置改变会使旧映射校验失败。`keep_local=1` 且副本仍存在时可回退本地；`keep_local=0` 的旧头像可能回退本用户旧固定头像或默认图，附件本地链接可能不可读。因此迁移域名、bucket、路径或相关目的配置前，必须保留可恢复副本，先迁移对象并核对记录；本批**不提供自动改写历史目标摘要的迁移器**，不能承诺任意改配置后旧图仍可用。

## 失败、并发和恢复边界

| 故障位置 | 对外结果与保留状态 |
| --- | --- |
| 校验/权限/CSRF/图片处理/本地发布失败 | 受控失败；没有 SDK 调用，清理仅限本次已创建文件 |
| 任一 prepare 失败或旧库缺意图表 | 整批本地成功；零 SDK；保留已 prepare 的证据 |
| SDK 返回 false、抛错、返回不可信 URL或混合成功 | 逐张可验证本地回退；未知远端效果保留为 `outcome_unknown`，不声称已删除远端对象 |
| SDK 后回执写入失败/源改变/Annex 或 User 拒写/引用登记失败 | 受控失败；业务事务回滚，旧头像/cookie 不变；本次本地文件、独立意图和私有 manifest 保留，待核对 |
| COMMIT 回执丢失 | 受控失败，保留可能已经被提交记录引用的文件及 `commit_outcome_unknown` manifest；不能按“报错”直接删除 |
| COMMIT 后进程被终止，清理未执行 | 已提交引用可读，最多留下额外本地副本；不删除旧头像或另一次上传的文件 |

两个同 UID 请求在各自 SDK 阶段不持有业务锁；完成传输后分别在短事务中更新指针，最后成功提交者生效。每次随机路径独立，旧 URL 与历史缓存读者不会被新请求删除。本批不自动清理旧头像、不自动重试未知意图、不执行云端删除。

实际 SIGKILL 测试覆盖发布后、供应商实际写对象后、业务 COMMIT 前及 COMMIT 后；实际连接注入覆盖 COMMIT 前失败和已提交后应答丢失。私有 manifest 位于 `/tmp/maccms-attachment-*/manifest.json`，权限目录 0700，不写云凭据。临时目录在主机重启/清理后可能消失，不能把它当成备份；已调用 SDK 的意图以数据库记录为主要核对证据。对于随机图床，外部已收到对象但响应/数据库同时不可用时，调用前意图仍在，随机 key 可能无法恢复，不能伪造“跨系统回滚”。

`admin/Annex::check()` 不再因本地副本缺失删除有任意持久意图关联的 Annex；记录暂不可读或表不可用时也保留。此组没有修改管理员手工 `del`/`fieldData`，它们对在用引用的影响仍属后续独立组；未建立审计撤销与远端清理规则前，不应将普通附件删除当成对象生命周期回收。

## 迁移、测试与复现

需要先显式运行基础迁移 `migration/create-storage-intents.php --apply`；参数、只读 preflight 与引擎合同见[基础说明](storage-intent-foundation.md)。新旧安装缺表时本组仍可本地上传，但不会发起任何供应商调用。没有新增 Composer 依赖或扩展，沿用已提交的 GD/Imagick 图片部署要求。

新入口 `tests/security_audit_remote_upload.php` 使用真实 Request/UploadedFile、当前 ORM、图片处理和真实 DDL。只替换云 SDK 的外部效果，复制实际处理后的文件到受控对象目录；没有真实云凭据/外部请求。七种供应商、旧数字别名、全部衍生图、部分成功、可信 URL、长 URL、读取投影、主库/副本引擎差异、真实数据库触发器、非严格整数截断、权限错误、并发和进程中断均有行为断言。另运行独立会员/编辑器进程，验证 echo/exit 之后的数据库与文件状态。

```sh
php tests/security_audit_remote_upload.php
# 独立测试 MySQL 需允许固定两个 fixture 库；禁止指向业务库。
REMOTE_UPLOAD_AUDIT_MYSQL=1 php tests/security_audit_remote_upload.php
php tests/run_audit.php --suite=upload
```

MySQL 固定库 `maccms_audit_remote_upload`，前缀 `upload_audit_`；主库/副本测试创建 `maccms_audit_remote_upload_read` 并使用同一服务器的真实分离连接。可选 `REMOTE_UPLOAD_AUDIT_HOST`/`REMOTE_UPLOAD_AUDIT_PASSWORD`，仅测试 root 账户。测试重建这些专用表，主测试必须串行使用该库；独立编辑器子进程只用 SQLite。原 upload suite 使用原 `UPLOAD_AUDIT_*` 和 `maccms_audit_upload`，不混用。

真实 Chromium 使用仓库已锁定 Playwright 工具与系统 Chromium；远端模式开启后仍只访问隔离 loopback HTTP，服务端复制真实已处理图片模拟云对象，浏览器实际重新 GET 响应 URL：

```sh
# 先按 tests/browser/package-lock.json 安装固定工具依赖。
NODE_PATH=/isolated/browser-tools/node_modules PHP_BINARY=/path/to/php node tests/browser/upload_csrf.cjs
NODE_PATH=/isolated/browser-tools/node_modules PHP_BINARY=/path/to/php REMOTE_UPLOAD_AUDIT_BROWSER=1 node tests/browser/upload_csrf.cjs
```

PHP 8.3.33 / 8.4.25 均通过：新主测试 SQLite 1424 项、非严格 MySQL 1440 项；原 upload suite 各数据库 6 进程零失败；图片处理 111、图片上传 38、TinyMCE 104、旧适配器 65、实际严格 SDK 25、Annex 单元 4 项。原客户端模式保持 74 项，远端模式 90 项（8 个正常上传分别验证已提交意图与实际对象可读）。本批 23 个 PHP 文件双版本 lint 通过，浏览器脚本语法检查通过。已验证客户端不表示仓库缺失的旧编辑器依赖已经补齐；该既有部署限制仍以先前 CSRF 报告为准。

## 明确未处理的入口

静态扩查发现 `Image::down_exec()` 经 `Upload::api()`，`VodAiCover` 的主图和缩略图也调用该旧方法；它们仍可能在引用可靠提交前按旧 `keep_local` 删除源文件。③c 应分别接入各自业务事务，不能通过全局替换读取 helper 或悄悄改 `api()` 单参数合同假装已经解决。手工 Annex 删除/改路径、远端对象正式归档与撤销、存储目标迁移、孤立对象人工核对工具另行分组。本批不执行任何历史数据清理。
