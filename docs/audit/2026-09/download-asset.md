# 下载图片资产登记一致性（C1）

本批只修改 `Image::down_load/down_exec` 与本地/远端附件服务的内部下载入口。它保证返回成功的下载图片及全部衍生图进入 Annex，并在使用已接入供应商时与 StorageIntent 引用一起提交；Collect 或后台 Images 随后写入资源行仍是另一个阶段，不能据此宣称资源行与资产原子提交。

## 已确认问题与处理

旧下载路径先把字节写进公开目录，然后才验证图片，失败可留下文件；Annex 返回零写入也没有阻止成功返回。启用远端存储时只转投主图，全部缩略图没有完整登记；主图本地副本还可能在后续元数据失败之前删除。旧代码在水印之前取得大小，不能代表最终输出字节。此前普通 PNG、真实 ORM 与隔离供应商记录已确认这些路径。

现在 HTTP 图片仍由现有公共 HTTP 客户端获取，调用入口继续返回路径字符串，失败继续返回原 URL 加 `#err`。下载内部入口接收有界图片字节，不伪造上传请求；仅允许普通资源目录标识，`user` 不属于此入口。输入上限沿用 ImageProcessor 的 20 MiB。扩展名由实际 JPEG、PNG、GIF、WebP 类型决定，然后完整解码，在私有目录完成扫描、水印与全部缩略处理后才发布随机不可变文件。既有动画帧、延迟和循环以及正常本地/手工/头像上传合同保持。

所有文件都登记处理后的精确字节数，检查 Annex 保存结果并从主库精确读回。远端转投先准备完整意图集合，再调用供应商；网络阶段不持有 Annex/User 事务锁。下载意图使用 `scope=download`、`owner_id=0`，元数据和引用在同一短事务提交。缺少意图表、配置不适用、准备中途失败时整批保留本地，调用供应商次数为零。已确认提交之后才执行 `keep_local=0` 清理，失败不会删除已有旧图。

## 资源 URL 与故障凭证

资源图片列长度上限为 1024；Annex 保存最多 255 的本地逻辑路径，StorageIntent 独立保存供应商回执。所有可预测目标（包括缩略图）在第一次 SDK 调用之前检查长度。只要其中一个超出资源列限制，整批使用本地文件。

图床可能返回不可预测、经过当前目标策略认可但超过 1024 的真实 URL。此时保存真实远端回执，但资源结果选择本地逻辑路径，禁止删除该本地文件。失败 manifest 的 `selected_urls` 明确记录资源实际选择，Annex 管理页面仍可显示经过验证的完整回执 URL，不将它强行截断写入资源字段。当前目的配置发生变化时，映射读取仍遵循已有当前配置匹配规则，本批没有改变这个策略。

SDK 已产生效果而 Annex/引用写入失败时，保留已发布源文件、独立意图和私有 manifest，状态为 `remote_reference_failed`。提交曾尝试但未收到确认时保留文件与 manifest，标记 `commit_outcome_unknown`，不能把 API 失败理解为远端对象已撤销。未产生远端效果且可确认回滚的普通失败只清理本次文件。测试在隔离 fixture 退出时清理自身证据；应用不会因此自动删除这些待核对资产。

## 回归与复现

新增入口：`php tests/framework_audit_download_asset.php`。使用现有 `security_audit_remote_upload_db.php`，真实 Request、图片处理、Annex、StorageIntent 和 ORM；只有图片 HTTP 与供应商外部传输用普通图片数据替代，不访问公网或真实云账户。

- PHP 8.3.33 / 8.4.25，各自 SQLite 591 项、MySQL 565 项。
- MySQL 使用安装 DDL、InnoDB 与非严格 SQL 模式；实际拒写、第二张拒写、字节变更、窄字段截断和非事务表均由数据库执行。SQLite 额外覆盖真实零行写入。
- PNG/JPEG/WebP/GIF、全部缩略图、动画时序、水印后大小、SDK false/异常/部分成功、缺表、部分意图准备、可预测/不可预测长 URL、原始 PDO/ORM 外层事务、正常旧入口和旧文件保留。
- 独立 SQLite 子进程覆盖普通写入权限失败，以及本地/远端 COMMIT 调用前后异常：核验实际行、引用状态、文件和 manifest。子进程不连接 MySQL，不会重置父进程数据库。
- 本批 7 个 PHP 文件在两个版本均通过语法检查。未运行执行型浏览器样本或外部请求。

容器需当前图片依赖及 GD、Imagick 3.8.1、PDO SQLite/MySQL。SQLite 可直接使用隔离网络运行：

```sh
docker run --rm --network none -v "$PWD:/app:ro" -w /app --entrypoint php \
  maccms-audit-image83:20260910 tests/framework_audit_download_asset.php
```

MySQL 使用独立测试服务器及已创建的 `maccms_audit_remote_upload` / `maccms_audit_remote_upload_read` 数据库，以 `REMOTE_UPLOAD_AUDIT_MYSQL=1`、`REMOTE_UPLOAD_AUDIT_HOST`、`REMOTE_UPLOAD_AUDIT_PASSWORD` 传入 fixture 连接。同一测试库的两个版本必须串行运行，禁止对生产数据库执行这些建表/故障 fixture。版本 8.4 使用对应 `maccms-audit-image84:20260910` 镜像。

## 独立后续项

LocalAttachment 自身 BEGIN/ROLLBACK 异常及 ORM/PDO 深度失配需要独立状态机与连接隔离批次。当前 COMMIT 不确定保留已经覆盖，但不能以本批测试宣称所有回滚失败都能正确保留文件或隔离连接。

AI 封面的完整资源更新、Collect/Images 资源绑定、主动附件/远端对象删除、正式凭证核对与回收工具仍分别待处理。本批不修改这些调用方，也不自动回收已经登记但资源绑定失败的图片。
