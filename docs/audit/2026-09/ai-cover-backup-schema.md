# AI 封面备份表结构

原有 `vod_pic_original` 只保存主图，无法恢复生成前的缩略图。新增 `vod_pic_thumb_original VARCHAR(1024) NULL DEFAULT NULL`：NULL 表示没有完整的缩略图备份；字符串（包括空字符串）表示已记录生成前的真实值。迁移不会用当前 AI 缩略图冒充原图，也不会覆盖历史主图备份。

新安装包含该列。已有数据库在维护窗口中使用独立 CLI 工具，显式指定目标；默认只读预检，`--apply` 才添加列：

```sh
php migration/add-vod-cover-backup.php --help
# 设置 VOD_COVER_SCHEMA_DSN、VOD_COVER_SCHEMA_USER、VOD_COVER_SCHEMA_PASSWORD；
# 非 mac_ 表前缀另设 VOD_COVER_SCHEMA_PREFIX。
php migration/add-vod-cover-backup.php
php migration/add-vod-cover-backup.php --apply
```

工具拒绝外层事务、非 InnoDB 视频表和不兼容列定义，使用数据库锁防止同一目标的迁移同时执行。MySQL DDL 会独立提交，实际发布须先备份并评估表大小和锁等待；应用请求不承担该 DDL。

专项回归使用固定隔离库 `maccms_audit_ai_cover`，设置 `VOD_COVER_AUDIT_MYSQL=1`、`VOD_COVER_AUDIT_HOST/PASSWORD` 后执行 `php tests/framework_audit_vod_cover_schema.php`。覆盖新装、旧表预检、幂等执行、历史数据保留、NULL/空字符串差异、不兼容列和调用方事务保全。此提交只提供表结构，生成和还原业务接入另作一批。
