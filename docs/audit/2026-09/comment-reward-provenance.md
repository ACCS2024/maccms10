# 可信评论奖励标记与历史数据切分

本提交只建立评论来源证明。任务领奖的资格校验和客户端进度关闭在下一独立提交完成，不能将本提交单独视为任务奖励漏洞已关闭。

## 设计和边界

安装表及独立迁移新增 `comment_reward_verified TINYINT UNSIGNED NOT NULL DEFAULT 0`。历史记录、普通后台新增及匿名评论均保持 0；不依据旧 `user_id`、旧时间戳或旧任务状态追认可信来源。只在安全公开创建服务完成身份验证后，通过 `Comment::saveData($data, true)` 的内部参数为新会员评论写入 1。

字段键先校验为普通标识字符串并统一小写，拒绝大小写重复键以及限定列名/JSON字段表达式，避免 MySQL 大小写不敏感和通用字段过滤规则形成旁路。客户端或后台参数中的同名标记始终被剥离；通用 `fieldData` 不能修改标记，内部 trusted 参数也不能用于更新已存在的记录。改动用户归属、时间、内容、模块、目标或父评论会清除标记。仅修改审核状态或者保存未变化的原始字段会保留来源证明；批量修改上述关键字段保守清除标记。

审核尚未通过的新会员评论可以带有来源标记，但该标记不等于已获领奖资格；后续任务统计必须同时要求审核状态为 1、当前用户和当日服务器创建时间。已领取奖励的历史不在此处撤销。

未执行迁移的旧数据库继续支持普通评论，不自动执行 DDL，也不虚构奖励标记。迁移前安全创建的评论仍保持未认证，避免滚动部署期间错误追认。

## 迁移

独立入口：`migration/verify-comment-rewards.php`。默认只读 preflight，需要显式提供 `COMMENT_REWARD_SCHEMA_DSN`（带 dbname 的 MySQL DSN）、`COMMENT_REWARD_SCHEMA_USER`、`COMMENT_REWARD_SCHEMA_PASSWORD`，可选 `COMMENT_REWARD_SCHEMA_PREFIX`（默认 `mac_`）。不读取应用配置或 `.env`，不启动项目。

```sh
php migration/verify-comment-rewards.php
php migration/verify-comment-rewards.php --apply
```

操作人员先检查只读报告和备份，再在维护窗口显式 apply。一个 ALTER 添加默认 0 的标记和 `user_id,comment_reward_verified,comment_status,comment_time` 组合索引。报告包含现有行数、已认证行数以及固定 `backfill_verified=false`，不输出评论内容或连接密码。

已有错误列类型/默认值、非法标记值、同名索引冲突、缺失表/字段或非 InnoDB 表会阻止自动应用，须人工核对；不自动改写这些状态。重复执行保留已有记录和部署后合法的新标记。迁移后刷新应用数据库字段缓存或重启长期运行的 PHP 进程；缓存仍未更新时只会暂时不认证评论，不会给旧数据发放奖励。

## 验证

- `tests/security_audit_comment_provenance.php`：78 项 × PHP 8.3.33/8.4.25 × SQLite/MySQL，四组通过。覆盖两公开入口、游客/后台伪造标记、旧记录不追认、审核保留、关键字段修改撤销、普通与批量编辑，以及缺列兼容。
- `tests/security_audit_comment_reward_schema.php`：19 项 × 两个 PHP 的真实 MySQL，验证只读 preflight 不写、旧行默认 0、不改原字段、数据库新行默认 0、幂等、错误 schema/值/索引受控拒绝及非法表前缀。
- 现有公开评论创建 112 项在 PHP 8.4/SQLite 和真实 MySQL 复核通过。
- 日志：`/tmp/maccms-audit-20260910/comment-provenance-{sqlite,mysql}-php{83,84}.log`、`comment-reward-schema-php{83,84}.log`。
- 仅使用 MEMBERSHIP 测试环境；模型测试使用 `audit_*`，迁移测试使用独立 `audit_provenance_comment`。与同库其他套件串行执行。
