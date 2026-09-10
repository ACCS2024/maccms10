# 视频重复目录：保存结果与维护故障隔离

日期：2026-09-11。固定复现源为 `78ddcf4f`；本批仅处理保存后的目录维护、调用方事务边界和受控失败，审计继续进行。

## 真实故障

双 PHP、真实安装 MySQL 的隔离副本中，删除派生目录表后，在调用方事务中修改普通标记并保存视频：原 PDO 由活动变为非活动；调用方随后 rollback 没有报错，但独立 PDO 仍读到已提交的视频和标记。另一用例只让原表的 BEFORE DELETE 触发器报告普通数据库拒写，原流程仍返回成功，却删掉重建原表，额外列和触发器一并消失。

这不是 SQL 语法问题。MySQL 的 CREATE / DROP / ALTER / TRUNCATE TABLE 会造成隐式提交，不能放进调用方业务保存的异常补救中；见 [MySQL 8.0 官方事务说明](https://dev.mysql.com/doc/refman/8.0/en/implicit-commit.html)。原 catch 无法区分缺表、拒写和其它数据库故障。

## 本批合同

- 普通保存只在无调用方事务的当前 MySQL writer 上维护现有目录。缺表、视图、数据库拒写都不触发 DDL，任何错误均不 DROP 原表。实际连接的查询构造器决定表名，摆脱固定 `connections.mysql.prefix`。
- ORM 层有嵌套计数，或原 PDO 正在事务中时，目录 DML 全部延后；维护代码不 BEGIN、不 COMMIT、不 ROLLBACK，也不修改调用方的嵌套状态。显式重建同样先拒绝调用方事务。
- 主记录 SQL 已被确认后，目录失败不再抛成失败插入：返回 code 1，同时 `info.repeat_index_pending=true`，消息明确提示目录待更新。此确认不代表调用方的外层事务已经提交。
- 目录失败尝试失效完整重建时间；缓存失效失败也保留待更新响应。单名刷新不能把全表的更新时间续成“刚完成全量重建”。一次刷新失败后不继续处理下一个名字。
- 更新前确认资源存在，UPDATE 零影响时再次从主库确认；合法幂等更新继续成功，已不存在的 ID 返回 1002。此检查不构成并发版本控制。
- 后台 data 动作的主动和过期目录重建均返回受控失败提示。重建仅在确实缺表时 CREATE，保留已有表的附加列、索引及触发器。

## 验证入口

`tests/framework_audit_vod_repeat_faults.php` 使用真实 TP8 Model / DbManager、安装 MySQL、独立观察 PDO，以及只作用于测试目录的原生拒写触发器。覆盖非严格、NO_AUTO_VALUE_ON_ZERO、STRICT_ALL_TABLES + NO_AUTO_VALUE_ON_ZERO 三种模式。

```sh
python3 tests/run_vod_save_audit.py <php83-image> <php84-image>
```

该入口使用独立、禁网、随机凭据的 MySQL socket 容器，依次运行保存、普通目录和故障目录三个专项。PHP 8.3.33 / 8.4.25 各通过保存 438 项、普通目录 120 项、故障目录 162 项；故障项含真实后台 data 动作的主动/过期重建失败响应（鉴权构造与页面渲染不属于这个夹具）。普通输入专项 `php tests/framework_audit_vod_save_input.php` 各 148 项。修改 PHP 文件在两版 E_ALL 下编译无诊断。

## 后续边界

现有显式重建仍为 TRUNCATE 后全量 INSERT，失败可能留下空/部分目录；本批确保不删表并报告失效，尚未保证原子发布。单名 DELETE / INSERT 的并发唯一性、重建与保存竞争、全局缓存键命名空间、GET 触发重建和其它写入口的一致性仍待下一阶段处理。事务内延后仅有响应与失效标记，没有持久任务队列或提交后钩子；主记录仍必须由调用方最终提交或回滚。

本批没有执行生产建表、目录清理或数据库迁移，没有把派生目录的隔离结论扩大到 SEO、Meilisearch、附件绑定等其它写后操作。
