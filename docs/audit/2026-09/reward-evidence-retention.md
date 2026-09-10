# 奖励凭证留存（2026-09-10）

## 已确认根因与边界

`TaskLog::delData()`、`SignLog::delData()`、`Visit::delData()` 原来物理删除记录。任务的每日唯一键、签到日期/连续天数以及访问的用户/IP/日期配额都依赖这些记录。积分及 Plog 已经入账以后，删除凭证不会撤销积分，却会移除防重复领奖所需的证据。`Visit::saveData()` 原来还支持传入既有 `visit_id` 更新记录，`fieldData()` 可以改变归属、IP、日期，具有相同风险。

后台 `Task::log_del()` 和 `Visit::del()` 暴露按 ID 删除和清空入口。两个列表也提供删除/清空及勾选功能。访问列表另有两个实际非空数据错误：模型没有回填模板所需的 `user_name`；勾选项错用 `ulog_id`。缺省筛选参数也可能产生 PHP 8 未定义键错误。

本组只关闭普通记录修改/删除入口。任务进度和领取状态仍由原有受控事务推进，签到及访问正常创建仍保留。未修改任务定义删除、里程碑定义、User、API 或原始账变模型。

## 当前留存政策

* 任务和签到记录一律拒绝普通删除，包括未领取、零积分、已领取及历史记录，不按状态执行隐式清理。
* 访问记录只允许正常新增；`saveData()` 出现显式主键即拒绝，包括大小写不同、零值、空值。新增只接收归属/IP/来源字段，时间仍由服务端写入；数据库失败返回受控错误。`fieldData()`、`delData()` 一律拒绝。
* **`user_id=0` 的网站引荐记录同样保留。** 这些记录与会员访问混表，且 `Website::visit()` 使用它们判断网站引荐的每日额度，不能当作无主记录任意清理。本次明确对整个 Visit 表的普通界面采用只追加、只读政策，并在界面说明包含网站引荐。没有执行归档、迁移或删除现存数据。
* 后台两个删除方法直接返回可读的错误，不再解析 ID、查询或尝试删除。列表保留搜索/分页，移除勾选、删除和清空入口并说明凭证保留。
* Visit 列表仅对当前页用户 ID 批量查询 `user_name`，不加载完整用户资料；网站记录和已删除用户使用空名，原始归属 ID 保留。页面安全转义来源和用户名，已经保存为 HTML 实体的来源不会重复转义。

正式归档、撤销和保留期限应另行设计具备操作审计的流程，并先保证重复领奖屏障仍然存在；不能以物理删除已结算凭证替代资金撤销。已被旧版本删除的记录无法由本补丁重建，需根据可信备份和账变单独核对。本补丁也不限制数据库管理员直接执行 SQL 的能力。

## 验证

新增两套独立进程回归，分别复用已有任务奖励和访问奖励数据库 fixture，避免重复加载公共会员 fixture。MySQL 使用安装 SQL 的真实表结构、真实 Think ORM，专用测试库 `maccms_audit_membership` 与 `audit_` 前缀；SQLite 镜像相同业务字段约束。MySQL 测试串行执行且关闭严格模式。

| 测试 | PHP 8.3 / SQLite | PHP 8.4 / SQLite | PHP 8.3 / MySQL | PHP 8.4 / MySQL |
| --- | ---: | ---: | ---: | ---: |
| `security_audit_task_retention.php` | 68 | 68 | 68 | 68 |
| `security_audit_visit_retention.php` | 76 | 76 | 76 | 76 |
| 原有 `security_audit_task_rewards.php` | 88 | 88 | 88 | 88 |
| 原有 `security_audit_visit_rewards.php` | 55 | 55 | 61 | 61 |

覆盖真实成功领奖/签到/访问后，按 ID、批量、清空、异常参数及 GET/POST 删除全部拒绝，原始余额/账变/凭证逐项不变，再次领奖或访问不再入账；另覆盖零积分、历史签到连续天数、网站引荐新建及每日额度、已有 Visit 主键更新、修改日期/IP/归属、正常新建和数据库写入失败。

两个后台真实控制器执行真实 ORM 列表查询，使用实际 Think 模板引擎渲染非空列表，覆盖会员、网站、已删除用户及 HTML 内容。仅后台公共布局与认证壳使用 fixture，未启动原工作区应用入口；未将该测试声称为全后台 HTTP/鉴权回归。

运行示例（PHP 8.4；8.3 对应镜像为 `maccms-audit-image83:20260910`）：

```sh
docker run --rm -v /home/dev/maccms10:/work:ro -w /work \
  maccms-audit-image84:20260910 php tests/security_audit_task_retention.php
# 根据 tests/README.md 准备专用库，设置 MEMBERSHIP_AUDIT_HOST/PASSWORD 后：
MEMBERSHIP_AUDIT_MYSQL=1 php tests/security_audit_visit_retention.php
```

MySQL 参数沿用 `MEMBERSHIP_AUDIT_MYSQL/HOST/PASSWORD`。日志保存在 `/tmp/maccms-audit-20260910/reward-retention/`。测试只使用隔离库，未访问生产数据。

## 同类扩查与后续

当前应用源码未发现这三类记录其他直接物理删除调用；普通模型和后台删除入口已闭合。任意数据库管理能力不属于此局部接口边界。Visit 后台既有 `mid` 筛选尚未实现、来源关键字协议前缀判断存在独立旧问题，本组未修改其查询语义，应在只读列表健壮性批次处理。
