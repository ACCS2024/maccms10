# 签到、任务与里程碑奖励原子性

范围：`SignLog::doSign`、`TaskLog::claimReward/addProgress/getOrCreateDaily/getUserTaskStatus`、`SignMilestone::claimMilestone`，以及 `PointsBalance::amount` 的零积分解析选项。未修改 API 控制器、Plog 新增接口或安装表结构。

## 已确认及修复

1. 三条领奖路径原先直接 `setInc(user_points, points)`，未限制用户余额的 INT UNSIGNED 上界。在非严格 MySQL 中，余额可被截断为 4294967295，而签到/任务/里程碑仍记作领取成功并写入全额账变。现在使用有上界条件的原子加法，要求恰好更新一个用户；超限、用户不存在及账变失败均回滚整个事务。
2. `TaskLog::addProgress` 使用锁前旧记录计算并无条件写回状态，新手任务自动检测也无条件写状态 1。若领奖已将状态改成 2，陈旧写入可再次打开领奖入口。进度现在在事务中加锁重读，只有状态 0 能被更新；新手检测也只推进状态 0 并重读实际状态。
3. 签到忽略 `addProgress` 的错误返回，以及最后同步已领奖状态的失败。现在检查嵌套进度操作和最终条件更新；失败撤销签到记录、余额、账变及任务进度。
4. 原先 `catch (Exception)` 无法回滚 TypeError 等 Throwable。三个领奖方法及进度操作覆盖 Throwable，仍返回受控业务错误。
5. 并发创建每日任务可能在空读后撞到现有唯一键。仅针对 MySQL/SQLite 的完整性冲突重读唯一键获胜记录，其他数据库错误继续抛出。不会把死锁错误当作成功创建。
6. 签到积分由 `SignLog::doSign` 发放。通用任务领奖拒绝另行支付 `daily_sign`，避免导入或陈旧的“可领取”签到任务记录形成第二支付入口。

## 业务语义

零积分任务和里程碑仍可正常完成并领取；零积分签到仍计入连续签到。事务锁定并确认用户存在后，记录领取状态及零积分账变，不执行余额加法。`PointsBalance::credit` 仍只接受正整数；新增 `amount(value, true)` 仅用于解析明确允许零的奖励。默认解析行为保持不变。

保留现有签到任务不存在时奖励 5 积分的逻辑。任务奖励取服务器当前启用任务的积分；本批未改变后台配置或引入订单式价格快照。

## 验证

- `tests/security_audit_task_rewards.php`：88 项，PHP 8.3.33/8.4.25 × SQLite/真实安装 DDL 的 MySQL 8.0，四矩阵通过。MySQL 强制当前测试会话 `sql_mode=''`，验证宽松 SQL 模式也无法截断入账。
- 覆盖合法奖励、重放、精确余额上界、UINT32 最大奖励、零奖励、已删除用户、账变校验返回失败、TypeError、失败后重试、已通过初查的陈旧领奖请求、进度/新手检测与领奖交错、唯一键创建竞争、签到同步及嵌套进度晚失败。
- 竞争用真实 ORM 的受控交错钩子重放危险时序，不将其声称为并行压力测试。
- 现有 `security_audit_points_overflow.php` 29 项（PHP 8.4/SQLite）复核共享正积分工具默认行为。
- 日志：`/tmp/maccms-audit-20260910/task-rewards-{sqlite,mysql}-php{83,84}.log`。
- Fixture 只使用临时 SQLite 或专用 `maccms_audit_membership` 库的 `audit_*` 表；MySQL 套件与其他 MEMBERSHIP 套件必须串行。CI 新增同一 financial 分类测试即可，无需新环境变量。

## 后续独立组

`API/Task` 的领奖入口仍需强制 POST；客户端 `report_progress` 可自报观看、分享和评论，尚不能证明真实服务端行为。下一组需把评论推进绑定真实评论入库/审核结果；观看/分享先列明服务器可证明的事件及不能证明的边界，再调整接口和客户端。本批解决支付原子性，不将客户端自报进度视为可信资格证明。

其他待处理余额入口继续按独立组推进：Cash 退款、注册/OAuth 邀请奖励、访问奖励、分阶段邀请奖励。原始账变留存由主线程负责。
