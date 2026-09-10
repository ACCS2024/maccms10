# 非严格 MySQL 下的余额加法上界：订单与推荐奖励

## 已复现并修复

真实 MySQL 8.0、当前安装 DDL、当前 ORM，设置本测试连接 `sql_mode=''` 后：

| 入口 | 初始余额 / 应入账 | 原行为 |
| --- | --- | --- |
| `Order::notify()` | 4294967285 / 20 | 返回成功、订单已支付；余额只增加 10，账变却记录 20。 |
| `User::reward()` | 推荐人余额 4294967294 / 2 | 返回成功；余额只增加 1，账变记录 2。 |

日志：`/tmp/maccms-audit-20260910/points-overflow-before.log`。这不是金额输入超限：单笔积分合法，但与已有余额相加超过 `user_points INT UNSIGNED` 的 4294967295 上界。非严格 SQL 会截断结果，受影响行数仍然为 1，事务和异常捕获无法单独识别它。

新增 `application/common/util/PointsBalance.php`，校验正整数积分及用户 ID，并在同一条更新语句中要求：

```sql
UPDATE ...user SET user_points = user_points + :points
WHERE user_id = :user_id AND user_points <= 4294967295 - :points
```

只有恰好更新一行才返回成功。边界判断由数据库按当前行执行，不能用请求中的余额或事务前的快照代替。工具本身不创建事务或写账变；调用者必须将其与业务状态、账变放在同一事务，遇到 `false` 或异常整体回滚。

订单与推荐奖励已接入；原来已完成且金额正确的订单重放仍成功，不再尝试加分。推荐人任一层上溢会回滚全部层级奖励，以及外层会员扣款/期限/订单入账。恰好达到上界的完整入账仍被允许。

## 验证

`tests/security_audit_points_overflow.php` 已加入 financial suite，使用 `MEMBERSHIP_AUDIT_MYSQL/HOST/PASSWORD`，固定隔离库 `maccms_audit_membership`。会重建 `audit_user/group/order/plog`，需和同库测试串行；未访问生产、未初始化应用。

PHP 8.3.33 / 8.4.25 × SQLite / MySQL 非严格模式，各 29 项通过。覆盖真实截断复现的修复、精确上界、三层推荐溢出事务回滚、外层余额升级及现金会员订单回滚、初次读取后余额变化、成功订单重放、重复加分、非法积分和用户 ID。

原 `framework_audit_payment.php` 两版 PHP 各 158 项、`security_audit_membership.php` 两版各 51 项通过。日志为 `/tmp/maccms-audit-20260910/points-overflow-{mysql,sqlite,payment,member}-php{83,84}.log`。

## 同类扩查清单（本提交未修复）

| 入口 | 当前结论与后续有界批次 |
| --- | --- |
| `Card::useData()` | 已有条件认领卡密，但余额加法无上界，忽略加分受影响行数和账变返回错误；只捕获 Exception。单独处理兑换完整性。 |
| `SignLog::doSign()` | 签到入账无上界且不检查 affected；已有账变错误检查。需验证签到唯一约束与任务同步状态，补 Throwable 回滚。 |
| `TaskLog::claimReward()` | 已有完成→已领取的条件更新闸门；余额加法无上界且不检查 affected。需确保加分失败撤销领取。 |
| `SignMilestone::claimMilestone()` | 余额加法无上界且不检查 affected；已有账变错误检查。需验证领取唯一约束及失败可重试。 |
| `Cash::delData()` | 待审核提现删除会从冻结余额退回可用余额，仅检查冻结余额下界，未检查可用余额上界；必须防止截断后删提现记录。 |
| `User::register()`、`loginOrRegister()` | 普通注册和 OAuth 注册的推荐加分无上界；注册/关系/奖励不是完整事务，部分路径忽略加分与账变结果。需单独定义失败回滚语义并验证登录状态。 |
| `User::visit()` | 分享访问奖励无上界，访问记录、加分和账变不在同一事务；额度检查在写前，需检查并发领取。 |
| `User::processInviteReward()` | 已有用户行锁；阶梯奖励的加分和账变未检查结果，仍可能写已领取层级。需保证任何阶梯失败整体回滚。 |

上述未接入入口仍需各自真实行为验证和修复；不能将本提交理解为所有积分入口已安全。注册初始赠送积分为直接赋值，也应验证配置上界。推荐百分比当前仍沿用旧浮点计算，精确百分比计算可作为独立计价修复。

本轮还对 `addons/extend/bin/scripts` 的 PHP/SQL 中实际 `user_points` 使用点做了扩查，未发现额外余额加法入口。
