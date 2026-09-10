# 卡密兑换完整性

本批只修改 `Card::useData()`，复用已提交的 `PointsBalance::credit()`。两个实际调用入口是 `index/User::buy()` 的卡密分支与 `API/Payment::use_card()`，没有修改入口控制器。

## 已确认问题

实际安装 DDL、真实 ORM、MySQL 非严格模式复现：

- 20 积分卡、余额距离上界只余 10：旧逻辑返回成功，卡密已使用，实际仅加 10，账变记录 20。
- `Plog::saveData()` 返回非异常失败：旧逻辑仍加 20 并消耗卡密，账变为零条。
- 加分受影响行数未检查，因此接收用户已删除时仍可能消耗卡密；`TypeError` 不在原 `catch (Exception)` 范围内。
- 安装表对卡号和密码只有普通索引；旧认领会更新所有匹配凭据但只给第一条卡面值加分。已用重复凭据负例确认必须拒绝这种歧义，不能自动删除或任意选一张兑换。

修复前证据：`/tmp/maccms-audit-20260910/card-credit-before.log`。

## 修复

在事务内锁定当前卡记录和面值；匹配凭据必须恰好一张，且仍未使用。按卡 ID 和未使用状态进行条件认领，必须恰好更新一行。加分采用原子余额上界，账变必须返回成功，任何失败和 `Throwable` 都回滚完整兑换，使卡密可重试。

输入拒绝数组、布尔值、缺失用户 ID、非法编码和超出当前 VARCHAR 长度的凭据；保持字符串/整数形式的合法凭据。零积分卡不再作为成功充值消耗。实际卡积分列上限仍是 65535，没有改变发卡面额或存储定义。

重复凭据只做受控拒绝，不修改原数据。数据库唯一约束及历史重复清理需要另行预检和迁移；本批没有扩展到卡号生成或批量发卡。

## 验证

`tests/security_audit_card_credit.php` 在 PHP 8.3.33 / 8.4.25 × SQLite / MySQL 非严格模式下，各 25 项通过。覆盖成功兑换、精确余额上界、余额超界、已删除用户、账变返回失败、TypeError、失败后重试、竞争用户仅一方成功、重放、重复凭据、零积分及非法输入。

`tests/fixtures/security_audit_card_db.php` 复用会员资金 fixture，MySQL 从当前安装文件创建真实卡表。采用 `MEMBERSHIP_AUDIT_MYSQL/HOST/PASSWORD`，固定隔离库 `maccms_audit_membership`，额外重建 `audit_card`。已加入 financial suite，与共享库用例串行。未初始化应用、未连接生产或执行 Git。

日志为 `/tmp/maccms-audit-20260910/card-credit-{mysql,sqlite}-php{83,84}.log`。
