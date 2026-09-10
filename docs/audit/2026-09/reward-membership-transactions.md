# 返利和会员升级事务收尾（F2b）

日期：2026-09-11，基于 `a478462e` 的独立修复批次。订单支付回调外层另列 F2c。

独立返利和会员升级接入 FinancialTransaction。BEGIN 在受保护范围内执行，保存原 PDO，确认回滚后才报告普通失败；COMMIT 确认丢失返回未知结果和诊断编号，同一上下文阻止再次操作。返利保留异常传播合同，FinancialOperationException 携带结构化结果。借用调用方事务时使用私有保存点，未确认的局部回滚要求外层拥有者中止整个原事务。

会员升级重新锁定主库用户，以当前余额扣款，验证实际存储的余额、会员组、到期时间和全部升级台账字段；拒绝超出 UINT 的到期时间。MySQL 写入前确认 User/Plog 实际表为 InnoDB。调用方事务内升级成功带 `info.transaction_pending=true`，尚不发布会员 Cookie；独立提交未知也不发布。公共机制接收各业务原失败结果，避免将会员的 1009 补偿结果错换成购买的 2003。

## 验证

PHP 8.3.33 与 8.4.25 各自完成：

- 改动 PHP 编译检查和默认金融套件 20 个进程，零失败。
- 新增返利/会员真实故障检查 SQLite 192 项、安装 MySQL 非严格模式 195 项；覆盖 ORM/PDO BEGIN、COMMIT、ROLLBACK 前后，1/3 层调用方事务、实际私有保存点失败、独立连接观察、有限清理、跨业务重试阻止和 Cookie 时机。
- 会员普通回归 51 项（SQLite/MySQL），MySQL 原购买 110、返利落库 37、购买 owner 120、caller 129 项。新增故障断言确认真实钩子被触发，不能只看最终响应。
- 正式 MySQL 视频/文章/漫画购买分别 1300、1273、940 项。
- 普通触发器改变会员或台账存储值、非严格 SMALLINT 截断、非事务表及到期时间溢出，均受控失败且恢复完整资金状态。

原竞争回归钩子挂在 facade Manager 的 startTrans。接入保存的实际 Connection 后该钩子不再执行，第一次回归因此失败；已移至实际连接 BEGIN 前并重跑全部上述检查。保留首次失败日志，没有把失效夹具记作新业务漏洞。

原始记录：`/tmp/maccms-audit-20260910/reward-followups/integration-check1.log`、`integration-check2.log`、`integration-validated-tree.txt`。后一文件仅在所有检查通过后生成；验证代码树为 `b07075348dc544371e7e7206a8253154bedea859`。持久可复跑入口为 `tests/framework_audit_reward_membership_owner.php` 和金融套件。

## 尚未闭环

Order::notify 仍使用原外层 BEGIN / rollback / commit，不能借用本批结论。尤其内层未知清理可能保留额外 ORM 层级，单次外层 ORM rollback 未必结束原物理事务，需要独立故障验证及修复。跨请求持久操作编号、核对器、通用 rollback-only、会员配置与旧记录的全部输入边界另行审计。最近完整静态/运行检查固定在 `691eb9ab`，本批仅使用上述专项证据。
