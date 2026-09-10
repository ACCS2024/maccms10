# 内容购买兼容方法：调用方 SAVEPOINT 收尾

日期：2026-09-11。本批处理 F1b，并让没有外层事务的兼容 buy 使用既有 owner 收尾。三个锁内报价入口仍必须拥有外层事务。

## 根因和合同

原兼容方法在余额不足分支执行 ORM rollback，若调用已经成功但确认阶段抛异常，catch 又执行一次 rollback。锁定 ORM 会先减少事务计数，因此第二次可能结束调用方的外层事务。此前双版本真实 SQLite 复现观察到两次 rollback、原 PDO 关闭事务、调用方普通标记丢失；普通 owner 失败还有回滚异常取代业务结果的情况。

现在 `ContentPurchase::buy` 使用 `PurchaseTransaction`。没有外层事务时，复用原 PDO 身份、BEGIN 前标记、有限 owner 清理、COMMIT 不明响应和同上下文阻止重试。在已由 ORM 管理的调用方事务中：

- 在增加 ORM 嵌套前创建随机命名的私有 SAVEPOINT，保留原连接、PDO 和调用方层级。它不依赖发生确认故障后可能已改变的 `transTimes` 来决定 SQL 回滚范围。
- 正常成功只完成内层 ORM 嵌套并释放私有保存点，物理 COMMIT 仍由调用方决定。正常失败只对私有保存点执行一次 `ROLLBACK TO SAVEPOINT`；确认真实局部回滚且连接身份仍一致后，才恢复本方法增加的嵌套元数据。
- 不对调用方执行 ORM rollback、全 PDO rollback 或 close。返利自身的嵌套收尾即使出现确认异常，购买也不再追加一次可能结束外层的 ORM rollback。
- 局部回滚未确认、返回 false、保存点已丢失或连接/事务被替换时，返回 2005、`retryable=false`、`caller_rollback_required=true` 和诊断编号。它不是“扣款已经回滚”的声明；同 Request 内的兼容和锁内报价购买都被阻止。
- 原生 PDO 已开启但没有 ORM 层级的调用方，以及 PDO 不活动但 ORM 层级残留的连接，均在购买写入前受控拒绝。不能把不一致状态当成新的事务 owner。

没有 HTTP Request 绑定的独立 ORM/CLI 客户端使用其现有 Container 作为不确定结果的作用域，避免调用不存在的 `request` 别名或自动创建不断更换的重试上下文。HTTP 入口继续按实际 Request 隔离。

## 调用方责任

嵌套 code 1 仅表示本次作用域完成，不表示外层已提交。收到 `caller_rollback_required` 时，调用方必须中止整个原物理事务并核对结果；不能继续提交，也不能把单次 ORM rollback 当成所有层级都已结束的证明。未知清理分支没有擅自修复调用方层级，原 PDO 的事务状态是必要依据。若物理事务已经被外部提交，后续回滚无法撤销它，结果必须核对。

本次当前应用源扫描未见 `ContentPurchase::buy(...)` 的直接调用；三个正式入口为 buyVideo / buyArt / buyManga。兼容方法仍保留给内部调用者，因此保留成功嵌套和外层最终决定的能力，未把它直接禁用。跨请求持久业务编号、核对器及通用外层事务的 rollback-only 机制仍未实现。

## 验证

`tests/framework_audit_purchase_caller.php` 使用真实 ORM、原 PDO、独立观察 PDO，以及真实 SQLite / 安装 MySQL。保存点创建、嵌套 BEGIN / 完成、返利失败、局部 ROLLBACK / RELEASE 的前后确认故障都包围实际数据库操作；另用原生静默 PDO 的 false 返回验证失败不能被当作确认。

每个 PHP 版本：

- 调用方专项 127 项，分别在 SQLite、MySQL 上通过；含 1 / 3 层调用方、提交与回滚、幂等、外层标记、观察连接不可见未提交扣款、错误上下文阻止重试。
- 原 owner 专项 108 项，分别在 SQLite、MySQL 上通过。
- 默认金融套件 19 个独立进程，零失败；既有 MySQL 兼容购买正常/并发测试 110 项。
- 三个正式购买入口 MySQL 回归：视频 1,300、文章 1,273、漫画 940 项。

```sh
php tests/run_audit.php --suite=financial
# 在专用审计数据库环境中设置 MEMBERSHIP_AUDIT_MYSQL/HOST/PASSWORD 后：
php tests/framework_audit_purchase_caller.php
php tests/framework_audit_purchase_owner.php
php tests/security_audit_content_purchase.php
```

两份变更工具另作 level 5 定向静态复审，无全局错误；事务工具无诊断，协调器保留两处既有 ORM 动态方法推导项（setDec / Db::query），未添加忽略规则。

本批还抽取 owner/caller 共用的真实数据库启动夹具，测试仍独立进程运行。`tests/run_audit.php --suite=financial` 包含新增调用方检查；工作区其它测试入口修改没有混入提交。

## 剩余边界

这里没有修改 User::reward 本身。独立返利、其它金融 owner / caller、StorageIntent 的 BEGIN / ROLLBACK / COMMIT 故障仍需各自验证。购买对返利内层错误的隔离不等于独立返利已安全。没有访问生产数据库，也没有将正常、故障或并发测试通过扩展为商业上线验收完成。
