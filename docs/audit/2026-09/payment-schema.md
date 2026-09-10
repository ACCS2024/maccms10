# 支付订单与积分账变存储一致性

本批只处理订单编号唯一性、账变积分容量与对应存储错误。PHP 8.3.33 / 8.4.25、MySQL 8.0 隔离库验证；未连接生产或运行应用入口。

## 已确认问题与修复

| 问题 | 证据与影响 | 修复 |
| --- | --- | --- |
| `order_code` 只有普通索引 | 通知根据订单码查单，但数据库允许同码多单；订单状态的条件更新只能保护单行，无法替代订单码唯一性。 | 新安装建立完整单列唯一索引；旧库迁移前按原列排序规则检查重复和空值，发现后阻断，不删除或合并任何订单。 |
| `plog_points` 比可售订单积分窄 | 旧 DDL 的账变 `SMALLINT UNSIGNED` 只能保存 65535，订单 `MEDIUMINT UNSIGNED` 可保存 16777215，用户 `INT UNSIGNED` 可保存 4294967295。实际 ORM 能创建 65536 积分订单，但支付入账因账变溢出而回滚；扩列后同订单成功入账。 | 账变列扩为 `INT UNSIGNED`，覆盖现有订单与用户余额范围；不增加订单允许售卖的积分上界，不缩小已有更宽的定制账变列。 |
| 唯一约束冲突可能抛出数据库异常 | `Order::saveData()` 原本没有捕获插入/更新异常。增加唯一约束后，重复编号必须成为受控失败。 | 返回既有 `code=1002, msg=save_err`，避免 SQL、已有订单号等驱动错误进入响应；原记录保持完整。 |

整数上界参见 [MySQL 数值类型文档](https://dev.mysql.com/doc/refman/8.0/en/numeric-type-syntax.html)。应用入口的精确金额、积分计算与上界校验属于独立提交；存储错误处理不能代替这些输入校验。

## 旧库操作步骤

独立脚本 `migration/harden-payment-schema.php` 不加载应用或 `.env`。通过运维环境注入以下参数，不将密码写入命令行或迁移报告：

| 环境变量 | 含义 |
| --- | --- |
| `PAYMENT_SCHEMA_DSN` | 显式 MySQL DSN，必须选择 `dbname`，建议带 `charset=utf8mb4` |
| `PAYMENT_SCHEMA_USER` | 预检账号只需读取目标表及可见元数据；执行账号另需对应 DDL 权限 |
| `PAYMENT_SCHEMA_PASSWORD` | 通过部署环境的密钥机制注入 |
| `PAYMENT_SCHEMA_PREFIX` | 表前缀，默认 `mac_`；仅字母、数字、下划线 |

先用只读账号运行：

```sh
php migration/harden-payment-schema.php
```

默认只执行 `SELECT`，输出 JSON，包括阻断原因、待执行 DDL 和重复记录定位用的首末订单 ID，不输出原始订单码、用户记录或连接密钥。返回值 0 表示预检通过，**不表示无需迁移**；以 `changes` 是否为空判断。返回值 1 表示阻断或操作失败。重复检查会扫描订单数据，大库应先在近期副本评估资源开销。

遇到重复或空订单码时，依据支付平台交易号、订单归属与账变记录人工核对并形成独立修复方案。不能直接删除“多余”记录、随意改已支付订单码或用 `IGNORE` 建索引；这可能破坏通知重试与资金对账。脚本不会进行这些操作。缺表、非 InnoDB、未知列定义、负账变值、索引命名冲突等也会阻断自动执行。

在完成备份和恢复演练、评估表重建所需空间、暂停订单与账变写入、清理长事务后，以有 DDL 权限的账号在维护窗口运行：

```sh
php migration/harden-payment-schema.php --apply
php migration/harden-payment-schema.php
```

执行阶段取得同库同前缀的迁移互斥锁，再次预检。唯一索引使用 `ALGORITHM=INPLACE, LOCK=SHARED`；账变类型变更使用 `ALGORITHM=COPY, LOCK=SHARED`，需要重建表并阻止该表写入。此操作不承诺无停机，所需时间取决于实际表大小和负载。[MySQL 在线 DDL 文档](https://dev.mysql.com/doc/refman/8.0/en/innodb-online-ddl-operations.html)明确将列类型变更列为需要复制的操作。

迁移互斥锁只防止本脚本并发执行，**不会阻止应用写入**。维护期间支付网关重试应返回失败，恢复服务后重试、对账，不能为减少重试而提前返回成功。

MySQL DDL 会隐式提交，两个改动不处于一个可回滚事务内。第二步失败时第一步可能已成功；保留数据库现状，重新只读预检并排除错误，再执行剩余变更。脚本支持这种部分完成后的重跑。不要自动降回 `SMALLINT`，新账变可能已经超过 65535；也不要为回退应用版本删除唯一约束。应用代码可回退与数据库恢复应分别制定方案。

## 回归证据和范围

`tests/security_audit_payment_schema.php` 使用实际安装 DDL、实际 Think ORM/Order/Plog/User 模型和隔离的 `maccms_audit_membership` 库。测试会重建该库中 `audit_user/group/order/plog` 四张专用表，不能对业务库运行。运行方式：

```sh
MEMBERSHIP_AUDIT_MYSQL=1 MEMBERSHIP_AUDIT_HOST=127.0.0.1 php tests/security_audit_payment_schema.php
```

该组每个 PHP 版本 43 项断言，覆盖只读事务内预检、CLI 默认只读/显式应用、排序规则等价重复、无敏感值报告、空码、复检时新到重复、部分完成重跑、并发迁移互斥、前缀注入、定制索引冲突、负账变阻断、保留更宽列，以及 65536/16777215 积分实际入账与支付幂等、订单积分/用户余额溢出回滚、重复新增和更新的受控失败。

日志为 `/tmp/maccms-audit-20260910/payment-schema-php83.log` 和 `payment-schema-php84.log`。MySQL 以严格 SQL 模式测试；应用上界校验仍需独立覆盖非严格模式下的截断风险。MariaDB、旧 MySQL、分区或定制存储结构未获本次兼容性验证，应在目标版本的副本先行验证。
