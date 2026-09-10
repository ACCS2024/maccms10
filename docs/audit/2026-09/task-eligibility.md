# 任务奖励的服务端资格与公开写入方法

前置提交为安全评论创建及 `comment_reward_verified` 来源迁移。本提交关闭客户端自报进度与历史任务就绪状态直接换取积分的路径，不改变已领取的账变历史。

## 资格规则

`post_comment` 每日任务只统计当前已验证用户、当前任务日期内由服务器创建、已审核通过且 `comment_reward_verified=1` 的真实评论行。进度按不同记录统计并封顶于服务器任务目标，重复调用刷新接口不增加次数。历史未认证评论、匿名/其他账号评论、待审核/已删除/撤审评论、编辑后失去来源标记的评论，以及日期不匹配或未来时间的记录均不作为资格。

任务列表会根据真实评论自动更新显示；领取本身在事务中再次锁定任务和评论证据并检查资格，因此无需先调用 `report_progress` 或访问任务列表，也不能依靠旧 `TaskLog.log_status=1` 领奖。未领取的资格可随撤审、删除或证据变更撤回；已领取状态 2 始终保留。账户入账、任务状态及账变继续使用此前的原子事务和余额上限保护，合法零积分任务仍可完成。

同一领取使用固定任务日期及该日期的日界范围，即使请求跨过午夜，也不会把新一天的评论同时用于前一天和当天。用户编号、任务编号、里程碑编号及目标次数依实际安装 DDL 使用 UINT32 上限；与订单充值的 MEDIUMINT 积分额度分开。

`watch_vod` 和 `share_vod` 在当前仓库没有可验证实际观看或社交平台分享完成的服务端事件。前端计时、点击及自报观看记录不构成证明。本次停止这两类任务的新进度上报和领奖，保留配置与已领取历史；没有把它们改名为“已验证观看”。接入可信事件前不恢复奖励。

## 接口与客户端能力

`daily_sign`、`claim_reward`、`claim_sign_milestone`、`report_progress` 强制 POST。任务/里程碑编号及上报动作只读取 POST body，拒绝数组、布尔、非法数字格式和越界编号。用户归属来自登录结果；里程碑连续签到天数仍从服务器签到记录取得。

兼容保留 `report_progress` 的 `post_comment` 动作，但它只触发真实数据重算，忽略客户端次数/进度。其他两种旧上报动作受控返回不可用。任务列表和刷新结果新增：

| 字段 | 含义 |
| --- | --- |
| `reward_available` | 当前能否通过受支持的服务器规则取得新奖励 |
| `progress_source` | `approved_comment`、`server` 或 `unavailable` |
| `reward_unavailable_reason` | `trusted_server_event_unavailable`、`comment_provenance_migration_required`、`invalid_comment_task_configuration` 或 `comment_verification_unavailable` |

不支持的任务在未领取时显示进度/状态 0，不能保留“可领取”承诺；已经领取的状态 2 保留。缺少来源迁移时普通评论和签到仍正常，评论任务明确不可领奖。评论任务目标必须为正整数；零积分奖励本身合法。

全仓未发现 `report_progress`/`claim_reward` 的现存客户端调用。默认签到 UI 已用 POST 调用签到和里程碑领取，因此本组没有增加无必要的模板变更。强制 POST 不是完整的前台 CSRF token 协议，整体前台 CSRF 仍须独立审计。

## 验证

- `tests/security_audit_task_eligibility.php`：PHP 8.3.33/8.4.25，SQLite 各 166 项、MySQL 各 171 项，全部通过。实际 Cookie 登录、安全评论创建、审核操作、Task 控制器、TaskLog/SignLog/里程碑模型、余额和 Plog 在同一隔离数据库闭环运行。
- MySQL 额外使用第二个真实 PDO 连接尝试在领取事务提交前撤审，确认对评论证据的锁使撤审等待并超时；事务完成后撤审正常且不抹除已领取历史。这是实际数据库锁验证，不只模拟执行顺序。
- 其他覆盖伪造状态/进度、旧数据、撤审/编辑/删除、同记录重复刷新、多个真实评论、无预创建任务记录直接领奖、缺迁移、四写接口非 POST 和类型负例、跨午夜请求，以及 UINT32 最大用户/任务/里程碑编号和目标次数。
- 现有 `security_audit_task_rewards.php` 88 项 × 两 PHP × SQLite/MySQL 非严格模式全部通过。仅将其原人工 `post_comment` 资格 fixture 补为真实可信已审核评论，并抽出共享任务表 fixture，保留资金事务、溢出、账变失败和陈旧竞争回归的原意。
- 日志：`/tmp/maccms-audit-20260910/task-eligibility-{sqlite,mysql}-php{83,84}.log`、`task-eligibility-financial-{sqlite,mysql}-php{83,84}.log`。
- 新测试沿用 MEMBERSHIP 环境、`maccms_audit_membership` 的 `audit_*` 表；必须和其他同库金融套件串行。

## 另行处理

管理端物理删除已领奖 TaskLog/SignLog 后可能重新开放活动资格，需独立核实资金记录保留/活动重置边界；本组没有改变后台删除语义。默认签到 UI 的“周期重置”文案与当前每账号一次的里程碑模型也存在既有不一致，需独立业务规则修复。其他余额加法入口（Cash 退款、访问奖励、邀请奖励）继续分批处理。
