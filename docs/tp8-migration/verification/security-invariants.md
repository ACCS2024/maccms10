# ★ 安全不变量(迁移期不可破)

> 本 fork 是被持续加固过的(见 `SECURITY_AUDIT_REPORT.md` 与 A/B 系列 commit)。迁移最大的风险**不是跑不起来,而是悄悄丢掉一层防护**。
> 这 8 条不变量对应现有 `application/common/behavior/` 的 8 个行为类 + `tags.php` 钩子;P3 把它们迁成中间件/事件后,**行为必须逐条等价**。
> 任一条在某轮被打破而未在同轮恢复 → 该轮**禁止合并**(铁律 #4)。

| 编号 | 不变量 | 现状落点(TP5.0) | TP8 落点 | 验证方法(必须实跑) |
|---|---|---|---|---|
| **INV-1** | **防挂马持久化**:每次请求扫 `application/extra/`,自动删非白名单 PHP | `behavior/Begin.php`(app_begin) | `app/middleware/security/AntiShell` | 往 `app/extra/` 放个 `evil.php` → 请求一次 → 文件应被删 |
| **INV-2** | **CSRF 防护**:变更类动作强制校验 token / 强制 POST | `behavior/CsrfGuard.php`(app_begin) | `app/middleware/security/CsrfGuard` | 伪造无 token 的 POST/GET 变更请求 → 应被拒 |
| **INV-3** | **安全响应头**:CSP / X-Frame-Options / nosniff 等 | `behavior/SecurityHeaders.php`(app_end) | `app/middleware/security/SecurityHeaders` | `curl -I` 关键页 → 头齐全且值一致 |
| **INV-4** | **后台审计留痕**:敏感操作/ SQL 控制台执行落审计日志 | `behavior/AdminAudit.php`(app_end) | `app/listener/AdminAudit`(事件) | 后台做一次敏感操作 → 审计表有记录 |
| **INV-5** | **请求安全/输入消毒**:XSS 入参归一、危险参数拦截 | `behavior/RequestSecurity.php`(app_init) | `app/middleware/security/RequestSecurity` | 带 `<script>`/越权参数请求 → 被消毒/拦截 |
| **INV-6** | **防爬/限流**:异常高频/特征爬虫拦截 | `behavior/AntiScrape.php`(app_begin) | `app/middleware/security/AntiScrape` | 触发高频规则 → 被限流 |
| **INV-7** | **会话安全**:SameSite / 会话初始化策略 | `behavior/SessionSameSite.php`(app_init) | `app/middleware/security/SessionSameSite` | 检查 Set-Cookie 的 SameSite/HttpOnly/Secure |
| **INV-8** | **全局初始化不变量**:`Init.php` 内的安全相关初始化(配置/常量/环境) | `behavior/Init.php`(app_init) | `app/middleware/Init` | 启动后关键安全配置生效(逐项核对 Init 内容) |

---

## 迁移期还要守的"非行为类"既有加固(对照 SECURITY_AUDIT_REPORT.md,别在迁移中改回)

> 这些不在 behavior 里,但同样是已修复项,迁移触碰相关文件时**必须保持**:

- 控制器名/方法正则校验(原 `App.php:555` 的 invokefunction RCE 防线)——P1/P5 改路由分发时务必保留等价校验。
- `_method` 方法伪装禁用(`config var_method=''`)——P2 迁配置时保留。
- `mac_arr2file()` 用 `var_export()`(防写配置闭合注入)——P6 迁 common.php 时保留。
- 列表 `order/by` 白名单、`Database` 控制台 `isValidTable/Field`+参数化——P4 数据层迁移时保留。
- 后台模板编辑器扩展名白名单 + `<?`/`eval` 黑名单——P5/P7 触碰模板/插件时保留。
- 登录态 cookie 常量时间比较(`hash_equals`)、口令处理——P6 会话迁移时保留。
- 支付回调金额二次核对、各类原子化扣分/兑换——P5/支付相关轮保留事务与校验。

## 如何用

- 每轮 round-log 的 **D 段**勾出触碰项;🔴 轮**8 条全跑**。
- P3 / P9 阶段 DoD 要求 **8 条全绿** + 人工签字。
- 建议把这 8 条做成一个半自动脚本 `tests/security/check_invariants.sh`(P0/P3 落地),每轮可一键复验。
