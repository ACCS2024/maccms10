# P3 · 行为(behavior)→ 中间件 / 事件 🔴

> **本阶段是整个迁移的风险峰值。** TP6/8 **删除了 behavior/Hook 机制**,而本 fork 的安全防护几乎全压在 8 个行为类上。迁错 = 静默开洞。
> 整阶段按 🔴 处理:每轮 Docker 全栈 + 安全不变量实跑 + 人工安全复核。

## 目标

把 `application/tags.php` 的 8 个钩子点 + `application/common/behavior/` 的 8 个类,**逐条等价**迁成 TP8 的**中间件 + 事件**,且 `verification/security-invariants.md` 的 INV-1..8 **全绿**。

## 前置依赖

P1(中间件挂载点就位)、P2(安全配置已迁且值不变)。

## 现状(实测)

`tags.php` 钩子 → 行为类:

| 钩子点 | 行为类 | 不变量 |
|---|---|---|
| `app_init` | `SessionSameSite`、`Init`、`RequestSecurity` | INV-7 / INV-8 / INV-5 |
| `app_begin` | `Begin`(防挂马)、`CsrfGuard`、`AntiScrape` | INV-1 / INV-2 / INV-6 |
| `app_end` | `SecurityHeaders`、`AdminAudit` | INV-3 / INV-4 |

(`module_init/addon_begin/action_begin/view_filter/log_write` 当前为空)

## 设计:钩子 → TP8 生命周期映射

| TP5.0 钩子 | TP8 等价 | 落点 |
|---|---|---|
| `app_init`(请求最早) | 全局中间件(前置)/ `HttpRun` 事件 | `app/middleware.php` 顶部 |
| `app_begin`(分发前) | 全局中间件(前置) | `app/middleware.php` |
| `app_end`(响应后) | 中间件(后置,处理 `$response`) | 同一中间件 `$next()` 之后 |
| `view_filter` | 视图事件 / 中间件改 response | P5 配合 |
| `log_write` | `LogWrite` 事件监听 | `app/event.php` |

**落点规范**(见 `02-conventions.md`):安全中间件集中 `app/middleware/security/*`,审计这类"旁路记录"用事件监听 `app/listener/*`。

中间件骨架:
```php
namespace app\middleware\security;
class CsrfGuard {
    public function handle($request, \Closure $next) {
        // ← 原 behavior/CsrfGuard::run() 的"前置"逻辑等价搬此
        $response = $next($request);
        // ← 原"后置"逻辑(如有)搬此
        return $response;
    }
}
```

注册(`app/middleware.php`,**顺序等价于 tags.php 内的顺序**):
```php
return [
    app\middleware\security\SessionSameSite::class,
    app\middleware\Init::class,
    app\middleware\security\RequestSecurity::class,
    app\middleware\security\AntiShell::class,    // 原 Begin
    app\middleware\security\CsrfGuard::class,
    app\middleware\security\AntiScrape::class,
    app\middleware\security\SecurityHeaders::class, // 后置
];
```
审计走事件:`app/event.php` 注册 `AdminAudit` 监听(对应 app_end 的旁路记录)。

## 切片建议(每轮一个行为类,先分析,逐条验不变量)

每轮迁**一个**行为类(8 轮),顺序建议从"独立性强、好验"到"耦合深":
SecurityHeaders(INV-3,`curl -I` 即可验)→ SessionSameSite(INV-7)→ AntiScrape(INV-6)→ RequestSecurity(INV-5)→ CsrfGuard(INV-2)→ Begin/AntiShell(INV-1)→ AdminAudit(INV-4)→ Init(INV-8,最后收口)。

> 每轮 round-log 的 D 段必须勾出对应 INV,G 段贴出该 INV 的实跑结果。

## 风险 & 安全不变量

🔴 最高。常见坑:
- 中间件**执行顺序**与原钩子顺序不一致 → 防护错位。
- TP8 中间件拿 `$request`/`$response` 的方式与 behavior 的 `$params` 不同 → 漏改导致防护空转。
- 后置逻辑(响应头/审计)放错位置 → 头不下发/审计漏记。
- **绕过风险**:多应用/插件路由是否都经过全局中间件?要确认 admin/api/addons 路径**无旁路**。

## 验证(每轮 + 阶段)

```bash
# 全栈起 target-8.4
cd docker && docker compose -f docker-compose.yml -f docker-compose.84.yml up -d --build
# 逐条不变量(本轮相关 + 阶段末全部)
bash tests/security/check_invariants.sh INV-3      # 例:本轮 SecurityHeaders
bash tests/security/check_invariants.sh            # 阶段末:8 条全跑
```
冒烟行:#2 #6 #8 #11..16 #19..22(几乎所有 🔴 行)。

## 退出标准(DoD)

- [ ] 8 个行为全部迁为中间件/事件,`tags.php` 删除
- [ ] 中间件注册顺序与原钩子顺序等价
- [ ] **INV-1..8 在 Docker 全栈实跑全绿**
- [ ] 确认 admin/api/install/addons 路由**均经过**安全中间件(无旁路)
- [ ] 人工安全复核签字(对照 `SECURITY_AUDIT_REPORT.md`,无回退)
- [ ] tag `tp8-p3-done`

## 回滚

每轮单行为可单独 revert;阶段 tag 兜底。**未达 8 条全绿,禁止进入 P4**。
