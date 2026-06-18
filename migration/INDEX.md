# TP8 迁移任务索引

> **规则**：每完成一个任务，必须将下方对应条目的 `[ ]` 改为 `[x]`，并更新「进度」栏。
> 任务详情见各 P 文件，链接可直接跳转。
>
> ⚠️ **重要参考**：[PITFALLS.md](PITFALLS.md) — TP5→TP8 所有已知破坏性变更汇总（含 526 处 TP5 数组条件、mac_search_wd_like 修复方案、allowField 等）。开始任何 P 阶段前必读。

---

## 总进度

| 优先级 | 文件 | 完成/总计 | 状态 |
|--------|------|----------|------|
| P0 | [P0.md](P0.md) — 启动层（入口+Shim+Middleware+Addons） | 25/25 | ✅ 完成 |
| P1 | [P1.md](P1.md) — ORM/DB 层 | 7/8 | 🟡 P1-07 烟雾测试待做 |
| P2 | [P2.md](P2.md) — API 模块 | 5/6 | 🟡 P2-05 回归测试待做 |
| P3 | [P3.md](P3.md) — Admin 模块 | 4/6 | 🟡 P3-05/06 待做 |
| P4 | [P4.md](P4.md) — 前台 + Console | 0/6 | 🔴 未开始 |
| P5 | [P5.md](P5.md) — 清理 + 回归 | 0/9 | 🔴 未开始 |
| **合计** | | **41/63** | |

---

## P0 — 启动层（阻塞所有后续工作）

| ID | 任务 | 状态 |
|----|------|------|
| [P0-01](P0.md#p0-01-更新-composerjson) | 更新 composer.json（添加 TP8 依赖，移除 thinkphp\ autoload） | [x] |
| [P0-02](P0.md#p0-02-运行-composer-update) | 运行 composer update，确认 TP8 进入 vendor | [x] |
| [P0-03](P0.md#p0-03-创建-configappphp) | 创建 config/app.php（app_path 指向 application/，多应用开启） | [x] |
| [P0-04](P0.md#p0-04-创建-configdatabasephp) | 创建 config/database.php（从 application/database.php 迁移，修正键名） | [x] |
| [P0-05](P0.md#p0-05-创建-configcachephp) | 创建 config/cache.php | [x] |
| [P0-06](P0.md#p0-06-创建-configsessionphp) | 创建 config/session.php | [x] |
| [P0-07](P0.md#p0-07-创建-configviewphp) | 创建 config/view.php（保留 taglib_pre_load） | [x] |
| [P0-08](P0.md#p0-08-创建-configlogphp) | 创建 config/log.php | [x] |
| [P0-09](P0.md#p0-09-改造-indexphp) | 改造 index.php（require thinkphp → TP8 App 启动） | [x] |
| [P0-10](P0.md#p0-10-改造-adminphp) | 改造 admin.php | [x] |
| [P0-11](P0.md#p0-11-改造-apiphp) | 改造 api.php | [x] |
| [P0-12](P0.md#p0-12-shim-函数写入-applicationcommonphp) | Shim 函数写入 application/common.php（model/input/url） | [x] |
| [P0-13](P0.md#p0-13-改造-allphp-controller-shim) | 改造 All.php（use 改 facade，追加 success/error/assign/fetch） | [x] |
| [P0-14](P0.md#p0-14-sessionsamesite-→-middleware) | SessionSameSite → app/middleware/SessionSameSite.php | [x] |
| [P0-15](P0.md#p0-15-init-→-middleware) | Init → app/middleware/AppInit.php（27 处 config() 写 → Config::set） | [x] |
| [P0-16](P0.md#p0-16-requestsecurity-→-middleware) | RequestSecurity → app/middleware/RequestSecurity.php | [x] |
| [P0-17](P0.md#p0-17-begin-→-middleware) | Begin → app/middleware/Begin.php（dispatch() → currentUrl() 适配） | [x] |
| [P0-18](P0.md#p0-18-csrfguard-→-middleware) | CsrfGuard → app/middleware/CsrfGuard.php（think\Session 改 facade） | [x] |
| [P0-19](P0.md#p0-19-antiscrape-→-middleware) | AntiScrape → app/middleware/AntiScrape.php | [x] |
| [P0-20](P0.md#p0-20-securityheaders-→-middleware) | SecurityHeaders → app/middleware/SecurityHeaders.php（Response 传参改造） | [x] |
| [P0-21](P0.md#p0-21-adminaudit-→-middleware) | AdminAudit → app/middleware/AdminAudit.php | [x] |
| [P0-22](P0.md#p0-22-创建-applicationmiddlewarephp) | 创建 application/middleware.php，注册 8 个 middleware | [x] |
| [P0-23](P0.md#p0-23-内化-fastadmin-addons) | 内化 fastadmin-addons（Hook/Loader/Route → TP8 Event/PSR-4/Route facade） | [x] |
| [P0-24](P0.md#p0-24-创建-applicationprovidephp) | 创建 application/provider.php（服务绑定） | [x] |
| [P0-25](P0.md#p0-25-冒烟测试-3-个入口) | 冒烟测试 3 个入口，均返回 HTTP 200 | [x] |

---

## P1 — ORM/DB 层（P0 完成后执行）

| ID | 任务 | 状态 |
|----|------|------|
| [P1-01](P1.md#p1-01-模型基类-basephp-适配) | Base.php：initialize() → __construct()，追加 getError() 兼容 | [x] |
| [P1-02](P1.md#p1-02-模型层-use-thinkdb-批量改-facade) | 51 个文件：`use think\Db` → `use think\facade\Db`（model 38 + util 13） | [x] |
| [P1-03](P1.md#p1-03-模型层-use-thinkcache-批量改-facade) | 20 个文件：`use think\Cache` → `use think\facade\Cache`（model 16 + util 4） | [x] |
| [P1-04](P1.md#p1-04-修复-cache-false-判断) | 修复 Cache::get 返回值判断（null vs false，2 处） | [x] |
| [P1-05](P1.md#p1-05-修复-fetchsqlfalse-调用) | 修复 fetchSql(false) → fetchSql()（3 处） | [x] |
| [P1-06](P1.md#p1-06-config-database-键名迁移验证) | 验证 config/database.php 键名与 TP8 ORM 对齐 | [x] |
| [P1-07](P1.md#p1-07-后台登录冒烟测试) | 后台登录冒烟测试（验证 DB + Session + Model 全链路） | [ ] |
| [P1-08](P1.md#p1-08-修复-commonmodel--commonphp-tp5-数组条件语法新增) | **NEW** common/model + common.php TP5 数组条件 → TP8（~306+22 处） | [x] |

---

## P2 — API 模块

| ID | 任务 | 状态 |
|----|------|------|
| [P2-01](P2.md#p2-01-api-控制器-use-声明批量更新) | api/controller/：`use think\*` → facade（批量） | [x] |
| [P2-02](P2.md#p2-02-api-控制器-model-替换) | api/controller/：model() 169 处 → new Model() | [x] |
| [P2-03](P2.md#p2-03-api-控制器-input-替换) | api/controller/：input() → request()->方法（约 5 处） | [x] |
| [P2-04](P2.md#p2-04-创建-routeapiphp) | 创建 route/api.php（从 application/route.php 提取 API 路由段） | [x] |
| [P2-05](P2.md#p2-05-api-接口回归测试) | API 接口回归测试（列表/搜索/用户接口） | [ ] |
| [P2-06](P2.md#p2-06-修复-apicontroller-tp5-数组条件语法新增) | **NEW** api/controller TP5 数组条件 → TP8（~132 处，依赖 P1-08） | [x] |

---

## P3 — Admin 模块（最大工作量）

| ID | 任务 | 状态 |
|----|------|------|
| [P3-01](P3.md#p3-01-admin-控制器-use-声明批量更新) | admin/controller/：`use think\*` → facade | [x] |
| [P3-02](P3.md#p3-02-admin-控制器-model-替换) | admin/controller/：model() 297 处 → new Model() | [x] |
| [P3-03](P3.md#p3-03-admin-控制器-input-替换) | admin/controller/：input() 280 处 → request()->方法 | [x] |
| [P3-04](P3.md#p3-04-addonphp-适配内化-addons) | admin/controller/Addon.php 适配内化后的 AddonsLoader | [x] |
| [P3-05](P3.md#p3-05-后台功能回归测试) | 后台功能回归测试（增删改查/上传/设置） | [ ] |
| [P3-06](P3.md#p3-06-修复-admincontroller-tp5-数组条件语法新增) | **NEW** admin/controller TP5 数组条件 → TP8（~346 处，依赖 P1-08） | [ ] |

---

## P4 — 前台 + Console

| ID | 任务 | 状态 |
|----|------|------|
| [P4-01](P4.md#p4-01-index-控制器适配) | index/controller/：use 改 facade，model() 91 处替换 | [ ] |
| [P4-02](P4.md#p4-02-taglib-适配) | Maccms.php / Macdiy.php：use think\Db → facade | [ ] |
| [P4-03](P4.md#p4-03-创建-routeindexphp) | 创建 route/index.php（前台路由，从 route.php 提取） | [ ] |
| [P4-04](P4.md#p4-04-console-commands-配置迁移) | 创建 config/console.php，注册 10 个 Command | [ ] |
| [P4-05](P4.md#p4-05-前台功能回归测试) | 前台回归测试（首页/分类/详情/搜索） | [ ] |
| [P4-06](P4.md#p4-06-console-commands-验证) | Console 验证：`php think list` 完整，`php think info` 成功 | [ ] |

---

## P5 — 清理 + 全量回归

| ID | 任务 | 状态 |
|----|------|------|
| [P5-01](P5.md#p5-01-移除-model-shim) | 移除 common.php 中 model() shim | [ ] |
| [P5-02](P5.md#p5-02-移除-input-shim) | 移除 common.php 中 input() shim | [ ] |
| [P5-03](P5.md#p5-03-移除-allphp-controller-shim) | 移除 All.php 中 success/error/assign/fetch shim | [ ] |
| [P5-04](P5.md#p5-04-删除-thinkphp-目录) | 删除 thinkphp/ 目录 | [ ] |
| [P5-05](P5.md#p5-05-全量回归---前台) | 全量回归 — 前台 | [ ] |
| [P5-06](P5.md#p5-06-全量回归---后台) | 全量回归 — 后台 | [ ] |
| [P5-07](P5.md#p5-07-全量回归---api) | 全量回归 — API | [ ] |
| [P5-08](P5.md#p5-08-全量回归---console) | 全量回归 — Console | [ ] |
| [P5-09](P5.md#p5-09-composer-优化-+-最终清理) | composer dump-autoload --optimize，移除多余 autoload 条目 | [ ] |
