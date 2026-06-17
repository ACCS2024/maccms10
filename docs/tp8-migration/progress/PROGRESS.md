# ★ TP8 迁移进度看板(单一事实源)

> 规则:**每轮收工必须更新本文件**(铁律 #7)。看板与代码不一致 = 流程故障。
> 状态图例:⬜ 未开始 · 🟦 进行中 · ✅ 完成 · ⚠️ 完成但有残留 · 🟥 受阻

- **当前阶段**:— (尚未开工)
- **当前轮次**:—
- **集成分支**:`feat/tp8-migration`(未创建)
- **最近更新**:2026-06-17(设计交付,未开工)
- **运行时落点**:PHP 8.4 验证中 → 目标 8.5

---

## 阶段总览

| 阶段 | 名称 | 状态 | 子项 | tag | 备注 |
|---|---|---|---|---|---|
| P0 | 基线 & 回归网 | ⬜ | 0/6 | `tp8-p0-done` | **必须最先完成** |
| P1 | TP8 骨架/单入口多应用 | ⬜ | 0/5 | `tp8-p1-done` | |
| P2 | 配置体系 → config/+.env | ⬜ | 0/4 | `tp8-p2-done` | 341 处 config() |
| P3 | 行为 → 中间件/事件 | ⬜ | 0/8 | `tp8-p3-done` | 🔴 安全脊柱 |
| P4 | 数据层(Db/模型) | ⬜ | 0/4 | `tp8-p4-done` | 459+820 |
| P5 | 控制器/视图/taglib | ⬜ | 0/6 | `tp8-p5-done` | 151+953+727 |
| P6 | 助手/会话/缓存/路由 | ⬜ | 0/6 | `tp8-p6-done` | input/cache/cookie/session/url |
| P7 | 插件系统 | ⬜ | 0/4 | `tp8-p7-done` | fastadmin-addons |
| P8 | 三方库 & PHP8.4→8.5 | ⬜ | 0/5 | `tp8-p8-done` | 见 PHP85 审计 |
| P9 | 回归/灰度/切换 | ⬜ | 0/5 | `tp8-p9-done` | |

---

## 阶段明细(勾选项)

### P0 基线 & 回归网 ⬜
- [ ] 创建 `feat/tp8-migration`,worktree 留存 baseline commit
- [ ] 三套 Docker(7.4基线 / 8.4目标 / 8.5前瞻)compose 就绪
- [ ] 冒烟矩阵 `verification/smoke-matrix.md` URL 清单落地
- [ ] 黄金快照脚本 `tests/golden/{capture,diff}.sh` + 最小数据集
- [ ] CI 增加 PHP 8.4/8.5 lint matrix
- [ ] 冻结 API 调用点基线计数(写入本看板"基线"区)

### P1 骨架 ⬜
- [ ] composer 引 `topthink/framework:^8.0` + `think-multi-app` + `think-view`,删 vendored `thinkphp/`
- [ ] `public/index.php` 单入口 + `public/router.php`(内置server用)
- [ ] `application/` → `app/`,多应用目录(index/admin/api/install)
- [ ] 站点能在 8.4 启动到"框架就绪"(允许业务报错)
- [ ] 入口/重写规则(apache/nginx)更新

### P2 配置 ⬜
- [ ] `extra/*.php`(10个)+ `config.php` → `config/*.php` 分组
- [ ] 生成"旧 key → 新 key"映射表
- [ ] 341 处 `config()` 按映射改写
- [ ] `.env` + 敏感项迁出仓库

### P3 行为→中间件/事件 ⬜(🔴)
- [ ] SessionSameSite → 中间件
- [ ] Init → 中间件
- [ ] RequestSecurity → 中间件
- [ ] Begin(防挂马) → 中间件
- [ ] CsrfGuard → 中间件
- [ ] AntiScrape → 中间件
- [ ] SecurityHeaders → 中间件(app_end)
- [ ] AdminAudit → 事件/中间件(app_end)+ 安全不变量全绿

### P4 数据层 ⬜
- [ ] `use think\Db` → 门面(459)
- [ ] 模型基类/事件迁移(~60)
- [ ] `model()` 调用收口(820)
- [ ] DB 连接配置格式迁移 + 黄金 diff 通过

### P5 控制器/视图/taglib ⬜
- [ ] `app\BaseController` 自建(承接 fetch/assign 习惯)
- [ ] 151 控制器迁基类/命名空间
- [ ] `->fetch()`(184)/`->assign()`(769)收口
- [ ] taglib(Maccms/Macdiy 727行)迁 think-view 注册
- [ ] 模板渲染黄金 diff 全绿
- [ ] 50 验证器迁移

### P6 助手/会话/缓存/路由 ⬜
- [ ] Cache(265)/ Cookie(118)/ Session(54)门面
- [ ] input(371)签名核对
- [ ] url(277)行为核对
- [ ] Request 注入收口(43)
- [ ] `common.php` 174 个 mac_ helper 内部 API 迁移
- [ ] 路由 `route/*.php` 拆分

### P7 插件 ⬜
- [ ] addons 加载器迁 TP8(fastadmin-addons TP6+ 或自维护)
- [ ] `addons/` 内现有插件适配
- [ ] 插件安装/卸载/渲染冒烟
- [ ] 第三方插件兼容性说明(破坏性变更公告)

### P8 三方 & PHP8.5 ⬜
- [ ] 低成本移除(think-queue/installer/aws/按配置 upyun/qiniu)— 见 PHP85 审计 §3
- [ ] PHPMailer 6.0.3 → 6.9.x
- [ ] PclZip → ZipArchive(或补 ereg)
- [ ] 8.4 弃用日志清零
- [ ] 切 PHP 8.5,弃用复零

### P9 切换 ⬜
- [ ] 全量回归(冒烟矩阵 100% + 黄金 diff 全绿)
- [ ] 安全不变量全绿 + 安全复核签字
- [ ] 性能对照(对比 PERFORMANCE_OPTIMIZATION.md 基线)
- [ ] 灰度(预发 8.4 → 8.5)
- [ ] 生产切换 + 回滚预案演练

---

## 基线计数(P0 冻结,后续对照用)

| 指标 | 基线值 | 来源 |
|---|---|---|
| app 总 PHP 文件 / LOC | 507 / ~158K | `PHP_UPGRADE_PLAN.md` |
| API 调用点合计 | ~3,700 | `02-conventions.md` 总表 |
| 控制器 / 验证器 / 模型 | 151 / 50 / ~60 | 同上 |
| 行为类 / 钩子点 / Hook引用 | 8 / 8 / 49 | P3 |
| taglib 行数 | 727 | P5 |
| 安全不变量条数 | 8 | `security-invariants.md` |

---

## 债务 / 残留登记(跨轮)

> 每轮绕过/打 TODO/暂留的,登记在此,迁移收尾前清零。

| 编号 | 描述 | 引入轮次 | 计划处理 | 状态 |
|---|---|---|---|---|
| — | (空) | — | — | — |
