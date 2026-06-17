# maccms10 → ThinkPHP 8 迁移方案(总入口)

> 本目录是 **ThinkPHP 5.0.25 → ThinkPHP 8 + PHP 8.5** 全量迁移(路线 B)的**分阶段设计与执行手册**。
> 上游背景与取舍见仓库根目录的 `PHP_UPGRADE_PLAN.md`(策略)与 `PHP85_UPGRADE_AUDIT.md`(三方依赖审计)。本目录只讲"**怎么一步步迁、怎么验、进度怎么记**"。

---

## 0. 一句话目标

把 maccms10 从 **TP5.0.25 / 多入口 / 行为钩子 / 扁平配置** 迁到 **TP8 / 单入口多应用 / 中间件+事件 / `config/`+`.env`**,运行时落到 **PHP 8.4 验证 → 8.5 落地**,**功能等价、安全不变量不破**。

## 1. 为什么需要一整套手册(而不是一个 md)

这是**移植**,不是打补丁。实测改动面(证据见 `PHP_UPGRADE_PLAN.md` / `PHP85_UPGRADE_AUDIT.md`):

- **~3,700 个 TP5.0 API 调用点**(`model()`820 / `->assign()`769 / `Db::`459 / `input()`371 / `config()`341 / `url()`277 / `cache`265 / `->fetch()`184 / `cookie`118 …)
- **~210 个类**要迁基类/命名空间(151 控制器 + 50 验证器 + ~60 模型),315 处 `use think\`
- **8 个安全行为类 + `tags.php` 8 个钩子点**要重构成中间件/事件(**最高风险:这是本 fork 的安全脊柱**)
- **727 行自定义模板标签库** + **config.php(251行)+ extra/(10个文件)** 配置体系 + 多入口引导全变
- **关键约束:项目几乎没有自动化测试**(CI 仅 `php -l` + 建表)。所以**回归网要先建**,否则 AI 改得快、但没人敢信。

> 结论:必须**切片化、每片先分析、每片可验证、进度可见、可回滚**。本手册就是为此而设。

## 2. 怎么用本手册(AI / 人 都按这个来)

1. 先读 `00-principles.md`(**铁律 + 每轮工作循环**)——这是不可跳过的。
2. 配好环境 `01-environment.md`(双轨:宿主 PHP 8.4 + Docker 全栈)。
3. 约定看 `02-conventions.md`(分支/提交/**TP5→TP8 路径与 API 映射总表**)。
4. **每开工一轮:先按 `templates/round-analysis-template.md` 产出《本轮分析》→ 存进 `progress/round-log/` → 才允许改代码。**
5. 干当前阶段:进 `phases/phase-N-*.md`,按其《改动清单 / 设计 / 验证 / 退出标准》执行。
6. 收工:更新 `progress/PROGRESS.md` 勾选,跑 `verification/` 冒烟与安全不变量,**一轮一提交**。

## 3. 目录地图

```
docs/tp8-migration/
├── README.md                      ← 你在这里(总入口/路线图)
├── 00-principles.md               迁移铁律 + 每轮工作循环(分析→设计→改→验→记→提)
├── 01-environment.md              双轨验证环境(宿主 PHP8.4 + Docker 全栈)实操命令
├── 02-conventions.md              分支/提交/PR + TP5→TP8 目录与 API 映射总表 + Rector
├── progress/
│   ├── PROGRESS.md                ★ 全局进度看板(单一事实源,每轮更新)
│   └── round-log/                 每轮《分析报告》归档(ROUND-XXX.md)
├── phases/
│   ├── phase-0-baseline.md        建回归网 + 冻结基线(先做,最重要)
│   ├── phase-1-scaffold.md        TP8 骨架/单入口多应用/composer/目录
│   ├── phase-2-config.md          配置体系 extra/* → config/ + .env
│   ├── phase-3-behaviors.md       ★ 行为→中间件/事件(安全脊柱,最高风险)
│   ├── phase-4-data-layer.md      Db 门面/模型/查询
│   ├── phase-5-controllers-views.md  控制器/视图/taglib/模板
│   ├── phase-6-helpers.md         input/session/cache/cookie/url/common.php
│   ├── phase-7-addons.md          插件系统(fastadmin-addons)迁移
│   ├── phase-8-thirdparty.md      三方库收口 + 落 PHP 8.4→8.5
│   └── phase-9-cutover.md         全量回归/灰度/切换/回滚
├── verification/
│   ├── smoke-matrix.md            ★ 全流程冒烟矩阵(每轮跑相关行)
│   └── security-invariants.md     ★ 必须保持的安全不变量(对应 8 个行为)
└── templates/
    ├── round-analysis-template.md ★ 「每轮先分析」强制模板
    └── phase-exit-criteria.md     每阶段 Definition of Done 模板
```

★ = 高频使用 / 强制项。

## 4. 路线图全景(阶段依赖)

```
P0 基线&回归网 ──► P1 骨架 ──► P2 配置 ──► P3 行为→中间件(安全脊柱)
                                                  │
        ┌─────────────────────────────────────────┘
        ▼
P4 数据层 ──► P5 控制器/视图/taglib ──► P6 助手/会话/缓存 ──► P7 插件 ──► P8 三方&PHP8.5 ──► P9 回归/灰度/切换
```

- **P0 必须最先做完**(没有回归网,后面全是裸奔)。
- **P3 是风险峰值**(安全不变量),单独成阶段、单独安全复核。
- P4–P6 可切更细的片并行推进,但每片都走"分析→验证"循环。
- **每个阶段结束**必须满足 `templates/phase-exit-criteria.md` 的 DoD 才进下一阶段。

## 5. 当前状态

迁移**尚未开工**;本目录为**设计交付**。开工从 `phases/phase-0-baseline.md` 起,实时进度看 `progress/PROGRESS.md`。
