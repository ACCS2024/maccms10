# P0 · 基线 & 回归网(必须最先完成)

> 没有回归网,后面每一轮都是裸奔。本阶段**不动业务代码**,只搭"能证明迁移没改坏东西"的脚手架。

## 目标

1. 立 **PHP 8.4 / 8.5** 可验证环境(对照 `01-environment.md`)。
2. 建**黄金快照对照**(弥补"无单测")。
3. 冻结 API 调用点**基线计数**,作为后续对照锚点。

## 前置依赖

无(起点阶段)。需确认:docker daemon 可起、宿主 PHP 8.4 可用、库 schema 可装(均已实测可用)。

## 改动清单(只增不改业务)

| 产出 | 位置 | 说明 |
|---|---|---|
| 集成分支 + baseline worktree | `feat/tp8-migration` | 留一份迁移前代码用于黄金对照 |
| 8.4 / 8.5 Dockerfile + compose | `docker/Dockerfile.84` `.85`、`docker-compose.84.yml` `.85.yml` | 复用现有 mysql/redis/meili |
| 黄金快照脚本 | `tests/golden/capture.sh` `diff.sh` | 抓取+归一化(去时间戳/CSRF token)+ 比对 |
| 冒烟脚本 | `tests/smoke/*.sh` | 交互类(下单/回调/上传/插件) |
| 安全不变量脚本 | `tests/security/check_invariants.sh` | INV-1..8 半自动复验 |
| 最小数据集 | `tests/fixtures/` | 分类/视频/文章/会员/订单/1插件 |
| CI matrix | `.github/workflows/ci.yml` | 增 PHP 8.4 / 8.5 lint(先 `continue-on-error`) |

## 设计要点

- **黄金对照法**:baseline-7.4 抓 `verification/smoke-matrix.md` 全部 URL 的响应 → 归一化存 `tests/golden/`;迁移每轮在 target-8.4 重抓 diff。**结构性差异 = 回归信号**。
- 归一化要点:剥离 CSRF token、session id、时间戳、随机排序;保留 DOM 结构与关键文案。
- CI 暂不卡门(8.4/8.5 lint `continue-on-error`),P8 弃用清零后再转强制。

## 切片建议(每片一轮,每轮先分析)

- ROUND-001:环境(三套 docker + 宿主跑通)
- ROUND-002:黄金快照脚本 + 最小数据集 + baseline 抓取
- ROUND-003:安全不变量脚本 + CI matrix + 冻结基线计数

## 风险 & 安全不变量

🟢 低(不改业务)。但**黄金基线必须在"干净的迁移前代码"上抓**,否则对照失真。

## 验证

```bash
docker ps && php -v                       # 环境
bash tests/golden/capture.sh baseline     # 能抓到非空快照
bash tests/security/check_invariants.sh   # 8 条在 baseline 上全绿(确立"应有的样子")
```

## 退出标准(DoD)

- [ ] 三套环境可启动;站点在 baseline-7.4 正常
- [ ] 黄金快照覆盖冒烟矩阵全部 URL,`diff.sh` 自比对为空
- [ ] 安全不变量脚本在 baseline 全绿
- [ ] 基线计数写入 `progress/PROGRESS.md`
- [ ] tag `tp8-p0-done`

## 回滚

P0 全是新增文件,`git revert` 即可,无业务影响。
