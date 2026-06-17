# 01 · 验证环境(双轨)

迁移期**每轮都要能跑起来验**。本环境已在当前会话**实测可用**(2026-06-17):

- **宿主 PHP 8.4.19**(CLI,NTS),扩展齐全:`gd curl mbstring mysqli pdo_mysql intl zip redis opcache openssl sodium xsl gettext exif bcmath? sqlite3 ...` → 快路径验证。
- **Docker 29.3.1 + Compose v5.1.1**,守护进程可起、镜像可拉(已成功 `docker pull`)→ 全栈/平价验证。

> 设计原则:**快路径用宿主 PHP,平价/高风险用 Docker**。两条轨都要随时可用。

---

## A. 快路径:宿主 PHP 8.4(秒级,日常每轮用)

适合:语法检查、启动冒烟、单接口/单页面验证。

```bash
# 1) 语法全绿(迁移期把扫描范围从 application/ 切到 app/)
find app -name '*.php' -print0 | xargs -0 -n1 -P4 php -l >/dev/null

# 2) 起内置服务器(TP8 web root = public/)
php -S 127.0.0.1:8800 -t public public/router.php   # router 见 P1 产出
#   前台 http://127.0.0.1:8800/    后台 .../admin.php(多应用) 等

# 3) 单元/集成测试(P0 之后才有)
./vendor/bin/phpunit --testsuite smoke
```

数据库快路径(无需 MySQL 容器时):用一次性 MySQL 容器或宿主已有实例;Redis 同理(宿主有 `redis` 扩展,跑个 redis 容器即可)。

> ⚠️ 宿主 PHP 默认 `display_errors=On`——验证弃用/类型问题时设 `-d display_errors=Off -d log_errors=On -d error_reporting=E_ALL`,把弃用打进日志而不是污染响应(对应仓库已做的"500 不回显"加固)。

---

## B. 平价路径:Docker 全栈(高风险切片 / 阶段验收用)

仓库已有 `docker/`(`docker-compose.yml` + `Dockerfile`)。迁移期需要**三套并存**做对照:

| 环境 | 用途 | 基于 |
|---|---|---|
| **baseline-7.4** | 抓"迁移前黄金行为"(P0) | 现有 `docker/Dockerfile`(`php:7.4-apache`)+ 原 TP5.0 代码 |
| **target-8.4** | 迁移期主验证 | 新 `docker/Dockerfile.84`(`php:8.4-apache`)+ TP8 代码 |
| **target-8.5** | 落地前前瞻 | 新 `docker/Dockerfile.85`(`php:8.5-apache`) |

配套服务(沿用现有 compose):`mysql:5.7`、`redis:7-alpine`、`getmeili/meilisearch:v1.6`。

启动(守护进程若未起,先起):

```bash
# 起 docker 守护(本环境需手动拉起;有 daemon 的会话可跳过)
dockerd >/tmp/dockerd.log 2>&1 &   ; sleep 4 ; docker ps

# 全栈(目标 8.4)
cd docker && docker compose -f docker-compose.yml -f docker-compose.84.yml up -d --build
# 访问 http://localhost:8088 ;首次走 /install.php(库主机填 db)
```

> P0 会产出 `docker-compose.84.yml` / `.85.yml` 与对应 Dockerfile;baseline-7.4 直接用现有文件 + `git worktree` 检出迁移前的 commit。

---

## C. 黄金基线对照(P0 的关键产出)

因为**没有单测**,迁移正确性靠"**与迁移前逐页对照**":

1. 在 **baseline-7.4** 上,用脚本抓取关键页面/接口的**响应快照**(HTML 归一化后去掉时间戳/CSRF token,存 `tests/golden/`)。
2. 迁移每轮后,在 **target-8.4** 上重抓,`diff` 比对——**结构性差异即回归信号**。
3. 抓取清单 = `verification/smoke-matrix.md` 的 URL 列。

```bash
# 例:抓取 + 归一化(P0 落脚本 tests/golden/capture.sh)
bash tests/golden/capture.sh baseline   # 迁移前
bash tests/golden/capture.sh target      # 每轮后
bash tests/golden/diff.sh                 # 输出回归差异
```

---

## D. 数据准备

- 库 schema:`application/install/sql/install.sql` + `initdata.sql`(CI 已在用,见 `.github/workflows/ci.yml`)。
- 造数:P0 准备一份**最小可演示数据集**(若干分类/视频/文章/会员/订单/1个插件),供冒烟与黄金对照复用,纳入 `tests/fixtures/`。

---

## E. 这套环境如何支撑"每轮都要分析+验证"

| 工作循环步骤 | 用哪条轨 |
|---|---|
| ① 分析(复扫现状) | 宿主 `grep/wc/php -l` |
| ④ 验证 · 🟢🟠 切片 | 宿主 `php -S` + 冒烟子集 + 黄金 diff |
| ④ 验证 · 🔴 切片 | Docker `target-8.4` 全栈 + 安全不变量 + 黄金 diff |
| 阶段验收 | Docker 全栈三套对照(含 8.5 前瞻) |
