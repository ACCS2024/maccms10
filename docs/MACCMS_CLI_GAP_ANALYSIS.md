# maccms-cli 对标 WP-CLI:设计差距分析

- **基准**:WP-CLI(WordPress 官方 CLI,业界 CMS 命令行的事实标准)
- **被测**:本仓库 `maccms-cli`(`think` + `bin/maccms` + `site:install`/`site:destroy` + `Installer` 服务)
- **日期**:2026-06-17
- **方法**:拆解 WP-CLI 的设计要素 → 逐项对标 maccms-cli 现状 → 差距分级 → **映射 maccms 已有可复用实现** → 给优先级与路线
- **状态**:分析交付,未改代码。落地批次见 §六。

---

## 〇、结论速览

现状的 maccms-cli 把**建站闭环**(install / reinstall / destroy / doctor)做扎实了,且**安全基线**(口令零泄漏、最小权限账号、bcrypt、var_export、退出码、幂等)已达 WP-CLI 同级水准。

对标 WP-CLI,**缺的主要是三类**——而且其中很多 maccms 后台**已有现成实现可直接下沉复用**:

1. **命令广度(建站之外的生命周期)**:`db`(备份/导入/搜索替换/进 SQL)、`config`、`admin/user`、`cache`、`cron`、`addon`、`update`、`info`。
2. **输出与脚本化设计**:`--format=table/json/csv`、`--porcelain`、`--quiet/--debug`、`--dry-run`、`--prompt`、tab 补全。
3. **多环境/多站工程化**:项目配置文件(`wp-cli.yml` 之于本项目)、**别名 `@alias` + 批量 `@all`**、`--ssh` 远程——**这恰是"频繁起多个测试站 debug"的最大价值点,却是目前最大空白**。

> 一句话:**核心闭环够用了;离 WP-CLI 的差距在"广度 + 脚本化 + 多站编排"。** 且 60% 的高价值缺口能复用 maccms 后台已有代码,落地成本低。

---

## 一、WP-CLI 的"优秀设计"要素(对标基准)

| 设计要素 | 价值 |
|---|---|
| **统一层级命令** `wp <group> <sub>` | 心智一致,可发现性强 |
| **`--format=table\|json\|csv\|yaml\|ids\|count`** | 人读 + 机器读,天然可脚本化 |
| **`--porcelain`** | 只输出关键结果(如新建 ID),便于管道 |
| **`--prompt` / 读 STDIN** | 交互补参 + 非交互两不误 |
| **全局参数** `--path --url --user --yes --quiet --debug --color` | 行为可控、可静默、可强制 |
| **项目配置 `wp-cli.yml`** | 每项目默认值(免重复敲参) |
| **别名 `@prod`/`@staging` + `@all`** | 一套命令打多套环境/站点 |
| **`--ssh=user@host:path`** | 透明远程执行 |
| **`db search-replace`(支持序列化/`--dry-run`)** | 换域名/迁移的杀手锏 |
| **`--dry-run` / 确认 / 进度条** | 破坏性操作安全 |
| **自动生成 `help`/man + bash 补全** | 上手与效率 |
| **可扩展**:`package install` / `add_command` / hooks | 生态与二次开发 |
| **统一日志** `success/warning/error/log/debug` + 退出码 | 可观测、可判定 |

---

## 二、逐项对标矩阵

图例:✅ 已具备 · 🟡 部分 · ❌ 缺失 · ⛔ 不适用(maccms 无此概念)
优先级:P0 立刻(debug 刚需)· P1 高(多站/迁移)· P2 中(打磨)· P3 低/可选

### A. 命令广度

| 能力 | WP-CLI | maccms-cli | 差距 | **maccms 可复用点(证据)** | 优先级 |
|---|---|---|---|---|---|
| 建站 | `core install` | ✅ `site:install` | — | — | — |
| 删站 | `site delete` | ✅ `site:destroy` | — | — | — |
| **DB 备份** | `db export` | ❌ | 缺 | `admin/controller/Database.php:62 export()` + `common/util/BulkTableIo.php` | **P0** |
| **DB 恢复** | `db import` | ❌ | 缺 | `Database.php:141 import()` | **P0** |
| **搜索替换** | `db search-replace`(`--dry-run`) | ❌ | 缺 | **已有** `admin/controller/DataReplace.php:31 doReplace()`(`UPDATE .. REPLACE(field,?,?)` + 表白名单) | **P1** |
| 进 SQL/查询 | `db query` / `db cli` | ❌ | 缺 | `Database.php:368 sql()`;或直接 `mysql` 封装 | P2 |
| DB 优化/修复/引擎 | `db optimize/repair` | ❌ | 缺 | `Database.php:182 optimize / 208 repair / 240 convert_engine` | P2 |
| **管理员改密** | `user reset-password` | ❌ | 缺(**锁号自救刚需**) | `common/model/Admin.php:49 saveData()`(`admin_id`+`admin_pwd`→bcrypt) | **P0** |
| 建管理员 | `user create` | 🟡(仅装站时建) | 缺独立命令 | 同上 | P1 |
| **清缓存** | `cache flush` | ❌ | 缺 | **一行复用** `admin/controller/Base.php:146 Dir::delDir(RUNTIME_PATH.'cache/')`(+log/temp) | **P0** |
| 读写配置 | `config get/set` | 🟡(装站写一次) | 缺独立读写 | `Installer::writeMaccmsConfig()` 已支持点号路径写入 | P1 |
| 计划任务 | `cron event run` | ❌ | 缺 | `admin/controller/Timming.php` + `extra/timming.php`(56 项) | P2 |
| 插件 | `plugin install/activate/list` | ❌ | 缺 | fastadmin-addons + `extra/addons.php` | P2 |
| 升级 | `core update` | ❌ | 缺 | `admin/controller/Update.php` | P3 |
| 环境信息 | `cli info` / `--info` | 🟡(`doctor` 基础) | 弱 | 扩展 `doctor`:DB 连通/锁状态/版本/写权限 | **P0** |
| REPL/执行 | `eval` / `shell` | ❌ | 缺 | TP `Console` 可加 | P3 |
| 维护模式 | `maintenance-mode` | ❌ | 缺 | maccms 有"站点关闭"配置位 | P3 |

### B. 输出与脚本化设计

| 能力 | WP-CLI | maccms-cli | 差距 | 优先级 |
|---|---|---|---|---|
| `--format=table/json/csv` | ✅ 全命令 | ❌ | 列表/信息类需补 | **P1** |
| `--porcelain`(极简输出) | ✅ | ❌ | `new`/`admin create` 应能只吐关键值(密码/JSON) | **P1** |
| `--quiet` / `--debug` 分级 | ✅ | 🟡(TP 自带 `-q/-v`) | 语义对齐即可 | P2 |
| `--yes` 统一免确认 | ✅ 全局 | 🟡(`destroy` 有 `--yes`/`MACCMS_YES`) | 统一到所有破坏性命令 | P1 |
| `--dry-run` | ✅(replace 等) | ❌ | destroy/search-replace/reinstall 前 | **P1** |
| `--prompt` 交互补参 | ✅ | 🟡(仅口令交互) | 缺参可提示 | P3 |
| 进度条 | ✅ 批量 | ❌ | 大表导入/替换时 | P3 |
| bash 补全 | ✅ | ❌ | 高频效率项 | P2 |

### C. 多环境 / 多站(对"频繁多站"价值最高)

| 能力 | WP-CLI | maccms-cli | 差距 | 优先级 |
|---|---|---|---|---|
| **项目配置文件** | `wp-cli.yml`/`.local` | ❌ | 缺(每次重复敲 host/root/prefix) | **P1** |
| **别名 `@name`** | ✅(ssh/path/url) | ❌ | 缺(无法 `maccms @site1 db export`) | **P1** |
| **批量 `@all`** | ✅ | ❌ | 缺(无法一条命令打所有测试站) | **P1** |
| 远程 `--ssh=` | ✅ | ❌ | 远程执行 | P3(可用 ssh 外包) |
| `--path` 指定站点根 | ✅ | 🟡(`new <path>`;其余命令默认当前树) | 让所有命令支持 `--path` | **P1** |

### D. 扩展性 / 安全健壮

| 能力 | WP-CLI | maccms-cli | 差距 | 优先级 |
|---|---|---|---|---|
| 退出码语义 | ✅ | ✅(0/2/3/4/5/6/7) | — | — |
| 破坏性确认 | ✅ | 🟡(destroy) | 扩到 reinstall/replace | P1 |
| **破坏前自动备份** | 🟡(靠用户) | ❌ | reinstall/destroy 前可选 `db export` | **P1** |
| 命令包生态 | ✅ `package` | ⛔ | maccms 体量不需要 | P3 |
| `add_command` API/hooks | ✅ | 🟡(TP `command.php` 注册) | 够用 | — |
| 校验和/完整性 | `core verify-checksums` | ❌ | 呼应仓库"防挂马";可校验核心文件哈希 | P2 |

---

## 三、对 maccms 最高价值的缺口(Top,带复用映射)

> 排序 = 价值/成本。括号内为可直接复用的现有实现。

1. **`admin:reset-password`(P0)**——后台进不去时一条命令重置(复用 `Admin::saveData`,bcrypt)。**debug 刚需,成本极低**。
2. **`cache:flush`(P0)**——清 `runtime/{cache,log,temp}`(复用 `Base.php:146` 三行)。改完代码即清,**debug 高频**。
3. **`db:export` / `db:import`(P0)**——备份/恢复(复用 `Database.php::export/import` + `BulkTableIo`)。起站/改库前先备份。
4. **`doctor` 升级为 `info`(P0)**——加 DB 连通、`install.lock` 状态、表数、框架版本、写权限、PHP 版本——一屏自检。
5. **`db:search-replace`(P1)**——换域名/路径迁移(复用 `DataReplace.php::doReplace`,补**全表扫描 + `--dry-run`**)。**迁移/克隆站刚需**。
6. **别名 `@` + `maccms-cli.yml` + 全命令 `--path`(P1)**——"频繁多站"的真正杠杆:`maccms @site1 cache:flush`、`maccms @all db:export`。
7. **`--format=json` + `--porcelain`(P1)**——CI/脚本友好(`new` 吐 JSON:含 admin 口令/库名/路径)。
8. **`--dry-run` + 破坏前自动备份(P1)**——destroy/reinstall/replace 更安全。
9. **`config:get/set`(P1)**——CLI 读写站点配置(复用 `Installer::writeMaccmsConfig` 点号路径)。
10. **bash 补全 / `db:query` / `cron:run`(P2)**——效率与运维打磨。

---

## 四、明确"先不做 / 不做"(避免镀金)

- **`--ssh` 远程**:可用 `ssh host 'maccms ...'` 组合替代,先不内建(P3)。
- **命令包生态 `package`**:maccms 体量用不上(⛔)。
- **multisite**:WP 概念,maccms 无对应(⛔)。
- **`media regenerate` / `rewrite flush`**:maccms 无等价或意义小(⛔)。
- **`eval`/`shell` REPL**:低频,P3。

---

## 五、架构建议(支撑命令从 2 个长到 ~15 个)

1. **命令按域命名,对齐 WP-CLI 的 `group:sub`**:
   `db:export` `db:import` `db:search-replace` `db:query` / `admin:create` `admin:reset-password` / `cache:flush` / `config:get` `config:set` / `cron:run` / `addon:list` …
2. **`bin/maccms` 增加"透传"**:除编排类(new/destroy/reinstall),其余直接 `maccms <group:sub> ...` → `php think <group:sub>`,避免每个命令都在 bash 写分支;并让**所有命令支持 `--path`**(定位站点根)。
3. **逻辑下沉到 `common/util` 服务**,Web 后台与 CLI 共用(`Installer` 已开头):
   - `BackupService`(export/import/optimize)← 抽自 `Database.php`
   - `DataReplaceService`(search-replace + dry-run)← 抽自 `DataReplace.php`
   这样**修一处两端生效**,也顺带消除后台控制器里的重逻辑。
4. **统一输出 helper**:封装 `--format`/`--porcelain`/`--quiet`(一个 `CliOutput` 工具)。
5. **`maccms-cli.yml`(项目配置 + 别名表)**:
   ```yaml
   defaults: { db-host: 127.0.0.1, root-user: root, db-prefix: mac_ }
   aliases:
     "@site1": { path: /srv/site1 }
     "@all":  [ "@site1", "@site2" ]
   ```

---

## 六、落地路线(分批,价值优先)

| 批次 | 内容 | 预估 | 价值 |
|---|---|---|---|
| **批 1(debug 刚需)✅ 已完成** | `admin:reset-password`、`cache:flush`、`info`、`db:export`/`db:import`(+ `bin/maccms` 透传 `--path`) | — | 已实测通过 |
| **批 2(多站/脚本化)✅ 已完成** | `--path` 全命令、`maccms-cli.yml`(defaults)+ `@别名`/`@all`、`--format=json`/`--porcelain` | — | 已实测通过 |
| **批 3(迁移/安全)✅ 已完成** | `db:search-replace`(+`--dry-run`)、reinstall 破坏前自动备份(`--no-backup` 可跳)、`destroy` 确认 | — | 已实测通过 |
| **批 4(打磨)** | bash 补全、`db:query`、`cron:run`、`config:get/set`、`addon:list` | 按需 | 效率 |

---

## 附:WP-CLI → maccms-cli 命令对照速查

| WP-CLI | maccms-cli(现/拟) |
|---|---|
| `wp core download` | `maccms new <path>` ✅ |
| `wp core install` | `site:install` ✅ |
| `wp config set` | `config:set`(拟) |
| `wp db export` / `import` | `db:export` / `db:import`(拟,复用 Database.php) |
| `wp db search-replace` | `db:search-replace`(拟,复用 DataReplace.php) |
| `wp db query` | `db:query`(拟) |
| `wp user reset-password` | `admin:reset-password`(拟,复用 Admin::saveData) |
| `wp cache flush` | `cache:flush`(拟,复用 Base.php) |
| `wp cron event run` | `cron:run`(拟,复用 Timming) |
| `wp cli info` / `--info` | `info`(拟,扩展 doctor) |
| `wp @alias / @all` | `@别名` + `maccms-cli.yml`(拟) |
| `wp db reset` | `maccms reinstall --fresh` ✅ |
| `wp site delete` | `site:destroy` ✅ |
