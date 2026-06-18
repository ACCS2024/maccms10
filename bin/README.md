# maccms-cli 使用帮助

WP-CLI 式一键建站 / 快速部署工具。设计文档见 [`docs/MACCMS_CLI_DESIGN.md`](../docs/MACCMS_CLI_DESIGN.md)。

只需 **路径 / MySQL root 口令 / 库名 / 站名** 四要素即可起一个可用站点。

## 快速开始

```bash
# 全新站点(部署代码到新路径 + 安装),root 口令走 stdin
echo "$MYSQL_ROOT_PASS" | bin/maccms new /var/www/site1 \
    --db-name=site1 --site-name="我的站点"

# 就地安装(当前目录已是 maccms 代码)
MACCMS_DB_ROOT_PASS=secret bin/maccms install --db-name=demo --site-name=Demo

# 开发期秒级重置到干净态(删锁 + 覆盖重装)
echo "$MYSQL_ROOT_PASS" | bin/maccms reinstall --db-name=demo

# 回收(删目录;加 --drop-db 同时删库)
echo "$MYSQL_ROOT_PASS" | MACCMS_YES=1 bin/maccms destroy /var/www/site1 --drop-db --db-name=site1 --drop-user=site1_app

# 环境体检
bin/maccms doctor
```

安装成功后,命令会打印 **管理员账号 / 口令** 与 **应用数据库账号口令**(仅此一次),并提示访问 `<站点地址>/admin.php`。

## 命令一览

| 命令 | 作用 |
|---|---|
| `new <路径> --db-name --site-name` | 部署代码到路径并安装全新站点 |
| `install --db-name --site-name` | 当前代码树就地安装 |
| `reinstall --db-name` | 删锁 + 覆盖重装(开发回到干净态) |
| `destroy <路径> [--drop-db --db-name --drop-user]` | 删目录(可选删库/账号) |
| `doctor` | PHP/扩展/rsync 体检 |
| `help` | 使用帮助 |

### 站点运维命令(透传给 `php think`,可加 `--path=<站点根>` 指定其它站点)

| 命令 | 作用 |
|---|---|
| `info [--format=table\|json]` | 站点/环境自检(版本/扩展/安装状态/数据库/可写目录/性能建议) |
| `cache:flush [--with-log]` | 清空 runtime 缓存(改完代码即清),重置 opcache |
| `admin:reset-password --user=admin [--password=xxx]` | 重置后台管理员口令(进不去后台时自救;缺省随机) |
| `db:export [--file=xx.sql] [--tables=a,b]` | 导出数据库到 .sql(PDO 实现,无需 mysqldump) |
| `db:import --file=xx.sql [--src-prefix=mac_ --dst-prefix=site1_]` | 从 .sql 恢复(可选表前缀替换) |
| `db:search-replace OLD NEW [--dry-run] [--tables=a,b]` | 跨表文本字段搜索替换(换域名/改路径);先 `--dry-run` 演练 |

```bash
# 例:对另一个站点目录做运维
bin/maccms info --path=/srv/site1
bin/maccms cache:flush --path=/srv/site1
bin/maccms admin:reset-password --path=/srv/site1 --user=admin
bin/maccms db:export --path=/srv/site1 --file=/backup/site1.sql
# 换域名(先演练再执行)
bin/maccms db:search-replace http://old.com http://new.com --dry-run --path=/srv/site1
bin/maccms db:search-replace http://old.com http://new.com --path=/srv/site1
```

## 多站编排(maccms-cli.yml)

复制 `maccms-cli.yml.example` 为 `maccms-cli.yml`(或用 `MACCMS_CLI_CONFIG=路径` 指定):

```yaml
defaults: { db-host: 127.0.0.1, db-port: "3306", root-user: root, db-prefix: mac_ }
aliases:  { site1: /srv/site1, site2: /srv/site2 }
groups:   { all: site1 site2 }
```

- **defaults**:为 `new`/`install`/`reinstall` 提供默认参数(免重复敲;命令行显式参数覆盖之)。
- **aliases / groups**:运维命令首参用 `@别名` / `@分组` 对多个站点**批量执行**:

```bash
bin/maccms info @all                 # 对所有站点跑 info
bin/maccms cache:flush @site1        # 对 site1 清缓存
bin/maccms db:export @all            # 备份所有站点
```

## 脚本化输出

- `--porcelain`:`site:install` 输出一行 JSON(含库名/账号/口令);`db:export` 仅输出文件路径;`admin:reset-password` 仅输出新口令。
- `info --format=json`:结构化自检结果。

## 安全网

- `reinstall` 默认在**删库重装前自动备份**到 `runtime/backup/pre-reinstall-*.sql`,加 `--no-backup` 跳过。
- `db:search-replace` / `destroy` 等破坏性操作:先 `--dry-run` / 二次确认(`destroy` 需 `--yes` 或 `MACCMS_YES=1`)。

## root 口令传递(三选一,按优先级)

1. **环境变量**:`MACCMS_DB_ROOT_PASS=secret bin/maccms install ...`
2. **标准输入**:`echo "$ROOTPW" | bin/maccms install ...`
3. **交互输入**:`bin/maccms install ...`(终端隐藏回显提示)

> ⚠️ **绝不要**把口令写进命令行参数(如 `--root-pass=xxx`)——`ps`、shell 历史都会泄漏。本工具刻意不提供该参数。

## 常用选项

透传给底层命令 `php think site:install`,完整列表见:

```bash
php think site:install --help
```

| 选项 | 默认 | 说明 |
|---|---|---|
| `--db-host` / `--db-port` | `127.0.0.1` / `3306` | 数据库地址 |
| `--db-name` | (必填) | 新库名 |
| `--db-prefix` | `mac_` | 表前缀(形如 `mac_`) |
| `--db-charset` | `utf8mb4` | 建库字符集 |
| `--root-user` | `root` | 建库用高权限账号 |
| `--app-user` / `--app-pass` | `<库名>_app` / 随机 | 应用最小权限账号 |
| `--no-app-user` | 关 | 配置直接用 root(**仅开发**) |
| `--site-name` | (必填) | 站点名称 |
| `--admin-user` / `--admin-pass` | `admin` / 随机 | 管理员账号/口令 |
| `--with-initdata` | `1` | 是否导入演示数据 |
| `--install-dir` | `/` | 站点子目录 |
| `--lang` | `zh-cn` | 语言 |
| `--cover` | 关 | 库已存在则复用(不删旧表) |
| `--fresh` | 关 | 删库重建后再装(干净重装,`reinstall` 使用) |
| `--force` | 关 | 忽略 install.lock |

## 退出码

| 码 | 含义 |
|---|---|
| 0 | 成功 |
| 2 | 参数错误 |
| 3 | 文件写入权限不足 |
| 4 | 数据库连接失败 |
| 5 | 建库失败 |
| 6 | SQL 导入 / 建管理员失败 |
| 7 | 已安装(需 `--force`) |

## 安全与设计要点

- **复用网页安装器同款核心**(`app\common\util\Installer`):配置 `var_export` 防注入、口令 `bcrypt`、SQL 前缀替换 —— 与 `install.php` 同源同行为。
- **最小权限**:root 仅用于建库 + 建专用账号;应用配置写专用账号而非 root。
- **每站隔离**:独立库名 + 前缀 + 独立应用账号 + 独立 `api_jwt_secret` / `cache_flag`。
- **幂等**:已安装默认拒绝;`--force` / `--cover` 显式覆盖;`destroy` 需确认或 `MACCMS_YES=1`。

## 批量起多个隔离测试站

```bash
for i in 1 2 3; do
  echo "$ROOTPW" | bin/maccms new "/srv/site$i" --db-name="site$i" --site-name="测试站$i"
done
```
