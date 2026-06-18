# maccms10 站点初始化 CLI(`maccms-cli`)设计文档

> 目标:做一个 **WP-CLI 式的一键建站工具**,服务"开发/测试环境频繁、快速地起站 debug + 快速部署"。
> 一条命令,只要 **路径 / MySQL root 口令 / 新库名 / 站名**,产出一个可用站点。
> 商业级要求:**非交互可脚本化、口令零泄漏、最小权限、与 Web 安装器行为/安全等价、幂等、可秒级销毁重建**。
>
> 状态:**设计交付**(含可直接落地的代码骨架),未改业务代码。落地后置于 §3 的文件位置。
>
> 📌 本文为**建站(install)**部分的设计与实现记录。工具其后已扩展为完整的 WP-CLI 式命令集
> (`info`/`cache:flush`/`admin:reset-password`/`db:export`/`db:import`/`db:search-replace` +
> 多站 `@别名`/`maccms-cli.yml` + `--porcelain`)。**完整命令与用法见 [`bin/README.md`](../bin/README.md)**;
> 与 WP-CLI 的对标与演进见 [`docs/MACCMS_CLI_GAP_ANALYSIS.md`](MACCMS_CLI_GAP_ANALYSIS.md)。

---

## 〇、为什么能做、怎么做(结论先行)

maccms 的 Web 安装器(`application/install/controller/Index.php`)已经把"建库 / 写配置 / 导 SQL / 建管理员 / 锁定"做全了,并且**做了安全加固**(配置用 `var_export` 防注入、口令 `bcrypt`、生成 JWT 密钥)。
→ 我们**不重写**这套逻辑,而是**封装成命令行复用同一套 helper**,保证 CLI 与网页安装"同源、同行为、同安全"。这正是 WP-CLI 相对网页安装的价值:**同一套核心,换成可脚本化的入口**。

复用的现成 helper(均在 `application/common.php`):

| Helper | 位置 | 作用 |
|---|---|---|
| `mac_parse_sql($sql, 0, ['mac_'=>$prefix])` | `common.php:1495` | SQL dump 拆语句 + 表前缀替换 |
| `mac_arr2file($file, $arr)` | `common.php:323` | 配置写盘(`var_export`,已加固防注入) |
| `mac_get_rndstr($len)` | `common.php:530` | 随机密钥(JWT / interface pass) |
| `mac_password_hash()`(经 `model('Admin')->saveData`) | `model/Admin.php:67` | 管理员口令 bcrypt |

---

## 一、用户故事 / 目标 UX

**最简(4 个必填,其余默认):**

```bash
# 一键新建一个站点到指定路径(口令走 stdin,不进 argv)
bin/maccms new /var/www/site1 \
    --db-name=site1 \
    --site-name="我的测试站" \
  <<<"$MYSQL_ROOT_PASS"
```

执行后:复制代码 → 建库 → 导表 → 写配置(站名生效)→ 建管理员 → 写锁 → **打印访问地址 + 管理员账号/一次性随机口令**。

**开发者高频动作(快速 debug):**

```bash
bin/maccms install  --db-name=demo --site-name=Demo   # 当前目录就地装(已是 maccms 代码树)
bin/maccms reinstall --db-name=demo                    # 删锁+清库+重装 → 秒级回干净态
bin/maccms destroy  /var/www/site1                     # 删库+删目录(回收测试站)
bin/maccms doctor                                      # 环境体检(PHP/扩展/目录权限)
```

> 设计取舍:**默认非交互**(适合脚本/CI);缺关键参数时**回落交互提示**;口令**绝不**通过 `--root-pass=xxx` 这种 argv 明文传(`ps` 可见)。

---

## 二、架构(三层,单一事实源)

```
┌───────────────────────────────────────────────────────────────┐
│ ① 编排层  bin/maccms  (bash)                                   │
│   · 解析参数、口令安全传递(env/stdin/prompt)                  │
│   · "创建网站":把源码树复制/同步到目标路径 + 设权限            │
│   · dev 工作流:destroy / reinstall / doctor                   │
│   · 调用 → php <site>/think site:install ...                   │
└───────────────────────────────────────────────────────────────┘
                         │ 调用
                         ▼
┌───────────────────────────────────────────────────────────────┐
│ ② 核心层  application/command/SiteInstall.php  (TP5 console)    │
│   site:install —— 建库 / 写配置 / 导SQL / 建管理员 / 写锁       │
│   ★ 复用 Web 安装器同款 helper(parse_sql/arr2file/Admin/rnd)  │
└───────────────────────────────────────────────────────────────┘
                         │ 跑在
                         ▼
┌───────────────────────────────────────────────────────────────┐
│ ③ 入口  ./think  (新建,TP5 console 入口)                       │
└───────────────────────────────────────────────────────────────┘
```

**为什么核心层不用纯 bash + mysql 客户端重写?**
建库/配置/SQL/口令哈希若用 bash 重做,会与 Web 安装器**逻辑漂移**,且容易绕过已加固的 `var_export` 配置写入与 `bcrypt` 口令。**复用框架命令 = 单一事实源**,Web 装和 CLI 装永远一致。

---

## 三、文件落点(放在哪)

```
think                                   # 新建:TP5 console 入口(项目根)
bin/maccms                              # 新建:bash 编排/分发器(WP-CLI 式)
bin/_common.sh                          # 新建:bash 公共函数(日志/校验/口令读取)
application/command/SiteInstall.php     # 新建:核心命令 site:install
application/command/SiteDestroy.php     # 新建:site:destroy(清库/清锁,dev 回收)
application/command.php                 # 改:注册上述命令
docs/MACCMS_CLI_DESIGN.md               # 本文档
```

- **不动** `application/install/`:网页安装器保留,CLI 与之**并存**、共用底层 helper。
- **推荐(避免漂移)**:把"写 database.php"和"导 SQL"从 install 控制器抽到一个共享服务 `application/common/util/Installer.php`,供 Web 安装器与 `site:install` **同时调用**。本文档先给"复用 helper + 受控复制 25 行 mkDatabase 结构"的落地版,并把"抽共享服务"列为收尾优化(见 §10)。

---

## 四、命令接口:`site:install` 选项

| 选项 | 含义 | 必填 | 默认 | 口令来源 |
|---|---|---|---|---|
| `--db-host` | MySQL 主机 | | `127.0.0.1` | |
| `--db-port` | 端口 | | `3306` | |
| `--db-name` | **新库名** | ✅ | — | |
| `--db-prefix` | 表前缀(正则同安装器 `^[a-z0-9]{1,20}_`) | | `mac_` | |
| `--root-user` | 建库用的高权限账号 | | `root` | |
| (root 口令) | 建库/建用户 | ✅ | — | **env `MACCMS_DB_ROOT_PASS` / stdin / 交互**,**禁 argv** |
| `--app-user` | 应用连接用的**最小权限**账号 | | 自动生成 `<db>_app` | |
| `--app-pass` | 应用账号口令 | | 自动随机生成 | 自动生成则打印一次 |
| `--no-app-user` | 跳过建专用用户,直接用 root 写配置(**仅 dev**) | | 关 | |
| `--site-name` | **站点名**(写入 `maccms.site.site_name`) | ✅ | — | |
| `--admin-user` | 管理员账号 | | `admin` | |
| `--admin-pass` | 管理员口令 | | 强随机(打印一次) | 缺省自动生成 |
| `--with-initdata` | 导入演示数据 | | `1` | |
| `--install-dir` | 站点子目录 | | `/` | |
| `--cover` | 库已存在时覆盖 | | 关 | |
| `--force` | 已装(有 install.lock)仍继续 | | 关 | |
| `--lang` | 语言 | | `zh-cn` | |

退出码:`0` 成功 · `2` 参数错 · `3` 环境/权限不达标 · `4` 连接失败 · `5` 建库失败 · `6` SQL 失败 · `7` 已安装(未 `--force`)。

---

## 五、执行流程(逐步映射 `install/controller/Index.php`)

| 步 | 动作 | 复用/对应 | 安装器行号 |
|---|---|---|---|
| 1 | 环境/扩展/权限体检 | `doctor`(等价 checkNnv/checkDir/checkFunc) | `Index.php:290-381` |
| 2 | root 连接(无库)→ `select version()` 探活 | `Db::connect($rootCfg)` | `:146-152` |
| 3 | 建库 `CREATE DATABASE IF NOT EXISTS \`..\``(反引号转义) | 同 | `:170-173` |
| 4 | **(商业级)建最小权限 app 用户 + 仅本库 GRANT** | 新增 | — |
| 5 | 写 `application/database.php`(用 app 用户,`var_export`)→ **`Config::set('database',$cfg)` 让本进程后续走新连接** | 复用 mkDatabase 结构 | `:387-416` |
| 6 | 读 `config('maccms')` → 设 `site.site_name`/`app.cache_flag`/`app.lang`/`app.api_jwt_secret`(32)/`interface.pass`/`site.install_dir` → `mac_arr2file(extra/maccms.php)` | `mac_arr2file` | `:212-230` |
| 7 | 导 `install.sql`:`mac_parse_sql($sql,0,['mac_'=>$prefix])` → 逐句 `Db::execute` | `mac_parse_sql` | `:234-248` |
| 8 | (可选)导 `initdata.sql` | 同 | `:250-266` |
| 9 | 建管理员 `model('Admin')->saveData([...])`(bcrypt) | `Admin::saveData` | `:268-277` |
| 10 | 写 `data/install/install.lock` | 同 | `:278` |
| 11 | 打印:前台/后台地址 + 管理员账号口令 + app 库用户口令(一次性) | 新增 | — |

> **单进程连接切换(关键点)**:网页安装 step4/step5 是两个请求,step5 重新读 `database.php`。CLI 是一个进程,写完 `database.php` 后必须 `Config::set('database', $appCfg)`(并用该配置连接),否则 `model('Admin')` 仍用启动时的空配置。§6 代码已处理。

---

## 六、代码骨架(代码怎么写)

### 6.1 根 `think`(TP5 console 入口,新建)

```php
#!/usr/bin/env php
<?php
// maccms CLI console 入口(等价 thinkphp 标准 think 文件)
define('APP_PATH', __DIR__ . '/application/');
// 复用 web 入口的目录常量,部分 helper 依赖
define('MAC_COMM', __DIR__ . '/application/common/common/');
require __DIR__ . '/thinkphp/console.php';
```
> 赋可执行:`chmod +x think`。

### 6.2 `application/command.php`(注册)

```php
return [
    'app\\command\\SeoAiGenerate',
    'app\\command\\SiteInstall',
    'app\\command\\SiteDestroy',
];
```

### 6.3 `application/command/SiteInstall.php`(核心)

```php
<?php
namespace app\command;

use think\console\Command;
use think\console\Input;
use think\console\input\Option;
use think\console\Output;
use think\Config;
use think\Db;

class SiteInstall extends Command
{
    protected function configure()
    {
        $this->setName('site:install')
            ->setDescription('Non-interactive maccms site installer (WP-CLI style)')
            ->addOption('db-host', null, Option::VALUE_OPTIONAL, '', '127.0.0.1')
            ->addOption('db-port', null, Option::VALUE_OPTIONAL, '', '3306')
            ->addOption('db-name', null, Option::VALUE_REQUIRED, 'New database name')
            ->addOption('db-prefix', null, Option::VALUE_OPTIONAL, '', 'mac_')
            ->addOption('root-user', null, Option::VALUE_OPTIONAL, '', 'root')
            ->addOption('app-user', null, Option::VALUE_OPTIONAL, 'App DB user', '')
            ->addOption('app-pass', null, Option::VALUE_OPTIONAL, 'App DB pass', '')
            ->addOption('no-app-user', null, Option::VALUE_NONE, 'Use root in config (dev only)')
            ->addOption('site-name', null, Option::VALUE_REQUIRED, 'Site name')
            ->addOption('admin-user', null, Option::VALUE_OPTIONAL, '', 'admin')
            ->addOption('admin-pass', null, Option::VALUE_OPTIONAL, 'Auto-gen if empty', '')
            ->addOption('with-initdata', null, Option::VALUE_OPTIONAL, '', '1')
            ->addOption('install-dir', null, Option::VALUE_OPTIONAL, '', '/')
            ->addOption('cover', null, Option::VALUE_NONE, 'Overwrite existing DB')
            ->addOption('force', null, Option::VALUE_NONE, 'Ignore install.lock')
            ->addOption('lang', null, Option::VALUE_OPTIONAL, '', 'zh-cn');
    }

    protected function execute(Input $input, Output $output)
    {
        $opt = fn($k) => $input->getOption($k);

        // 0) 幂等:已装则拒绝(除非 --force)
        $lock = APP_PATH . 'data/install/install.lock';
        if (is_file($lock) && !$opt('force')) {
            $output->writeln('<error>already installed (use --force to override)</error>');
            return 7;
        }

        // 1) 必填校验 + 前缀正则(与安装器一致)
        $dbName = (string)$opt('db-name');
        $prefix = (string)$opt('db-prefix');
        $siteNm = (string)$opt('site-name');
        if ($dbName === '' || $siteNm === '') { $output->writeln('<error>--db-name and --site-name required</error>'); return 2; }
        if (!preg_match('/^[a-z0-9]{1,20}_$/', $prefix)) { $output->writeln('<error>bad --db-prefix</error>'); return 2; }

        // 2) root 口令:env / stdin,绝不读 argv
        $rootPass = getenv('MACCMS_DB_ROOT_PASS');
        if ($rootPass === false || $rootPass === '') {
            $rootPass = trim((string)fgets(STDIN));        // 由 bin/maccms 经管道喂入
        }

        // 3) root 连接(无库)+ 探活 + 建库
        $rootCfg = [
            'type' => 'mysql', 'hostname' => $opt('db-host'), 'hostport' => $opt('db-port'),
            'username' => $opt('root-user'), 'password' => $rootPass,
            'database' => '', 'charset' => 'utf8', 'prefix' => $prefix,
        ];
        $root = Db::connect($rootCfg);
        try { $root->execute('select version()'); }
        catch (\Exception $e) { $output->writeln('<error>db connect failed: '.$e->getMessage().'</error>'); return 4; }

        if (!$opt('cover')) {
            $exist = $root->query('SELECT SCHEMA_NAME FROM information_schema.schemata WHERE schema_name=? LIMIT 1', [$dbName]);
            if (!empty($exist)) { $output->writeln('<error>database exists (use --cover)</error>'); return 5; }
        }
        $dbQuoted = '`' . str_replace('`', '``', $dbName) . '`';
        $root->execute("CREATE DATABASE IF NOT EXISTS {$dbQuoted} DEFAULT CHARACTER SET utf8mb4");

        // 4) 最小权限 app 用户(商业级:应用不跑 root)
        $appUser = (string)$opt('app-user'); $appPass = (string)$opt('app-pass');
        if ($opt('no-app-user')) {
            $appUser = $opt('root-user'); $appPass = $rootPass;       // dev 模式
        } else {
            if ($appUser === '') { $appUser = substr(preg_replace('/[^a-z0-9_]/','',$dbName),0,24).'_app'; }
            if ($appPass === '') { $appPass = mac_get_rndstr(24); }
            $root->execute("CREATE USER IF NOT EXISTS ?@'%' IDENTIFIED BY ?", [$appUser, $appPass]);
            $root->execute("GRANT ALL PRIVILEGES ON {$dbQuoted}.* TO ?@'%'", [$appUser]);
            $root->execute('FLUSH PRIVILEGES');
        }

        // 5) 写 database.php(用 app 用户;var_export 加固,结构同 install mkDatabase)
        $appCfg = $this->dbConfig($opt('db-host'), $opt('db-port'), $dbName, $appUser, $appPass, $prefix);
        $this->writeDbConfig($appCfg);                 // file_put_contents + var_export
        Config::set('database', $appCfg);              // ★ 本进程后续 Db/model 走新连接

        // 6) 写 maccms 配置(站名/密钥/语言/install_dir)
        $mac = config('maccms');
        $mac['site']['site_name']        = $siteNm;
        $mac['site']['install_dir']      = $opt('install-dir') ?: '/';
        $mac['app']['cache_flag']        = substr(md5(microtime(true)), 0, 10);
        $mac['app']['lang']              = $opt('lang');
        $mac['app']['api_jwt_secret']    = mac_get_rndstr(32);
        $mac['interface']['status']      = 0;
        $mac['interface']['pass']        = mac_get_rndstr(16);
        if (mac_arr2file(APP_PATH.'extra/maccms.php', $mac) === false) {
            $output->writeln('<error>write maccms.php failed</error>'); return 3;
        }

        // 7+8) 导入 SQL(前缀替换),逐句执行
        foreach (['install.sql' => true, 'initdata.sql' => $opt('with-initdata')=='1'] as $file => $do) {
            if (!$do) continue;
            $path = APP_PATH.'install/sql/'.$file;
            if (!is_file($path)) continue;
            $list = array_filter(mac_parse_sql(file_get_contents($path), 0, ['mac_' => $prefix]));
            foreach ($list as $stmt) {
                try { Db::execute($stmt); }
                catch (\Exception $e) { $output->writeln("<error>SQL[$file] failed: ".$e->getMessage()."</error>"); return 6; }
            }
        }

        // 9) 管理员(bcrypt via Admin::saveData)
        $adminUser = $opt('admin-user') ?: 'admin';
        $adminPass = $opt('admin-pass') ?: mac_get_rndstr(12);
        $res = model('Admin')->saveData(['admin_name'=>$adminUser, 'admin_pwd'=>$adminPass, 'admin_status'=>1]);

        // 10) 锁
        @mkdir(APP_PATH.'data/install', 0755, true);
        file_put_contents($lock, date('Y-m-d H:i:s'));

        // 11) 汇总(口令一次性打印)
        $output->writeln('<info>✔ installed</info>');
        $output->writeln("  site_name : {$siteNm}");
        $output->writeln("  database  : {$dbName} (prefix {$prefix}), app_user {$appUser}");
        if (!$opt('no-app-user')) $output->writeln("  app_pass  : {$appPass}   (saved in application/database.php)");
        $output->writeln("  admin     : {$adminUser} / {$adminPass}");
        $output->writeln("  next      : open <site>/admin.php");
        return 0;
    }

    /** 与 install/controller/Index.php::mkDatabase 完全一致的配置结构 */
    private function dbConfig($host,$port,$db,$user,$pass,$prefix): array
    {
        return [
            'type'=>'mysql','hostname'=>(string)$host,'database'=>(string)$db,
            'username'=>(string)$user,'password'=>(string)$pass,'hostport'=>(string)$port,
            'dsn'=>'','params'=>[],'charset'=>'utf8','prefix'=>(string)$prefix,
            'debug'=>false,'deploy'=>0,'rw_separate'=>false,'master_num'=>1,'slave_no'=>'',
            'fields_strict'=>false,'resultset_type'=>'array','auto_timestamp'=>false,
            'datetime_format'=>'Y-m-d H:i:s','sql_explain'=>false,'builder'=>'',
            'query'=>'\\think\\db\\Query',
        ];
    }

    private function writeDbConfig(array $cfg): void
    {
        // 与安装器同款:var_export 序列化,杜绝向 database.php 注入 PHP
        $code = "<?php\n// 数据库配置(maccms CLI 生成)\nreturn ".var_export($cfg, true).";\n";
        file_put_contents(APP_PATH.'database.php', $code);
    }
}
```

> 注:`dbConfig()`/`writeDbConfig()` 复制了安装器 25 行结构——**§10 收尾优化建议把它和 SQL 导入抽到 `Installer` 共享服务**,让 Web 装与 CLI 装零漂移。

### 6.4 `bin/maccms`(bash 编排器,新建)

```bash
#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"   # 源码树根
source "$HERE/bin/_common.sh"

cmd="${1:-help}"; shift || true

read_root_pass() {            # 优先 env;否则从 stdin(管道/here-string)读;否则交互
  if [ -n "${MACCMS_DB_ROOT_PASS:-}" ]; then printf '%s' "$MACCMS_DB_ROOT_PASS"; return; fi
  if [ ! -t 0 ]; then cat -; return; fi
  read -rs -p "MySQL root password: " p; echo >&2; printf '%s' "$p"
}

case "$cmd" in
  new)        # bin/maccms new <path> --db-name=.. --site-name=.. [flags]   (root pass via stdin/env)
    dest="$1"; shift
    [ -n "$dest" ] || die "usage: maccms new <path> --db-name=.. --site-name=.."
    log "provisioning code → $dest"
    mkdir -p "$dest"
    rsync -a --delete \
      --exclude '.git' --exclude 'runtime/*' --exclude 'application/data/install/install.lock' \
      "$HERE/" "$dest/"
    ensure_writable "$dest"
    log "installing…"
    MACCMS_DB_ROOT_PASS="$(read_root_pass)" \
      php "$dest/think" site:install "$@" < /dev/null
    ;;
  install)    # 就地安装(当前已是 maccms 代码树)
    ensure_writable "$HERE"
    MACCMS_DB_ROOT_PASS="$(read_root_pass)" php "$HERE/think" site:install "$@" < /dev/null
    ;;
  reinstall)  # 删锁 + 清库 + 重装(dev 快速回干净态)
    rm -f "$HERE/application/data/install/install.lock"
    MACCMS_DB_ROOT_PASS="$(read_root_pass)" php "$HERE/think" site:install --cover --force "$@" < /dev/null
    ;;
  destroy)    # 删目录(+ 可选删库:php think site:destroy)
    dest="${1:?usage: maccms destroy <path> [--drop-db]}"
    confirm "destroy site at $dest ?" || exit 1
    [ -f "$dest/think" ] && { shift; MACCMS_DB_ROOT_PASS="$(read_root_pass)" php "$dest/think" site:destroy "$@" < /dev/null || true; }
    rm -rf "$dest"; log "removed $dest"
    ;;
  doctor)     php "$HERE/think" site:install --help >/dev/null && check_env ;;
  *)          cat "$HERE/docs/MACCMS_CLI_DESIGN.md" | sed -n '1,40p' ;;
esac
```

`bin/_common.sh`:`log/die/confirm/ensure_writable/check_env`(设置 `runtime upload application/data application/extra` 可写,`application/database.php`/`route.php` 可写;不让代码目录世界可写)。

---

## 七、安全与商业级处理(怎么处理)

| 关注点 | 处理 |
|---|---|
| **口令零泄漏** | root/app 口令**不进 argv**(`ps`/历史可见):走 `MACCMS_DB_ROOT_PASS` 环境变量、stdin 管道、或交互 `read -s`。app 用户口令仅写进 `database.php`(权限 600)并一次性打印 |
| **最小权限** | root 仅用于**建库 + 建专用用户**;`GRANT ALL ON <db>.*` 只授本库;**应用配置写 app 用户而非 root**(`--no-app-user` 仅限 dev) |
| **复用加固,不绕过** | 配置写盘统一 `var_export`(同 `mac_arr2file`/`mkDatabase`),杜绝注入;管理员口令 `bcrypt`(`mac_password_hash`);自动生成 `api_jwt_secret`(32)/`interface.pass`(16) |
| **幂等 / 防误伤** | 已装(`install.lock`)默认拒绝,需 `--force`;库已存在需 `--cover`;`destroy` 二次确认 |
| **文件权限** | 仅 `runtime/ upload/ application/data/ application/extra/ application/database.php application/route.php` 可写;代码不世界可写;可选 `chown www-data` |
| **退出码** | 0/2/3/4/5/6/7 分类,CI 可判 |
| **审计** | 安装/销毁动作落日志(谁/何时/哪库/哪路径),呼应仓库审计文化 |
| **多站隔离** | 每站独立**库名 + 前缀 + 独立 app 用户 + 独立 jwt/cache_flag** → 天然隔离(与 `deploy/meilisearch` 多站索引隔离一致) |

---

## 八、开发者工作流(快速 debug / 部署)

```bash
# 批量起多个隔离测试站
for i in 1 2 3; do
  echo "$ROOTPW" | bin/maccms new "/srv/site$i" --db-name="site$i" --site-name="站$i"
done

# 改完代码 → 秒级重置某站到干净态
echo "$ROOTPW" | bin/maccms reinstall --db-name=site1

# 用完回收
echo "$ROOTPW" | bin/maccms destroy /srv/site1 --drop-db
```

- **配合 Docker**(`docker/`):在 compose 里加一个 `oneshot` 服务跑 `maccms install`,实现"起容器即装好站"(免手点 `/install.php`)。
- **CI**:`site:install` 非交互 + 退出码 → 可做"全新安装冒烟"(呼应 `.github/workflows/ci.yml` 已有的 schema-load,把"装得起来"也纳入门禁)。

---

## 九、验证(本机 PHP 8.4 可实测)

本环境已具备:`php 8.4.19`(含 `pdo_mysql`/`mysqli`)、Docker(可起一次性 MySQL)。验证步骤:

```bash
# 起一次性 MySQL
docker run -d --name mc_mysql -e MYSQL_ROOT_PASSWORD=rootpw -p 3306:3306 mysql:5.7
# 就地装
echo rootpw | bin/maccms install --db-host=127.0.0.1 --db-name=cli_demo --site-name="CLI Demo" --admin-user=admin --admin-pass=admin888
# 断言
test -f application/data/install/install.lock && echo "LOCK OK"
mysql -h127.0.0.1 -uroot -prootpw -N -e "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='cli_demo'"   # >0
php -S 127.0.0.1:8800 -t . >/dev/null 2>&1 &   # 访问 /admin.php 能登录
```

冒烟断言:`install.lock` 生成、目标库表数 > 0、`database.php` 含 app 用户、后台可用所建管理员登录。

---

## 十、边界与收尾优化

- **不替代** Web 安装器(并存);**不自动改** web server vhost(附录给 nginx/apache 片段,但不动系统配置)。
- **收尾优化(强烈建议)**:抽 `application/common/util/Installer.php` 共享服务(`createDatabase / writeDbConfig / importSql / createAdmin`),让 `install/controller/Index.php` 与 `command/SiteInstall.php` **同时调用**,彻底消除 §6.3 的 25 行复制、保证两条安装路径零漂移。
- **TP8 迁移注意**:迁移后 console 命令注册从 `application/command.php` 改为 `config/console.php`,`model()`/`Db::` 写法按 `docs/tp8-migration/` 调整——本命令届时随之迁移(改动很小)。

## 十一、实现状态与实测(已落地)

**状态:已全量实现并在 PHP 8.4 + MySQL 5.7 实测通过。** 实际落地文件:

| 文件 | 说明 |
|---|---|
| `think` | console 入口(已建) |
| `bin/maccms`、`bin/_common.sh`、`bin/README.md` | bash 编排器 + 公共函数 + 使用帮助 |
| `application/command/SiteInstall.php` | `site:install` 命令 |
| `application/command/SiteDestroy.php` | `site:destroy` 命令 |
| `application/common/util/Installer.php` | 安装核心服务(单一事实源) |
| `application/command.php` | 注册上述命令 |

实现期相对本设计的关键决策(均已验证):

1. **PHP 8.x 兼容**:`think` 入口在框架引导后安装一个错误处理器,**吞掉 `E_DEPRECATED`**、其余错误交回框架。原因:TP5.0(EOL)的处理器会把 PHP 8.4+ 的"隐式可空参数已弃用"升级为致命(`App.php:77` 等),且其 `appError` 在不抛出时仍 `report()` 而触发尚在编译中的 `App` 引用。生产 PHP 7.4 不触发,等价无操作。根治见 `docs/tp8-migration/`。
2. **安装上下文常量**:`think` 入口定义 `ENTRANCE='install'`(及 `BIND_MODULE`/`IN_FILE`),令 `app_init` 行为(`Init`/`RequestSecurity`/`SessionSameSite`)按网页安装器同样的方式运行(仅读配置、不触库,适配全新环境)。
3. **管理员模型解析**:命令行无当前模块,`model('Admin')` 会误解析为 `app\model\Admin`;改为显式 `new \app\common\model\Admin()`,口令仍走 `mac_password_hash`(实测入库为 `$2y$12$` bcrypt)。
4. **重装口令对齐**:应用账号已存在时 `CREATE USER IF NOT EXISTS` 不改口令,补 `ALTER USER ... IDENTIFIED BY` 强制对齐为写入配置的口令,修复"重装后鉴权失败"。
5. **新增 `--fresh`**:删库重建后再装(干净重装),`bin/maccms reinstall` 使用之;`--cover` 保留为"复用已存在库"。
6. **共享服务**:已抽 `Installer`(§十 的收尾优化)并供命令使用;网页安装器 `install/controller/Index.php` **暂保持原状未重构**(其表单/会话/视图流需浏览器端 E2E,本轮未触),迁移到 `Installer` 列为低风险跟进项。

实测验证(host PHP 8.4.19 + `mysql:5.7` 容器):

```
bin/maccms new /tmp/site1 --db-name=clidemo --site-name="CLI Demo" --admin-pass=admin888
  → ✔ 安装完成;install.lock 生成;clidemo 53 张表;
    mac_admin 有 admin($2y$12$ bcrypt);database.php 用最小权限账号 clidemo_app(非 root);
    maccms.php site_name=CLI Demo、api_jwt_secret(32)、interface.pass(16)
重装(无 --force)        → 退出码 7(幂等拒绝)✓
重装(--fresh --force)   → 退出码 0,库重建干净、表/管理员正常 ✓
site:destroy             → 删库/删账号/删锁/删目录 ✓
doctor                   → PHP/扩展(pdo_mysql/mbstring/curl/zip 等)/rsync 体检 ✓
```

## 十二、安全与健壮性自审(含"是否扩大攻击面")

> 关键问题:**给一个 docroot=项目根、且被反复挂马过的站点,新增 CLI 是否扩大了 Web 攻击面?**
> 结论:**初版确有扩大,已定位并修复;修复后对 Web 攻击面无净增加。** 详见下。

### 12.1 曾经引入、现已修复的暴露点(🔴)

| 问题 | 风险 | 修复 |
|---|---|---|
| `db:export` / reinstall 自动备份默认写 `runtime/backup/*.sql` | `runtime/` **无 Web 保护**,DB 全量(含数据 + 管理员 `$2y$` 哈希)可被 `http://站点/runtime/backup/x.sql` **直接下载** | 默认改写到 `application/data/backup/`(受 `application/.htaccess` `deny from all`);并给 `runtime/` 补 `.htaccess` 拒绝(顺带保护日志/缓存) |
| `think` 位于 docroot 且无扩展名 | Web 误配置为用 PHP 解析时可能被 HTTP 触达 console;静态访问则源码泄露 | 入口加 `if (PHP_SAPI !== 'cli') exit;`,即便被解析也立即 403;另加 `bin/.htaccess` |
| `bin/_config.php` 在 docroot 内、是 `.php` | `register_argc_argv=On` 时 `?/etc/passwd+...` 可被 HTTP 执行并 `file()` 攻击者指定路径 | 同样加 `PHP_SAPI !== 'cli'` 守卫 + `bin/.htaccess` `deny from all` |

### 12.2 其余新增 PHP 均不可 Web 触达

- `application/command/*`、`application/common/util/{Installer,DbBackup}.php`:位于 `application/`,已被 `deny from all` 拒绝;且命令类只由 `console`(`php think`)加载,Web 的 `App::run()` 不读 `command.php`。
- 因此命令本身**不存在 Web 调用入口**:唯一入口 `think` 已 CLI-only。

### 12.3 命令实现的健壮性 / 注入面

- **SQL 注入**:`db:search-replace` 的 search/replace 走占位符 `?`;表名/列名取自 `information_schema`(可信)且反引号转义。`db:export` 表名反引号转义、值用 `PDO::quote()`。建库/建用户:库名反引号转义、用户名收敛 `[A-Za-z0-9_]`、口令字面量转义(`CREATE USER`/`GRANT` 不支持占位符)。`admin:reset-password` 全程 TP 查询构造器参数化。
- **配置写盘**:`database.php`/`maccms.php` 一律 `var_export()`(沿用仓库既有加固),无 PHP 注入。
- **口令哈希**:`mac_password_hash`(bcrypt `$2y$12$`),与网页登录校验同源;已实测 `password_verify` 通过。
- **幂等/破坏防护**:`install.lock` 守卫(`--force` 显式)、`--cover`/`--fresh` 区分、`reinstall` 删库前自动备份(`--no-backup` 可关)、`destroy` 需 `--yes`/`MACCMS_YES=1`、`db:search-replace` 提供 `--dry-run`。
- **失败处理**:各步抛 `\RuntimeException` → 命令分类退出码(0/2/3/4/5/6/7),不吞错。

### 12.4 信任模型与可接受残留(⚪)

- **CLI = 已具备文件/Shell 访问 = 受信操作者**:这些命令(改密、删库、导库)本就假定操作者已能登录服务器,**不构成新的 Web 提权路径**(同 WP-CLI / artisan / drush 模型)。
- **root 口令传递**:仅经 env/stdin,**不进 argv**(`ps` 不可见);env 在同用户 `/proc/PID/environ` 可见属可接受残留,**stdin 方式最安全**(文档已注明)。
- **`db:import` 执行文件内 SQL**:由操作者指定文件,属 import 固有语义;非 Web 向量。
- **`database.php` 文件权限**:沿用网页安装器(umask 默认),**未强制 `chmod 600`**——因 CLI 执行者与 Web 运行用户可能不同,强制 600 可能导致 Web 读不到配置而站点不可用;权限策略交由部署方(与现状一致,未变差)。
- **`maccms-cli.yml`**:不含口令(口令永不入文件);已 `.gitignore` 真实配置文件,仅 `.example` 入库。

### 12.5 部署侧建议(纵深防御)

- Apache:已随仓库提供 `application/.htaccess`、`bin/.htaccess`、`runtime/.htaccess`。
- **Nginx**(无 .htaccess):请在 server 段补:
  ```nginx
  location ~ ^/(bin|runtime)/ { deny all; return 403; }
  location = /think          { deny all; return 403; }
  ```
- 长期最佳实践:将 Web 根切到独立 `public/`(TP8 迁移后即为此结构,见 `docs/tp8-migration/`),根治"工具/框架文件与 docroot 混放"。

## 附:与 WP-CLI 能力对照

| WP-CLI | 本工具 |
|---|---|
| `wp core download` | `maccms new <path>`(复制源码树) |
| `wp config create` | 写 `application/database.php`(var_export) |
| `wp db create` | `site:install` 内 `CREATE DATABASE` + 建 app 用户 |
| `wp core install` | `site:install` 导 SQL + 建管理员 + 写锁 |
| `wp db reset` | `maccms reinstall` |
| `wp site delete` | `maccms destroy` |
