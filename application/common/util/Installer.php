<?php
namespace app\common\util;

use think\facade\Db;

/**
 * 站点安装核心服务(单一事实源)
 *
 * 把"建库 / 写库配置 / 写程序配置 / 导 SQL / 建管理员 / 写锁"这些安装原语
 * 收口到一处,供命令行安装器 app\command\SiteInstall 复用,行为/安全与
 * 网页安装器 app\install\controller\Index 保持一致:
 *   - 配置写盘统一 var_export(杜绝向 database.php / maccms.php 注入 PHP)
 *   - 管理员口令 bcrypt(mac_password_hash)
 *   - SQL 导入复用 mac_parse_sql(表前缀替换)
 *
 * 说明:网页安装器目前仍是自带实现;后续可改为委托本服务以彻底消除重复
 * (属低风险但需浏览器端 E2E 验证的收尾项,见 docs/MACCMS_CLI_DESIGN.md §10)。
 *
 * 所有失败以 \RuntimeException 抛出,由调用方决定如何呈现。
 */
class Installer
{
    /** @var string 形如 /path/to/application/ */
    protected $appPath;

    public function __construct($appPath = null)
    {
        $this->appPath = $appPath ?: APP_PATH;
    }

    /** 站点是否已安装(存在安装锁) */
    public function isInstalled()
    {
        return is_file($this->appPath . 'data/install/install.lock');
    }

    public function lockFile()
    {
        return $this->appPath . 'data/install/install.lock';
    }

    /**
     * 用高权限账号连接(不指定库),并探活。
     * @return \think\db\Connection
     * @throws \RuntimeException
     */
    public function connect(array $cfg)
    {
        $conn = Db::connect($cfg);
        try {
            $conn->execute('select version()');
        } catch (\Exception $e) {
            throw new \RuntimeException('数据库连接失败:' . $e->getMessage());
        }
        return $conn;
    }

    public function databaseExists($conn, $name)
    {
        $rows = $conn->query(
            'SELECT SCHEMA_NAME FROM information_schema.schemata WHERE schema_name = ? LIMIT 1',
            [$name]
        );
        return !empty($rows);
    }

    /** 创建数据库(反引号转义库名,默认 utf8mb4) */
    public function createDatabase($conn, $name, $charset = 'utf8mb4')
    {
        $q = $this->quoteIdent($name);
        $cs = preg_replace('/[^a-z0-9_]/i', '', (string)$charset) ?: 'utf8mb4';
        if (false === $conn->execute("CREATE DATABASE IF NOT EXISTS {$q} DEFAULT CHARACTER SET {$cs}")) {
            throw new \RuntimeException('建库失败:' . $conn->getError());
        }
    }

    /** 删库(用于 dev 回收) */
    public function dropDatabase($conn, $name)
    {
        $conn->execute('DROP DATABASE IF EXISTS ' . $this->quoteIdent($name));
    }

    /**
     * 创建最小权限应用账号,只授予目标库权限(商业级:应用不跑 root)。
     * 注意:MySQL 的 CREATE USER / GRANT 不支持预处理占位符,故对库名做反引号转义、
     * 对用户名收敛到 [A-Za-z0-9_]、对口令做字符串字面量转义。
     */
    public function createAppUser($conn, $db, $user, $pass)
    {
        $u  = preg_replace('/[^A-Za-z0-9_]/', '', (string)$user);
        if ($u === '') {
            throw new \RuntimeException('应用账号名非法');
        }
        $pe = str_replace(['\\', "'"], ['\\\\', "\\'"], (string)$pass);
        $dbq = $this->quoteIdent($db);
        $conn->execute("CREATE USER IF NOT EXISTS '{$u}'@'%' IDENTIFIED BY '{$pe}'");
        // 账号已存在时 CREATE IF NOT EXISTS 不改口令,这里强制对齐为我们将写入配置的口令,
        // 保证重装(账号复用)时 database.php 里的口令与实际口令一致(否则连接鉴权失败)。
        $conn->execute("ALTER USER '{$u}'@'%' IDENTIFIED BY '{$pe}'");
        $conn->execute("GRANT ALL PRIVILEGES ON {$dbq}.* TO '{$u}'@'%'");
        $conn->execute('FLUSH PRIVILEGES');
    }

    public function dropAppUser($conn, $user)
    {
        $u = preg_replace('/[^A-Za-z0-9_]/', '', (string)$user);
        if ($u !== '') {
            $conn->execute("DROP USER IF EXISTS '{$u}'@'%'");
            $conn->execute('FLUSH PRIVILEGES');
        }
    }

    /** 规范化的数据库连接配置(与网页安装器 mkDatabase 结构一致) */
    public function buildDbConfig(array $p)
    {
        return [
            'type'            => 'mysql',
            'hostname'        => (string)($p['hostname'] ?? '127.0.0.1'),
            'database'        => (string)($p['database'] ?? ''),
            'username'        => (string)($p['username'] ?? ''),
            'password'        => (string)($p['password'] ?? ''),
            'hostport'        => (string)($p['hostport'] ?? '3306'),
            'dsn'             => '',
            'params'          => [],
            'charset'         => (string)($p['charset'] ?? 'utf8mb4'),
            'prefix'          => (string)($p['prefix'] ?? 'mac_'),
            'debug'           => false,
            'deploy'          => 0,
            'rw_separate'     => false,
            'master_num'      => 1,
            'slave_no'        => '',
            'fields_strict'   => false,
            'resultset_type'  => 'array',
            'auto_timestamp'  => false,
            'datetime_format' => 'Y-m-d H:i:s',
            'sql_explain'     => false,
            'builder'         => '',
            'query'           => '\\think\\db\\Query',
        ];
    }

    /**
     * 写 application/database.php(var_export,防注入)。
     * @throws \RuntimeException 写入或回读校验失败
     */
    /**
     * 写数据库凭据。
     *
     * TP8 的 config/database.php 是 ['default'=>..,'connections'=>['mysql'=>..]] 结构,
     * 且各字段一律取自 env();框架【不会】加载 application/database.php。
     * 历史上安装器把扁平的 TP5 结构写进 application/database.php,那个文件谁都不读,
     * 于是装完站 Db 门面仍用空账号连库,报 Access denied for user ''@'localhost'。
     *
     * 所以凭据的唯一事实源是根目录 .env(已在 .gitignore 中,不会被提交)。
     */
    public function writeDbConfig(array $cfg)
    {
        $root = dirname(rtrim($this->appPath, '/\\')) . DIRECTORY_SEPARATOR;
        $file = $root . '.env';

        // ThinkPHP 用 parse_ini_file($file, true, INI_SCANNER_RAW) 读 .env。
        // RAW 模式下【不会】剥离引号 —— 写 DB_PASS="x" 读回来就是带引号的 "x"。
        // 所以一律写裸值;同时 RAW 模式仍会把 ; 当行注释、把引号当词法符号,
        // 这类字符无法安全表达,宁可报错也不要写出一个能解析但值是错的文件。
        $pairs = [
            'DB_HOST'    => $cfg['hostname'],
            'DB_PORT'    => $cfg['hostport'],
            'DB_NAME'    => $cfg['database'],
            'DB_USER'    => $cfg['username'],
            'DB_PASS'    => $cfg['password'],
            'DB_PREFIX'  => $cfg['prefix'],
            'DB_CHARSET' => $cfg['charset'],
        ];
        $lines = ['; 数据库凭据(maccms 安装器生成) —— 含明文口令,已被 .gitignore 排除'];
        foreach ($pairs as $k => $v) {
            $v = (string)$v;
            if (preg_match('/[;"\'\r\n]/', $v)) {
                throw new \RuntimeException(
                    "{$k} 含有无法写入 .env 的字符(; \" ' 或换行),请改用不含这些字符的值"
                );
            }
            $lines[] = $k . ' = ' . $v;
        }
        $lines[] = '';
        $content = implode("\n", $lines);

        // 原子写入,避免半截文件被并发请求读到
        $tmp = $file . '.tmp' . getmypid();
        if (false === @file_put_contents($tmp, $content)) {
            throw new \RuntimeException("无法写入 {$tmp}(检查目录权限)");
        }
        @chmod($tmp, 0640);
        // 口令文件不给 other 读;属主/属组对齐 application/ 目录,
        // 否则 CLI 以 root 装站、FPM 以 www 运行时,PHP 读不到 .env 会连不上库。
        $st = @stat($this->appPath);
        if ($st !== false) {
            @chown($tmp, $st['uid']);
            @chgrp($tmp, $st['gid']);
        }
        if (!@rename($tmp, $file)) {
            @unlink($tmp);
            throw new \RuntimeException("无法写入 {$file}(检查权限)");
        }

        // 回读校验:必须用和 think\Env::load() 完全相同的解析方式,
        // 否则校验通过而框架读到的是另一回事。
        $back = @parse_ini_file($file, true, INI_SCANNER_RAW);
        if (!is_array($back)
            || ($back['DB_NAME'] ?? null) !== (string)$cfg['database']
            || ($back['DB_USER'] ?? null) !== (string)$cfg['username']
            || ($back['DB_PASS'] ?? null) !== (string)$cfg['password']) {
            throw new \RuntimeException('.env 写入校验失败(凭据回读不一致)');
        }
    }

    /**
     * 写 application/extra/maccms.php:在现有 maccms 配置上套用覆盖项后整体落盘。
     * $overrides 用点号路径,如 ['site.site_name' => 'xx', 'app.api_jwt_secret' => '...']
     * @throws \RuntimeException
     */
    public function writeMaccmsConfig(array $overrides)
    {
        $cfg = config('maccms');
        if (!is_array($cfg)) {
            $cfg = [];
        }
        foreach ($overrides as $path => $val) {
            $this->arraySet($cfg, $path, $val);
        }
        $file = $this->appPath . 'extra/maccms.php';
        mac_arr2file($file, $cfg);
        $back = is_file($file) ? include $file : null;
        if (!is_array($back)) {
            throw new \RuntimeException("maccms.php 写入失败:{$file}");
        }
    }

    /**
     * 导入一个 SQL 文件(复用 mac_parse_sql 做表前缀替换),逐句执行。
     * @return int 执行语句数
     * @throws \RuntimeException 任一语句失败
     */
    public function importSqlFile($absPath, $prefix)
    {
        if (!is_file($absPath)) {
            return 0;
        }
        $sql  = file_get_contents($absPath);
        $list = array_filter(mac_parse_sql($sql, 0, ['mac_' => $prefix]));
        $n = 0;
        foreach ($list as $stmt) {
            try {
                Db::execute($stmt);
                $n++;
            } catch (\Exception $e) {
                throw new \RuntimeException('SQL 执行失败(' . basename($absPath) . '):' . $e->getMessage());
            }
        }
        return $n;
    }

    /**
     * 创建管理员:直接以 bcrypt 入库(mac_password_hash),与网页安装器口令哈希一致。
     * 不走 Admin::saveData 的模块相关校验(命令层已校验入参),以保证 CLI 健壮。
     * @throws \RuntimeException
     */
    public function createAdmin($name, $pass)
    {
        // 显式使用 common 模块模型:命令行无当前模块,(new \app\common\model\Admin()) 会误解析为 app\model\Admin
        $admin = new \app\common\model\Admin();
        $exists = $admin->where('admin_name', $name)->find();
        if (!empty($exists)) {
            throw new \RuntimeException("管理员已存在:{$name}");
        }
        $ok = $admin->insert([
            'admin_name'   => $name,
            'admin_pwd'    => mac_password_hash($pass),
            'admin_status' => 1,
            'admin_auth'   => '',
        ]);
        if (false === $ok) {
            throw new \RuntimeException('管理员创建失败:' . $admin->getError());
        }
    }

    /** 写安装锁 */
    public function writeLock()
    {
        $dir = $this->appPath . 'data/install';
        if (!is_dir($dir)) {
            @mkdir($dir, 0755, true);
        }
        if (false === @file_put_contents($this->lockFile(), date('Y-m-d H:i:s'))) {
            throw new \RuntimeException('写入 install.lock 失败');
        }
    }

    /** 删锁(用于 reinstall) */
    public function removeLock()
    {
        if (is_file($this->lockFile())) {
            @unlink($this->lockFile());
        }
    }

    // ---- 内部工具 ----

    /** 反引号转义标识符(库名/表名) */
    protected function quoteIdent($name)
    {
        return '`' . str_replace('`', '``', (string)$name) . '`';
    }

    /** 按点号路径写入多维数组 */
    protected function arraySet(array &$arr, $path, $val)
    {
        $keys = explode('.', $path);
        $ref = &$arr;
        foreach ($keys as $k) {
            if (!isset($ref[$k]) || !is_array($ref[$k])) {
                $ref[$k] = [];
            }
            $ref = &$ref[$k];
        }
        $ref = $val;
    }
}
