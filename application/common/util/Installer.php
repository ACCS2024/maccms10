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
    public function writeDbConfig(array $cfg)
    {
        $file = $this->appPath . 'database.php';
        $code = "<?php\n// 数据库配置(maccms 安装器生成)\nreturn " . var_export($cfg, true) . ";\n";
        if (false === @file_put_contents($file, $code)) {
            throw new \RuntimeException("无法写入 {$file}(检查权限)");
        }
        if (function_exists('opcache_invalidate')) {
            opcache_invalidate($file, true);
        }
        $back = include $file;
        if (empty($back['database']) || $back['database'] !== $cfg['database']) {
            throw new \RuntimeException('database.php 写入校验失败');
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
