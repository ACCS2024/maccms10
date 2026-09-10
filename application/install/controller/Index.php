<?php
namespace app\install\controller;
use think\facade\Db;
use think\facade\Lang;

class Index extends \app\common\controller\All
{

    public function __construct()
    {
        // 仅安装脚本可进入
        if (!defined('BIND_MODULE') || BIND_MODULE != 'install') {
            header('HTTP/1.1 403 Forbidden');
            exit();
        }
        // 安全加固(V10):控制器层也校验安装锁,防止锁存在时仍能重装/覆盖配置(不止依赖入口文件)
        if (is_file(APP_PATH . 'data/install/install.lock')) {
            header('HTTP/1.1 403 Forbidden');
            exit('already installed');
        }
        parent::__construct();
    }

    public function index($step = 0)
    {
        $langs = glob(APP_PATH . 'lang/*.php') ?: [];
        foreach ($langs as $k => &$v) {
            $v = basename($v, '.php');
        }
        $this->assign('langs', $langs);

        if(in_array(session('lang'),$langs)){
            $lang = session('lang');
            Lang::setLangSet($lang);
            Lang::load(APP_PATH . 'lang/'.$lang.'.php', $lang);
        }

        switch ($step) {
            case 2:
                session('install_error', false);
                return self::step2();
                break;
            case 3:
                if (session('install_error')) {
                    return $this->error(lang('install/environment_failed'));
                }
                return self::step3();
                break;
            case 4:
                if (session('install_error')) {
                    return $this->error(lang('install/environment_failed'));
                }
                return self::step4();
                break;
            case 5:
                if (session('install_error')) {
                    return $this->error(lang('install/init_err'));
                }
                return self::step5();
                break;
            default:
                $param = \think\facade\Request::param();

                if(!in_array($param['lang'] ?? '', $langs, true)) {
                    $param['lang'] = 'zh-cn';
                }
                $lang = $param['lang'];
                Lang::setLangSet($lang);
                Lang::load(APP_PATH . 'lang/'.$lang.'.php', $lang);
                session('lang',$param['lang']);
                $this->assign('lang',$param['lang']);

                session('install_error', false);
                return $this->fetch('install@/index/index');
                break;
        }
    }

    /**
     * 第二步：环境检测
     */
    private function step2()
    {
        $data = [];
        $data['env'] = self::checkNnv();
        $data['dir'] = self::checkDir();
        $data['func'] = self::checkFunc();
        $this->assign('data', $data);
        return $this->fetch('install@index/step2');
    }

    /**
     * 第三步：初始化配置
     */
    private function step3()
    {
        $script = $_SERVER['SCRIPT_NAME'] ?? '';
        $slash = is_string($script) ? strrpos($script, '/') : false;
        // SCRIPT_NAME positions are byte offsets; keep UTF-8 directory names intact.
        $install_dir = $slash === false ? '/' : substr($script, 0, $slash + 1);
        $this->assign('install_dir',$install_dir);
        return $this->fetch('install@index/step3');
    }

    /**
     * 第四步：执行安装
     */
    private function step4()
    {
        if (\think\facade\Request::isPost()) {
            // 凭据的唯一事实源是根目录 .env(TP8 的 config/database.php 一律取自 env()),
            // 不再是 application/database.php —— 那个文件框架从不加载。
            $envDir = rtrim(dirname(rtrim(APP_PATH, '/\\')), '/\\') . DIRECTORY_SEPARATOR;
            if (!is_writable($envDir)) {
                return $this->error('[' . $envDir . '.env]' . lang('install/write_read_err'));
            }
            $data = \think\facade\Request::post();
            $data['type'] = 'mysql';
            $rule = [
                'hostname|'.lang('install/server_address') => 'require',
                'hostport|'.lang('install/database_port') => 'require|number',
                'database|'.lang('install/database_name') => 'require',
                'username|'.lang('install/database_username') => 'require',
                'prefix|'.lang('install/database_pre') => 'require|regex:^[a-z0-9]{1,20}_$',
                'cover|'.lang('install/overwrite_database') => 'require|in:0,1',
            ];
            $vld = (new \think\Validate())->rule($rule);
            if (!$vld->check($data)) {
                return $this->error($vld->getError());
            }
            $cover = $data['cover'];
            unset($data['cover']);
            $config = (new \app\common\util\Installer())->buildDbConfig([]);
            foreach ($data as $k => $v) {
                if (array_key_exists($k, $config) === false) {
                    return $this->error(lang('param').''.$k.''.lang('install/not_found'));
                }
            }
            // 不存在的数据库会导致连接失败
            $database = $data['database'];
            unset($data['database']);
            // 创建数据库连接
            $db_connect = Db::connect($data);
            // 检测数据库连接
            try{
                $db_connect->execute('select version()');
            }catch(\Throwable $e){
                return $this->error(lang('install/database_connect_err'));
            }


            // 不覆盖检测是否已存在数据库
            if (!$cover) {
                $check = $db_connect->query(
                    'SELECT SCHEMA_NAME FROM information_schema.schemata WHERE schema_name = ? LIMIT 1',
                    [$database]
                );
                if (!empty($check)) {
                    return $this->error(lang('install/database_name_haved'));
                }
            }
            // 创建数据库
            $dbQuoted = '`' . str_replace('`', '``', $database) . '`';
            try {
                $db_connect->execute("CREATE DATABASE IF NOT EXISTS {$dbQuoted} DEFAULT CHARACTER SET utf8");
            } catch (\Exception $e) {
                return $this->error($e->getMessage());
            }

            // 验证目标库与覆盖选项成功后才写入连接配置。
            $data['database'] = $database;
            try {
                $this->mkDatabase($data);
            } catch (\Throwable $e) {
                return $this->error(lang('install/write_read_err'));
            }
            return $this->success(lang('install/database_connect_ok'), '');
        } else {
            return $this->error(lang('install/access_denied'));
        }
    }

    /**
     * 第五步：数据库安装
     */
    private function step5()
    {
        $account = \think\facade\Request::post('account');
        $password = \think\facade\Request::post('password');
        $install_dir = \think\facade\Request::post('install_dir');
        $initdata = \think\facade\Request::post('initdata');

        // 第 4 步已把凭据写进 .env,本请求(新的一次 HTTP)在 App 初始化时已把它读进 env(),
        // 所以这里直接取运行期生效的连接配置即可,不再 include 那个没人加载的 database.php。
        $config = (array)config('database.connections.mysql');
        if (empty($config['hostname']) || empty($config['database']) || empty($config['username'])) {
            return $this->error(lang('install/please_test_connect'));
        }
        if (empty($account) || empty($password)) {
            return $this->error(lang('install/please_input_admin_name_pass'));
        }

        $rule = [
            'account|'.lang('install/admin_name') => 'require|alphaNum',
            'password|'.lang('install/admin_pass') => 'require|length:6,20',
        ];
        $vld = (new \think\Validate())->rule($rule);
        if (!$vld->check(['account' => $account, 'password' => $password])) {
            return $this->error($vld->getError());
        }
        if(empty($install_dir)) {
            $install_dir='/';
        }
        $config_new = config('maccms');
        $config_new['app']['cache_flag'] = bin2hex(random_bytes(5));
        $config_new['app']['lang'] = session('lang') ?: 'zh-cn';

        $config_new['api']['vod']['status'] = 0;
        $config_new['api']['art']['status'] = 0;

        $config_new['interface']['status'] = 0;
        $config_new['interface']['pass'] = mac_get_rndstr(16);
        if (!isset($config_new['app']['api_jwt_secret']) || strlen(trim((string)$config_new['app']['api_jwt_secret'])) < 32) {
            $config_new['app']['api_jwt_secret'] = mac_get_rndstr(32);
        }
        $config_new['site']['install_dir'] = $install_dir;

        // 配置写入须通过临时文件回读校验,不能仅检查无返回值的 mac_arr2file。
        $installer = new \app\common\util\Installer();
        try {
            $installer->writeMaccmsConfig($config_new);
        } catch (\Throwable $e) {
            return $this->error(lang('write_err_config'));
        }

        // 导入失败或缺少 SQL 源文件时不得继续创建管理员和写安装锁。
        try {
            $installer->importSqlFile(APP_PATH . 'install/sql/install.sql', $config['prefix']);
            if ($initdata === '1') {
                $installer->importSqlFile(APP_PATH . 'install/sql/initdata.sql', $config['prefix']);
            }
        } catch (\Throwable $e) {
            return $this->error(lang('install/sql_err'));
        }

        // 注册管理员账号
        $data = [
            'admin_name' => $account,
            'admin_pwd' => $password,
            'admin_status' =>1,
        ];
        try {
            $res = (new \app\common\model\Admin())->saveData($data);
        } catch (\Throwable $e) {
            return $this->error(lang('install/admin_name_err'));
        }
        if ((int)($res['code'] ?? 0) !== 1) {
            return $this->error(lang('install/admin_name_err').'：'.($res['msg'] ?? ''));
        }
        try {
            (new \app\common\util\Installer())->writeLock();
        } catch (\Throwable $e) {
            return $this->error(lang('install/write_read_err'));
        }

        // 获取站点根目录
        $root_dir = request()->baseFile();
        $root_dir  = preg_replace(['/install.php$/'], [''], $root_dir);
        return $this->success(lang('install/is_ok'), $root_dir.'admin.php');
    }

    /**
     * 环境检测
     */
    private function checkNnv()
    {
        $items = [
            'os'      => [lang('install/os'), lang('install/not_limited'), 'Windows/Unix', PHP_OS, 'ok'],
            'php'     => [lang('install/php'), '8.3', 'PHP 8.3 / 8.4', PHP_VERSION, 'ok'],
        ];
        if (version_compare(PHP_VERSION, '8.3.0', '<') || version_compare(PHP_VERSION, '8.5.0', '>=')) {
            $items['php'][4] = 'no';
            session('install_error', true);
        }
        return $items;
    }

    /**
     * 目录权限检查
     */
    private function checkDir()
    {
        $items = [
            // 凭据的唯一事实源是根目录 .env(TP8 的 config/database.php 一律取自 env()),
            // 所以这里检查的是【根目录可写】而不是那两个已删除的 TP5 死文件
            // (application/database.php / route.php,TP8 从不加载,继续检查它们
            //  只会让全新代码树的安装器在第一步就报"文件不存在"而卡死)。
            ['dir', '.', lang('install/read_and_write'), lang('install/read_and_write'), 'ok'],
            ['dir', './application/extra', lang('install/read_and_write'), lang('install/read_and_write'), 'ok'],
            ['dir', './application/data/backup', lang('install/read_and_write'), lang('install/read_and_write'), 'ok'],
            ['dir', './application/data/update', lang('install/read_and_write'), lang('install/read_and_write'), 'ok'],
            ['dir', './runtime', lang('install/read_and_write'), lang('install/read_and_write'), 'ok'],
            ['dir', './upload', lang('install/read_and_write'), lang('install/read_and_write'), 'ok'],
        ];
        $root = dirname(rtrim(APP_PATH, '/\\'));
        foreach ($items as &$v) {
            $path = $root . DIRECTORY_SEPARATOR . ltrim($v[1], './');
            if (!is_writable($path)) {
                $v[3] = lang(is_dir($path) ? 'install/not_writable' : 'install/not_found');
                $v[4] = 'no';
                session('install_error', true);
            }
        }
        return $items;
    }

    /**
     * 函数及扩展检查
     */
    private function checkFunc()
    {
        $requirements = [
            'PDO' => 'class',
            'pdo_mysql' => 'extension', 'zip' => 'extension', 'fileinfo' => 'extension',
            'curl' => 'extension', 'xml' => 'extension', 'dom' => 'extension',
            'gd' => 'extension', 'imagick' => 'extension', 'iconv' => 'extension', 'json' => 'extension',
            'mbstring' => 'extension', 'openssl' => 'extension',
            'file_get_contents' => 'function', 'mb_strlen' => 'function',
        ];
        $items = [];
        foreach ($requirements as $name => $kind) {
            $supported = match ($kind) {
                'class' => class_exists($name),
                'extension' => extension_loaded($name),
                default => function_exists($name),
            };
            if ($name === 'imagick' && $supported) {
                $version = (string)phpversion('imagick');
                $supported = version_compare($version, '3.8.1', '>=') && version_compare($version, '4.0.0', '<');
            }
            $items[] = [$name, lang($supported ? 'install/support' : 'install/not_support'),
                $supported ? 'yes' : 'no', lang('install/' . ($kind === 'extension' ? 'model' : $kind))];
            if (!$supported) {
                session('install_error', true);
            }
        }

        return $items;
    }

    /**
     * 生成数据库配置文件
     */
    private function mkDatabase(array $data)
    {
        // TP8 的 config/database.php 各字段一律取自 env(),框架【不会】加载
        // application/database.php。历史上这里把扁平的 TP5 结构写进那个文件,
        // 谁都不读 —— 于是第 5 步导 install.sql 时默认连接仍是空账号,
        // 报 "Access denied for user ''@'localhost'",却把操作者指向 install.sql。
        // install.lock 因此永远写不出来,浏览器安装器根本走不完。
        // 改为与 CLI 安装器(php think site:install)同一条路径:写根目录 .env。
        $installer = new \app\common\util\Installer();
        $dbConfig  = $installer->buildDbConfig([
            'hostname' => $data['hostname'] ?? '',
            'hostport' => $data['hostport'] ?? '',
            'database' => $data['database'] ?? '',
            'username' => $data['username'] ?? '',
            'password' => $data['password'] ?? '',
            'prefix'   => $data['prefix']   ?? '',
            'charset'  => $data['charset']  ?? 'utf8mb4',
        ]);

        $installer->writeDbConfig($dbConfig);

        // 本进程后续步骤(建库/建表)也要立刻用上新凭据。
        // 注意 Config::set 的第二参数是【配置组名】,不解析点号路径,
        // 必须整组取出、改嵌套、再整组写回(传 'database.connections.mysql'
        // 只会建出一个名字带点的孤儿组,是空操作)。
        $group = \think\facade\Config::get('database', []);
        $group['connections']['mysql'] = array_merge($group['connections']['mysql'] ?? [], $dbConfig);
        \think\facade\Config::set($group, 'database');
        Db::connect('mysql', true);
    }

}
