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
        $langs = glob('./application/lang/*.php');
        foreach ($langs as $k => &$v) {
            $v = str_replace(['./application/lang/','.php'],['',''],$v);
        }
        $this->assign('langs', $langs);

        if(in_array(session('lang'),$langs)){
            $lang = session('lang');
            Lang::setLangSet($lang);
            Lang::load('./application/lang/'.$lang.'.php', $lang);
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

                if(!in_array($param['lang'],$langs)) {
                    $param['lang'] = 'zh-cn';
                }
                $lang = $param['lang'];
                Lang::setLangSet($lang);
                Lang::load('./application/lang/'.$lang.'.php', $lang);
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
        $install_dir = $_SERVER["SCRIPT_NAME"];
        $install_dir = mac_substring($install_dir, strripos($install_dir, "/")+1);
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
                'prefix|'.lang('install/database_pre') => 'require|regex:^[a-z0-9]{1,20}[_]{1}',
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
            }catch(\Exception $e){
                $this->error(lang('install/database_connect_err'));
            }

            // 生成数据库配置文件
            $data['database'] = $database;
            self::mkDatabase($data);


            // 不覆盖检测是否已存在数据库
            if (!$cover) {
                $check = $db_connect->query(
                    'SELECT SCHEMA_NAME FROM information_schema.schemata WHERE schema_name = ? LIMIT 1',
                    [$database]
                );
                if (!empty($check)) {
                    $this->success(lang('install/database_name_haved'),'');
                }
            }
            // 创建数据库
            $dbQuoted = '`' . str_replace('`', '``', $database) . '`';
            try {
                $db_connect->execute("CREATE DATABASE IF NOT EXISTS {$dbQuoted} DEFAULT CHARACTER SET utf8");
            } catch (\Exception $e) {
                return $this->error($e->getMessage());
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
        $cofnig_new['app']['cache_flag'] = substr(md5(time()),0,10);
        $cofnig_new['app']['lang'] = session('lang');

        $config_new['api']['vod']['status'] = 0;
        $config_new['api']['art']['status'] = 0;

        $config_new['interface']['status'] = 0;
        $config_new['interface']['pass'] = mac_get_rndstr(16);
        if (!isset($config_new['app']['api_jwt_secret']) || strlen(trim((string)$config_new['app']['api_jwt_secret'])) < 32) {
            $config_new['app']['api_jwt_secret'] = mac_get_rndstr(32);
        }
        $config_new['site']['install_dir'] = $install_dir;

        // 更新程序配置文件
        $res = mac_arr2file(APP_PATH . 'extra/maccms.php', $config_new);
		if ($res === false) {
			return $this->error(lang('write_err_config'));
		}

        // 导入系统初始数据库结构
        $sql_file = APP_PATH.'install/sql/install.sql';
        if (file_exists($sql_file)) {
            $sql = file_get_contents($sql_file);
            $sql_list = mac_parse_sql($sql, 0, ['mac_' => $config['prefix']]);
            if ($sql_list) {
                $sql_list = array_filter($sql_list);
                foreach ($sql_list as $v) {
                    try {
                        Db::execute($v);
                    } catch(\Exception $e) {
                        return $this->error(lang('install/sql_err'). $e);
                    }
                }
            }
        }
        //初始化数据
        if($initdata=='1'){
            $sql_file = APP_PATH.'install/sql/initdata.sql';
            if (file_exists($sql_file)) {
                $sql = file_get_contents($sql_file);
                $sql_list = mac_parse_sql($sql, 0, ['mac_' => $config['prefix']]);
                if ($sql_list) {
                    $sql_list = array_filter($sql_list);
                    foreach ($sql_list as $v) {
                        try {
                            Db::execute($v);
                        } catch(\Exception $e) {
                            return $this->error(lang('install/init_data_err'). $e);
                        }
                    }
                }
            }
        }

        // 注册管理员账号
        $data = [
            'admin_name' => $account,
            'admin_pwd' => $password,
            'admin_status' =>1,
        ];
        $res = (new \app\common\model\Admin())->saveData($data);
        if (!$res['code']>1) {
            return $this->error(lang('install/admin_name_err').'：'.$res['msg']);
        }
        file_put_contents(APP_PATH.'data/install/install.lock', date('Y-m-d H:i:s'));

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
            'php'     => [lang('install/php'), '5.5', '5.5及以上', PHP_VERSION, 'ok'],
        ];
        if ($items['php'][3] < $items['php'][1]) {
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
            ['file', './application/database.php', lang('install/read_and_write'), lang('install/read_and_write'), 'ok'],
            ['file', './application/route.php', lang('install/read_and_write'), lang('install/read_and_write'), 'ok'],
            ['dir', './application/extra', lang('install/read_and_write'), lang('install/read_and_write'), 'ok'],
            ['dir', './application/data/backup', lang('install/read_and_write'), lang('install/read_and_write'), 'ok'],
            ['dir', './application/data/update', lang('install/read_and_write'), lang('install/read_and_write'), 'ok'],
            ['dir', './runtime', lang('install/read_and_write'), lang('install/read_and_write'), 'ok'],
            ['dir', './upload', lang('install/read_and_write'), lang('install/read_and_write'), 'ok'],
        ];
        foreach ($items as &$v) {
            if ($v[0] == 'dir') {
                if(!is_writable($v[1])) {
                    if(is_dir($v[1])) {
                        $v[3] = lang('install/not_writable');
                        $v[4] = 'no';
                    } else {
                        $v[3] = lang('install/not_found');
                        $v[4] = 'no';
                    }
                    session('install_error', true);
                }
            } else {
                if(!is_writable($v[1])) {
                    $v[3] = lang('install/not_writable');
                    $v[4] = 'no';
                    session('install_error', true);
                }
            }
        }
        return $items;
    }

    /**
     * 函数及扩展检查
     */
    private function checkFunc()
    {
        $items = [
            ['pdo', lang('install/support'), 'yes',lang('install/class')],
            ['pdo_mysql', lang('install/support'), 'yes', lang('install/model')],
            ['zip', lang('install/support'), 'yes', lang('install/model')],
            ['fileinfo', lang('install/support'), 'yes', lang('install/model')],
            ['curl', lang('install/support'), 'yes', lang('install/model')],
            ['xml', lang('install/support'), 'yes', lang('install/function')],
            ['file_get_contents', lang('install/support'), 'yes', lang('install/function')],
            ['mb_strlen', lang('install/support'), 'yes', lang('install/function')],
        ];

        if(version_compare(PHP_VERSION,'5.6.0','ge') && version_compare(PHP_VERSION,'5.7.0','lt')){
            $items[] = ['always_populate_raw_post_data',lang('install/support'),'yes',lang('install/config')];
        }

        foreach ($items as &$v) {
            if(('类'==$v[3] && !class_exists($v[0])) || (lang('install/model')==$v[3] && !extension_loaded($v[0])) || (lang('install/function')==$v[3] && !function_exists($v[0])) || (lang('install/config')==$v[3] && ini_get('always_populate_raw_post_data')!=-1)) {
                $v[1] = lang('install/not_support');
                $v[2] = 'no';
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

        try {
            $installer->writeDbConfig($dbConfig);
        } catch (\Exception $e) {
            return $this->error($e->getMessage());
        }

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
