<?php
namespace app\install\controller;
use think\Controller;
use think\Db;
use think\Lang;
use think\Request;

class Index extends Controller
{

    /**
     * 构造方法
     * @access public
     * @param Request $request Request 对象
     */
    public function __construct(Request $request = null)
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
        parent::__construct($request);
    }

    public function index($step = 0)
    {
        $langs = glob('./application/lang/*.php');
        foreach ($langs as $k => &$v) {
            $v = str_replace(['./application/lang/','.php'],['',''],$v);
        }
        $this->assign('langs', $langs);

        if(in_array(session('lang'),$langs)){
            $lang = Lang::range(session('lang'));
            Lang::load('./application/lang/'.$lang.'.php',$lang);
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
                $lang = Lang::range($param['lang']);
                Lang::load('./application/lang/'.$lang.'.php',$lang);
                session('lang',$param['lang']);
                $this->assign('lang',$param['lang']);

                session('install_error', false);
                return $this->fetch('install@/index/index');
                break;
        }
    }

    /**
     * 第二步：环境检测
     * @return mixed
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
     * @return mixed
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
     * @return mixed
     */
    private function step4()
    {
        if ($this->request->isPost()) {
            if (!is_writable(APP_PATH.'database.php')) {
                return $this->error('[app/database.php]'.lang('install/write_read_err'));
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
            $validate = $this->validate($data, $rule);
            if (true !== $validate) {
                return $this->error($validate);
            }
            $cover = $data['cover'];
            unset($data['cover']);
            $config = include APP_PATH.'database.php';
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
            if (!$db_connect->execute("CREATE DATABASE IF NOT EXISTS {$dbQuoted} DEFAULT CHARACTER SET utf8")) {
                return $this->error($db_connect->getError());
            }


            return $this->success(lang('install/database_connect_ok'), '');
        } else {
            return $this->error(lang('install/access_denied'));
        }
    }
    
    /**
     * 第五步：数据库安装
     * @return mixed
     */
    private function step5()
    {
        $account = \think\facade\Request::post('account');
        $password = \think\facade\Request::post('password');
        $install_dir = \think\facade\Request::post('install_dir');
        $initdata = \think\facade\Request::post('initdata');

        $config = include APP_PATH.'database.php';
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
        $validate = $this->validate(['account' => $account, 'password' => $password], $rule);
        if (true !== $validate) {
            return $this->error($validate);
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
        // 导入SQL
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
     * @return array
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
        /*
        $tmp = function_exists('gd_info') ? gd_info() : [];
        if (empty($tmp['GD Version'])) {
            $items['gd'][3] = lang('install/not_installed');
            $items['gd'][4] = 'no';
            session('install_error', true);
        } else {
            $items['gd'][3] = $tmp['GD Version'];
        }
        */
        return $items;
    }
    
    /**
     * 目录权限检查
     * @return array
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
            if ($v[0] == 'dir') {// 文件夹
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
            } else {// 文件
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
     * @return array
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
     * @return array
     */
    private function mkDatabase(array $data)
    {
        // 安全加固(V10):改用 var_export 序列化,杜绝 hostname/database/username/password
        // 等连接参数中的单引号/反斜杠逃逸出字符串、向 database.php 注入任意 PHP。
        $dbConfig = [
            'type'            => 'mysql',
            'hostname'        => (string)($data['hostname'] ?? ''),
            'database'        => (string)($data['database'] ?? ''),
            'username'        => (string)($data['username'] ?? ''),
            'password'        => (string)($data['password'] ?? ''),
            'hostport'        => (string)($data['hostport'] ?? ''),
            'dsn'             => '',
            'params'          => [],
            'charset'         => 'utf8',
            'prefix'          => (string)($data['prefix'] ?? ''),
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
        $code = "<?php\n// 数据库配置(安装器生成)\nreturn " . var_export($dbConfig, true) . ";\n";
        file_put_contents(APP_PATH.'database.php', $code);
        // 判断写入是否成功
        $config = include APP_PATH.'database.php';
        if (empty($config['database']) || $config['database'] != $data['database']) {
            return $this->error('[application/database.php]'.lang('write_err_database'));
            exit;
        }
    }
}