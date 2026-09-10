<?php
/** Real identity/metadata models and isolated files; admin/page shells never bootstrap the app. */
namespace app\admin\controller { class Base {} }
namespace app\index\controller {
    class Base { public function fetch($template) { return $template; } }
}
namespace {
    require dirname(__DIR__, 2).'/vendor/autoload.php';
    require __DIR__.'/security_audit_test_helpers.php';
    use think\facade\Db;

    function lang($key, $vars = []) { return $key; }
    function config($key, $default = null) { return \think\facade\Config::get($key, $default); }
    function request() { return \think\Container::getInstance()->make('request'); }
    function json($data, $code = 200) { return new \think\response\Json(new \think\Cookie(request()), $data, $code); }
    function cookie($key, $value = null, $options = []) {
        if (func_num_args() === 1) { return $GLOBALS['upload_cookies'][$key] ?? null; }
        $GLOBALS['upload_cookies'][$key] = $value;
    }
    function session($key, $value = null) {
        if (func_num_args() === 1) { return $GLOBALS['upload_session'][$key] ?? null; }
        $GLOBALS['upload_session'][$key] = $value;
    }
    function mac_validate($name) { $class = 'app\\common\\validate\\'.$name; return new $class(); }
    function mac_mkdirss($path) { return mkdir($path, 0777, true); }
    class UploadIdentityCache {
        public function get($key, $default = null) {
            return [1=>['group_id'=>1, 'group_name'=>'guest'], 2=>['group_id'=>2, 'group_name'=>'member']];
        }
    }
    class UploadIdentityRequest extends \think\Request {
        public function file(string $name = '') {
            $file = parent::file($name);
            if ($file instanceof \think\file\UploadedFile) {
                // CLI files lack HTTP upload provenance. Set only the framework's explicit test flag;
                // keep real Request parsing, errors, UploadedFile validation and filesystem move behavior.
                (new \ReflectionProperty(\think\file\UploadedFile::class, 'test'))->setValue($file, true);
            }
            return $file;
        }
    }
    $mysql = getenv('UPLOAD_AUDIT_MYSQL') === '1';
    $configuration = ['default'=>'upload', 'auto_timestamp'=>false, 'connections'=>['upload'=>[
        'type'=>$mysql ? 'mysql' : 'sqlite', 'database'=>$mysql ? 'maccms_audit_upload' : ':memory:',
        'prefix'=>'upload_audit_', 'hostname'=>getenv('UPLOAD_AUDIT_HOST') ?: '127.0.0.1',
        'username'=>'root', 'password'=>getenv('UPLOAD_AUDIT_PASSWORD') ?: '',
        'charset'=>'utf8mb4', 'trigger_sql'=>false, 'fields_cache'=>false,
    ]]];
    $manager = new \think\DbManager();
    $manager->setConfig($configuration);
    $config = new \think\Config();
    $config->set($configuration, 'database');
    $config->set(['site'=>['install_dir'=>'/'], 'upload'=>['mode'=>'local', 'watermark'=>0, 'thumb'=>0]], 'maccms');
    \think\Container::getInstance()->instance('think\\DbManager', $manager);
    \think\Container::getInstance()->instance('config', $config);
    \think\Container::getInstance()->instance('cache', new UploadIdentityCache());
    $GLOBALS['config'] = ['app'=>['cache_flag'=>'upload-identity', 'api_jwt_enabled'=>'1',
        'api_jwt_secret'=>str_repeat('fixture-', 8), 'api_jwt_iss'=>'upload-identity'],
        'user'=>['portrait_status'=>'1', 'portrait_size'=>'30x20']];

    if ($mysql) {
        $ddl = file_get_contents(dirname(__DIR__, 2).'/application/install/sql/install.sql');
        Db::execute("SET SESSION sql_mode=''");
        foreach (['user', 'group', 'admin', 'annex'] as $table) {
            if (!preg_match('/CREATE TABLE `mac_'.$table.'` \([\s\S]*?\) ENGINE[^;]*;/', $ddl, $match)) {
                throw new \RuntimeException('Upload schema missing');
            }
            Db::execute('DROP TABLE IF EXISTS upload_audit_'.$table);
            Db::execute(str_replace('`mac_'.$table.'`', '`upload_audit_'.$table.'`', $match[0]));
        }
    } else {
        Db::execute('CREATE TABLE upload_audit_user (user_id INTEGER PRIMARY KEY, user_name TEXT, user_random TEXT,
            user_status INTEGER DEFAULT 1, group_id TEXT DEFAULT "2", user_portrait TEXT DEFAULT "", user_points INTEGER DEFAULT 0)');
        Db::execute('CREATE TABLE upload_audit_group (group_id INTEGER PRIMARY KEY, group_name TEXT)');
        Db::execute('CREATE TABLE upload_audit_admin (admin_id INTEGER PRIMARY KEY, admin_name TEXT,
            admin_pwd TEXT, admin_status INTEGER DEFAULT 1, admin_auth TEXT)');
        Db::execute('CREATE TABLE upload_audit_annex (annex_id INTEGER PRIMARY KEY AUTOINCREMENT, annex_time INTEGER,
            annex_file TEXT, annex_size INTEGER, annex_type TEXT)');
    }
    $temporary = audit_temp_dir('upload-identity');
    $originalCwd = getcwd();
    define('ROOT_PATH', $temporary.'/');
    define('MAC_PATH', '/');
    define('ENTRANCE', getenv('UPLOAD_AUDIT_ENTRANCE') === 'admin' || ($argv[1] ?? '') === 'admin' ? 'admin' : 'index');
    chdir($temporary);
    register_shutdown_function(static function () use ($temporary, $originalCwd): void {
        try {
            // CLI-server restores its working directory before shutdown callbacks.
            chdir($temporary);
            if (isset($GLOBALS['upload_identity_before_cleanup'])) { ($GLOBALS['upload_identity_before_cleanup'])(); }
        } finally {
            chdir($originalCwd);
            if (is_dir($temporary)) { audit_remove_temp($temporary); }
        }
    });
    mkdir('upload');
    $canvas = imagecreatetruecolor(40, 30);
    imagefill($canvas, 0, 0, imagecolorallocate($canvas, 32, 180, 240));
    imagepng($canvas, 'source.png');
    foreach ([1, 2, 4294967295] as $id) {
        mkdir('upload/user/'.($id % 10), 0777, true);
        imagejpeg($canvas, 'upload/user/'.($id % 10).'/'.$id.'.jpg');
        Db::name('User')->insert(['user_id'=>$id, 'user_name'=>'fixture'.$id, 'user_random'=>'upload-random-'.$id,
            'user_status'=>1, 'group_id'=>'2', 'user_portrait'=>'upload/user/'.($id % 10).'/'.$id.'.jpg']);
    }
    Db::name('Admin')->insert(['admin_id'=>2, 'admin_name'=>'editor', 'admin_pwd'=>'fixture-hash', 'admin_auth'=>',upload/upload,']);
    Db::name('Admin')->insert(['admin_id'=>1, 'admin_name'=>'super', 'admin_pwd'=>'fixture-super', 'admin_auth'=>'']);
    $GLOBALS['user'] = ['user_id'=>1];
    $GLOBALS['upload_cookies'] = $GLOBALS['upload_session'] = [];

    function uploadIdentityRequest(array $parameters = [], string $method = 'POST', bool $file = true, array $headers = []): void {
        $GLOBALS['upload_session']['__csrf_token__'] = 'upload-identity-csrf';
        $headers = array_merge(['X-CSRF-Token'=>'upload-identity-csrf'], $headers);
        $request = (new UploadIdentityRequest())->withServer(['REQUEST_METHOD'=>$method, 'REQUEST_TIME'=>time()])->withHeader($headers);
        $request = match ($method) {
            'GET' => $request->withGet($parameters),
            'POST' => $request->withPost($parameters),
            default => $request->withHeader(['content-type'=>'application/x-www-form-urlencoded'])
                ->withInput(http_build_query($parameters)),
        };
        if ($file) {
            copy('source.png', 'incoming.png');
            $request->withFiles(['file'=>['tmp_name'=>ROOT_PATH.'incoming.png', 'name'=>'client.PNG',
                'type'=>'image/png', 'error'=>UPLOAD_ERR_OK, 'size'=>filesize('incoming.png')]]);
        }
        \think\Container::getInstance()->instance('request', $request);
    }
    function uploadIdentityMember(int $id = 1): void {
        $name = 'fixture'.$id;
        $GLOBALS['upload_cookies'] = ['user_id'=>(string)$id, 'user_name'=>$name,
            'user_check'=>md5('upload-random-'.$id.'-'.$name.'-'.$id.'-')];
    }
    function uploadIdentityAdmin(string $permissions = ',upload/upload,', int $id = 2): void {
        Db::name('Admin')->where('admin_id', $id)->update(['admin_auth'=>$permissions]);
        $GLOBALS['upload_session'] = ['admin_auth'=>'1', 'admin_info'=>Db::name('Admin')->find($id)];
    }
    function uploadIdentitySnapshot(): array {
        $files = [];
        $iterator = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator('upload', \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::SELF_FIRST);
        foreach ($iterator as $entry) { $files[$entry->getPathname()] = $entry->isDir() ? 'directory' : hash_file('sha256', $entry->getPathname()); }
        ksort($files);
        return [Db::name('User')->order('user_id')->select()->toArray(), Db::name('Annex')->order('annex_id')->select()->toArray(), $files];
    }
    function uploadIdentityController(string $which): array {
        $class = $which === 'admin' ? 'app\\admin\\controller\\Upload' : 'app\\index\\controller\\User';
        $controller = (new \ReflectionClass($class))->newInstanceWithoutConstructor();
        $result = $which === 'admin' ? $controller->upload() : $controller->portrait();
        return $result instanceof \think\response\Json ? $result->getData() : $result;
    }
    function uploadIdentityPath(array $result): string {
        return ltrim(explode('?', $result['file'] ?? $result['data']['file'] ?? '')[0], '/');
    }
    function uploadIdentityDenied(callable $call, string $message): void {
        $before = uploadIdentitySnapshot();
        $hasIncoming = is_file('incoming.png');
        $result = $call();
        check(($result['code'] ?? null) === 0 && uploadIdentitySnapshot() === $before, $message);
        if ($hasIncoming) { check(is_file('incoming.png'), 'Rejected request moved its UploadedFile: '.$message); }
    }
}
