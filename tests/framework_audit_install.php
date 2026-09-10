<?php
/**
 * Real installer/controller/CLI logic in disposable directories, with no App initialization.
 * Run as an unprivileged user to verify denied writes. Optional MySQL is restricted to
 * maccms_audit_install; no production configuration is read or changed.
 */
declare(strict_types=1);

namespace app\common\controller {
    // Isolate HTTP rendering and parent bootstrap while exercising the actual installer methods.
    class All {
        public array $assigned = [];
        public function __construct() {}
        public function assign($name, $value) { $this->assigned[$name] = $value; }
        public function fetch($template) { return $template; }
        public function error($message, $url = '') { return ['code'=>0, 'msg'=>$message, 'url'=>$url]; }
        public function success($message, $url = '') { return ['code'=>1, 'msg'=>$message, 'url'=>$url]; }
    }
}
namespace app\install\controller {
    function extension_loaded($name) {
        return $name !== ($GLOBALS['audit_missing_extension'] ?? null) && \extension_loaded($name);
    }
}
namespace {
    require dirname(__DIR__) . '/vendor/autoload.php';
    function config($name, $default = null) { return think\facade\Config::get($name, $default); }
    function lang($name, $vars = []) { return $name; }
    function session($name, $value = null) {
        if (func_num_args() === 1) { return $GLOBALS['audit_session'][$name] ?? null; }
        $GLOBALS['audit_session'][$name] = $value;
    }
    function request() { return think\Container::getInstance()->make('request'); }
    function mac_validate(string $name): think\Validate {
        if ($name === 'Admin' && !empty($GLOBALS['audit_admin_rejected'])) {
            return (new think\Validate())->rule(['admin_name'=>'in:rejectedbyfixture']);
        }
        $class = 'app\\common\\validate\\' . $name;
        return new $class();
    }
    require dirname(__DIR__) . '/application/common.php';
    error_reporting(E_ALL);
    set_error_handler(static function ($severity, $message, $file, $line) {
        if (error_reporting() & $severity) { throw new ErrorException($message, 0, $severity, $file, $line); }
        return false;
    });
    $root = sys_get_temp_dir() . '/maccms-install-audit-' . bin2hex(random_bytes(8)) . '/';
    foreach (['application/extra','application/data/install','application/data/backup','application/data/update','application/install/sql','application/lang','runtime','upload'] as $dir) {
        mkdir($root . $dir, 0700, true);
    }
    define('APP_PATH', $root . 'application/');
    define('BIND_MODULE', 'install');
    file_put_contents(APP_PATH . 'lang/zh-cn.php', '<?php return [];');
    $app = new think\App($root);
    $configuration = new think\Config();
    $configuration->set(['site'=>['site_name'=>'fixture'], 'app'=>['cache_flag'=>'original']], 'maccms');
    think\Container::getInstance()->instance('config', $configuration);
    think\Container::getInstance()->instance('lang', new think\Lang($app));
    class InstallAuditRequest {
        public array $data = [];
        public function post($name = '') { return $name === '' ? $this->data : ($this->data[$name] ?? null); }
        public function param() { return $this->data; }
        public function isPost() { return true; }
        public function baseFile() { return '/fixture/install.php'; }
    }
    $request = new InstallAuditRequest();
    think\Container::getInstance()->instance('request', $request);
    $controller = new app\install\controller\Index();
    $installer = new app\common\util\Installer();
    $checks = 0;
    function installExpect($condition, string $message): void {
        global $checks;
        ++$checks;
        if (!$condition) { throw new RuntimeException($message); }
    }
    function installThrows(callable $operation, string $message): void {
        try { $operation(); } catch (RuntimeException $exception) { installExpect(true, $message); return; }
        installExpect(false, $message);
    }
    function installStep($controller, string $name) {
        return (new ReflectionMethod($controller, $name))->invoke($controller);
    }
    function installRunCommand(array $options): array {
        $command = new app\command\SiteInstall();
        $input = new think\console\Input($options);
        $input->bind($command->getDefinition());
        $output = new think\console\Output('buffer');
        $result = (new ReflectionMethod($command, 'execute'))->invoke($command, $input, $output);
        return [$result, $output->fetch()];
    }
    try {
        $env = installStep($controller, 'checkNnv');
        installExpect($env['php'][1] === '8.3' && $env['php'][4] === 'ok', 'PHP 8.3 and 8.4 must pass the installation baseline');
        $extensions = array_column(installStep($controller, 'checkFunc'), null, 0);
        installExpect($extensions['PDO'][2] === 'yes' && $extensions['xml'][2] === 'yes', 'Translated labels must not determine PDO/XML capability checks');
        installExpect(!in_array('no', array_column($extensions, 2), true), 'All required extensions must pass in the supported runtime');
        $GLOBALS['audit_missing_extension'] = 'xml';
        session('install_error', false);
        $extensions = array_column(installStep($controller, 'checkFunc'), null, 0);
        installExpect($extensions['xml'][2] === 'no' && session('install_error') === true, 'Missing XML must block installation');
        unset($GLOBALS['audit_missing_extension']);
        session('install_error', false);
        installExpect(!in_array('no', array_column(installStep($controller, 'checkDir'), 4), true), 'Directory checks must use APP_PATH instead of the current working directory');
        $controller->index();
        installExpect(session('lang') === 'zh-cn' && $controller->assigned['langs'] === ['zh-cn'], 'Initial language must load from APP_PATH without a lang parameter or repository cwd');

        $cfg = $installer->buildDbConfig(['hostname'=>'test-host','database'=>'test-db','username'=>'test-user','password'=>'test-password']);
        $sentinel = "EXISTING_SETTING = keep\n";
        file_put_contents($root . '.env', $sentinel);
        foreach ([' test-password ', 'false', "quoted'password"] as $invalid) {
            installThrows(fn () => $installer->writeDbConfig(array_replace($cfg, ['password'=>$invalid])), 'Unrepresentable credentials must be rejected');
            installExpect(file_get_contents($root . '.env') === $sentinel, 'Invalid new credentials must preserve the existing .env');
        }
        $installer->writeDbConfig($cfg);
        $loadedEnv = new think\Env();
        $loadedEnv->load($root . '.env');
        installExpect($loadedEnv->get('DB_PASS') === 'test-password' && $loadedEnv->get('DB_NAME') === 'test-db', 'Valid .env must round-trip through actual Think Env');
        installExpect((fileperms($root . '.env') & 0007) === 0, 'Database credentials must not be world-readable');
        $installer->writeMaccmsConfig(['site.site_name'=>'updated']);
        installExpect((include APP_PATH . 'extra/maccms.php')['site']['site_name'] === 'updated', 'Application config overrides must persist');
        $originalConfig = file_get_contents(APP_PATH . 'extra/maccms.php');
        chmod(APP_PATH . 'extra', 0500);
        clearstatcache();
        if (is_writable(APP_PATH . 'extra')) { throw new RuntimeException('Run this regression as an unprivileged user to verify denied writes'); }
        installThrows(fn () => $installer->writeMaccmsConfig(['site.site_name'=>'must-not-persist']), 'Unwritable config must report failure');
        installExpect(file_get_contents(APP_PATH . 'extra/maccms.php') === $originalConfig, 'Failed application config write must preserve its existing content');
        chmod(APP_PATH . 'extra', 0700);
        foreach (['missing.sql'=>null, 'empty.sql'=>'', 'comment.sql'=>"-- no statements\n"] as $file => $sql) {
            if ($sql !== null) { file_put_contents(APP_PATH . 'install/sql/' . $file, $sql); }
            installThrows(fn () => $installer->importSqlFile(APP_PATH . 'install/sql/' . $file, 'audit_'), 'Missing or empty SQL source must fail');
        }
        installExpect(glob($root . '.install-*') === [] && glob(APP_PATH . 'extra/.install-*') === [], 'Configuration failures must not leave temporary files');

        if (getenv('FRAMEWORK_AUDIT_MYSQL') === '1') {
            $password = getenv('FRAMEWORK_AUDIT_PASSWORD') ?: '';
            $cfg = $installer->buildDbConfig([
                'hostname'=>getenv('FRAMEWORK_AUDIT_HOST') ?: '127.0.0.1',
                'username'=>'root', 'password'=>$password, 'database'=>'maccms_audit_install', 'prefix'=>'audit_',
            ]);
            $configuration->set(['default'=>'mysql','auto_timestamp'=>false,'connections'=>['mysql'=>$cfg]], 'database');
            $manager = new think\Db();
            $manager->setConfig($configuration);
            think\Container::getInstance()->instance('think\\DbManager', $manager);
            think\Model::maker(static function ($model) use ($manager) { $model->setOption('db', $manager); $model->isAutoWriteTimestamp(false); });
            $connection = $installer->connect(array_replace($cfg, ['database'=>'']));
            $installer->dropDatabase($connection, 'maccms_audit_install');
            $installer->createDatabase($connection, 'maccms_audit_install');
            file_put_contents($root . '.env', $sentinel);
            $request->data = array_intersect_key($cfg, array_flip(['hostname','hostport','database','username','password','prefix']));
            $request->data['cover'] = '0';
            $result = installStep($controller, 'step4');
            installExpect($result['code'] === 0 && $result['msg'] === 'install/database_name_haved', 'Existing database without cover must fail, not invite step 5');
            installExpect(file_get_contents($root . '.env') === $sentinel, 'Existing database refusal must preserve previous credentials');
            $request->data['cover'] = '1';
            $request->data['prefix'] = 'audit_invalid suffix';
            installExpect(installStep($controller, 'step4')['code'] === 0, 'Prefix validation must reject trailing input after the underscore');
            $request->data['prefix'] = 'audit_';
            installExpect(installStep($controller, 'step4')['code'] === 1, 'Explicit database cover must write usable config');
            installExpect(think\facade\Db::query('SELECT DATABASE() AS current_db')[0]['current_db'] === 'maccms_audit_install', 'Step 4 must switch the live framework connection to the selected database');

            $request->data = ['account'=>'auditadmin','password'=>'audit-password','install_dir'=>'/fixture/','initdata'=>'0'];
            installExpect(installStep($controller, 'step5')['code'] === 0 && !$installer->isInstalled(), 'Missing schema SQL must not create the installation lock');
            $schema = "DROP TABLE IF EXISTS `mac_admin`;\nCREATE TABLE `mac_admin` (`admin_id` INTEGER PRIMARY KEY AUTO_INCREMENT, `admin_name` VARCHAR(32), `admin_pwd` VARCHAR(255), `admin_status` INTEGER, `admin_auth` TEXT);\n";
            file_put_contents(APP_PATH . 'install/sql/install.sql', $schema);
            $request->data['initdata'] = '1';
            installExpect(installStep($controller, 'step5')['code'] === 0 && !$installer->isInstalled(), 'Missing requested demo SQL must not create the installation lock');
            $request->data['initdata'] = '0';
            chmod(APP_PATH . 'extra', 0500);
            $result = installStep($controller, 'step5');
            installExpect($result['code'] === 0 && $result['msg'] === 'write_err_config' && !$installer->isInstalled(), 'Web installation must stop when application configuration cannot be saved');
            chmod(APP_PATH . 'extra', 0700);
            $trigger = "CREATE TRIGGER reject_admin BEFORE INSERT ON `mac_admin` FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'fixture rejected';\n";
            file_put_contents(APP_PATH . 'install/sql/install.sql', $schema . $trigger);
            $result = installStep($controller, 'step5');
            installExpect($result['code'] === 0 && $result['msg'] === 'install/admin_name_err' && !$installer->isInstalled(), 'A database exception while creating the administrator must fail without a lock');
            file_put_contents(APP_PATH . 'install/sql/install.sql', $schema);
            $GLOBALS['audit_admin_rejected'] = true;
            $result = installStep($controller, 'step5');
            installExpect($result['code'] === 0 && str_starts_with($result['msg'], 'install/admin_name_err'), 'A model validation error must stop installation');
            installExpect(!$installer->isInstalled() && think\facade\Db::name('Admin')->count() === 0, 'Administrator failure must not create a lock or administrator');
            $GLOBALS['audit_admin_rejected'] = false;
            $result = installStep($controller, 'step5');
            installExpect($result['code'] === 1 && $installer->isInstalled(), 'Successful web installation must create the lock');
            installExpect($result['url'] === '/fixture/admin.php', 'Successful web installation must point at the installed admin entry');
            $admin = think\facade\Db::name('Admin')->where('admin_name', 'auditadmin')->find();
            installExpect(password_verify('audit-password', $admin['admin_pwd']), 'Web installation must store a valid password hash');
            $writtenConfig = include APP_PATH . 'extra/maccms.php';
            installExpect($writtenConfig['app']['cache_flag'] !== 'original' && $writtenConfig['app']['lang'] === 'zh-cn', 'Web installation must persist its cache flag and language');

            putenv('MACCMS_DB_ROOT_PASS=' . $password);
            $options = ['--db-host='.$cfg['hostname'], '--db-name=maccms_audit_install', '--site-name=Audit', '--admin-pass=audit-password', '--no-app-user', '--with-initdata=0', '--cover', '--porcelain'];
            installExpect(installRunCommand($options)[0] === 7, 'CLI installation must reject an existing lock');
            $installer->removeLock();
            unlink(APP_PATH . 'install/sql/install.sql');
            installExpect(installRunCommand($options)[0] === 6 && !$installer->isInstalled(), 'CLI missing SQL must return failure without a lock');
            copy(dirname(__DIR__) . '/application/install/sql/install.sql', APP_PATH . 'install/sql/install.sql');
            [$status, $output] = installRunCommand($options);
            installExpect($status === 0 && $installer->isInstalled(), 'CLI must import the actual schema, create an administrator, and lock successfully: ' . $output);
            installExpect(think\facade\Db::name('Admin')->where('admin_name','admin')->count() === 1, 'CLI must persist exactly one administrator');
        }
        echo 'framework_audit_install: ' . $checks . ' checks passed on PHP ' . PHP_VERSION . (getenv('FRAMEWORK_AUDIT_MYSQL') === '1' ? ' / MySQL' : ' / filesystem') . PHP_EOL;
    } catch (Throwable $exception) {
        fwrite(STDERR, get_class($exception) . ': ' . $exception->getMessage() . PHP_EOL . $exception->getTraceAsString() . PHP_EOL);
        $failed = true;
    } finally {
        restore_error_handler();
        chmod(APP_PATH . 'extra', 0700);
        $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
        foreach ($files as $file) {
            if ($file->isDir()) { rmdir($file->getPathname()); } else { unlink($file->getPathname()); }
        }
        rmdir($root);
    }
    exit(empty($failed) ? 0 : 1);
}
