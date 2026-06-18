<?php
namespace app\command;

use app\common\util\Installer;
use think\Config;
use think\console\Command;
use think\console\Input;
use think\console\input\Option;
use think\console\Output;

/**
 * 非交互式站点安装命令(WP-CLI 式)
 *
 *   php think site:install --db-name=demo --site-name="我的站点"
 *
 * MySQL root 口令通过环境变量 MACCMS_DB_ROOT_PASS 或标准输入传入,绝不走命令行参数
 * (argv 在 `ps` / shell 历史中可见)。建议用封装脚本 bin/maccms。
 */
class SiteInstall extends Command
{
    protected function configure()
    {
        $this->setName('site:install')
            ->setDescription('一键安装 maccms 站点(建库/导表/写配置/建管理员/锁定)')
            ->addOption('db-host', null, Option::VALUE_OPTIONAL, 'MySQL 主机', '127.0.0.1')
            ->addOption('db-port', null, Option::VALUE_OPTIONAL, 'MySQL 端口', '3306')
            ->addOption('db-name', null, Option::VALUE_REQUIRED, '【必填】新数据库名')
            ->addOption('db-prefix', null, Option::VALUE_OPTIONAL, '表前缀(形如 mac_)', 'mac_')
            ->addOption('db-charset', null, Option::VALUE_OPTIONAL, '建库字符集', 'utf8mb4')
            ->addOption('root-user', null, Option::VALUE_OPTIONAL, '建库用高权限账号', 'root')
            ->addOption('app-user', null, Option::VALUE_OPTIONAL, '应用最小权限账号(默认 <库名>_app)', '')
            ->addOption('app-pass', null, Option::VALUE_OPTIONAL, '应用账号口令(默认随机生成)', '')
            ->addOption('no-app-user', null, Option::VALUE_NONE, '不建专用账号,配置直接用 root(仅限开发)')
            ->addOption('site-name', null, Option::VALUE_REQUIRED, '【必填】站点名称')
            ->addOption('admin-user', null, Option::VALUE_OPTIONAL, '管理员账号', 'admin')
            ->addOption('admin-pass', null, Option::VALUE_OPTIONAL, '管理员口令(默认随机生成并打印)', '')
            ->addOption('with-initdata', null, Option::VALUE_OPTIONAL, '导入演示数据(1/0)', '1')
            ->addOption('install-dir', null, Option::VALUE_OPTIONAL, '站点子目录', '/')
            ->addOption('lang', null, Option::VALUE_OPTIONAL, '语言', 'zh-cn')
            ->addOption('cover', null, Option::VALUE_NONE, '库已存在时复用(不删旧表)')
            ->addOption('fresh', null, Option::VALUE_NONE, '先删除同名库再重建(干净重装,reinstall 使用)')
            ->addOption('force', null, Option::VALUE_NONE, '已安装(存在 install.lock)仍继续')
            ->addOption('porcelain', null, Option::VALUE_NONE, '仅输出一行 JSON 安装结果(便于脚本/CI)')
            ->setHelp(
                "示例:\n" .
                "  echo \"\$ROOT_PASS\" | php think site:install --db-name=demo --site-name=Demo\n" .
                "  MACCMS_DB_ROOT_PASS=secret php think site:install --db-name=demo --site-name=Demo --admin-pass=admin888\n\n" .
                "退出码:0 成功 / 2 参数错 / 3 写入权限 / 4 连接失败 / 5 建库失败 / 6 SQL失败 / 7 已安装"
            );
    }

    protected function execute(Input $input, Output $output)
    {
        $o = function ($k) use ($input) { return $input->getOption($k); };
        $installer = new Installer();

        // 0) 幂等:已装则拒绝(除非 --force)
        if ($installer->isInstalled() && !$o('force')) {
            $output->writeln('<error>站点已安装(存在 install.lock)。如需重装请加 --force,或用 bin/maccms reinstall。</error>');
            return 7;
        }

        // 1) 必填 + 前缀正则校验(与网页安装器一致)
        $dbName   = trim((string)$o('db-name'));
        $prefix   = trim((string)$o('db-prefix'));
        $siteName = trim((string)$o('site-name'));
        if ($dbName === '' || $siteName === '') {
            $output->writeln('<error>--db-name 与 --site-name 必填</error>');
            return 2;
        }
        if (!preg_match('/^[a-z0-9]{1,20}_$/', $prefix)) {
            $output->writeln('<error>--db-prefix 非法(需形如 mac_,小写字母数字结尾下划线)</error>');
            return 2;
        }
        $adminUser = trim((string)$o('admin-user')) ?: 'admin';
        if (!preg_match('/^[A-Za-z0-9]{1,30}$/', $adminUser)) {
            $output->writeln('<error>--admin-user 仅允许字母数字</error>');
            return 2;
        }
        $adminPass = (string)$o('admin-pass');
        if ($adminPass === '') {
            $adminPass = mac_get_rndstr(12);
        } elseif (strlen($adminPass) < 6 || strlen($adminPass) > 20) {
            $output->writeln('<error>--admin-pass 长度需 6~20</error>');
            return 2;
        }

        // 2) root 口令:env > stdin,绝不读 argv
        $rootPass = getenv('MACCMS_DB_ROOT_PASS');
        if ($rootPass === false) {
            $rootPass = '';
        }
        if ($rootPass === '' && !$this->isStdinTty()) {
            $rootPass = rtrim((string)fgets(STDIN), "\r\n");
        }

        // 3) root 连接 + 探活
        try {
            $rootCfg = $installer->buildDbConfig([
                'hostname' => $o('db-host'), 'hostport' => $o('db-port'),
                'username' => $o('root-user'), 'password' => $rootPass,
                'database' => '', 'prefix' => $prefix, 'charset' => $o('db-charset'),
            ]);
            $conn = $installer->connect($rootCfg);
        } catch (\Exception $e) {
            $output->writeln('<error>' . $e->getMessage() . '</error>');
            return 4;
        }

        // 4) 建库(--fresh 先删库重建;否则非 --cover 时检测已存在)
        $fresh = (bool)$o('fresh');
        try {
            if ($fresh) {
                $installer->dropDatabase($conn, $dbName);
            } elseif (!$o('cover') && $installer->databaseExists($conn, $dbName)) {
                $output->writeln("<error>数据库已存在:{$dbName}(复用请加 --cover,干净重装请加 --fresh)</error>");
                return 5;
            }
            $installer->createDatabase($conn, $dbName, $o('db-charset'));
        } catch (\Exception $e) {
            $output->writeln('<error>' . $e->getMessage() . '</error>');
            return 5;
        }

        // 5) 最小权限应用账号
        $appUser = trim((string)$o('app-user'));
        $appPass = (string)$o('app-pass');
        $usingRoot = (bool)$o('no-app-user');
        if ($usingRoot) {
            $appUser = (string)$o('root-user');
            $appPass = $rootPass;
        } else {
            if ($appUser === '') {
                $appUser = substr(preg_replace('/[^a-z0-9_]/', '', strtolower($dbName)), 0, 24) . '_app';
            }
            if ($appPass === '') {
                $appPass = mac_get_rndstr(24);
            }
            try {
                $installer->createAppUser($conn, $dbName, $appUser, $appPass);
            } catch (\Exception $e) {
                $output->writeln('<error>创建应用账号失败:' . $e->getMessage() . '</error>');
                return 5;
            }
        }

        // 6) 写 database.php 并切换本进程默认连接
        try {
            $appCfg = $installer->buildDbConfig([
                'hostname' => $o('db-host'), 'hostport' => $o('db-port'),
                'username' => $appUser, 'password' => $appPass,
                'database' => $dbName, 'prefix' => $prefix, 'charset' => $o('db-charset'),
            ]);
            $installer->writeDbConfig($appCfg);
            Config::set('database', $appCfg); // ★ 单进程关键:后续 Db/model 走新连接
        } catch (\Exception $e) {
            $output->writeln('<error>' . $e->getMessage() . '</error>');
            return 3;
        }

        // 7) 写程序配置(站名/密钥/语言/install_dir)
        try {
            $installer->writeMaccmsConfig([
                'site.site_name'      => $siteName,
                'site.install_dir'    => $o('install-dir') ?: '/',
                'app.cache_flag'      => substr(md5(microtime(true) . mt_rand()), 0, 10),
                'app.lang'            => $o('lang'),
                'app.api_jwt_secret'  => mac_get_rndstr(32),
                'interface.status'    => 0,
                'interface.pass'      => mac_get_rndstr(16),
            ]);
        } catch (\Exception $e) {
            $output->writeln('<error>' . $e->getMessage() . '</error>');
            return 3;
        }

        // 8) 导入 SQL(结构 + 可选演示数据)
        $quiet = (bool)$o('porcelain');
        try {
            $n1 = $installer->importSqlFile(APP_PATH . 'install/sql/install.sql', $prefix);
            if (!$quiet) {
                $output->writeln("  导入结构:{$n1} 条语句");
            }
            if ((string)$o('with-initdata') === '1') {
                $n2 = $installer->importSqlFile(APP_PATH . 'install/sql/initdata.sql', $prefix);
                if (!$quiet) {
                    $output->writeln("  导入演示数据:{$n2} 条语句");
                }
            }
        } catch (\Exception $e) {
            $output->writeln('<error>' . $e->getMessage() . '</error>');
            return 6;
        }

        // 9) 管理员
        try {
            $installer->createAdmin($adminUser, $adminPass);
        } catch (\Exception $e) {
            $output->writeln('<error>' . $e->getMessage() . '</error>');
            return 6;
        }

        // 10) 锁
        try {
            $installer->writeLock();
        } catch (\Exception $e) {
            $output->writeln('<error>' . $e->getMessage() . '</error>');
            return 3;
        }

        // 11) 汇总(口令一次性打印)
        if ($o('porcelain')) {
            $output->writeln(json_encode([
                'site_name'  => $siteName,
                'database'   => $dbName,
                'prefix'     => $prefix,
                'app_user'   => $usingRoot ? $o('root-user') : $appUser,
                'app_pass'   => $usingRoot ? null : $appPass,
                'admin_user' => $adminUser,
                'admin_pass' => $adminPass,
            ], JSON_UNESCAPED_UNICODE));
            return 0;
        }
        $output->writeln('');
        $output->writeln('<info>✔ 安装完成</info>');
        $output->writeln("  站点名称 : {$siteName}");
        $output->writeln("  数据库   : {$dbName}(前缀 {$prefix})");
        if ($usingRoot) {
            $output->writeln('  数据库账号: <comment>root(开发模式,生产请勿如此)</comment>');
        } else {
            $output->writeln("  应用账号 : {$appUser}");
            $output->writeln("  应用口令 : <comment>{$appPass}</comment>(已写入 application/database.php)");
        }
        $output->writeln("  管理员   : <comment>{$adminUser} / {$adminPass}</comment>");
        $output->writeln('  下一步   : 浏览器打开  <站点地址>/admin.php  登录');
        $output->writeln('  调优(可选): 以 root 运行  php think tune --apply  优化并发(PHP/MySQL/Nginx/ulimit)');
        return 0;
    }

    /** 判断 STDIN 是否为终端(交互),非交互(管道)时才尝试读口令 */
    private function isStdinTty()
    {
        if (function_exists('stream_isatty')) {
            return @stream_isatty(STDIN);
        }
        if (function_exists('posix_isatty')) {
            return @posix_isatty(STDIN);
        }
        return false;
    }
}
