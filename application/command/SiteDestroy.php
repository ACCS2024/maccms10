<?php
namespace app\command;

use app\common\util\Installer;
use think\console\Command;
use think\console\Input;
use think\console\input\Option;
use think\console\Output;

/**
 * 销毁站点的数据库侧资源(开发回收用):删库 + 删应用账号 + 删安装锁。
 * 不删代码目录(由 bin/maccms destroy 负责)。root 口令同 site:install,经 env/stdin。
 *
 *   echo "$ROOT_PASS" | php think site:destroy --db-name=demo --drop-user=demo_app --yes
 */
class SiteDestroy extends Command
{
    protected function configure()
    {
        $this->setName('site:destroy')
            ->setDescription('销毁站点数据库资源(删库/删账号/删锁,开发回收用)')
            ->addOption('db-host', null, Option::VALUE_OPTIONAL, 'MySQL 主机', '127.0.0.1')
            ->addOption('db-port', null, Option::VALUE_OPTIONAL, 'MySQL 端口', '3306')
            ->addOption('root-user', null, Option::VALUE_OPTIONAL, '高权限账号', 'root')
            ->addOption('db-name', null, Option::VALUE_REQUIRED, '【必填】要删除的数据库名')
            ->addOption('drop-user', null, Option::VALUE_OPTIONAL, '同时删除的应用账号', '')
            ->addOption('keep-lock', null, Option::VALUE_NONE, '保留 install.lock(默认删除)')
            ->addOption('yes', null, Option::VALUE_NONE, '跳过二次确认(脚本/CI)')
            ->setHelp('危险操作:会删除整个数据库。请确认 --db-name 正确。');
    }

    protected function execute(Input $input, Output $output)
    {
        $o = function ($k) use ($input) { return $input->getOption($k); };
        $dbName = trim((string)$o('db-name'));
        if ($dbName === '') {
            $output->writeln('<error>--db-name 必填</error>');
            return 2;
        }

        if (!$o('yes')) {
            $output->writeln("<error>将删除数据库 [{$dbName}] 及其数据。请加 --yes 确认执行。</error>");
            return 2;
        }

        $rootPass = getenv('MACCMS_DB_ROOT_PASS');
        if ($rootPass === false) {
            $rootPass = '';
        }
        if ($rootPass === '' && !(function_exists('stream_isatty') && @stream_isatty(STDIN))) {
            $rootPass = rtrim((string)fgets(STDIN), "\r\n");
        }

        $installer = new Installer();
        try {
            $conn = $installer->connect($installer->buildDbConfig([
                'hostname' => $o('db-host'), 'hostport' => $o('db-port'),
                'username' => $o('root-user'), 'password' => $rootPass, 'database' => '',
            ]));
            $installer->dropDatabase($conn, $dbName);
            $output->writeln("  已删除数据库:{$dbName}");
            if (trim((string)$o('drop-user')) !== '') {
                $installer->dropAppUser($conn, trim((string)$o('drop-user')));
                $output->writeln('  已删除应用账号:' . trim((string)$o('drop-user')));
            }
        } catch (\Exception $e) {
            $output->writeln('<error>' . $e->getMessage() . '</error>');
            return 4;
        }

        if (!$o('keep-lock')) {
            $installer->removeLock();
            $output->writeln('  已删除 install.lock');
        }

        $output->writeln('<info>✔ 销毁完成</info>');
        return 0;
    }
}
