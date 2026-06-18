<?php
namespace app\command;

use think\console\Command;
use think\console\Input;
use think\console\input\Option;
use think\console\Output;

/**
 * 重置后台管理员口令(后台进不去时自救)。
 *   php think admin:reset-password --user=admin [--password=xxxxxx]
 * 不给 --password 则生成强随机口令并打印一次。
 */
class AdminResetPassword extends Command
{
    protected function configure()
    {
        $this->setName('admin:reset-password')
            ->setDescription('重置管理员口令(bcrypt;不给则随机生成并打印)')
            ->addOption('user', null, Option::VALUE_REQUIRED, '【必填】管理员账号')
            ->addOption('password', null, Option::VALUE_OPTIONAL, '新口令(6~20;缺省随机)', '')
            ->setHelp("示例:php think admin:reset-password --user=admin --password=newpass123");
    }

    protected function execute(Input $input, Output $output)
    {
        $user = trim((string)$input->getOption('user'));
        if ($user === '') {
            $output->writeln('<error>--user 必填</error>');
            return 2;
        }
        $pass = (string)$input->getOption('password');
        if ($pass === '') {
            $pass = mac_get_rndstr(12);
        } elseif (strlen($pass) < 6 || strlen($pass) > 20) {
            $output->writeln('<error>--password 长度需 6~20</error>');
            return 2;
        }

        // 显式 common 模型(命令行无当前模块);口令走与网页一致的 bcrypt
        $admin = new \app\common\model\Admin();
        try {
            $row = $admin->where('admin_name', $user)->find();
        } catch (\Exception $e) {
            $output->writeln('<error>数据库访问失败(站点是否已安装?):' . $e->getMessage() . '</error>');
            return 4;
        }
        if (empty($row)) {
            $output->writeln("<error>管理员不存在:{$user}</error>");
            return 2;
        }

        $id = is_array($row) ? ($row['admin_id'] ?? 0) : $row->admin_id;
        $ok = (new \app\common\model\Admin())
            ->where('admin_id', $id)
            ->update(['admin_pwd' => mac_password_hash($pass)]);
        if (false === $ok) {
            $output->writeln('<error>更新失败</error>');
            return 6;
        }

        $output->writeln('<info>✔ 口令已重置</info>');
        $output->writeln("  管理员 : <comment>{$user} / {$pass}</comment>");
        return 0;
    }
}
