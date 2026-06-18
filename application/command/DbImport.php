<?php
namespace app\command;

use app\common\util\DbBackup;
use think\console\Command;
use think\console\Input;
use think\console\input\Option;
use think\console\Output;

/**
 * 从 .sql 文件恢复数据库(复用 mac_parse_sql,支持表前缀替换)。
 *   php think db:import --file=backup.sql [--src-prefix=mac_ --dst-prefix=site1_]
 */
class DbImport extends Command
{
    protected function configure()
    {
        $this->setName('db:import')
            ->setDescription('从 .sql 文件恢复数据库(可选表前缀替换)')
            ->addOption('file', null, Option::VALUE_REQUIRED, '【必填】.sql 文件路径')
            ->addOption('src-prefix', null, Option::VALUE_OPTIONAL, '源前缀(配合 --dst-prefix 做替换)', '')
            ->addOption('dst-prefix', null, Option::VALUE_OPTIONAL, '目标前缀', '')
            ->setHelp('恢复会执行文件内的 DROP/CREATE/INSERT;请确认目标库正确。');
    }

    protected function execute(Input $input, Output $output)
    {
        $file = trim((string)$input->getOption('file'));
        if ($file === '') {
            $output->writeln('<error>--file 必填</error>');
            return 2;
        }
        if (!is_file($file)) {
            $output->writeln("<error>文件不存在:{$file}</error>");
            return 2;
        }

        $map = [];
        $src = trim((string)$input->getOption('src-prefix'));
        $dst = trim((string)$input->getOption('dst-prefix'));
        if ($src !== '' && $dst !== '') {
            $map = [$src => $dst];
        }

        try {
            $n = (new DbBackup())->import($file, $map);
        } catch (\Exception $e) {
            $output->writeln('<error>' . $e->getMessage() . '</error>');
            return 6;
        }

        $output->writeln('<info>✔ 恢复完成</info>');
        $output->writeln("  执行语句 : {$n}");
        return 0;
    }
}
