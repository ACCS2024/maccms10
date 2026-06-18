<?php
namespace app\command;

use app\common\util\DbBackup;
use think\Config;
use think\console\Command;
use think\console\Input;
use think\console\input\Option;
use think\console\Output;

/**
 * 导出数据库到 .sql 文件(默认导出当前前缀下的全部表)。
 *   php think db:export [--file=backup.sql] [--tables=mac_vod,mac_art]
 */
class DbExport extends Command
{
    protected function configure()
    {
        $this->setName('db:export')
            ->setDescription('导出数据库到 .sql 文件(PDO 实现,无需 mysqldump)')
            ->addOption('file', null, Option::VALUE_OPTIONAL, '输出文件(默认 runtime/backup/<时间>.sql)', '')
            ->addOption('tables', null, Option::VALUE_OPTIONAL, '指定表(逗号分隔;缺省=当前前缀全部表)', '')
            ->setHelp('备份开发/测试库;大库建议用 mysqldump。');
    }

    protected function execute(Input $input, Output $output)
    {
        $backup = new DbBackup();
        $prefix = (string)Config::get('database.prefix');

        try {
            if (trim((string)$input->getOption('tables')) !== '') {
                $tables = array_values(array_filter(array_map('trim', explode(',', $input->getOption('tables')))));
            } else {
                $tables = $backup->listTables($prefix);
            }
        } catch (\Exception $e) {
            $output->writeln('<error>读取表失败(站点是否已安装?):' . $e->getMessage() . '</error>');
            return 4;
        }
        if (empty($tables)) {
            $output->writeln('<error>没有可导出的表</error>');
            return 2;
        }

        $file = trim((string)$input->getOption('file'));
        if ($file === '') {
            $dir = RUNTIME_PATH . 'backup/';
            if (!is_dir($dir)) {
                @mkdir($dir, 0755, true);
            }
            $file = $dir . date('Ymd-His') . '.sql';
        }

        try {
            $r = $backup->export($tables, $file);
        } catch (\Exception $e) {
            $output->writeln('<error>' . $e->getMessage() . '</error>');
            return 6;
        }

        $output->writeln('<info>✔ 导出完成</info>');
        $output->writeln("  表数 : {$r['tables']}    行数 : {$r['rows']}");
        $output->writeln("  文件 : {$file}");
        return 0;
    }
}
