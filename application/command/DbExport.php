<?php
namespace app\command;

use app\common\util\DbBackup;
use think\facade\Config;
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
            ->addOption('porcelain', null, Option::VALUE_NONE, '仅输出生成的文件路径(便于脚本)')
            ->setHelp('备份开发/测试库;大库建议用 mysqldump。');
    }

    protected function execute(Input $input, Output $output)
    {
        $backup = new DbBackup();
        // TP8 只有 database.connections.<name>.prefix,扁平的 database.prefix 恒为 null。
        // 退化成 '' 会让 listTables 的前缀过滤整体失效 → 把同库里其它应用的表
        // 一并导进备份,之后 db:import 的 DROP TABLE + CREATE 会连带清掉它们。
        $prefix = (string)\think\facade\Db::connect()->getConfig('prefix');
        if ($prefix === '') {
            $output->writeln('<error>表前缀解析为空,拒绝按前缀导出(否则会把整库所有表都导出来)。'
                . '请检查 .env 的 DB_PREFIX,或用 --tables 显式指定要导出的表。</error>');
            return 2;
        }

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
            // 默认写到 application/data/backup/(该目录受 application/.htaccess `deny from all`
            // 保护,不会被 HTTP 下载);避免把含数据/口令哈希的 .sql 落到 Web 可读路径。
            $file = APP_PATH . 'data/backup/' . date('Ymd-His') . '.sql';
        }
        // 确保目标目录存在(显式 --file 指向不存在目录时也兜底)
        $pdir = dirname($file);
        if ($pdir !== '' && !is_dir($pdir)) {
            @mkdir($pdir, 0755, true);
        }

        try {
            $r = $backup->export($tables, $file);
        } catch (\Exception $e) {
            $output->writeln('<error>' . $e->getMessage() . '</error>');
            return 6;
        }

        if ($input->getOption('porcelain')) {
            $output->writeln($file);
            return 0;
        }
        $output->writeln('<info>✔ 导出完成</info>');
        $output->writeln("  表数 : {$r['tables']}    行数 : {$r['rows']}");
        $output->writeln("  文件 : {$file}");
        return 0;
    }
}
