<?php
namespace app\command;

use think\Config;
use think\console\Command;
use think\console\Input;
use think\console\input\Argument;
use think\console\input\Option;
use think\console\Output;
use think\Db;

/**
 * 跨表/字段搜索替换(换域名、改路径、批量改文案),WP-CLI `search-replace` 的对应物。
 *   php think db:search-replace OLD NEW [--dry-run] [--tables=mac_vod,mac_art]
 *
 * 说明:对当前前缀下所有文本字段执行 REPLACE。REPLACE 区分大小写;maccms 多为明文/JSON
 *      存储,不处理 PHP 序列化串(maccms 基本不用);--dry-run 先看影响行数,确认再执行。
 */
class DbSearchReplace extends Command
{
    protected function configure()
    {
        $this->setName('db:search-replace')
            ->setDescription('跨表文本字段搜索替换(换域名/改路径用),支持 --dry-run')
            ->addArgument('search', Argument::REQUIRED, '被替换的字符串')
            ->addArgument('replace', Argument::REQUIRED, '替换为的字符串')
            ->addOption('tables', null, Option::VALUE_OPTIONAL, '限定表(逗号分隔;缺省=当前前缀全部表)', '')
            ->addOption('dry-run', null, Option::VALUE_NONE, '只统计将影响的行数,不实际修改')
            ->setHelp("示例(先演练再执行):\n  php think db:search-replace http://old.com http://new.com --dry-run\n  php think db:search-replace http://old.com http://new.com");
    }

    protected function execute(Input $input, Output $output)
    {
        $search  = (string)$input->getArgument('search');
        $replace = (string)$input->getArgument('replace');
        $dry     = (bool)$input->getOption('dry-run');
        if ($search === '') {
            $output->writeln('<error>search 不能为空</error>');
            return 2;
        }

        $prefix = (string)Config::get('database.prefix');
        $only = [];
        if (trim((string)$input->getOption('tables')) !== '') {
            $only = array_values(array_filter(array_map('trim', explode(',', $input->getOption('tables')))));
        }

        // 发现文本型字段
        try {
            $cols = Db::query(
                "SELECT TABLE_NAME AS t, COLUMN_NAME AS c FROM information_schema.columns
                 WHERE table_schema = DATABASE()
                   AND DATA_TYPE IN ('char','varchar','text','tinytext','mediumtext','longtext')
                   AND TABLE_NAME LIKE ?
                 ORDER BY TABLE_NAME",
                [str_replace('_', '\\_', $prefix) . '%']
            );
        } catch (\Exception $e) {
            $output->writeln('<error>读取表结构失败(站点是否已安装?):' . $e->getMessage() . '</error>');
            return 4;
        }

        $totalRows = 0;
        $byTable = [];
        foreach ($cols as $row) {
            $t = $row['t'];
            $c = $row['c'];
            if (!empty($only) && !in_array($t, $only, true)) {
                continue;
            }
            $tq = '`' . str_replace('`', '``', $t) . '`';
            $cq = '`' . str_replace('`', '``', $c) . '`';
            try {
                if ($dry) {
                    $r = Db::query("SELECT COUNT(*) AS n FROM {$tq} WHERE INSTR({$cq}, ?) > 0", [$search]);
                    $n = (int)($r[0]['n'] ?? 0);
                } else {
                    $n = (int)Db::execute("UPDATE {$tq} SET {$cq} = REPLACE({$cq}, ?, ?) WHERE INSTR({$cq}, ?) > 0", [$search, $replace, $search]);
                }
            } catch (\Exception $e) {
                $output->writeln("<error>{$t}.{$c} 处理失败:" . $e->getMessage() . '</error>');
                return 6;
            }
            if ($n > 0) {
                $byTable[$t] = ($byTable[$t] ?? 0) + $n;
                $totalRows += $n;
            }
        }

        $verb = $dry ? '将影响' : '已修改';
        foreach ($byTable as $t => $n) {
            $output->writeln("  {$t}: {$verb} {$n} 行");
        }
        if ($dry) {
            $output->writeln("<comment>✔ 演练:{$verb} {$totalRows} 行(去掉 --dry-run 实际执行)</comment>");
        } else {
            $output->writeln("<info>✔ 完成:{$verb} {$totalRows} 行</info>");
        }
        return 0;
    }
}
