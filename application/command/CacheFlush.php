<?php
namespace app\command;

use app\common\util\Dir;
use think\console\Command;
use think\console\Input;
use think\console\input\Option;
use think\console\Output;

/**
 * 清空运行时缓存(改完代码 / 调试时一键清)。
 *   php think cache:flush [--with-log]
 */
class CacheFlush extends Command
{
    protected function configure()
    {
        $this->setName('cache:flush')
            ->setDescription('清理 runtime/cache、temp（可选 log），并尝试重置当前 CLI 的 OPcache')
            ->addOption('with-log', null, Option::VALUE_NONE, '同时清空 runtime/log')
            ->setHelp('清理 runtime/{cache,temp}(加 --with-log 时含 log)。清理失败返回非零退出码；OPcache 重置仅针对当前 PHP CLI。');
    }

    protected function execute(Input $input, Output $output)
    {
        $dirs = ['cache', 'temp'];
        if ($input->getOption('with-log')) {
            $dirs[] = 'log';
        }
        $failed = false;
        foreach ($dirs as $d) {
            $path = RUNTIME_PATH . $d . '/';
            $entry = rtrim($path, '/\\');
            clearstatcache(true, $entry);
            $link = is_link($entry);
            if (!file_exists($entry) && !$link) {
                $output->writeln("  跳过(不存在) runtime/{$d}");
                continue;
            }
            try { $removed = Dir::delDir($path); }
            catch (\Throwable $error) { $removed = false; }
            if ($removed) {
                $output->writeln($link ? "  已移除 runtime/{$d} 的符号链接，目标目录未改动" : "  已清空 runtime/{$d}");
            } else {
                $failed = true;
                $output->writeln("<error>  清理失败 runtime/{$d}，请检查目录权限和链接配置</error>");
            }
        }
        if (function_exists('opcache_reset')) {
            try { $reset = @opcache_reset(); }
            catch (\Throwable $error) { $reset = false; }
            $output->writeln($reset ? '  已请求重置当前 PHP CLI 的 OPcache' : '  当前 PHP CLI 的 OPcache 不可重置或未启用');
        }
        $output->writeln($failed ? '<error>运行目录清理未全部完成</error>' : '<info>运行目录清理完成</info>');
        return $failed ? 1 : 0;
    }
}
