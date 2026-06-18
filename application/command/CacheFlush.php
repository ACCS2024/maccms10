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
            ->setDescription('清空 runtime 缓存(cache/temp,可选 log),并重置 opcache')
            ->addOption('with-log', null, Option::VALUE_NONE, '同时清空 runtime/log')
            ->setHelp('清理 runtime/{cache,temp}(加 --with-log 时含 log),并调用 opcache_reset()。');
    }

    protected function execute(Input $input, Output $output)
    {
        $dirs = ['cache', 'temp'];
        if ($input->getOption('with-log')) {
            $dirs[] = 'log';
        }
        foreach ($dirs as $d) {
            $path = RUNTIME_PATH . $d . '/';
            if (is_dir($path)) {
                Dir::delDir($path);
                $output->writeln("  已清空 runtime/{$d}");
            } else {
                $output->writeln("  跳过(不存在) runtime/{$d}");
            }
        }
        if (function_exists('opcache_reset')) {
            @opcache_reset();
            $output->writeln('  已重置 opcache');
        }
        $output->writeln('<info>✔ 缓存已清空</info>');
        return 0;
    }
}
