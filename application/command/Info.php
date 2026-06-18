<?php
namespace app\command;

use think\Config;
use think\console\Command;
use think\console\Input;
use think\console\input\Option;
use think\console\Output;
use think\Db;

/**
 * 站点 / 环境自检信息(扩展版 doctor)。
 *   php think info [--format=table|json]
 */
class Info extends Command
{
    protected function configure()
    {
        $this->setName('info')
            ->setDescription('站点与环境自检(版本/扩展/安装状态/数据库/可写目录/性能建议)')
            ->addOption('format', null, Option::VALUE_OPTIONAL, '输出格式 table|json', 'table');
    }

    protected function execute(Input $input, Output $output)
    {
        $data = [];

        // 运行环境
        $data['php_version'] = PHP_VERSION;
        $exts = ['pdo_mysql', 'mbstring', 'curl', 'gd', 'zip', 'json', 'redis'];
        $loaded = [];
        foreach ($exts as $e) {
            $loaded[$e] = extension_loaded($e);
        }
        $data['extensions'] = $loaded;
        $data['framework'] = defined('THINK_VERSION') ? ('ThinkPHP ' . THINK_VERSION) : 'ThinkPHP';
        $mac = config('maccms');
        $data['site_name'] = is_array($mac) ? ($mac['site']['site_name'] ?? '') : '';

        // 安装状态
        $data['installed'] = is_file(APP_PATH . 'data/install/install.lock');

        // 数据库
        $db = ['configured' => false, 'connected' => false, 'database' => '', 'prefix' => '', 'tables' => 0, 'admins' => 0];
        $dbcfg = Config::get('database');
        if (!empty($dbcfg['database'])) {
            $db['configured'] = true;
            $db['database'] = $dbcfg['database'];
            $db['prefix'] = $dbcfg['prefix'] ?? '';
            try {
                $rows = Db::query('SELECT COUNT(*) AS c FROM information_schema.tables WHERE table_schema = DATABASE()');
                $db['tables'] = (int)($rows[0]['c'] ?? 0);
                $db['connected'] = true;
                try {
                    $db['admins'] = (int)Db::name('admin')->count();
                } catch (\Exception $e) {
                    $db['admins'] = 0;
                }
            } catch (\Exception $e) {
                $db['error'] = $e->getMessage();
            }
        }
        $data['database'] = $db;

        // 可写目录
        $paths = [
            'runtime'              => RUNTIME_PATH,
            'upload'               => ROOT_PATH . 'upload/',
            'application/extra'    => APP_PATH . 'extra/',
            'application/data'     => APP_PATH . 'data/',
            'application/database.php' => APP_PATH . 'database.php',
        ];
        $writable = [];
        foreach ($paths as $k => $p) {
            $writable[$k] = is_writable($p);
        }
        $data['writable'] = $writable;

        // 性能/环境建议(复用 mac_perf_env_checks)
        $perf = [];
        if (function_exists('mac_perf_env_checks')) {
            try {
                foreach (mac_perf_env_checks() as $c) {
                    $perf[] = ['label' => $c['label'], 'ok' => $c['ok'], 'detail' => $c['detail']];
                }
            } catch (\Throwable $e) {
            }
        }
        $data['perf'] = $perf;

        if (strtolower((string)$input->getOption('format')) === 'json') {
            $output->writeln(json_encode($data, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT));
            return 0;
        }

        // 表格渲染
        $yn = function ($b) { return $b ? '✔' : '✘'; };
        $output->writeln('── 环境 ──');
        $output->writeln("  PHP        : {$data['php_version']}");
        $output->writeln("  框架       : {$data['framework']}");
        $extLine = [];
        foreach ($loaded as $e => $ok) {
            $extLine[] = ($ok ? '' : '!') . $e;
        }
        $output->writeln('  扩展       : ' . implode(' ', $extLine) . '  (! = 缺失)');
        $output->writeln('── 站点 ──');
        $output->writeln('  站点名     : ' . ($data['site_name'] !== '' ? $data['site_name'] : '(未设置)'));
        $output->writeln('  已安装     : ' . $yn($data['installed']));
        $output->writeln('── 数据库 ──');
        if (!$db['configured']) {
            $output->writeln('  未配置(尚未安装)');
        } else {
            $output->writeln("  库名/前缀  : {$db['database']} / {$db['prefix']}");
            $output->writeln('  连接       : ' . $yn($db['connected']) . (isset($db['error']) ? '  ' . $db['error'] : ''));
            $output->writeln("  表数/管理员: {$db['tables']} / {$db['admins']}");
        }
        $output->writeln('── 可写目录 ──');
        foreach ($writable as $k => $ok) {
            $output->writeln('  ' . $yn($ok) . "  {$k}");
        }
        if (!empty($perf)) {
            $output->writeln('── 性能/环境建议 ──');
            foreach ($perf as $c) {
                $output->writeln('  ' . $yn($c['ok']) . "  {$c['label']}: {$c['detail']}");
            }
        }
        return 0;
    }
}
