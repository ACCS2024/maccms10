<?php
namespace app\command;

use think\facade\Config;
use think\console\Command;
use think\console\Input;
use think\console\input\Option;
use think\console\Output;
use think\facade\Db;

/**
 * 主机并发调优:检测 PHP / PHP-FPM / Nginx / MySQL / ulimit / sysctl,按本机 内存·核数 计算建议值,
 * 生成可直接使用的配置片段 + 教程;`--apply` 时把"非破坏性 drop-in"(conf.d / limits.d / sysctl.d)
 * 写入系统(自动备份),其余(Nginx 主配置、FPM 池、MySQL 重启项)给出精确教程。
 *
 *   php think tune                 # 仅检测+生成片段+教程(不动系统)
 *   php think tune --apply         # 额外尝试写入安全 drop-in,失败/找不到则转教程
 *   php think tune --apply --dry-run  # 演练:打印将写哪些,但不真正写
 *
 * 设计原则:绝不就地改写 php.ini / nginx.conf / my.cnf 等主文件;只在 *.d 目录新增独立文件;
 * 不自动重启任何服务(给出 reload/restart 指令)。
 */
class Tune extends Command
{
    protected function configure()
    {
        $this->setName('tune')
            ->setDescription('检测并优化主机并发(PHP/FPM/Nginx/MySQL/ulimit/sysctl);找不到则输出教程')
            ->addOption('apply', null, Option::VALUE_NONE, '尝试写入安全 drop-in(conf.d/limits.d/sysctl.d),自动备份')
            ->addOption('dry-run', null, Option::VALUE_NONE, '配合 --apply:只打印将写入的目标,不实际写')
            ->addOption('out', null, Option::VALUE_OPTIONAL, '配置片段/教程输出目录', '')
            ->addOption('revert', null, Option::VALUE_NONE, '撤销 --apply 写入的系统 drop-in(按账本恢复备份/删除并清理)');
    }

    protected function execute(Input $input, Output $output)
    {
        $apply = (bool)$input->getOption('apply');
        $dry   = (bool)$input->getOption('dry-run');
        $outDir = rtrim(trim((string)$input->getOption('out')) ?: (APP_PATH . 'data/optimize/'), '/') . '/';

        // 撤销:不需检测,直接按账本回滚 --apply 写入的系统改动
        if ($input->getOption('revert')) {
            return $this->doRevert($output, $outDir);
        }

        $d = $this->detect();
        $r = $this->recommend($d);

        $output->writeln('── 主机检测 ──');
        $output->writeln("  内存 {$d['ram_mb']} MB / CPU {$d['cores']} 核 / 当前 nofile {$d['nofile']}");
        $output->writeln('  PHP ' . PHP_VERSION . ' / OPcache ' . ($d['opcache'] ? '开' : '关')
            . ' / FPM ' . ($d['fpm'] ? '检测到' : '未检测到')
            . ' / Nginx ' . ($d['nginx'] ? '检测到' : '未检测到')
            . ' / MySQL ' . ($d['mysql_connected'] ? ('已连接, 缓冲池 ' . $d['mysql_buffer_mb'] . 'MB') : '未连接(用通用建议)'));

        $output->writeln('── 建议值(按本机算)──');
        $output->writeln("  PHP-FPM pm.max_children={$r['fpm_children']} start={$r['fpm_start']} max_spare={$r['fpm_maxspare']} / opcache {$r['opcache_mb']}MB");
        $output->writeln("  MySQL innodb_buffer_pool_size={$r['innodb_bp_mb']}MB max_connections={$r['mysql_maxconn']}");
        $output->writeln("  Nginx worker_connections={$r['nginx_conn']} worker_processes=auto / nofile={$r['nofile']}");

        // 生成配置片段 + 教程(始终,安全)
        if (!is_dir($outDir)) {
            @mkdir($outDir, 0755, true);
        }
        $files = $this->generate($outDir, $d, $r);
        $output->writeln('── 已生成配置片段 + 教程 ──');
        $output->writeln('  目录:' . $outDir . '(受 application/.htaccess 保护)');
        $output->writeln('  教程:' . $outDir . 'README.md');

        // 尝试应用安全 drop-in
        if ($apply) {
            $output->writeln('── 应用 drop-in' . ($dry ? '(--dry-run 演练)' : '') . ' ──');
            $applied = [];
            $manual = [];
            $ledger = [];
            foreach ($this->dropinTargets($d, $r) as $t) {
                $dir = $t['dir'];
                if ($dir === null) {
                    $manual[] = $t['label'] . ':未检测到(' . $t['why'] . ')→ 见教程';
                    continue;
                }
                if (!is_dir($dir) || !is_writable($dir)) {
                    $manual[] = $t['label'] . ":{$dir} 不可写(需 root?)→ 见教程";
                    continue;
                }
                $dst = $dir . '/' . $t['name'];
                if ($dry) {
                    $applied[] = '[演练] 将写 ' . $dst;
                    continue;
                }
                $ts = date('YmdHis');
                $backup = null;
                if (is_file($dst)) {
                    $backup = $dst . '.bak-' . $ts;
                    @copy($dst, $backup);
                }
                if (false !== @file_put_contents($dst, $t['content'])) {
                    $applied[] = '✔ ' . $dst;
                    $ledger[] = ['ts' => $ts, 'path' => $dst, 'backup' => $backup];
                } else {
                    $manual[] = $t['label'] . ":写入失败 {$dst} → 见教程";
                }
            }
            foreach ($applied as $a) {
                $output->writeln('  ' . $a);
            }
            foreach ($manual as $m) {
                $output->writeln('  <comment>手动:' . $m . '</comment>');
            }
            if (!$dry && !empty($ledger)) {
                $lf = $outDir . 'tune-ledger.json';
                $prev = is_file($lf) ? (json_decode((string)file_get_contents($lf), true) ?: []) : [];
                @file_put_contents($lf, json_encode(array_merge($prev, $ledger), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
                $output->writeln('  <info>撤销:运行  php think tune --revert</info>(账本 ' . $lf . ')');
            }
            if (!$dry) {
                $output->writeln('  生效需 reload:php-fpm reload · sysctl --system · 重新登录(ulimit) · 重启 MySQL(谨慎)');
            }
            // 始终手动的项
            $output->writeln('  <comment>手动:Nginx 主配置 / PHP-FPM 池 pm.* / MySQL 重启项 —— 见教程对应片段(风险较高,不自动改)</comment>');
        } else {
            $output->writeln('<comment>提示:加 --apply 尝试自动写入安全 drop-in(失败/找不到自动转教程);Nginx/FPM 池/MySQL 始终走教程。</comment>');
        }

        $output->writeln('<info>✔ tune 完成</info>');
        return 0;
    }

    // ---------------- 检测(纯文件读,无 shell 依赖)----------------

    private function detect()
    {
        $ram = 1024;
        if (is_readable('/proc/meminfo') && preg_match('/MemTotal:\s+(\d+)\s*kB/', file_get_contents('/proc/meminfo'), $m)) {
            $ram = (int)floor($m[1] / 1024);
        }
        $cores = 1;
        if (is_readable('/proc/cpuinfo')) {
            $cores = max(1, substr_count(file_get_contents('/proc/cpuinfo'), "processor\t"));
        }
        $nofile = 1024;
        if (is_readable('/proc/self/limits') && preg_match('/Max open files\s+(\d+)/', file_get_contents('/proc/self/limits'), $m)) {
            $nofile = (int)$m[1];
        }
        // PHP conf.d 候选目录(cli + 推导 fpm + docker 共享)
        $confd = [];
        $scanned = php_ini_scanned_files();
        if ($scanned) {
            $first = trim(explode(',', $scanned)[0]);
            if ($first) {
                $confd[] = dirname($first);
            }
        }
        $extra = [];
        foreach ($confd as $c) {
            $extra[] = str_replace('/cli/', '/fpm/', $c);
            $extra[] = str_replace('/cli/', '/apache2/', $c);
        }
        $extra[] = '/usr/local/etc/php/conf.d';
        foreach ($extra as $e) {
            if (is_dir($e) && !in_array($e, $confd, true)) {
                $confd[] = $e;
            }
        }
        $fpm = false;
        foreach (glob('/etc/php*/fpm', GLOB_ONLYDIR) ?: [] as $x) {
            $fpm = true;
        }
        foreach (glob('/usr/sbin/php-fpm*') ?: [] as $x) {
            $fpm = true;
        }
        $nginx = is_file('/usr/sbin/nginx') || is_file('/usr/bin/nginx') || is_dir('/etc/nginx');

        // MySQL 当前值(需站点已安装且可连)
        $mysqlConnected = false;
        $bufMb = 0;
        try {
            if (Config::get('database.database')) {
                $rows = Db::query("SHOW VARIABLES LIKE 'innodb_buffer_pool_size'");
                if (!empty($rows)) {
                    $bufMb = (int)floor(((int)$rows[0]['Value']) / 1048576);
                    $mysqlConnected = true;
                }
            }
        } catch (\Exception $e) {
        }

        return [
            'ram_mb' => $ram, 'cores' => $cores, 'nofile' => $nofile,
            'confd' => $confd, 'fpm' => $fpm, 'nginx' => $nginx,
            'opcache' => (function_exists('opcache_get_status') && (int)ini_get('opcache.enable') === 1),
            'mysql_connected' => $mysqlConnected, 'mysql_buffer_mb' => $bufMb,
            'mysql_confd' => (is_dir('/etc/mysql/conf.d') ? '/etc/mysql/conf.d' : (is_dir('/etc/my.cnf.d') ? '/etc/my.cnf.d' : null)),
            'sysctld' => (is_dir('/etc/sysctl.d') ? '/etc/sysctl.d' : null),
            'limitsd' => (is_dir('/etc/security/limits.d') ? '/etc/security/limits.d' : null),
        ];
    }

    private function recommend($d)
    {
        $ram = $d['ram_mb'];
        $children = max(8, min(512, (int)floor($ram * 0.55 / 80)));
        $start = max(2, (int)floor($children / 4));
        return [
            'fpm_children' => $children,
            'fpm_start' => $start,
            'fpm_minspare' => $start,
            'fpm_maxspare' => max($start, (int)floor($children / 2)),
            'opcache_mb' => $ram >= 2048 ? 256 : 128,
            'innodb_bp_mb' => max(256, (int)floor($ram * 0.5)),
            'mysql_maxconn' => max(151, min(1000, $children * 2 + 50)),
            'nginx_conn' => 4096,
            'nofile' => 65535,
            // sysctl:取 max(现状, 目标),绝不下调
            'somaxconn' => max($this->sysctl('net/core/somaxconn', 128), 1024),
            'syn_backlog' => max($this->sysctl('net/ipv4/tcp_max_syn_backlog', 256), 2048),
            'netdev_backlog' => max($this->sysctl('net/core/netdev_max_backlog', 1000), 5000),
            'file_max' => max($this->sysctl('fs/file-max', 100000), 1000000),
        ];
    }

    private function sysctl($path, $default)
    {
        $f = '/proc/sys/' . $path;
        return is_readable($f) ? (int)trim(file_get_contents($f)) : $default;
    }

    // ---------------- 生成片段 + 教程 ----------------

    private function generate($dir, $d, $r)
    {
        $files = [];
        $files['php-perf-maccms.ini'] = "; maccms tune — PHP 性能 drop-in(放 PHP conf.d)\n"
            . "opcache.enable=1\nopcache.enable_cli=0\nopcache.memory_consumption={$r['opcache_mb']}\n"
            . "opcache.interned_strings_buffer=16\nopcache.max_accelerated_files=20000\n"
            . "opcache.validate_timestamps=1 ; 生产可设 0(改代码后需 reload)\nopcache.revalidate_freq=60\n"
            . "realpath_cache_size=4096k\nrealpath_cache_ttl=600\nmemory_limit=256M\n"
            . ";opcache.jit=tracing\n;opcache.jit_buffer_size=64M ; PHP8 可选\n";

        $files['fpm-pool-maccms.conf'] = "; 合并进 PHP-FPM 池(如 /etc/php/8.x/fpm/pool.d/www.conf 的 [www] 段)\n"
            . "pm = dynamic\npm.max_children = {$r['fpm_children']}\npm.start_servers = {$r['fpm_start']}\n"
            . "pm.min_spare_servers = {$r['fpm_minspare']}\npm.max_spare_servers = {$r['fpm_maxspare']}\npm.max_requests = 500\n";

        $files['nginx-maccms.conf'] = "# Nginx 调优(按段合并到 nginx.conf;worker_* 不能放 conf.d)\n"
            . "# main:\nworker_processes auto;\nworker_rlimit_nofile {$r['nofile']};\n"
            . "# events:\nevents { worker_connections {$r['nginx_conn']}; multi_accept on; }\n"
            . "# http:\n#   gzip on; keepalive_timeout 30;\n#   fastcgi_buffers 16 16k; fastcgi_buffer_size 32k; fastcgi_read_timeout 120s;\n"
            . "#   (可选)匿名整页缓存 fastcgi_cache,详见 PERFORMANCE_OPTIMIZATION.md\n";

        $files['mysql-maccms.cnf'] = "[mysqld]\n; maccms tune — 注意 innodb_buffer_pool 假设 DB 独占本机;与 Web 同机/共享请下调(如 25%RAM)\n"
            . "innodb_buffer_pool_size = {$r['innodb_bp_mb']}M\ninnodb_log_file_size = 256M\n"
            . "innodb_flush_log_at_trx_commit = 2\ninnodb_flush_method = O_DIRECT\n"
            . "max_connections = {$r['mysql_maxconn']}\ntable_open_cache = 4000\ntmp_table_size = 64M\nmax_heap_table_size = 64M\n";

        $files['limits-maccms.conf'] = "# /etc/security/limits.d/ — 提高打开文件数(需重新登录/重启服务生效)\n"
            . "* soft nofile {$r['nofile']}\n* hard nofile {$r['nofile']}\nroot soft nofile {$r['nofile']}\nroot hard nofile {$r['nofile']}\n";

        $files['sysctl-maccms.conf'] = "# /etc/sysctl.d/ — 网络/文件句柄(sysctl --system 生效)\n"
            . "net.core.somaxconn = {$r['somaxconn']}\nnet.ipv4.tcp_max_syn_backlog = {$r['syn_backlog']}\n"
            . "net.core.netdev_max_backlog = {$r['netdev_backlog']}\nnet.ipv4.ip_local_port_range = 1024 65535\nfs.file-max = {$r['file_max']}\n";

        foreach ($files as $name => $content) {
            @file_put_contents($dir . $name, $content);
        }

        // 教程
        $readme = "# maccms 主机并发调优教程(本机自动生成)\n\n"
            . "检测:内存 {$d['ram_mb']}MB / {$d['cores']} 核 / nofile {$d['nofile']}。以下片段已按本机算好。\n\n"
            . "## 1. PHP(opcache/realpath)\n把 `php-perf-maccms.ini` 放进 PHP 的 conf.d:\n"
            . "- Debian/Ubuntu: `/etc/php/<ver>/fpm/conf.d/` 与 `/etc/php/<ver>/cli/conf.d/`\n"
            . "- 官方 docker 镜像: `/usr/local/etc/php/conf.d/`\n然后 `systemctl reload php<ver>-fpm`(或重启容器)。\n\n"
            . "## 2. PHP-FPM 池并发(最关键)\n编辑 FPM 池(如 `/etc/php/<ver>/fpm/pool.d/www.conf`),按 `fpm-pool-maccms.conf` 设置 `pm.*`,reload php-fpm。\n"
            . "经验:`pm.max_children ≈ 可用内存×0.55 / 单进程~80MB`;本机建议 {$r['fpm_children']}。\n\n"
            . "## 3. Nginx\n按 `nginx-maccms.conf` 合并到 `nginx.conf`(worker_* 在 main/events 段,不能放 conf.d),`nginx -t && nginx -s reload`。\n\n"
            . "## 4. MySQL\n把 `mysql-maccms.cnf` 放进 `/etc/mysql/conf.d/`(或 `/etc/my.cnf.d/`),`systemctl restart mysql`。\n"
            . "⚠️ `innodb_buffer_pool_size`={$r['innodb_bp_mb']}M 假设 **DB 独占本机**;与 Web 同机/虚拟机内存紧张时请下调,避免 OOM。\n\n"
            . "## 5. 打开文件数(ulimit)\n把 `limits-maccms.conf` 放进 `/etc/security/limits.d/`;systemd 服务还需在 unit 里设 `LimitNOFILE={$r['nofile']}`。重新登录/重启服务生效。\n\n"
            . "## 6. 内核(sysctl)\n把 `sysctl-maccms.conf` 放进 `/etc/sysctl.d/`,执行 `sysctl --system`。\n\n"
            . "## 一键(部分)\n`php think tune --apply` 会把第 1/5/6 项与(若存在 `/etc/mysql/conf.d`)第 4 项以 drop-in 方式写入并自动备份;\n"
            . "第 2(FPM 池)/3(Nginx)项需手动(改现有文件,风险较高)。所有改动都**不自动重启服务**。\n";
        @file_put_contents($dir . 'README.md', $readme);
        $files['README.md'] = $readme;
        return $files;
    }

    // 可自动写入的安全 drop-in 目标(*.d 新增独立文件,非破坏性)
    private function dropinTargets($d, $r)
    {
        $g = function ($n) use ($r) { return $this->genOne($n, $r, $d); };
        $targets = [];
        // PHP:写到所有检测到的 conf.d
        if (!empty($d['confd'])) {
            foreach ($d['confd'] as $i => $cd) {
                $targets[] = ['label' => 'PHP conf.d', 'dir' => $cd, 'name' => '99-maccms-perf.ini', 'content' => $g('php'), 'why' => ''];
            }
        } else {
            $targets[] = ['label' => 'PHP conf.d', 'dir' => null, 'name' => '99-maccms-perf.ini', 'content' => $g('php'), 'why' => '未找到 conf.d'];
        }
        $targets[] = ['label' => 'limits.d (nofile)', 'dir' => $d['limitsd'], 'name' => '99-maccms-nofile.conf', 'content' => $g('limits'), 'why' => '无 /etc/security/limits.d'];
        $targets[] = ['label' => 'sysctl.d', 'dir' => $d['sysctld'], 'name' => '99-maccms.conf', 'content' => $g('sysctl'), 'why' => '无 /etc/sysctl.d'];
        $targets[] = ['label' => 'MySQL conf.d', 'dir' => $d['mysql_confd'], 'name' => 'z-maccms.cnf', 'content' => $g('mysql'), 'why' => '无 /etc/mysql/conf.d(或未装本地 MySQL)'];
        return $targets;
    }

    private function genOne($which, $r, $d)
    {
        switch ($which) {
            case 'php':
                return "; maccms tune\nopcache.enable=1\nopcache.enable_cli=0\nopcache.memory_consumption={$r['opcache_mb']}\nopcache.interned_strings_buffer=16\nopcache.max_accelerated_files=20000\nopcache.revalidate_freq=60\nrealpath_cache_size=4096k\nrealpath_cache_ttl=600\nmemory_limit=256M\n";
            case 'limits':
                return "* soft nofile {$r['nofile']}\n* hard nofile {$r['nofile']}\nroot soft nofile {$r['nofile']}\nroot hard nofile {$r['nofile']}\n";
            case 'sysctl':
                return "net.core.somaxconn = {$r['somaxconn']}\nnet.ipv4.tcp_max_syn_backlog = {$r['syn_backlog']}\nnet.core.netdev_max_backlog = {$r['netdev_backlog']}\nnet.ipv4.ip_local_port_range = 1024 65535\nfs.file-max = {$r['file_max']}\n";
            case 'mysql':
                return "[mysqld]\ninnodb_buffer_pool_size = {$r['innodb_bp_mb']}M\ninnodb_log_file_size = 256M\ninnodb_flush_log_at_trx_commit = 2\ninnodb_flush_method = O_DIRECT\nmax_connections = {$r['mysql_maxconn']}\ntable_open_cache = 4000\n";
        }
        return '';
    }

    // ---------------- 撤销 ----------------

    /**
     * 按账本回滚 --apply 的系统改动:有备份则恢复原文件(并删备份),否则删除我们新建的文件。
     * 账本丢失时回退到"按已知文件名清理"。绝不触碰非 maccms 命名的文件。
     */
    private function doRevert(Output $o, $outDir)
    {
        $o->writeln('── 撤销 tune --apply 的系统改动 ──');
        $lf = $outDir . 'tune-ledger.json';
        $entries = is_file($lf) ? (json_decode((string)file_get_contents($lf), true) ?: []) : [];

        if (empty($entries)) {
            $o->writeln('  无账本(' . $lf . '),改用"按已知文件名"清理…');
            return $this->revertByName($o);
        }

        $done = 0;
        $fail = [];
        foreach (array_reverse($entries) as $e) {       // LIFO:后写的先撤
            $path = $e['path'] ?? '';
            $bak  = $e['backup'] ?? null;
            if ($path === '') {
                continue;
            }
            if (!empty($bak) && is_file($bak)) {
                if (@copy($bak, $path) && @unlink($bak)) {
                    $o->writeln('  ↩ 恢复原文件 ' . $path);
                    $done++;
                } else {
                    $fail[] = $path . '(恢复失败,需 root?)';
                }
            } else {
                if (!is_file($path) || @unlink($path)) {
                    $o->writeln('  ✗ 删除 ' . $path);
                    $done++;
                } else {
                    $fail[] = $path . '(删除失败,需 root?)';
                }
            }
        }
        foreach ($fail as $f) {
            $o->writeln('  <comment>手动:' . $f . '</comment>');
        }
        if (empty($fail)) {
            @unlink($lf);                                 // 全部成功才清账本
        }
        $o->writeln('  生效需 reload:php-fpm reload · sysctl --system · 重新登录(ulimit) · 重启 MySQL');
        $o->writeln('  <comment>注意:你按教程手改的 Nginx 主配置 / FPM 池 / MySQL 不在账本内,需手动还原</comment>');
        $o->writeln('<info>✔ 撤销完成(' . $done . ' 项' . (empty($fail) ? '' : ',' . count($fail) . ' 项需手动') . ')</info>');
        return empty($fail) ? 0 : 6;
    }

    /** 账本丢失时的兜底:按 maccms 专用文件名在已知目录里恢复/删除(只动 *maccms* 命名文件) */
    private function revertByName(Output $o)
    {
        $d = $this->detect();
        $cands = [];
        foreach ($d['confd'] as $cd) {
            $cands[] = $cd . '/99-maccms-perf.ini';
        }
        if ($d['limitsd']) {
            $cands[] = $d['limitsd'] . '/99-maccms-nofile.conf';
        }
        if ($d['sysctld']) {
            $cands[] = $d['sysctld'] . '/99-maccms.conf';
        }
        if ($d['mysql_confd']) {
            $cands[] = $d['mysql_confd'] . '/z-maccms.cnf';
        }
        $done = 0;
        foreach ($cands as $p) {
            if (!is_file($p)) {
                continue;
            }
            $baks = glob($p . '.bak-*') ?: [];
            if ($baks) {
                rsort($baks);
                if (@copy($baks[0], $p)) {
                    $o->writeln('  ↩ 恢复 ' . $p . '(来自 ' . basename($baks[0]) . ')');
                    @unlink($baks[0]);
                    $done++;
                    continue;
                }
            }
            if (@unlink($p)) {
                $o->writeln('  ✗ 删除 ' . $p);
                $done++;
            } else {
                $o->writeln('  <comment>手动:无法处理 ' . $p . '(需 root?)</comment>');
            }
        }
        $o->writeln($done ? ('<info>✔ 按名撤销完成(' . $done . ' 项)</info>') : '<comment>未发现 maccms drop-in,无需撤销</comment>');
        return 0;
    }
}
