<?php
declare(strict_types=1);
namespace app\common\util;

/** Optional dashboard diagnostics: finite numeric results and bounded local probes. */
final class SystemMetrics
{
    private const OUTPUT_LIMIT = 65536;

    public static function snapshot(string $root): array
    {
        $windows = PHP_OS_FAMILY === 'Windows';
        $disks = [];
        if ($windows) {
            foreach (range('A', 'Z') as $letter) {
                $disk = self::disk($letter.':\\');
                if ($disk !== null) { $disks[$letter] = $disk; }
            }
            $memory = self::wmicMemory(self::command(['wmic', 'OS', 'get', 'FreePhysicalMemory,TotalVisibleMemorySize', '/Value']));
            $cpu = self::wmicCpu(self::command(['wmic', 'cpu', 'get', 'loadpercentage']));
        } else {
            $disks['/'] = self::disk($root) ?? [0.0, 0.0, 0.0];
            $memory = self::procMemory(self::read('/proc/meminfo'))
                ?? self::freeMemory(self::command(['free', '-k']))
                ?? self::sysctlMemory(self::command(['/sbin/sysctl', '-n', 'hw.physmem', 'hw.pagesize', 'vm.stats.vm.v_free_count']));
            $first = self::procCpu(self::read('/proc/stat'));
            if ($first !== null) {
                usleep(100000);
                $cpu = self::cpuDelta($first, self::procCpu(self::read('/proc/stat')));
            } else {
                $first = self::sysctlCpu(self::command(['/sbin/sysctl', '-n', 'kern.cp_time']));
                if ($first !== null) {
                    usleep(100000);
                    $cpu = self::cpuDelta($first, self::sysctlCpu(self::command(['/sbin/sysctl', '-n', 'kern.cp_time'])));
                } else { $cpu = null; }
            }
        }
        $memory ??= ['total'=>0.0, 'used'=>0.0, 'usage'=>0.0];
        return ['os_name'=>$windows ? 'WINDOWS' : strtoupper(PHP_OS), 'disk_datas'=>$disks,
            'cpu_usage'=>$cpu ?? 0.0, 'mem_usage'=>$memory['usage'], 'mem_total'=>$memory['total'], 'mem_used'=>$memory['used']];
    }

    private static function number(mixed $value): ?float
    {
        if (is_string($value) && (strlen($value) > 32 || !preg_match('/^\d+(?:\.\d+)?$/D', $value))) { return null; }
        if (!is_string($value) && !is_int($value) && !is_float($value)) { return null; }
        $number = (float)$value;
        return is_finite($number) && $number >= 0 ? $number : null;
    }

    public static function diskValues(mixed $total, mixed $free): ?array
    {
        $total = self::number($total); $free = self::number($free);
        if ($total === null || $free === null || $total <= 0 || $free > $total) { return null; }
        // Consumers display (total - free) in GB. Calculate ratios before rounding tiny volumes.
        return [round($free / 1073741824, 2), round($total / 1073741824, 2), round(($total - $free) / $total * 100, 2)];
    }

    private static function disk(string $path): ?array
    {
        if (!function_exists('disk_total_space') || !function_exists('disk_free_space') || !mac_path_in_open_basedir($path)) { return null; }
        try { return self::diskValues(@disk_total_space($path), @disk_free_space($path)); }
        catch (\Throwable $error) { return null; }
    }

    private static function memory(mixed $total, mixed $available, float $unit): ?array
    {
        $total = self::number($total); $available = self::number($available);
        if ($total === null || $available === null || $total <= 0 || $available > $total) { return null; }
        $used = $total - $available;
        $totalMb = $total * $unit / 1048576; $usedMb = $used * $unit / 1048576;
        if (!is_finite($totalMb) || !is_finite($usedMb)) { return null; }
        return ['total'=>round($totalMb, 2), 'used'=>round($usedMb, 2), 'usage'=>round($used / $total * 100, 2)];
    }

    public static function procMemory(?string $text): ?array
    {
        if ($text === null || strlen($text) > self::OUTPUT_LIMIT) { return null; }
        preg_match_all('/^(MemTotal|MemAvailable|MemFree|Cached|Buffers):[ \t]+(\d+)[ \t]+kB[ \t]*$/m', $text, $matches, PREG_SET_ORDER);
        $values = [];
        foreach ($matches as $match) { $values[$match[1]] = self::number($match[2]); }
        if (!isset($values['MemTotal'])) { return null; }
        $available = $values['MemAvailable'] ?? null;
        if ($available === null && isset($values['MemFree'])) {
            $available = $values['MemFree'] + ($values['Cached'] ?? 0) + ($values['Buffers'] ?? 0);
        }
        return self::memory($values['MemTotal'], $available, 1024);
    }

    public static function freeMemory(?string $text): ?array
    {
        if ($text === null || strlen($text) > self::OUTPUT_LIMIT || !preg_match('/^Mem:[ \t]+([^\r\n]+)$/m', $text, $match)) { return null; }
        $parts = preg_split('/\s+/', trim($match[1]));
        if (count($parts) < 2) { return null; }
        $total = self::number($parts[0]); $used = self::number($parts[1]);
        if ($total === null || $used === null || $used > $total) { return null; }
        return self::memory($total, $total - $used, 1024);
    }

    public static function sysctlMemory(?string $text): ?array
    {
        if ($text === null || strlen($text) > self::OUTPUT_LIMIT) { return null; }
        $parts = preg_split('/\s+/', trim($text));
        if (count($parts) !== 3) { return null; }
        [$total, $page, $count] = array_map([self::class, 'number'], $parts);
        if ($total === null || $page === null || $count === null || $page <= 0) { return null; }
        return self::memory($total, $page * $count, 1);
    }

    public static function wmicMemory(?string $text): ?array
    {
        if ($text === null || strlen($text) > self::OUTPUT_LIMIT
            || !preg_match('/^TotalVisibleMemorySize=(\d+)\s*$/mi', $text, $total)
            || !preg_match('/^FreePhysicalMemory=(\d+)\s*$/mi', $text, $free)) { return null; }
        return self::memory($total[1], $free[1], 1024);
    }

    public static function wmicCpu(?string $text): ?float
    {
        if ($text === null || strlen($text) > self::OUTPUT_LIMIT) { return null; }
        $values = [];
        foreach (preg_split('/\R/', trim($text)) as $line) {
            $line = trim($line);
            if ($line === '' || strcasecmp($line, 'LoadPercentage') === 0) { continue; }
            $value = self::number($line);
            if ($value === null || $value > 100) { return null; }
            $values[] = $value;
        }
        return $values === [] ? null : round(array_sum($values) / count($values), 2);
    }

    public static function procCpu(?string $text): ?array
    {
        if ($text === null || strlen($text) > self::OUTPUT_LIMIT || !preg_match('/^cpu[ \t]+([^\r\n]+)$/m', $text, $match)) { return null; }
        $parts = preg_split('/\s+/', trim($match[1]));
        if (count($parts) < 4) { return null; }
        // guest and guest_nice are already included in user/nice. Count the first eight fields once.
        $values = array_map([self::class, 'number'], array_slice($parts, 0, 8));
        if (in_array(null, $values, true)) { return null; }
        return ['total'=>array_sum($values), 'idle'=>$values[3] + ($values[4] ?? 0)];
    }

    public static function sysctlCpu(?string $text): ?array
    {
        if ($text === null || strlen($text) > self::OUTPUT_LIMIT) { return null; }
        $parts = preg_split('/\s+/', trim($text));
        if (count($parts) !== 5) { return null; }
        $values = array_map([self::class, 'number'], $parts);
        if (in_array(null, $values, true)) { return null; }
        return ['total'=>array_sum($values), 'idle'=>$values[4]];
    }

    public static function cpuDelta(?array $first, ?array $second): ?float
    {
        if ($first === null || $second === null) { return null; }
        foreach ([$first, $second] as $row) {
            if (self::number($row['total'] ?? null) === null || self::number($row['idle'] ?? null) === null || $row['idle'] > $row['total']) { return null; }
        }
        $total = (float)$second['total'] - (float)$first['total']; $idle = (float)$second['idle'] - (float)$first['idle'];
        if ($total <= 0 || $idle < 0 || $idle > $total) { return null; }
        return round(100 * (1 - $idle / $total), 2);
    }

    private static function read(string $path): ?string
    {
        if (!mac_path_in_open_basedir($path)) { return null; }
        try {
            if (!is_readable($path)) { return null; }
            $data = @file_get_contents($path, false, null, 0, self::OUTPUT_LIMIT + 1);
            return is_string($data) && strlen($data) <= self::OUTPUT_LIMIT ? $data : null;
        } catch (\Throwable $error) { return null; }
    }

    /** Only fixed internal argv lists call this; no shell, inherited request arguments or unbounded output. */
    private static function command(array $argv): ?string
    {
        foreach (['proc_open', 'proc_get_status', 'proc_terminate', 'proc_close'] as $function) {
            if (!function_exists($function)) { return null; }
        }
        $process = null; $pipes = [];
        try {
            $process = @proc_open($argv, [0=>['pipe','r'], 1=>['pipe','w'], 2=>['pipe','w']], $pipes, null, null, ['bypass_shell'=>true]);
            if (!is_resource($process)) { return null; }
            fclose($pipes[0]); unset($pipes[0]);
            stream_set_blocking($pipes[1], false); stream_set_blocking($pipes[2], false);
            $output = ''; $size = 0; $deadline = hrtime(true) + 500000000;
            do {
                $chunk = stream_get_contents($pipes[1], 8192); $errors = stream_get_contents($pipes[2], 8192);
                if ($chunk === false || $errors === false) { return null; }
                $output .= $chunk; $size += strlen($chunk) + strlen($errors);
                if ($size > self::OUTPUT_LIMIT || hrtime(true) >= $deadline) { return null; }
                $state = proc_get_status($process);
                if (!$state['running'] && feof($pipes[1]) && feof($pipes[2])) {
                    return $state['exitcode'] === 0 ? $output : null;
                }
                usleep(5000);
            } while (true);
        } catch (\Throwable $error) { return null; }
        finally {
            if (is_resource($process)) {
                $state = proc_get_status($process);
                if ($state['running']) { @proc_terminate($process, 9); }
            }
            foreach ($pipes as $pipe) { if (is_resource($pipe)) { fclose($pipe); } }
            if (is_resource($process)) { @proc_close($process); }
        }
    }
}
