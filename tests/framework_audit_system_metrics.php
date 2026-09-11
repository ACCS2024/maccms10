<?php
/** Pure metric parsing, actual bounded child processes and the dashboard JSON action. */
declare(strict_types=1);
require dirname(__DIR__).'/vendor/autoload.php';
require __DIR__.'/fixtures/security_audit_test_helpers.php';
use app\common\util\SystemMetrics as Metrics;
function mac_path_in_open_basedir(string $path): bool { return empty($GLOBALS['metrics_paths_denied']); }
function json($data) { return \think\Response::create($data, 'json'); }
define('ROOT_PATH', sys_get_temp_dir().'/');
$app = new \think\App(sys_get_temp_dir().'/metrics-fixture/');
$disabled = ($argv[1] ?? '') === 'disabled';
if ($disabled) {
    $GLOBALS['metrics_paths_denied'] = true;
    check(!function_exists('proc_open') && !function_exists('disk_total_space'), 'Disabled-function regression requires disabled native probes');
    $status = Metrics::snapshot(ROOT_PATH);
    check($status['mem_total'] === 0.0 && $status['mem_used'] === 0.0 && $status['cpu_usage'] === 0.0, 'Unavailable metrics retain finite defaults');
    check($status['disk_datas'] === ['/'=>[0.0,0.0,0.0]], 'Unavailable disk metrics retain the response shape');
} else {
    check(Metrics::diskValues(1000,250) === [0.0,0.0,75.0], 'Sub-GB volumes must calculate usage before display rounding');
    check(Metrics::diskValues(4*1073741824,1073741824) === [1.0,4.0,75.0], 'Disk tuple must be free GB, total GB, used percent');
    check(Metrics::diskValues(1000,0) === [0.0,0.0,100.0], 'A full disk remains numeric');
    foreach ([[0,0],[false,0],[100,false],[100,101],[-1,0],[INF,1],['n/a',0],[[],0],[true,0],['1e10',0]] as [$total,$free]) {
        check(Metrics::diskValues($total,$free) === null, 'Invalid disk measurements must not enter arithmetic');
    }
    $memory = ['total'=>4.0,'used'=>3.0,'usage'=>75.0];
    check(Metrics::procMemory("MemTotal: 4096 kB\nMemAvailable: 1024 kB\nMemFree: 10 kB\nCached: 10 kB\nBuffers: 10 kB\n") === $memory, 'Linux should prefer available memory');
    check(Metrics::procMemory("MemTotal: 4096 kB\nMemFree: 512 kB\nCached: 256 kB\nBuffers: 256 kB\n") === $memory, 'Old Linux memory fallback preserves KB units');
    check(Metrics::freeMemory("header\nMem:\t4096  3072  1024 0 0 1024\nSwap: 0 0 0\n") === $memory, 'free parser accepts normal whitespace');
    check(Metrics::sysctlMemory("4194304\n4096\n256\n") === $memory, 'BSD memory converts byte/page counters to MB');
    check(Metrics::wmicMemory("FreePhysicalMemory=1024\r\nTotalVisibleMemorySize=4096\r\n") === $memory, 'Windows memory values normalize to the shared units');
    foreach (['procMemory','freeMemory','sysctlMemory','wmicMemory','procCpu','sysctlCpu','wmicCpu'] as $method) {
        foreach ([null,'','unavailable',str_repeat('1',65537)] as $value) {
            check(Metrics::$method($value) === null, 'Malformed or oversized optional probe must be rejected: '.$method);
        }
    }
    foreach (["Mem: 0 0", "Mem: total used", "Mem: 100 101", "Mem: 100 invalid"] as $value) {
        check(Metrics::freeMemory($value) === null, 'Malformed free output must not coerce to success');
    }
    check(Metrics::sysctlMemory("4096\n4096\n2") === null, 'Free memory cannot exceed total');
    check(Metrics::wmicCpu("LoadPercentage\r\n10\r\n30\r\n") === 20.0, 'Windows CPU reports an average across processors');
    check(Metrics::wmicCpu("LoadPercentage\n101") === null, 'Out of range CPU readings must fail');
    $first = Metrics::procCpu("cpu  10 0 20 60 10 0 0 0 5 0\ncpu0 0 0 0 0\n");
    $second = Metrics::procCpu("cpu\t15 0 25 65 15 0 0 0 7 0\n");
    check($first === ['total'=>100.0,'idle'=>70.0], 'CPU idle includes iowait and excludes duplicated guest counters');
    check(Metrics::cpuDelta($first,$second) === 50.0, 'CPU usage derives from counter deltas');
    check(Metrics::sysctlCpu("10 0 20 0 70\n") === ['total'=>100.0,'idle'=>70.0], 'BSD CPU includes five counters');
    foreach ([null,$first,['total'=>99,'idle'=>70],['total'=>120,'idle'=>100],['total'=>120,'idle'=>69],[]] as $bad) {
        check(Metrics::cpuDelta($first,$bad) === null, 'CPU reset/no sample/no elapsed ticks must not produce invalid percentages');
    }
    $command = new ReflectionMethod(Metrics::class, 'command');
    check($command->invoke(null,[PHP_BINARY,'-r','echo $argv[1];','ordinary argument']) === 'ordinary argument', 'Local probes use argv without shell splitting');
    check($command->invoke(null,[PHP_BINARY,'-r','fwrite(STDERR,"optional warning"); echo "value";']) === 'value', 'stderr must be drained separately from stdout');
    check($command->invoke(null,[PHP_BINARY,'-r','echo "partial"; exit(1);']) === null, 'Failed command output cannot masquerade as a valid probe');
    foreach (['echo str_repeat("x", 100000);','fwrite(STDERR,str_repeat("x",100000));','sleep(10);'] as $code) {
        $started = microtime(true);
        check($command->invoke(null,[PHP_BINARY,'-r',$code]) === null, 'Oversized or stalled probe must stop');
        check(microtime(true)-$started < 2.0, 'Probe deadline must bound request latency');
    }
    $GLOBALS['metrics_paths_denied'] = false;
    $status = Metrics::snapshot(ROOT_PATH);
    check($status['mem_total'] > 0 && $status['disk_datas']['/'][1] > 0, 'Actual Linux fixture must exercise readable host metrics');
}
$controller = (new ReflectionClass(\app\admin\controller\Index::class))->newInstanceWithoutConstructor();
$response = $controller->get_system_status();
check($response instanceof \think\response\Json, 'Dashboard action must preserve its JSON response contract');
$status = json_decode($response->getContent(), true, 512, JSON_THROW_ON_ERROR);
check(array_keys($status) === ['os_name','disk_datas','cpu_usage','mem_usage','mem_total','mem_used'], 'Dashboard fields must remain complete');
foreach (['cpu_usage','mem_usage','mem_total','mem_used'] as $key) {
    check(is_numeric($status[$key]) && is_finite((float)$status[$key]) && $status[$key]>=0, 'Dashboard metric must remain numeric and finite');
}
check($status['cpu_usage']<=100 && $status['mem_usage']<=100, 'Usage must stay within percentage bounds');
echo 'System metrics: '.$checks.' checks passed on PHP '.PHP_VERSION.' / '.($disabled?'disabled':'normal')."\n";
