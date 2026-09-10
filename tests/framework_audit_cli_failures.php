<?php
/** Actual CLI exit/logging and tuning branches; no remote requests or tuning file writes. */
declare(strict_types=1);

namespace app\common\util {
    class SeoAi {
        public static function generateByMidObj($mid, $id) {
            if ($id === 1) { throw new \RuntimeException('remote failure'); }
            if ($id === 2) { throw new \TypeError('malformed remote payload'); }
            return $id === 3 ? ['code'=>1] : ['code'=>1001,'msg'=>'upstream refused'];
        }
    }
}
namespace {
    require dirname(__DIR__) . '/vendor/autoload.php';
    error_reporting(E_ALL);
    set_error_handler(static function ($level, $message, $file, $line) {
        throw new ErrorException($message, 0, $level, $file, $line);
    });
    class AuditLogger {
        public array $errors = [];
        public function error($message) { $this->errors[] = $message; }
    }
    $logger = new AuditLogger();
    think\Container::getInstance()->instance('log', $logger);

    $checks = 0;
    function auditExpect($ok, $message) {
        global $checks;
        ++$checks;
        if (!$ok) { throw new RuntimeException($message); }
    }
    $command = new app\command\SeoAiGenerate();
    $execute = new ReflectionMethod($command, 'execute');
    foreach ([1=>1, 2=>1, 3=>0, 4=>1] as $id => $expected) {
        $input = new think\console\Input(['--mid=1', '--id=' . $id]);
        $input->bind($command->getDefinition());
        $output = new think\console\Output('buffer');
        auditExpect($execute->invoke($command, $input, $output) === $expected, 'SEO command must report success/failure through its exit status');
    }
    auditExpect(count($logger->errors) === 2, 'Both Exception and TypeError must use the log facade without a second fatal error');
    $input = new think\console\Input(['--mid=99']);
    $input->bind($command->getDefinition());
    auditExpect($execute->invoke($command, $input, new think\console\Output('buffer')) === 2, 'Invalid SEO input must fail the command');
    $tune = new app\command\Tune();
    $targets = new ReflectionMethod($tune, 'dropinTargets');
    $detected = ['confd'=>[], 'limitsd'=>null, 'sysctld'=>null, 'mysql_confd'=>null];
    $recommendations = array_fill_keys(['opcache_mb','nofile','somaxconn','syn_backlog','netdev_backlog','file_max','innodb_bp_mb','mysql_maxconn'], 64);
    auditExpect(count($targets->invoke($tune, $detected, $recommendations)) === 4, 'Tune target generation must capture detected settings without undefined variables');
    echo 'framework_audit_cli_failures: ' . $checks . ' checks passed on PHP ' . PHP_VERSION . "\n";
}
