<?php
declare(strict_types=1);
require dirname(__DIR__).'/vendor/autoload.php';
require __DIR__.'/fixtures/security_audit_test_helpers.php';
use app\common\util\LocalProcess;
$bytes=str_repeat("普通 text\r\n",10000);
check(LocalProcess::capture([PHP_BINARY,'-r','echo stream_get_contents(STDIN);'],$bytes,2,1048576)===$bytes,'Piped input must retain complete bytes, newlines and whitespace');
check(LocalProcess::capture([PHP_BINARY,'-r','echo $argv[1];','one two'])==='one two','Fixed argv must not undergo shell splitting');
check(LocalProcess::capture([PHP_BINARY,'-r',''])==='','Successful empty stdout differs from a failed process');
check(LocalProcess::capture([PHP_BINARY,'-r','echo "partial"; exit(2);'])===null,'Nonzero exit cannot publish partial output');
check(LocalProcess::capture([PHP_BINARY,'-r','fwrite(STDERR,"warning");echo "complete";'])==='complete','stderr must drain independently');
foreach (['echo str_repeat("x",100000);','fwrite(STDERR,str_repeat("x",100000));','echo "partial";sleep(10);','sleep(10);'] as $code) {
    $time=microtime(true);
    check(LocalProcess::capture([PHP_BINARY,'-r',$code], '',0.1,65536)===null,'Over-budget process must fail');
    check(microtime(true)-$time<2,'Terminated process must be reaped within a finite wait');
}
check(LocalProcess::capture([PHP_BINARY,'-r','echo "early exit";'],$bytes,0.5,65536)===null,'A child which leaves input unread cannot report a complete conversion');
foreach ([[],[[]],[1],["invalid\0argument"],array_fill(0,33,'arg')] as $argv) {
    check(LocalProcess::capture($argv)===null,'Invalid argv must be rejected before process creation');
}
foreach ([0.0,-1.0,INF,11.0] as $timeout)check(LocalProcess::capture([PHP_BINARY], '', $timeout)===null,'Invalid timeout must be rejected');
check(LocalProcess::capture([PHP_BINARY], str_repeat('x',8388609))===null,'Input must have a pre-launch memory budget');
check(LocalProcess::capture([PHP_BINARY], '',0.5,0)===null,'Output budget must be positive');
check(LocalProcess::capture([PHP_BINARY], '',0.5,16777217)===null,'Output budget must have an upper bound');
echo 'Local process: '.$checks.' checks passed on PHP '.PHP_VERSION."\n";
