<?php
declare(strict_types=1);
require __DIR__.'/fixtures/security_audit_test_helpers.php';
$cases=[];
foreach(['prepare','claim','finish'] as $phase)foreach(['orm_commit_before','pdo_commit_before','pdo_commit_after','orm_commit_after','rollback_unrecoverable'] as $fault) { $cases[]=[$phase,$fault,'admin']; }
$cases[]=['prepare','orm_commit_after','index'];$cases[]=['finish','orm_commit_after','index'];
foreach($cases as [$phase,$fault,$entrance]) {
    $process=proc_open([PHP_BINARY,__DIR__.'/fixtures/storage_attachment_worker.php',$phase,$fault,$entrance],[0=>['file','/dev/null','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);
    check(is_resource($process),'Cannot start storage attachment worker');
    $output=stream_get_contents($pipes[1]);$errors=stream_get_contents($pipes[2]);fclose($pipes[1]);fclose($pipes[2]);
    $status=proc_close($process);$result=json_decode(trim($output),true);
    check($status===0&&is_array($result)&&$result['result']==='passed','Storage attachment worker failed: '.$phase.'/'.$fault.' '.$output.' '.$errors);
    $checks+=$result['checks'];
}
echo 'Storage attachment evidence: '.$checks.' checks across 17 SQLite processes on PHP '.PHP_VERSION."\n";
