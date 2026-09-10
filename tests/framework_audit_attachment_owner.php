<?php
/** Ordinary image/file operations and real PDO acknowledgement faults, isolated per process. */
declare(strict_types=1);
require __DIR__.'/fixtures/security_audit_test_helpers.php';
$cases=['normal','caller_raw','caller_orm','rollback_unrecoverable'];
foreach (['begin','rollback','commit'] as $operation) {
    foreach (['orm','pdo'] as $layer) {
        foreach (['before','after'] as $when) { $cases[]=$layer.'_'.$operation.'_'.$when; }
    }
}
foreach ($cases as $case) {
    $process=proc_open([PHP_BINARY,'-d','error_reporting=-1','-d','display_errors=stderr',
        __DIR__.'/fixtures/attachment_owner_worker.php',$case],
        [0=>['file','/dev/null','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);
    check(is_resource($process),'Attachment owner fixture must start');
    $output=stream_get_contents($pipes[1]);fclose($pipes[1]);
    $errors=stream_get_contents($pipes[2]);fclose($pipes[2]);
    $status=proc_close($process);$result=json_decode($output,true);
    check($status===0&&is_array($result)&&($result['result']??null)==='passed',
        'Attachment owner case failed: '.$case.'; '.$output.'; '.$errors);
    check(!preg_match('/(?:Warning:|Deprecated:|Fatal error:|Uncaught )/',$errors),
        'Attachment owner emitted PHP diagnostics: '.$case.'; '.$errors);
    $checks+=(int)$result['checks'];
}
echo 'Attachment owner acknowledgements: '.$checks.' checks across '.count($cases).' SQLite processes on PHP '.PHP_VERSION."\n";
