<?php
/** Included only by the dedicated MySQL suite. Exercises the actual operator CLI without application config. */
use think\facade\Db;
$cliTable='storage_cli_storage_intent';
Db::execute('DROP TABLE IF EXISTS '.$cliTable);
function storageMigrationCli(array $arguments=[],array $overrides=[]):array {
    $environment=array_replace(getenv(),[
        'STORAGE_INTENT_SCHEMA_DSN'=>'mysql:host='.(getenv('STORAGE_AUDIT_HOST')?:'127.0.0.1').';dbname=maccms_audit_storage;charset=utf8mb4',
        'STORAGE_INTENT_SCHEMA_USER'=>'root','STORAGE_INTENT_SCHEMA_PASSWORD'=>getenv('STORAGE_AUDIT_PASSWORD')?:'',
        'STORAGE_INTENT_SCHEMA_PREFIX'=>'storage_cli_',
    ],$overrides);
    $process=proc_open([PHP_BINARY,dirname(__DIR__,2).'/migration/create-storage-intents.php',...$arguments],
        [0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes,null,$environment);
    fclose($pipes[0]);$output=stream_get_contents($pipes[1]);$error=stream_get_contents($pipes[2]);fclose($pipes[1]);fclose($pipes[2]);
    return [proc_close($process),$output,$error];
}
try {
    [$code,$output]=storageMigrationCli();$report=json_decode($output,true);
    check($code===0 && count($report['changes']??[])===1 && ($report['blockers']??null)===[],'Default migration CLI did not return a read-only plan');
    check(Db::query("SELECT COUNT(*) AS n FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name=?",[$cliTable])[0]['n']===0,'Default CLI applied DDL');
    [$code]=storageMigrationCli(['--apply']);
    check($code===0 && Db::query("SELECT COUNT(*) AS n FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name=?",[$cliTable])[0]['n']==1,'Explicit CLI apply did not create the actual table');
    Db::execute('INSERT INTO '.$cliTable.' SELECT * FROM storage_audit_storage_intent LIMIT 1');
    $saved=Db::query('SELECT * FROM '.$cliTable);
    [$code]=storageMigrationCli(['--apply']);
    check($code===0 && Db::query('SELECT * FROM '.$cliTable)===$saved,'Repeated CLI apply modified an existing receipt');
    Db::execute('ALTER TABLE '.$cliTable.' MODIFY source_bytes SMALLINT UNSIGNED NOT NULL');
    [$code,$output]=storageMigrationCli(['--apply']);
    check($code===1 && (json_decode($output,true)['blockers']??[])!==[]
        && Db::query('SELECT * FROM '.$cliTable)===$saved,'Incompatible CLI schema was silently altered or existing evidence changed');
    [$code]=storageMigrationCli([],['STORAGE_INTENT_SCHEMA_PREFIX'=>'invalid`prefix']);
    check($code===1,'Unsafe CLI prefix was accepted');
    [$code]=storageMigrationCli([],['STORAGE_INTENT_SCHEMA_DSN'=>'mysql:host=127.0.0.1']);
    check($code===1,'CLI inferred a database when none was selected');
    [$code]=storageMigrationCli(['--unknown']);
    check($code===1,'Unknown CLI option was ignored');
} finally {Db::execute('DROP TABLE IF EXISTS '.$cliTable);}
