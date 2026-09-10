<?php
/** Real MySQL and locally generated backup roundtrips; no site bootstrap or existing archive. */
declare(strict_types=1);
namespace app\common\util {
    function rename($from,$to){if($GLOBALS['cliExportFailRename']??false){return false;}return \rename($from,$to);}
    function fwrite($stream,$bytes){
        if(($GLOBALS['cliExportFailWrite']??false)&&str_ends_with(stream_get_meta_data($stream)['uri']??'','/complete.sql')){return 0;}
        return \fwrite($stream,$bytes);
    }
    function stream_copy_to_stream($from,$to){if($GLOBALS['cliExportFailCopy']??false){return 0;}return \stream_copy_to_stream($from,$to);}
}
namespace {
require dirname(__DIR__).'/vendor/autoload.php';
error_reporting(E_ALL);
set_error_handler(static function($level,$message,$file,$line) {
    if (!(error_reporting() & $level)) { return false; }
    throw new ErrorException($message,0,$level,$file,$line);
});
$database = getenv('DATABASE_AUDIT_DATABASE') ?: '';
if (!preg_match('/^maccms_audit_backup_[a-f0-9]+$/D',$database) || getenv('DATABASE_AUDIT_MYSQL_SOCKET') !== '/audit/mysql.sock') {
    throw new RuntimeException('Only the dedicated disposable backup database is allowed');
}
$app = new think\App('/audit/backup-app-'.getmypid().'/');
$dbConfig=['default'=>'audit','connections'=>['audit'=>['type'=>'mysql','socket'=>'/audit/mysql.sock','database'=>$database,
    'username'=>'root','password'=>getenv('DATABASE_AUDIT_PASSWORD'),'prefix'=>'audit_','charset'=>'utf8mb4','trigger_sql'=>true,'fields_cache'=>false]]];
$app->config->set($dbConfig,'database');
$manager=new think\DbManager();$manager->setConfig($dbConfig);$app->instance('think\DbManager',$manager);
use think\facade\Db;
use app\common\util\Database;
$checks=0;$failures=[];
function databaseUtilityExpect($ok,string $message):void { global $checks,$failures;++$checks;if(!$ok){$failures[]=$message;} }
$temporary='/audit/backup-files-'.getmypid();mkdir($temporary,0700,true);
require dirname(__DIR__).'/application/common.php';
$backup=new app\common\util\DbBackup();
function cliExportRunCommand(array $arguments):array{
    $command=new app\command\DbExport();$input=new think\console\Input($arguments);$input->bind($command->getDefinition());
    $output=new think\console\Output('buffer');
    return [(new ReflectionMethod($command,'execute'))->invoke($command,$input,$output),$output->fetch()];
}
try {
    $file=$temporary.'/existing.sql';file_put_contents($file,'previous good artifact');
    try{$backup->export(['audit_missing'],$file);databaseUtilityExpect(false,'missing table must fail export');}
    catch(Throwable $error){databaseUtilityExpect(file_get_contents($file)==='previous good artifact','failed export preserves existing output bytes');}
    foreach ([[],[[]],[true],[1],[''],['audit_missing; SELECT 1']] as $tables){
        try{$backup->export($tables,$file);databaseUtilityExpect(false,'invalid table selections must fail');}
        catch(RuntimeException $error){databaseUtilityExpect(file_get_contents($file)==='previous good artifact','invalid table selections preserve existing output');}
    }
    Db::execute("SET SESSION sql_mode='STRICT_TRANS_TABLES,NO_AUTO_VALUE_ON_ZERO,NO_BACKSLASH_ESCAPES'");
    Db::execute('CREATE TABLE audit_rich (id INT PRIMARY KEY AUTO_INCREMENT, notes LONGTEXT NULL, binary_data LONGBLOB, amount DECIMAL(16,4), flags BIT(8), precise_value DOUBLE, metadata JSON, doubled INT GENERATED ALWAYS AS (flags*2) STORED) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4');
    Db::table('audit_rich')->insertAll([
        ['id'=>0,'notes'=>"multi\r\nline; \\ quote' 中文 😀",'binary_data'=>"\0\xff\r\n",'amount'=>'123456789.1234','flags'=>255,'precise_value'=>'1.2345678901234567','metadata'=>'{"note":"中文;"}'],
        ['id'=>1,'notes'=>null,'binary_data'=>'','amount'=>'-0.0001','flags'=>49,'precise_value'=>'0.000000000123456789123456','metadata'=>null],
    ]);
    Db::execute('CREATE TABLE audit_empty (id INT PRIMARY KEY) ENGINE=InnoDB');
    $expected=Db::query('SELECT * FROM audit_rich ORDER BY id');
    $settings=Db::query('SELECT @@SESSION.sql_mode AS mode, @@SESSION.foreign_key_checks AS fk, @@SESSION.transaction_isolation AS isolation')[0];
    $result=$backup->export(['audit_rich','audit_empty','audit_rich'],$file);
    databaseUtilityExpect($result['tables']===2&&$result['rows']===2&&$result['consistent_snapshot']===true,'export returns deduplicated counts and snapshot coverage');
    databaseUtilityExpect((fileperms($file)&0777)===0600,'published export is private to its owner');
    databaseUtilityExpect(!Db::connect()->getPdo()->inTransaction(),'export closes its read transaction');
    databaseUtilityExpect(Db::query('SELECT @@SESSION.sql_mode AS mode, @@SESSION.foreign_key_checks AS fk, @@SESSION.transaction_isolation AS isolation')[0]===$settings,'export preserves connection settings');
    Db::execute('DELETE FROM audit_rich');
    databaseUtilityExpect($backup->import($file)>0,'existing CLI importer accepts the new complete dump');
    databaseUtilityExpect(Db::query('SELECT * FROM audit_rich ORDER BY id')===$expected,'CLI roundtrip preserves explicit zero, NULL, CR/LF, binary, exact numerics and generated columns');
    databaseUtilityExpect(Db::query('SELECT @@SESSION.sql_mode AS mode, @@SESSION.foreign_key_checks AS fk, @@SESSION.transaction_isolation AS isolation')[0]===$settings,'standalone dump restores SQL mode and foreign key checking');
    // More than one codec page, so the CLI adapter cannot accidentally stop after the first batch.
    $rows=[];for($i=1;$i<=1005;$i++){$rows[]=['id'=>$i];}Db::table('audit_empty')->insertAll($rows);
    $large=$temporary.'/pages.sql';$result=$backup->export(['audit_empty'],$large);
    databaseUtilityExpect($result['rows']===1005,'CLI export counts all codec pages');Db::execute('DELETE FROM audit_empty');$backup->import($large);
    databaseUtilityExpect(Db::query('SELECT COUNT(*) AS n FROM audit_empty')[0]['n']===1005,'CLI export writes all codec pages');
    // A second real connection commits updates after the first snapshot SELECT has executed.
    Db::execute('CREATE TABLE audit_first (id INT PRIMARY KEY, notes TEXT) ENGINE=InnoDB');
    Db::execute('CREATE TABLE audit_second (id INT PRIMARY KEY, notes TEXT) ENGINE=InnoDB');
    Db::execute("INSERT INTO audit_first VALUES (1,'old')");Db::execute("INSERT INTO audit_second VALUES (1,'old')");
    $other=new PDO('mysql:unix_socket=/audit/mysql.sock;dbname='.$database.';charset=utf8mb4','root',getenv('DATABASE_AUDIT_PASSWORD'),[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);
    $snapshotMutation=true;
    Db::listen(static function($sql) use ($other,&$snapshotMutation){
        if($snapshotMutation&&str_starts_with($sql,'SELECT COUNT(*) AS total FROM `audit_first`')){
            $snapshotMutation=false;$other->beginTransaction();
            $other->exec("UPDATE audit_first SET notes='new'");$other->exec("UPDATE audit_second SET notes='new'");$other->commit();
        }
    });
    $snapshot=$temporary.'/snapshot.sql';$result=$backup->export(['audit_first','audit_second'],$snapshot);
    databaseUtilityExpect(!$snapshotMutation&&Db::query('SELECT notes FROM audit_second')[0]['notes']==='new','a concurrent writer really commits while export is active');
    $backup->import($snapshot);
    databaseUtilityExpect(Db::query('SELECT notes FROM audit_first')[0]['notes']==='old'&&Db::query('SELECT notes FROM audit_second')[0]['notes']==='old','both exported tables share the same pre-update InnoDB snapshot');
    // Caller-owned transactions are not committed, rolled back or nested by the exporter.
    Db::startTrans();Db::execute("INSERT INTO audit_first VALUES (2,'uncommitted')");
    $original=hash_file('sha256',$file);
    try{$backup->export(['audit_first'],$file);databaseUtilityExpect(false,'export cannot own an existing transaction');}
    catch(RuntimeException $error){databaseUtilityExpect(Db::connect()->getPdo()->inTransaction()&&Db::query('SELECT COUNT(*) AS n FROM audit_first')[0]['n']===2&&hash_file('sha256',$file)===$original,'rejected nested export leaves caller transaction and output intact');}
    Db::rollback();databaseUtilityExpect(Db::query('SELECT COUNT(*) AS n FROM audit_first')[0]['n']===1,'caller can still roll back its own uncommitted row');
    Db::execute('CREATE TABLE audit_myisam (id INT PRIMARY KEY) ENGINE=MyISAM');Db::execute('INSERT INTO audit_myisam VALUES (4)');
    $result=$backup->export(['audit_myisam'],$temporary.'/myisam.sql');databaseUtilityExpect($result['consistent_snapshot']===false&&$result['rows']===1,'nontransactional engines remain exportable without claiming snapshot consistency');
    Db::execute('CREATE VIEW audit_view AS SELECT id FROM audit_first');
    databaseUtilityExpect(in_array('audit_first',$backup->listTables('audit_'),true)&&!in_array('audit_view',$backup->listTables('audit_'),true),'table listing selects base tables and excludes unsupported views');
    try{$backup->listTables([]);databaseUtilityExpect(false,'array prefix is invalid');}catch(InvalidArgumentException $error){databaseUtilityExpect(true,'invalid prefix has a controlled boundary');}
    foreach(['view','write','copy','publish'] as $failure){
        $GLOBALS['cliExportFailWrite']=$failure==='write';$GLOBALS['cliExportFailCopy']=$failure==='copy';$GLOBALS['cliExportFailRename']=$failure==='publish';
        $streams=count(get_resources('stream'));
        try{$backup->export([$failure==='view'?'audit_view':'audit_rich'],$file);databaseUtilityExpect(false,'injected export failure must fail');}
        catch(RuntimeException $error){databaseUtilityExpect(hash_file('sha256',$file)===$original,'failed '.$failure.' preserves last complete artifact');}
        databaseUtilityExpect(count(get_resources('stream'))===$streams&&!Db::connect()->getPdo()->inTransaction(),'failed '.$failure.' closes files and transaction');
        databaseUtilityExpect((glob($temporary.'/.db-export-*')?:[])===[],'failed '.$failure.' removes only its temporary artifacts');
        $GLOBALS['cliExportFailWrite']=false;$GLOBALS['cliExportFailCopy']=false;$GLOBALS['cliExportFailRename']=false;
    }
    symlink($file,$temporary.'/linked.sql');
    try{$backup->export(['audit_rich'],$temporary.'/linked.sql');databaseUtilityExpect(false,'symlink output must fail');}
    catch(RuntimeException $error){databaseUtilityExpect(hash_file('sha256',$file)===$original,'output symlink target remains unchanged');}
    foreach([[],null,'',$temporary.'/missing-dir/file.sql',$temporary] as $invalid){
        try{$backup->export(['audit_rich'],$invalid);databaseUtilityExpect(false,'invalid output must fail');}
        catch(RuntimeException $error){databaseUtilityExpect(true,'invalid output is a controlled failure');}
    }
    [$exit,$message]=cliExportRunCommand(['--tables=audit_rich','--file='.$temporary.'/command.sql']);
    databaseUtilityExpect($exit===0&&str_contains($message,'导出完成')&&is_file($temporary.'/command.sql'),'real command exports valid selected tables');
    [$exit,$message]=cliExportRunCommand(['--tables=audit_myisam','--file='.$temporary.'/command-myisam.sql']);
    databaseUtilityExpect($exit===0&&str_contains($message,'维护窗口'),'real command explains nontransactional snapshot limits');
    [$exit,$message]=cliExportRunCommand(['--tables=audit_myisam','--file='.$temporary.'/command-porcelain.sql','--porcelain']);
    databaseUtilityExpect($exit===0&&trim($message)===$temporary.'/command-porcelain.sql','porcelain remains exactly the output path');
    [$exit,$message]=cliExportRunCommand(['--tables=audit_missing','--file='.$file]);
    databaseUtilityExpect($exit===6&&hash_file('sha256',$file)===$original,'command failures preserve artifact bytes and return nonzero');
    $dbConfig['connections']['no_prefix']=$dbConfig['connections']['audit'];$dbConfig['connections']['no_prefix']['prefix']='';
    $dbConfig['default']='no_prefix';$manager->setConfig($dbConfig);$app->config->set($dbConfig,'database');
    [$exit,$message]=cliExportRunCommand(['--file='.$temporary.'/forbidden-whole-db.sql']);
    databaseUtilityExpect($exit===2&&!file_exists($temporary.'/forbidden-whole-db.sql'),'empty prefix without explicit tables never exports the whole database');
    [$exit,$message]=cliExportRunCommand(['--tables=audit_rich','--file='.$temporary.'/explicit-no-prefix.sql']);
    databaseUtilityExpect($exit===0&&is_file($temporary.'/explicit-no-prefix.sql'),'explicit table selection works without a configured prefix');
    Db::execute('CREATE TABLE `0` (id INT PRIMARY KEY) ENGINE=InnoDB');
    [$exit,$message]=cliExportRunCommand(['--tables=0','--file='.$temporary.'/numeric-table.sql']);
    databaseUtilityExpect($exit===0&&is_file($temporary.'/numeric-table.sql'),'an actual table named zero is not discarded by option filtering');
    $dbConfig['default']='audit';$manager->setConfig($dbConfig);$app->config->set($dbConfig,'database');
    if($failures){throw new RuntimeException(implode(PHP_EOL,$failures));}
    echo 'framework_audit_cli_export: '.$checks.' checks passed on PHP '.PHP_VERSION.PHP_EOL;
} finally {
    Db::execute('DROP VIEW IF EXISTS audit_view');
    Db::execute('DROP TABLE IF EXISTS audit_rich,audit_empty,audit_first,audit_second,audit_myisam,`0`');
    $iterator=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($temporary,FilesystemIterator::SKIP_DOTS),RecursiveIteratorIterator::CHILD_FIRST);
    foreach($iterator as $entry){$entry->isDir()&&!$entry->isLink()?rmdir($entry->getPathname()):unlink($entry->getPathname());}rmdir($temporary);
}
}
