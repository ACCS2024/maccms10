<?php
/** Real MySQL and locally generated backup roundtrips; no site bootstrap or existing archive. */
declare(strict_types=1);
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
    'username'=>'root','password'=>getenv('DATABASE_AUDIT_PASSWORD'),'prefix'=>'audit_','charset'=>'utf8mb4','trigger_sql'=>false,'fields_cache'=>false]]];
$app->config->set($dbConfig,'database');
$manager=new think\DbManager();$manager->setConfig($dbConfig);$app->instance('think\DbManager',$manager);
function session($name,$value=null) { return null; }
use think\facade\Db;
use app\common\util\Database;
$checks=0;$failures=[];
function databaseUtilityExpect($ok,string $message):void { global $checks,$failures;++$checks;if(!$ok){$failures[]=$message;} }
$temporary='/audit/backup-files-'.getmypid();mkdir($temporary,0700,true);
try {
    try {
        $unused=new Database(['name'=>'20260910-010101','part'=>1],['path'=>$temporary.'/','part'=>1048576,'compress'=>0,'level'=>6]);
        unset($unused);
        databaseUtilityExpect(true,'unused backup object closes safely');
    } catch(Throwable $error) { databaseUtilityExpect(false,'unused destructor: '.get_class($error).': '.$error->getMessage()); }
    foreach ([0,1] as $compress) {
        $folder=$temporary.'/mode-'.$compress;mkdir($folder);
        if($compress){Db::execute("SET SESSION sql_mode='STRICT_TRANS_TABLES,NO_BACKSLASH_ESCAPES'");}
        Db::execute('CREATE TABLE audit_roundtrip (id INT NOT NULL PRIMARY KEY, nullable_text TEXT NULL, notes TEXT NOT NULL, binary_data LONGBLOB NOT NULL, metadata JSON NULL, amount DECIMAL(16,4) NOT NULL, flags BIT(8) NOT NULL DEFAULT 0, precise_value DOUBLE NOT NULL DEFAULT 0, doubled INT GENERATED ALWAYS AS (id*2) STORED) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4');
        $rows=[
            ['id'=>0,'nullable_text'=>null,'notes'=>"line1\r\nline2\nend\\quote'\"; 😀",'binary_data'=>"\0\xff\n\r'\\",'metadata'=>'{"caption":"a;b","unicode":"中文"}','amount'=>'123456789.1234','flags'=>49,'precise_value'=>'1.2345678901234567'],
            ['id'=>1,'nullable_text'=>'','notes'=>'plain','binary_data'=>'','metadata'=>null,'amount'=>'-0.2500','flags'=>255,'precise_value'=>'0.000000000123456789123456'],
        ];
        Db::table('audit_roundtrip')->insertAll($rows);
        $beforeSettings=Db::query('SELECT @@SESSION.foreign_key_checks AS fk, @@SESSION.sql_mode AS mode')[0];
        $expected=Db::query('SELECT * FROM audit_roundtrip ORDER BY id');
        $config=['path'=>$folder.'/','part'=>1048576,'compress'=>$compress,'level'=>6];
        $backup=null;
        try {
            $backup=new Database(['name'=>'20260910-010102','part'=>1],$config);
            databaseUtilityExpect($backup->create() !== false,'mode '.$compress.' create succeeds');
            $next=$backup->backup('audit_roundtrip',0);
            while(is_array($next)) {$next=$backup->backup('audit_roundtrip',$next[0]);}
            databaseUtilityExpect($next === 0,'mode '.$compress.' backup finishes');
            unset($backup);$backup=null;
            $files=glob($folder.'/*.sql'.($compress?'.gz':''));sort($files);
            databaseUtilityExpect(count($files)===1,'mode '.$compress.' produces one complete archive');
            databaseUtilityExpect((fileperms($files[0])&0777)===0600,'backup files are created private to their owner');
            Db::execute('DELETE FROM audit_roundtrip');
            foreach($files as $file){
                $restore=new Database([1,$file,$compress],$config,'import');
                $next=$restore->import(0);$iterations=0;
                while(is_array($next)&&++$iterations<100){$next=$restore->import($next[0]);}
                databaseUtilityExpect($next===0,'mode '.$compress.' import reaches EOF');
                unset($restore);
            }
            databaseUtilityExpect(Db::query('SELECT * FROM audit_roundtrip ORDER BY id')===$expected,'mode '.$compress.' roundtrip preserves NULL, CR/LF, quotes, binary bytes, JSON and decimal values');
            databaseUtilityExpect(Db::query('SELECT @@SESSION.foreign_key_checks AS fk, @@SESSION.sql_mode AS mode')[0]===$beforeSettings,'mode '.$compress.' restores SQL mode and foreign key checking');
        } catch(Throwable $error){
            databaseUtilityExpect(false,'mode '.$compress.': '.get_class($error).': '.$error->getMessage());
            try {unset($backup,$restore);} catch(Throwable $ignored) {}
        }
        Db::execute('DROP TABLE IF EXISTS audit_roundtrip');
    }
    // More than one SELECT page, multiple files, and a complete statement larger than a part.
    foreach ([0,1] as $compress) {
        $folder=$temporary.'/parts-'.$compress;mkdir($folder);
        Db::execute('CREATE TABLE audit_roundtrip (id INT NOT NULL PRIMARY KEY, notes TEXT NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4');
        $fixture=[];
        for($i=1;$i<=1005;$i++){$fixture[]=['id'=>$i,'notes'=>$i===500?str_repeat('large-row-',1000):'row '.$i];}
        Db::table('audit_roundtrip')->insertAll($fixture);
        $expected=Db::query('SELECT * FROM audit_roundtrip ORDER BY id');
        $config=['path'=>$folder.'/','part'=>4096,'compress'=>$compress,'level'=>6];
        $backup=new Database(['name'=>'20260910-010103','part'=>1],$config);
        databaseUtilityExpect($backup->create(),'partitioned create');
        $next=$backup->backup('audit_roundtrip',0);
        databaseUtilityExpect(is_array($next)&&$next[0]===1000,'export stops at a bounded 1000-row page');
        databaseUtilityExpect($backup->backup('audit_roundtrip',$next[0])===0,'last export page finishes');
        databaseUtilityExpect($backup->close(),'partitioned archive flush completes');
        $files=$backup->createdFiles();
        databaseUtilityExpect(count($files)>2,'small partition limit creates multiple numbered parts');
        Db::execute('DELETE FROM audit_roundtrip');
        foreach($files as $index=>$file){
            databaseUtilityExpect(str_ends_with($file,'-'.($index+1).'.sql'.($compress?'.gz':'')),'parts remain contiguous');
            $restore=new Database([$index+1,$file,$compress],$config,'import');
            $streams=count(get_resources('stream'));
            $next=$restore->import(0);
            while(is_array($next)){$next=$restore->import($next[0]);}
            databaseUtilityExpect($next===0&&count(get_resources('stream'))===$streams,'import closes its stream on every part');
            unset($restore);
        }
        databaseUtilityExpect(Db::query('SELECT * FROM audit_roundtrip ORDER BY id')===$expected,'partitioned roundtrip retains all 1005 rows and oversized statement');
        $original=array_map('hash_file',array_fill(0,count($files),'sha256'),$files);
        $collision=new Database(['name'=>'20260910-010103','part'=>1],$config);
        databaseUtilityExpect($collision->create()===false,'an existing backup name must not be reopened for append');
        databaseUtilityExpect(array_map('hash_file',array_fill(0,count($files),'sha256'),$files)===$original,'name collision preserves existing part bytes');
        unset($collision,$backup);
        Db::execute('DROP TABLE audit_roundtrip');
    }
    // Only fixed SQL authored by this regression is executed here; no existing archive is read.
    $legacy=<<<'SQL'
-- legacy header; comment
;
DROP TABLE IF EXISTS `audit_roundtrip`;
CREATE TABLE `audit_roundtrip` (`id` INT PRIMARY KEY, `notes` TEXT NULL) ENGINE=InnoDB;
INSERT INTO `audit_roundtrip` VALUES (1, 'semi;colon'), (2, 'quote\' and \\ slash'); INSERT INTO `audit_roundtrip` VALUES (3, 'multi
line;
value');
/* ordinary ; comment */ INSERT INTO `audit_roundtrip` VALUES (4, NULL);
SQL;
    foreach([0,1] as $compress){
        $file=$temporary.'/legacy.sql'.($compress?'.gz':'');file_put_contents($file,$compress?gzencode($legacy):$legacy);
        $restore=new Database([1,$file,$compress],['path'=>$temporary.'/','compress'=>$compress],'import');
        $next=$restore->import(0);while(is_array($next)){$next=$restore->import($next[0]);}
        databaseUtilityExpect($next===0,'legacy quoted INSERT syntax and comments remain restorable');
        databaseUtilityExpect((Db::query('SELECT notes FROM audit_roundtrip WHERE id=3')[0]['notes']??null)==="multi\nline;\nvalue",'quoted multiline semicolons do not split a statement');
        databaseUtilityExpect(Db::query('SELECT COUNT(*) AS n FROM audit_roundtrip')[0]['n']===4,'multiple statements on one line execute once');
        unset($restore);Db::execute('DROP TABLE audit_roundtrip');
    }
    Db::execute("SET NAMES latin1");
    $encodingBefore=Db::query('SELECT @@SESSION.character_set_client AS client, @@SESSION.character_set_results AS results, @@SESSION.collation_connection AS collation')[0];
    $file=$temporary.'/encoding.sql';file_put_contents($file,'SET NAMES utf8mb4; CREATE TABLE audit_roundtrip (id INT PRIMARY KEY);');
    $restore=new Database([1,$file,0],['path'=>$temporary.'/','compress'=>0],'import');
    databaseUtilityExpect($restore->import(0)===0,'a dump may set its own input encoding');
    databaseUtilityExpect(Db::query('SELECT @@SESSION.character_set_client AS client, @@SESSION.character_set_results AS results, @@SESSION.collation_connection AS collation')[0]===$encodingBefore,'import restores the original client/result encoding and collation');
    unset($restore);
    $writer=new Database(['name'=>'20260910-010106','part'=>1],['path'=>$temporary.'/','compress'=>0]);
    databaseUtilityExpect($writer->create()&&$writer->backup('audit_roundtrip',0)===0&&$writer->close(),'export normalizes its input encoding');
    databaseUtilityExpect(Db::query('SELECT @@SESSION.character_set_client AS client, @@SESSION.character_set_results AS results, @@SESSION.collation_connection AS collation')[0]===$encodingBefore,'export restores the original connection encoding');
    unset($writer);Db::execute('DROP TABLE audit_roundtrip');Db::execute('SET NAMES utf8mb4');
    // Truncation is detected before executing even the leading DROP in a damaged gzip file.
    Db::execute('CREATE TABLE audit_roundtrip (id INT PRIMARY KEY)');Db::execute('INSERT INTO audit_roundtrip VALUES (9)');
    $file=$temporary.'/truncated.sql.gz';file_put_contents($file,substr(gzencode('DROP TABLE audit_roundtrip;'),0,-4));
    $restore=new Database([1,$file,1],['path'=>$temporary.'/','compress'=>1],'import');
    databaseUtilityExpect($restore->import(0)===false,'truncated gzip fails validation');
    databaseUtilityExpect(Db::query('SELECT id FROM audit_roundtrip')[0]['id']===9,'damaged gzip executes no SQL');unset($restore);
    Db::execute('DROP TABLE audit_roundtrip');
    foreach(['missing.sql','empty.sql'] as $name){
        $file=$temporary.'/'.$name;if($name==='empty.sql'){file_put_contents($file,'');}
        $restore=new Database([1,$file,0],['path'=>$temporary.'/','compress'=>0],'import');
        databaseUtilityExpect($restore->import(0)===false,'missing/empty archive returns false');unset($restore);
    }
    $settings=Db::query('SELECT @@SESSION.foreign_key_checks AS fk, @@SESSION.sql_mode AS mode')[0];
    $file=$temporary.'/failure.sql';file_put_contents($file,'CREATE TABLE audit_roundtrip (id INT PRIMARY KEY); INSERT INTO audit_roundtrip (missing) VALUES (1);');
    $restore=new Database([1,$file,0],['path'=>$temporary.'/','compress'=>0],'import');
    databaseUtilityExpect($restore->import(0)===false,'SQL execution failure is a controlled import failure');
    databaseUtilityExpect(Db::query('SELECT @@SESSION.foreign_key_checks AS fk, @@SESSION.sql_mode AS mode')[0]===$settings,'failed import still restores connection settings');
    unset($restore);Db::execute('DROP TABLE IF EXISTS audit_roundtrip');
    foreach(['-- only a comment',"INSERT INTO audit_roundtrip VALUES ('unterminated"] as $invalid){
        $file=$temporary.'/invalid.sql';file_put_contents($file,$invalid);
        $restore=new Database([1,$file,0],['path'=>$temporary.'/','compress'=>0],'import');
        databaseUtilityExpect($restore->import(0)===false,'comment-only and incomplete SQL archives fail');unset($restore);
    }
    foreach([['part'=>[]],['part'=>'wrong'],['level'=>[]],['level'=>10],['compress'=>[]]] as $badConfig){
        try{
            $invalid=new Database(['name'=>'20260910-010105','part'=>1],$badConfig+['path'=>$temporary.'/','compress'=>0]);
            databaseUtilityExpect(false,'invalid scalar backup options must be rejected');unset($invalid);
        }catch(InvalidArgumentException $error){databaseUtilityExpect(true,'invalid scalar backup options are rejected');}
    }
    $blockedName=$temporary.'/20260910-010105-1.sql';mkdir($blockedName);
    $writer=new Database(['name'=>'20260910-010105','part'=>1],['path'=>$temporary.'/','compress'=>0]);
    databaseUtilityExpect($writer->create()===false&&$writer->createdFiles()===[],'unopenable output never becomes a successful backup');unset($writer);rmdir($blockedName);
    class BackupAuditStream {
        public $context;
        public static string $bytes='';
        public static bool $fail=false;
        public function stream_open($path,$mode,$options,&$openedPath){self::$bytes='';return true;}
        public function stream_write($data){if(self::$fail){return 0;} $length=min(3,strlen($data));self::$bytes.=substr($data,0,$length);return $length;}
        public function stream_close(){}
        public function stream_stat(){return [];}
    }
    stream_wrapper_register('backup-audit',BackupAuditStream::class);
    foreach([0,1] as $compress){
        $writer=new Database(['name'=>'20260910-010104','part'=>1],['path'=>$temporary.'/','compress'=>$compress]);
        $property=new ReflectionProperty(Database::class,'fp');
        $property->setValue($writer,fopen('backup-audit://short','wb'));
        $write=new ReflectionMethod(Database::class,'writeBytes');
        BackupAuditStream::$fail=false;
        databaseUtilityExpect($write->invoke($writer,'complete bytes')===true&&BackupAuditStream::$bytes==='complete bytes','short writes complete without dropping a suffix');
        BackupAuditStream::$fail=true;
        databaseUtilityExpect($write->invoke($writer,'failure')===false,'zero-byte writes return failure');
        $writer->close();unset($writer);
    }
    stream_wrapper_unregister('backup-audit');
    if($failures){throw new RuntimeException(implode(PHP_EOL,$failures));}
    echo 'framework_audit_database_utility: '.$checks.' checks passed on PHP '.PHP_VERSION.PHP_EOL;
} finally {
    Db::execute('DROP TABLE IF EXISTS audit_roundtrip');
    $iterator=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($temporary,FilesystemIterator::SKIP_DOTS),RecursiveIteratorIterator::CHILD_FIRST);
    foreach($iterator as $entry){$entry->isDir()?rmdir($entry->getPathname()):unlink($entry->getPathname());}rmdir($temporary);
}
