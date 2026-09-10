<?php
/** Real MySQL and locally generated backup roundtrips; no site bootstrap or existing archive. */
declare(strict_types=1);
namespace app\common\util {
    function fread($stream,$length){if($GLOBALS['cliImportReadFailure']??false){return false;}return \fread($stream,$length);}
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
    'username'=>'root','password'=>getenv('DATABASE_AUDIT_PASSWORD'),'prefix'=>'audit_','charset'=>'utf8mb4','trigger_sql'=>false,'fields_cache'=>false]]];
$app->config->set($dbConfig,'database');
$manager=new think\DbManager();$manager->setConfig($dbConfig);$app->instance('think\DbManager',$manager);
use think\facade\Db;
use app\common\util\Database;
$checks=0;$failures=[];
function databaseUtilityExpect($ok,string $message):void { global $checks,$failures;++$checks;if(!$ok){$failures[]=$message;} }
$temporary='/audit/backup-files-'.getmypid();mkdir($temporary,0700,true);
require dirname(__DIR__).'/application/common.php';
$backup=new app\common\util\DbBackup();
function cliImportRunCommand(array $arguments):array{
    $command=new app\command\DbImport();$input=new think\console\Input($arguments);$input->bind($command->getDefinition());
    $output=new think\console\Output('buffer');
    return [(new ReflectionMethod($command,'execute'))->invoke($command,$input,$output),$output->fetch()];
}
try {
    if(($argv[1]??'')==='--large-import'){
        $file=$temporary.'/large.sql';$stream=fopen($file,'wb');
        $statement="SET @audit_bulk='".str_repeat('a',4096)."';\n";
        for($i=0;$i<12288;$i++){fwrite($stream,$statement);}fclose($stream);
        $count=$backup->import($file);
        if($count!==12288||filesize($file)<=33554432){throw new RuntimeException('large import fixture failed');}
        unlink($file);rmdir($temporary);
        echo 'cli_import_large: '.$count.' statements; peak '.memory_get_peak_usage(true).PHP_EOL;
        exit;
    }
    $file=$temporary.'/legacy.sql';
    $sql=<<<'SQL'
CREATE TABLE `audit_source` (`id` INT PRIMARY KEY, `notes` TEXT);
INSERT INTO `audit_source` VALUES (1, 'literal `audit_source` inside text');
SQL;
    file_put_contents($file,$sql);
    $backup->import($file,['audit_'=>'copy_']);
    databaseUtilityExpect(Db::query('SELECT notes FROM copy_source')[0]['notes']==='literal `audit_source` inside text','prefix remapping never changes quoted data');
    $file=$temporary.'/failure.sql';file_put_contents($file,"SET FOREIGN_KEY_CHECKS=0;\nINSERT INTO audit_missing VALUES (1);");
    Db::execute('SET FOREIGN_KEY_CHECKS=1');
    try{$backup->import($file);databaseUtilityExpect(false,'fixed nonexistent table SQL must fail');}catch(Throwable $error){}
    databaseUtilityExpect(Db::query('SELECT @@SESSION.foreign_key_checks AS fk')[0]['fk']===1,'failed import restores foreign key checks');
    $file=$temporary.'/quoted.sql';
    $sql=<<<'SQL'
-- ordinary comment;
;
DROP TABLE IF EXISTS audit_text;
CREATE TABLE audit_text (id INT PRIMARY KEY, notes TEXT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
INSERT INTO audit_text VALUES (1,'semi;colon'), (2,'quote\' and \\ slash'); INSERT INTO audit_text VALUES (3,'multi
-- this is data
line;
value');
/* comment ; */ INSERT INTO audit_text VALUES (4,NULL), (5,'doubled '' quote');
/*!40101 SET @audit_hint = 1 */;
# ordinary comment
INSERT INTO audit_text VALUES (6,'tail without delimiter')
SQL;
    file_put_contents($file,$sql);$count=$backup->import($file);
    databaseUtilityExpect($count===7,'comments, empty statements, same-line statements and a final undelimited statement are counted correctly');
    databaseUtilityExpect(Db::query('SELECT notes FROM audit_text WHERE id=3')[0]['notes']==="multi\n-- this is data\nline;\nvalue",'multiline strings retain comment-like lines and embedded semicolons');
    databaseUtilityExpect(Db::query('SELECT notes FROM audit_text WHERE id=2')[0]['notes']==="quote' and \\ slash",'backslash escape syntax remains compatible');
    databaseUtilityExpect(Db::query('SELECT notes FROM audit_text WHERE id=5')[0]['notes']==="doubled ' quote",'doubled quote syntax remains compatible');
    databaseUtilityExpect(Db::query('SELECT notes FROM audit_text WHERE id=6')[0]['notes']==='tail without delimiter','old EOF without final semicolon is still supported');
    databaseUtilityExpect(Db::query('SELECT @audit_hint AS hint')[0]['hint']===1,'versioned executable comments remain executable');
    file_put_contents($file,str_replace("\n","\r",$sql));$backup->import($file);
    databaseUtilityExpect(Db::query('SELECT notes FROM audit_text WHERE id=3')[0]['notes']==="multi\r-- this is data\rline;\rvalue",'CR-only files preserve literal line endings');
    $file=$temporary.'/identifiers.sql';
    $sql=<<<'SQL'
CREATE TABLE `audit_odd``table` (`id` INT PRIMARY KEY, `notes` TEXT);
INSERT INTO `audit_odd``table` VALUES (1,'literal `audit_odd` table');
CREATE TABLE `audit_long_item` (`id` INT PRIMARY KEY);
INSERT INTO `audit_long_item` VALUES (2);
SQL;
    file_put_contents($file,$sql);$backup->import($file,['audit_'=>'copy_','audit_long_'=>'mapped_']);
    databaseUtilityExpect(Db::query('SELECT notes FROM `copy_odd``table`')[0]['notes']==='literal `audit_odd` table','escaped identifier backticks remap while data remains unchanged');
    databaseUtilityExpect(Db::query('SELECT id FROM mapped_item')[0]['id']===2,'overlapping mappings select the longest source prefix without cascading');
    file_put_contents($file,'CREATE TABLE `audit_version` (id INT PRIMARY KEY, notes TEXT); /*!40101 INSERT INTO `audit_version` VALUES (9,\'literal `audit_version`\') */;');
    $backup->import($file,['audit_'=>'copy_']);
    databaseUtilityExpect(Db::query('SELECT notes FROM copy_version')[0]['notes']==='literal `audit_version`','versioned executable comments remap identifiers while preserving quoted values');
    $sql=<<<'SQL'
CREATE TABLE `audit_parent` (`audit_id` INT PRIMARY KEY) ENGINE=InnoDB;
CREATE TABLE `audit_child` (`audit_id` INT PRIMARY KEY, `audit_parent_id` INT,
 KEY `audit_idx` (`audit_parent_id`), CONSTRAINT `audit_fk` FOREIGN KEY (`audit_parent_id`) REFERENCES `audit_parent` (`audit_id`),
 CONSTRAINT `audit_positive` CHECK (`audit_id` > 0)) ENGINE=InnoDB;
INSERT INTO `audit_parent` (`audit_id`) VALUES (7);
INSERT INTO `audit_child` (`audit_id`,`audit_parent_id`) VALUES (1,7);
SQL;
    file_put_contents($file,$sql);$backup->import($file);$backup->import($file,['audit_'=>'copy_']);
    databaseUtilityExpect(array_column(Db::query('SHOW COLUMNS FROM copy_child'),'Field')===['audit_id','audit_parent_id'],'table remapping preserves business column names with the same prefix');
    databaseUtilityExpect(Db::query('SELECT * FROM copy_child')[0]===['audit_id'=>1,'audit_parent_id'=>7],'INSERT column lists remain consistent with unchanged schema columns');
    databaseUtilityExpect(count(Db::query("SHOW INDEX FROM copy_child WHERE Key_name='audit_idx'"))===1,'table remapping preserves index names');
    databaseUtilityExpect(Db::query("SELECT REFERENCED_TABLE_NAME AS target FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='copy_child' AND CONSTRAINT_NAME='copy_fk'")[0]['target']==='copy_parent','foreign key table targets and prefixed constraint symbols move to the target namespace');
    databaseUtilityExpect(Db::query('SELECT * FROM audit_child')[0]===['audit_id'=>1,'audit_parent_id'=>7]&&Db::query("SELECT REFERENCED_TABLE_NAME AS target FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='audit_child' AND CONSTRAINT_NAME='audit_fk'")[0]['target']==='audit_parent','same-database cloning leaves the existing source rows and constraints intact');
    databaseUtilityExpect(Db::query("SELECT COUNT(*) AS n FROM information_schema.TABLE_CONSTRAINTS WHERE CONSTRAINT_SCHEMA=DATABASE() AND TABLE_NAME='copy_child' AND CONSTRAINT_NAME='copy_positive' AND CONSTRAINT_TYPE='CHECK'")[0]['n']===1,'prefixed CHECK symbols also avoid the source schema-wide namespace');
    try{Db::execute('INSERT INTO copy_child VALUES (2,999)');databaseUtilityExpect(false,'restored foreign key must be active');}
    catch(think\db\exception\PDOException $error){databaseUtilityExpect(true,'the restored foreign key enforces the remapped parent table');}
    try{Db::execute('INSERT INTO copy_child VALUES (-1,7)');databaseUtilityExpect(false,'restored CHECK must be active');}
    catch(think\db\exception\PDOException $error){databaseUtilityExpect(true,'the restored named CHECK remains active');}
    file_put_contents($file,'ALTER TABLE `audit_child` DROP FOREIGN KEY `audit_fk`; ALTER TABLE `audit_child` DROP CHECK `audit_positive`;');
    $backup->import($file,['audit_'=>'copy_']);
    databaseUtilityExpect(Db::query("SELECT COUNT(*) AS n FROM information_schema.TABLE_CONSTRAINTS WHERE CONSTRAINT_SCHEMA=DATABASE() AND TABLE_NAME='copy_child' AND CONSTRAINT_TYPE IN ('FOREIGN KEY','CHECK')")[0]['n']===0,'explicit FK/CHECK symbol references follow the same namespace mapping');
    databaseUtilityExpect(Db::query("SELECT COUNT(*) AS n FROM information_schema.TABLE_CONSTRAINTS WHERE CONSTRAINT_SCHEMA=DATABASE() AND TABLE_NAME='audit_child' AND CONSTRAINT_TYPE IN ('FOREIGN KEY','CHECK')")[0]['n']===2,'target constraint changes leave source constraints in place');
    file_put_contents($file,'CREATE TABLE '.$database.'.`audit_qualified` (`audit_id` INT PRIMARY KEY); INSERT INTO '.$database.'.`audit_qualified` (`audit_id`) VALUES (5);');
    $backup->import($file,['audit_'=>'copy_']);
    databaseUtilityExpect(Db::query('SELECT audit_id FROM copy_qualified')[0]['audit_id']===5,'a bare database qualifier does not hide the quoted table position');
    file_put_contents($file,'CREATE TABLE `'.$database.'`.`maccms_qualified` (`maccms_id` INT PRIMARY KEY); INSERT INTO `'.$database.'`.`maccms_qualified` (`maccms_id`) VALUES (6);');
    $backup->import($file,['maccms_'=>'mapped_']);
    databaseUtilityExpect(Db::query('SELECT maccms_id FROM mapped_qualified')[0]['maccms_id']===6,'database qualifiers and column names remain unchanged even when they share the source prefix');
    foreach([[''=> 'copy_'],['audit_'=>[]],['audit_'=>'bad;value'],[-1=>'copy_']] as $mapping){
        try{$backup->import($file,$mapping);databaseUtilityExpect(false,'invalid mapping must fail');}
        catch(RuntimeException $error){databaseUtilityExpect(true,'invalid prefix maps fail before SQL execution');}
    }
    file_put_contents($file,'CREATE TABLE `0source` (id INT PRIMARY KEY); INSERT INTO `0source` VALUES (8);');
    $backup->import($file,['0'=>'1']);
    databaseUtilityExpect(Db::query('SELECT id FROM `1source`')[0]['id']===8,'numeric prefix strings survive PHP array-key coercion');
    $file=$temporary.'/modes.sql';
    $sql=<<<'SQL'
SET @audit_saved_mode=@@SESSION.SQL_MODE;
SET SQL_MODE='NO_BACKSLASH_ESCAPES';
DROP TABLE IF EXISTS audit_modes;
CREATE TABLE audit_modes (id INT PRIMARY KEY, notes TEXT) ENGINE=InnoDB;
INSERT INTO audit_modes VALUES (1,'trailing\');
SET SQL_MODE=@audit_saved_mode;
INSERT INTO audit_modes VALUES (2,'escaped\' quote');
SQL;
    file_put_contents($file,$sql);$backup->import($file);
    databaseUtilityExpect(Db::query('SELECT notes FROM audit_modes WHERE id=1')[0]['notes']==='trailing\\','simple NO_BACKSLASH_ESCAPES assignment changes parsing correctly');
    databaseUtilityExpect(Db::query('SELECT notes FROM audit_modes WHERE id=2')[0]['notes']==="escaped' quote",'saved SQL mode restoration changes parsing back');
    Db::execute('SET NAMES latin1');Db::execute('SET SESSION AUTOCOMMIT=0');
    $settings=Db::query('SELECT @@SESSION.sql_mode AS mode,@@SESSION.foreign_key_checks AS fk,@@SESSION.autocommit AS autocommit,@@SESSION.character_set_client AS client,@@SESSION.character_set_results AS results,@@SESSION.collation_connection AS collation')[0];
    $file=$temporary.'/settings.sql';file_put_contents($file,'SET NAMES utf8mb4; SET FOREIGN_KEY_CHECKS=0; SET SQL_MODE=\'\'; SELECT 1;');
    $backup->import($file);
    databaseUtilityExpect(Db::query('SELECT @@SESSION.sql_mode AS mode,@@SESSION.foreign_key_checks AS fk,@@SESSION.autocommit AS autocommit,@@SESSION.character_set_client AS client,@@SESSION.character_set_results AS results,@@SESSION.collation_connection AS collation')[0]===$settings,'successful import restores autocommit, SQL mode, FK, character sets and collation');
    file_put_contents($file,'SET NAMES utf8mb4; SET FOREIGN_KEY_CHECKS=0; SET SQL_MODE=\'\'; INSERT INTO audit_missing VALUES (1);');
    try{$backup->import($file);}catch(RuntimeException $error){}
    databaseUtilityExpect(Db::query('SELECT @@SESSION.sql_mode AS mode,@@SESSION.foreign_key_checks AS fk,@@SESSION.autocommit AS autocommit,@@SESSION.character_set_client AS client,@@SESSION.character_set_results AS results,@@SESSION.collation_connection AS collation')[0]===$settings,'failed import restores all captured session settings');
    Db::execute('SET SESSION AUTOCOMMIT=1');Db::execute('SET NAMES utf8mb4');
    Db::execute('CREATE TABLE audit_guard (id INT PRIMARY KEY) ENGINE=InnoDB');Db::execute('INSERT INTO audit_guard VALUES (9)');
    foreach(["/*!40101 SET SQL_MODE='NO_BACKSLASH_ESCAPES' */;","/*!40101 SET @audit_old_mode=@@SQL_MODE, SQL_MODE='NO_BACKSLASH_ESCAPES' */;"] as $conditionalMode){
        foreach([[],['audit_'=>'copy_']] as $map){
            $file=$temporary.'/conditional-mode.sql';file_put_contents($file,'DROP TABLE audit_guard; '.$conditionalMode);
            try{$backup->import($file,$map);databaseUtilityExpect(false,'conditional mode must fail preflight');}
            catch(RuntimeException $error){databaseUtilityExpect(Db::query('SELECT id FROM audit_guard')[0]['id']===9,'conditional SQL_MODE assignments are rejected before a leading DROP');}
        }
    }
    $file=$temporary.'/mode-expression.sql';
    foreach(["SET SQL_MODE=CONCAT(@@SQL_MODE, ',NO_BACKSLASH_ESCAPES');","SET `sql_mode`='NO_BACKSLASH_ESCAPES';","SET SQL_MODE='ANSI_QUOTES';","SET SQL_MODE='ANSI';","/*!40101 SET `sql_mode`='NO_BACKSLASH_ESCAPES' */;"] as $unsupportedMode){
        file_put_contents($file,'DROP TABLE audit_guard; '.$unsupportedMode);
        try{$backup->import($file);databaseUtilityExpect(false,'untracked mode expression must fail preflight');}
        catch(RuntimeException $error){databaseUtilityExpect(Db::query('SELECT id FROM audit_guard')[0]['id']===9,'unsupported SQL_MODE/identifier quoting variants are rejected before SQL execution');}
    }
    file_put_contents($file,"/*!40101 SET @audit_mode_text='SQL_MODE=NO_BACKSLASH_ESCAPES' */;");
    $backup->import($file);
    databaseUtilityExpect(Db::query('SELECT @audit_mode_text AS value')[0]['value']==='SQL_MODE=NO_BACKSLASH_ESCAPES','literal SQL_MODE text is not mistaken for a session assignment');
    $file=$temporary.'/truncated.sql';file_put_contents($file,"DROP TABLE audit_guard; INSERT INTO audit_text VALUES (99,'unterminated");
    try{$backup->import($file);databaseUtilityExpect(false,'incomplete quote must fail preflight');}
    catch(RuntimeException $error){databaseUtilityExpect(Db::query('SELECT id FROM audit_guard')[0]['id']===9,'lexical truncation fails before the leading DROP executes');}
    foreach(['','-- comment only', '/* unterminated'] as $empty){
        file_put_contents($file,$empty);$streams=count(get_resources('stream'));
        try{$backup->import($file);databaseUtilityExpect(false,'empty or incomplete input must fail');}
        catch(RuntimeException $error){databaseUtilityExpect(count(get_resources('stream'))===$streams,'invalid input releases its file handle');}
    }
    file_put_contents($file,'INSERT INTO audit_guard VALUES (10);');$GLOBALS['cliImportReadFailure']=true;
    try{$backup->import($file);databaseUtilityExpect(false,'read failure must fail');}
    catch(RuntimeException $error){databaseUtilityExpect(Db::query('SELECT COUNT(*) AS n FROM audit_guard')[0]['n']===1,'stream read failure executes no SQL');}
    $GLOBALS['cliImportReadFailure']=false;
    Db::startTrans();Db::execute('INSERT INTO audit_guard VALUES (11)');
    try{$backup->import($file);databaseUtilityExpect(false,'caller transaction must be rejected');}
    catch(RuntimeException $error){databaseUtilityExpect(Db::connect()->getPdo()->inTransaction()&&Db::query('SELECT COUNT(*) AS n FROM audit_guard')[0]['n']===2,'rejected import leaves the caller transaction intact');}
    Db::rollback();
    file_put_contents($file,'BEGIN; INSERT INTO audit_guard VALUES (12); COMMIT;');
    databaseUtilityExpect($backup->import($file)===3&&Db::query('SELECT COUNT(*) AS n FROM audit_guard')[0]['n']===2,'complete dump transactions execute normally');
    file_put_contents($file,'BEGIN; INSERT INTO audit_guard VALUES (13);');
    try{$backup->import($file);databaseUtilityExpect(false,'open transaction at EOF must fail');}
    catch(RuntimeException $error){databaseUtilityExpect(!Db::connect()->getPdo()->inTransaction()&&Db::query('SELECT COUNT(*) AS n FROM audit_guard')[0]['n']===2,'unfinished dump transactions are rolled back and reported');}
    symlink($file,$temporary.'/linked.sql');
    foreach([null,[],true,'',$temporary.'/missing.sql',$temporary,$temporary.'/linked.sql'] as $badFile){
        try{$backup->import($badFile);databaseUtilityExpect(false,'invalid file must fail');}
        catch(RuntimeException $error){databaseUtilityExpect(true,'invalid file boundary is controlled');}
    }
    file_put_contents($file,"\xEF\xBB\xBFSET @audit_bom=7;");
    databaseUtilityExpect($backup->import($file)===1&&Db::query('SELECT @audit_bom AS n')[0]['n']===7,'UTF-8 BOM is accepted without changing SQL data');
    file_put_contents($file,"DROP TABLE audit_guard;\nDELIMITER $$\nCREATE PROCEDURE audit_unused() BEGIN SELECT 1; END$$");
    try{$backup->import($file);databaseUtilityExpect(false,'unsupported delimiter script must fail preflight');}
    catch(RuntimeException $error){databaseUtilityExpect(Db::query('SELECT COUNT(*) AS n FROM audit_guard')[0]['n']===2,'unsupported DELIMITER fails before leading SQL executes');}
    file_put_contents($file,'CREATE TABLE `audit_command` (id INT PRIMARY KEY, notes TEXT); INSERT INTO `audit_command` VALUES (1,\'literal `audit_command`\');');
    foreach([['--src-prefix=audit_'],['--dst-prefix=command_'],['--src-prefix=audit_;','--dst-prefix=command_']] as $options){
        [$exit,$message]=cliImportRunCommand(array_merge(['--file='.$file],$options));
        databaseUtilityExpect($exit===2,'partial/invalid prefix CLI options do not silently restore to the original namespace');
    }
    [$exit,$message]=cliImportRunCommand(['--file='.$file,'--src-prefix=audit_','--dst-prefix=command_']);
    databaseUtilityExpect($exit===0&&str_contains($message,'恢复完成')&&Db::query('SELECT notes FROM command_command')[0]['notes']==='literal `audit_command`','real command performs prefix remapping without rewriting payloads');
    file_put_contents($file,'INSERT INTO audit_missing VALUES (1);');
    [$exit,$message]=cliImportRunCommand(['--file='.$file]);databaseUtilityExpect($exit===6,'real command returns nonzero on SQL errors');
    [$exit,$message]=cliImportRunCommand([]);databaseUtilityExpect($exit===2,'real command requires an input file');
    $process=proc_open([PHP_BINARY,'-d','memory_limit=32M',__FILE__,'--large-import'],[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);
    if(!is_resource($process)){throw new RuntimeException('Cannot create isolated memory regression process');}
    fclose($pipes[0]);$stdout=stream_get_contents($pipes[1]);$stderr=stream_get_contents($pipes[2]);fclose($pipes[1]);fclose($pipes[2]);$exit=proc_close($process);
    databaseUtilityExpect($exit===0,'SQL file larger than the memory limit imports: '.substr($stderr,0,500));
    databaseUtilityExpect(str_contains($stdout,'cli_import_large: 12288 statements'),'large streaming import executes every statement');
    if($exit===0){echo trim($stdout).PHP_EOL;}
    if($failures){throw new RuntimeException(implode(PHP_EOL,$failures));}
    echo 'framework_audit_cli_import: '.$checks.' checks passed on PHP '.PHP_VERSION.PHP_EOL;
} finally {
    Db::execute('SET FOREIGN_KEY_CHECKS=1');Db::execute('DROP TABLE IF EXISTS audit_source,copy_source,audit_text,`copy_odd``table`,mapped_item,copy_version,audit_modes,audit_guard,`1source`,command_command,copy_child,copy_parent,audit_child,audit_parent,copy_qualified,mapped_qualified');
    $iterator=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($temporary,FilesystemIterator::SKIP_DOTS),RecursiveIteratorIterator::CHILD_FIRST);
    foreach($iterator as $entry){$entry->isDir()&&!$entry->isLink()?rmdir($entry->getPathname()):unlink($entry->getPathname());}rmdir($temporary);
}
}
