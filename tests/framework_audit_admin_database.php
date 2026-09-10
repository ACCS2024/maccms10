<?php
/** Real Request/controller/backup utility and dedicated MySQL; no site bootstrap. */
declare(strict_types=1);
namespace app\admin\controller {
    // Failure injection is confined to filesystem syscalls; controller, codec, Request and MySQL stay real.
    function link($source,$destination){
        $GLOBALS['adminAuditLinks']=($GLOBALS['adminAuditLinks']??0)+1;
        if (($GLOBALS['adminAuditFailLink']??0)===$GLOBALS['adminAuditLinks']) { return false; }
        return \link($source,$destination);
    }
    function fwrite($stream,$data){
        $name=stream_get_meta_data($stream)['uri']??'';
        if (($GLOBALS['adminAuditFailWrite']??'')==='lock' && basename($name)==='backup.lock') { return 0; }
        if (($GLOBALS['adminAuditFailWrite']??'')==='manifest' && str_ends_with($name,'.json')) { return 0; }
        return \fwrite($stream,$data);
    }
    function unlink($filename){
        if (($GLOBALS['adminAuditFailUnlink']??'')!=='' && str_ends_with($filename,$GLOBALS['adminAuditFailUnlink'])) { return false; }
        return \unlink($filename);
    }
}
namespace {
require dirname(__DIR__).'/vendor/autoload.php';
error_reporting(E_ALL);
set_error_handler(static function($level,$message,$file,$line) {
    if (!(error_reporting() & $level)) { return false; }
    throw new ErrorException($message,0,$level,$file,$line);
});
$database=getenv('DATABASE_AUDIT_DATABASE') ?: '';
if (!preg_match('/^maccms_audit_backup_[a-f0-9]+$/D',$database) || getenv('DATABASE_AUDIT_MYSQL_SOCKET')!=='/audit/mysql.sock') {
    throw new RuntimeException('Only the dedicated disposable backup database is allowed');
}
$temporary='/audit/admin-backup-'.getmypid();mkdir($temporary,0700,true);
define('ROOT_PATH',$temporary.'/');
$app=new think\App($temporary.'/app/');
$dbConfig=['default'=>'audit','connections'=>['audit'=>['type'=>'mysql','socket'=>'/audit/mysql.sock','database'=>$database,
    'username'=>'root','password'=>getenv('DATABASE_AUDIT_PASSWORD'),'prefix'=>'audit_','charset'=>'utf8mb4','trigger_sql'=>false,'fields_cache'=>false]]];
$app->config->set($dbConfig,'database');
$manager=new think\DbManager();$manager->setConfig($dbConfig);$app->instance('think\DbManager',$manager);
use think\facade\Db;
function lang($key){return $key;}
class AdminDatabaseAuditController extends app\admin\controller\Database {
    public array $view=[];
    public function __construct(think\Request $request){$this->request=$request;}
    protected function success($msg='',$url=null,$data='',$wait=3){return ['code'=>1,'msg'=>$msg,'data'=>$data];}
    protected function error($msg='',$url=null,$data='',$wait=3){return ['code'=>0,'msg'=>$msg,'data'=>$data];}
    protected function assign($name,$value=''):void{$this->view[$name]=$value;}
    protected function fetch(string $template='',array $vars=[]):string{return $template;}
}
$checks=0;$failures=[];
function adminDatabaseExpect($ok,string $message):void{global $checks,$failures;++$checks;if(!$ok){$failures[]=$message;}}
function adminDatabaseCall(string $action,array $arguments=[],string $method='POST',int $time=1788998400,array $params=[]){
    global $app;
    $request=(new think\Request())->withServer(['REQUEST_METHOD'=>$method,'REQUEST_TIME'=>$time])->withGet($params);
    $app->instance('request',$request);
    $controller=new AdminDatabaseAuditController($request);
    return [$controller->$action(...$arguments),$controller];
}
function adminDatabaseConfig($path):void{$GLOBALS['config']=['db'=>['backup_path'=>$path,'part_size'=>4096,'compress'=>0,'compress_level'=>6]];}
try {
    Db::execute('CREATE TABLE audit_backup (id INT PRIMARY KEY, notes TEXT) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4');
    Db::execute("INSERT INTO audit_backup VALUES (1,'fixture')");
    $path=$temporary.'/normal';mkdir($path);adminDatabaseConfig($path);
    foreach([['import',[[1]]],['del',[[1]]],['export',[[['bad']]]]] as [$action,$arguments]){
        try{[$result]=adminDatabaseCall($action,$arguments);adminDatabaseExpect($result['code']===0,$action.' rejects array scalar arguments');}
        catch(Throwable $error){adminDatabaseExpect(false,$action.' throws '.get_class($error).': '.$error->getMessage());}
    }
    mkdir($path.'/20260910-000000-1.sql');
    try{[$result]=adminDatabaseCall('export',[['audit_backup']]);adminDatabaseExpect($result['code']===0,'output collision must never report success');}
    catch(Throwable $error){adminDatabaseExpect(false,'export collision throws '.get_class($error).': '.$error->getMessage());}
    rmdir($path.'/20260910-000000-1.sql');
    foreach ([null,[],[1],true,1.5,'wrong','1 OR 1=1','../file',str_repeat('9',50),0,-1] as $id) {
        foreach (['import','del'] as $action) {
            [$result]=adminDatabaseCall($action,[$id]);adminDatabaseExpect($result['code']===0,$action.' rejects invalid archive identifiers');
        }
    }
    foreach ([1,[],false,'bad'] as $start) {
        [$result]=adminDatabaseCall('export',[['audit_backup'],$start]);adminDatabaseExpect($result['code']===0,'export rejects cross-request or malformed offsets');
    }
    [$result]=adminDatabaseCall('export',[['not_a_current_table']]);adminDatabaseExpect($result['code']===0,'unknown tables cannot enter backup SQL');
    foreach([null,true,42,1.5,[],[''],[['nested']],['audit_backup; SELECT 1']] as $ids){
        [$result]=adminDatabaseCall('export',[$ids]);adminDatabaseExpect($result['code']===0,'malformed table selections fail before SQL or file output');
    }
    foreach (['export'=>[['audit_backup']], 'import'=>[1788998400], 'del'=>[1788998400]] as $action=>$arguments) {
        [$result]=adminDatabaseCall($action,$arguments,'GET');adminDatabaseExpect($result['code']===0,$action.' requires the existing UI POST contract');
    }
    foreach ([[],null,'','../escape',$temporary.'/blocked-path'] as $badPath) {
        if(is_string($badPath)&&str_ends_with($badPath,'blocked-path')) {file_put_contents($badPath,'fixture');}
        adminDatabaseConfig($badPath);
        [$result]=adminDatabaseCall('export',[['audit_backup']]);adminDatabaseExpect($result['code']===0,'invalid/uncreatable configured paths fail without PHP errors');
        [$result]=adminDatabaseCall('index',[],'GET',1788998400,['group'=>'import']);adminDatabaseExpect(is_array($result)&&$result['code']===0,'archive listing controls configured directory errors');
    }
    adminDatabaseConfig($path);
    foreach([['part_size'=>[]],['part_size'=>0],['compress'=>[]],['compress_level'=>[]],['compress_level'=>10]] as $invalid){
        foreach($invalid as $key=>$value){$GLOBALS['config']['db'][$key]=$value;}
        [$result]=adminDatabaseCall('export',[['audit_backup']],'POST',1788998401);
        adminDatabaseExpect($result['code']===0&&(glob($path.'/.backup-*')?:[])===[]&&!file_exists($path.'/.20260910-000001.pending'),'bad scalar backup options are controlled and clean their temporary state');
        adminDatabaseConfig($path);
    }
    $fixture=[];for($i=2;$i<=32;$i++){$fixture[]=['id'=>$i,'notes'=>str_repeat('row '.$i.' 中文;\n',40)];}
    Db::table('audit_backup')->insertAll($fixture);
    Db::execute('CREATE TABLE audit_other_admin (id INT PRIMARY KEY, notes TEXT) ENGINE=InnoDB');
    Db::execute("INSERT INTO audit_other_admin VALUES (1,'admin fixture')");
    $expected=Db::query('SELECT * FROM audit_backup ORDER BY id');
    foreach([0,1] as $compress){
        $GLOBALS['config']['db']['compress']=$compress;$time=1788998410+$compress;$name=date('Ymd-His',$time);
        [$result]=adminDatabaseCall('export',[['audit_other_admin','audit_backup','audit_backup']], 'POST',$time);
        adminDatabaseExpect($result['code']===1,'valid selected tables export synchronously');
        $files=glob($path.'/'.$name.'-*.sql'.($compress?'.gz':''));
        adminDatabaseExpect(count($files)>2,'controller publishes all numbered parts');
        adminDatabaseExpect(is_file($path.'/.'.$name.'.json')&&!file_exists($path.'/.'.$name.'.pending'),'complete archive has a manifest and no pending marker');
        adminDatabaseExpect((glob($path.'/.backup-*')?:[])===[],'private staging files disappear after completion');
        $manifest=json_decode(file_get_contents($path.'/.'.$name.'.json'),true);
        adminDatabaseExpect(count($manifest['parts'])===count($files),'manifest records every part including final part');
        $hashes=array_map(static fn($file)=>hash_file('sha256',$file),$files);
        [$result]=adminDatabaseCall('export',[['audit_backup']],'POST',$time);
        adminDatabaseExpect($result['code']===0&&$hashes===array_map(static fn($file)=>hash_file('sha256',$file),$files),'timestamp collision never overwrites an earlier archive');
        $last=end($manifest['parts']);$lastFile=$path.'/'.$last['name'];rename($lastFile,$lastFile.'.hold');
        [$result]=adminDatabaseCall('import',[(string)$time]);
        adminDatabaseExpect($result['code']===0&&Db::query('SELECT * FROM audit_backup ORDER BY id')===$expected,'missing final part is detected before executing any SQL');
        rename($lastFile.'.hold',$lastFile);
        $saved=file_get_contents($lastFile);file_put_contents($lastFile,str_repeat('X',strlen($saved)));
        [$result]=adminDatabaseCall('import',[$time]);
        adminDatabaseExpect($result['code']===0&&Db::query('SELECT * FROM audit_backup ORDER BY id')===$expected,'same-length tampering fails all-part hashes before SQL');
        file_put_contents($lastFile,$saved);
        $manifestFile=$path.'/.'.$name.'.json';$manifestBytes=file_get_contents($manifestFile);unlink($manifestFile);
        [$result]=adminDatabaseCall('import',[$time]);adminDatabaseExpect($result['code']===0,'new codec archives cannot masquerade as legacy when manifest is missing');
        file_put_contents($manifestFile,$manifestBytes);
        Db::execute('DELETE FROM audit_backup');Db::execute('DELETE FROM audit_other_admin');
        [$result]=adminDatabaseCall('import',[$time]);
        adminDatabaseExpect($result['code']===1&&Db::query('SELECT * FROM audit_backup ORDER BY id')===$expected,'controller restores real multipart '.($compress?'gzip':'plain').' data');
        adminDatabaseExpect(Db::query('SELECT notes FROM audit_other_admin')[0]['notes']==='admin fixture','selected administrator table is preserved');
        [$result,$controller]=adminDatabaseCall('index',[],'GET',1788998400,['group'=>'import']);
        adminDatabaseExpect($result==='admin@database/import'&&isset($controller->view['list'][date('Y-m-d H:i:s',$time)]),'completed archive is listed under its real absolute configured path');
        $lock=fopen($path.'/backup.lock','r+b');flock($lock,LOCK_EX);
        foreach (['export'=>[['audit_backup']], 'import'=>[$time], 'del'=>[$time]] as $action=>$arguments) {
            [$result]=adminDatabaseCall($action,$arguments,'POST',$time+100);
            adminDatabaseExpect($result['code']===0&&$result['msg']==='admin/database/lock_check',$action.' shares the exclusive backup lock');
        }
        flock($lock,LOCK_UN);fclose($lock);
        adminDatabaseExpect($hashes===array_map(static fn($file)=>hash_file('sha256',$file),$files),'contending requests leave existing archives intact');
        $loose=$path.'/'.$name.'-1.sql.extra';file_put_contents($loose,'unrelated fixture');
        [$result]=adminDatabaseCall('del',[$time]);
        adminDatabaseExpect($result['code']===1&&(glob($path.'/'.$name.'-*.sql'.($compress?'.gz':''))?:[])===[],'deletion removes all exact archive parts');
        adminDatabaseExpect(is_file($loose)&&!is_file($manifestFile),'deletion preserves loose suffix files and removes manifest');unlink($loose);
    }
    // Traditional archives are still restored by the real controller/codec without a new manifest.
    foreach([0,1] as $compress){
        $time=1788998440+$compress;$name=date('Ymd-His',$time);
        $sql="-- Think MySQL Data Transfer\nDROP TABLE IF EXISTS audit_legacy; CREATE TABLE audit_legacy (id INT PRIMARY KEY, notes TEXT); INSERT INTO audit_legacy VALUES (1,'legacy;\nvalue');";
        $file=$path.'/'.$name.'-1.sql'.($compress?'.gz':'');file_put_contents($file,$compress?gzencode($sql):$sql);
        [$result]=adminDatabaseCall('import',[$time]);
        adminDatabaseExpect($result['code']===1&&Db::query('SELECT notes FROM audit_legacy')[0]['notes']==="legacy;\nvalue",'legacy '.($compress?'gzip':'plain').' archive restores through the controller');
        [$result]=adminDatabaseCall('del',[$time]);adminDatabaseExpect($result['code']===1&&!file_exists($file),'legacy archive remains deletable');
    }
    $time=1788998450;$name=date('Ymd-His',$time);
    $fixtureSql='CREATE TABLE audit_never_executed (id INT);';
    file_put_contents($path.'/'.$name.'-1.sql',$fixtureSql);file_put_contents($path.'/'.$name.'-3.sql',$fixtureSql);
    [$result]=adminDatabaseCall('import',[$time]);adminDatabaseExpect($result['code']===0,'legacy missing middle part is rejected');
    rename($path.'/'.$name.'-3.sql',$path.'/'.$name.'-2.sql.gz');
    [$result]=adminDatabaseCall('import',[$time]);adminDatabaseExpect($result['code']===0,'mixed compression parts are rejected');
    [$result]=adminDatabaseCall('del',[$time]);adminDatabaseExpect($result['code']===1,'incomplete legacy archives can be deleted safely by their identifier');
    $outside=$temporary.'/outside.sql';file_put_contents($outside,$fixtureSql);
    symlink($outside,$path.'/'.$name.'-1.sql');
    foreach(['import','del'] as $action){[$result]=adminDatabaseCall($action,[$time]);adminDatabaseExpect($result['code']===0&&file_get_contents($outside)===$fixtureSql,$action.' refuses a file symlink');}
    unlink($path.'/'.$name.'-1.sql');
    unlink($path.'/backup.lock');symlink($outside,$path.'/backup.lock');
    [$result]=adminDatabaseCall('export',[['audit_backup']]);adminDatabaseExpect($result['code']===0&&file_get_contents($outside)===$fixtureSql,'lock symlink never truncates its target');unlink($path.'/backup.lock');
    link($outside,$path.'/backup.lock');
    [$result]=adminDatabaseCall('export',[['audit_backup']]);adminDatabaseExpect($result['code']===0&&file_get_contents($outside)===$fixtureSql,'lock hardlink never truncates its target');unlink($path.'/backup.lock');
    // Fail after actual DDL/export work and after one part was published.
    $GLOBALS['config']['db']['compress']=0;
    foreach(['publish','manifest','lock','view'] as $failure){
        $time=1788998460;$name=date('Ymd-His',$time);
        $GLOBALS['adminAuditLinks']=0;$GLOBALS['adminAuditFailLink']=$failure==='publish'?2:0;
        $GLOBALS['adminAuditFailWrite']=in_array($failure,['manifest','lock'],true)?$failure:'';
        if($failure==='view'){Db::execute('CREATE VIEW audit_backup_view AS SELECT id FROM audit_backup');}
        [$result]=adminDatabaseCall('export',[[$failure==='view'?'audit_backup_view':'audit_backup']],'POST',$time);
        adminDatabaseExpect($result['code']===0,'failed '.$failure.' never reports backup success');
        adminDatabaseExpect((glob($path.'/'.$name.'-*.sql*')?:[])===[]&&!file_exists($path.'/.'.$name.'.json')&&!file_exists($path.'/.'.$name.'.pending'),'failed '.$failure.' removes owned visible output');
        adminDatabaseExpect((glob($path.'/.backup-*')?:[])===[],'failed '.$failure.' removes owned staging files');
        $lock=fopen($path.'/backup.lock','r+b');adminDatabaseExpect(flock($lock,LOCK_EX|LOCK_NB),'failed '.$failure.' releases its lock');flock($lock,LOCK_UN);fclose($lock);
        $GLOBALS['adminAuditFailWrite']='';$GLOBALS['adminAuditFailLink']=0;
        if($failure==='view'){Db::execute('DROP VIEW audit_backup_view');}
    }
    // An interrupted job marker stays unavailable, and administrative deletion can clean it up.
    $time=1788998470;$name=date('Ymd-His',$time);
    [$result]=adminDatabaseCall('export',[['audit_backup']],'POST',$time);adminDatabaseExpect($result['code']===1,'a stale unlocked lock file permits the next complete job');
    file_put_contents($path.'/.'.$name.'.pending','simulated interrupted publication');
    [$result]=adminDatabaseCall('import',[$time]);adminDatabaseExpect($result['code']===0,'pending publication never becomes restorable');
    [$result,$controller]=adminDatabaseCall('index',[],'GET',1788998400,['group'=>'import']);
    adminDatabaseExpect(!isset($controller->view['list'][date('Y-m-d H:i:s',$time)]),'pending publication is absent from the usable archive list');
    [$result]=adminDatabaseCall('del',[$time]);adminDatabaseExpect($result['code']===1&&!file_exists($path.'/.'.$name.'.pending'),'explicit deletion can clean an interrupted archive');
    // A real unlink failure is reported, and a subsequent attempt can delete the remainder.
    $time=1788998480;$name=date('Ymd-His',$time);
    [$result]=adminDatabaseCall('export',[['audit_backup']],'POST',$time);adminDatabaseExpect($result['code']===1,'prepare deletion failure fixture');
    $GLOBALS['adminAuditFailUnlink']='-2.sql';[$result]=adminDatabaseCall('del',[$time]);
    adminDatabaseExpect($result['code']===0,'failed unlink is not reported as successful deletion');$GLOBALS['adminAuditFailUnlink']='';
    [$result]=adminDatabaseCall('del',[$time]);adminDatabaseExpect($result['code']===1,'a partially deleted archive is recoverably deletable');
    adminDatabaseConfig('relative/nested');
    [$result]=adminDatabaseCall('export',[['audit_backup']],'POST',1788998490);
    adminDatabaseExpect($result['code']===1&&is_file($temporary.'/relative/nested/.'.date('Ymd-His',1788998490).'.json'),'relative configured backup directory resolves under ROOT_PATH');
    Db::execute('CREATE TABLE `audit_odd``table` (`id` INT PRIMARY KEY)');Db::execute('INSERT INTO `audit_odd``table` VALUES (7)');
    [$result]=adminDatabaseCall('export',[['audit_odd`table']],'POST',1788998500);
    adminDatabaseExpect($result['code']===1,'an actual unusual table name is backed up with identifier quoting');
    Db::execute('DELETE FROM `audit_odd``table`');[$result]=adminDatabaseCall('import',[1788998500]);
    adminDatabaseExpect($result['code']===1&&Db::query('SELECT id FROM `audit_odd``table`')[0]['id']===7,'quoted identifier roundtrip does not alter the SQL boundary');
    if($failures){throw new RuntimeException(implode(PHP_EOL,$failures));}
    echo 'framework_audit_admin_database: '.$checks.' checks passed on PHP '.PHP_VERSION.PHP_EOL;
} finally {
    Db::execute('DROP VIEW IF EXISTS audit_backup_view');
    Db::execute('DROP TABLE IF EXISTS audit_backup,audit_other_admin,audit_legacy,audit_never_executed,`audit_odd``table`');
    $iterator=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($temporary,FilesystemIterator::SKIP_DOTS),RecursiveIteratorIterator::CHILD_FIRST);
    foreach($iterator as $entry){$entry->isDir()&&!$entry->isLink()?rmdir($entry->getPathname()):unlink($entry->getPathname());}rmdir($temporary);
}
}
