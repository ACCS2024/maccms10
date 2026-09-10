<?php
/** Included by the storage suite; real concurrent connections and SIGKILL at the external-effect boundary. */
use think\facade\Db;
use app\common\util\StorageIntent;
use app\common\util\StoragePublicUrl;
$processDatabase=$database;
if (!$mysql) {
    Db::execute('VACUUM INTO ?',[ROOT_PATH.'process.sqlite']);
    $processDatabase['connections']['storage']['database']=ROOT_PATH.'process.sqlite';
}
file_put_contents(ROOT_PATH.'process.json',json_encode(['database'=>$processDatabase,'settings'=>$GLOBALS['config']['upload']['api']],JSON_THROW_ON_ERROR));
$processDb=$mysql?Db::connect():Db::connect($processDatabase['connections']['storage']);
function storageWorker(string $id,string $mode):array {
    $marker=ROOT_PATH.'worker-'.bin2hex(random_bytes(6));
    $process=proc_open([PHP_BINARY,__DIR__.'/security_audit_storage_worker.php',ROOT_PATH,$id,$mode,$marker],
        [0=>['pipe','r'],1=>['file',$marker.'.out','w'],2=>['file',$marker.'.err','w']],$pipes);
    fclose($pipes[0]);return[$process,$marker];
}
function storageReady(array $worker):void {
    $until=microtime(true)+10;
    while (!is_file($worker[1].'.ready') && microtime(true)<$until && proc_get_status($worker[0])['running']){usleep(10000);clearstatcache();}
    check(is_file($worker[1].'.ready'),'Storage worker did not reach provider boundary: '.file_get_contents($worker[1].'.out').file_get_contents($worker[1].'.err'));
}
// Prepare in the same actual DB used by both workers, with a temporary manager binding for the SQLite copy.
$oldManager=think\Container::getInstance()->make('think\\DbManager');
$newManager=new think\DbManager();$newManager->setConfig($processDatabase);
think\Container::getInstance()->instance('think\\DbManager',$newManager);
try {
    foreach (['release','kill'] as $ending) {
        $path=storageFile();$row=StorageIntent::prepare($path,StoragePublicUrl::current('s3'));
        // Fully consume reads; a deliberately open SQLite read cursor would block the writer's COMMIT.
        $first=storageWorker($row['intent_id'],'pause');storageReady($first);
        $second=storageWorker($row['intent_id'],'normal');check(proc_close($second[0])===0,'Concurrent claimant escaped an error');
        $denied=json_decode(file_get_contents($second[1].'.out'),true,512,JSON_THROW_ON_ERROR);
        check($denied['outcome']==='rejected' && $denied['provider_calls']===0,'Concurrent claimant submitted the same object again');
        $observed=$processDb->name('StorageIntent')->where('intent_id',$row['intent_id'])->select()->toArray()[0];
        check($observed['transfer_state']==='attempting' && $observed['reference_state']==='pending','Pre-provider intent was not visible outside the worker transaction');
        if ($ending==='kill') {proc_terminate($first[0],9);proc_close($first[0]);}
        else {file_put_contents($first[1].'.release','continue');check(proc_close($first[0])===0,'First transfer did not complete');}
        $observed=$processDb->name('StorageIntent')->where('intent_id',$row['intent_id'])->select()->toArray()[0];
        check($observed['transfer_state']===($ending==='kill'?'attempting':'remote_confirmed') && $observed['reference_state']==='pending','Process completion/kill changed the reference state');
        check(is_file($path) && is_file(ROOT_PATH.'remote-object-'.$row['intent_id']),'Process kill triggered a fake local/remote rollback');
        $calls=file(ROOT_PATH.'provider-calls.log',FILE_IGNORE_NEW_LINES|FILE_SKIP_EMPTY_LINES);
        check(count(array_filter($calls,fn($id)=>$id===$row['intent_id']))===1,'Concurrent attempts reached the provider more than once');
    }
} finally {think\Container::getInstance()->instance('think\\DbManager',$oldManager);}
