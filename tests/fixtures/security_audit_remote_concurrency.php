<?php
/** Included by the manual remote suite: actual competing writers and process death without cleanup handlers. */
use think\facade\Db;
$processConfiguration=$configuration;
if(!$mysql){Db::execute('VACUUM INTO ?',[ROOT_PATH.'remote-process.sqlite']);$processConfiguration['connections']['upload']['database']=ROOT_PATH.'remote-process.sqlite';}
file_put_contents(ROOT_PATH.'remote-process.json',json_encode(['database'=>$processConfiguration,'settings'=>$GLOBALS['config']],JSON_THROW_ON_ERROR));
$processDb=$mysql?Db::connect():Db::connect($processConfiguration['connections']['upload']);
function remoteWorker(string $case):array {
    $marker=ROOT_PATH.'remote-worker-'.bin2hex(random_bytes(6));
    $process=proc_open([PHP_BINARY,__DIR__.'/security_audit_remote_worker.php',ROOT_PATH,$case,$marker],
        [0=>['pipe','r'],1=>['file',$marker.'.out','w'],2=>['file',$marker.'.err','w']],$pipes);fclose($pipes[0]);return[$process,$marker];
}
function remoteReady(array $worker):array {
    $until=microtime(true)+10;
    while(!is_file($worker[1].'.ready')&&microtime(true)<$until&&proc_get_status($worker[0])['running']){usleep(10000);clearstatcache();}
    check(is_file($worker[1].'.ready'),'Remote worker did not reach its fault boundary: '.file_get_contents($worker[1].'.out').file_get_contents($worker[1].'.err'));
    return json_decode(file_get_contents($worker[1].'.ready'),true,512,JSON_THROW_ON_ERROR);
}
foreach(['published','provider','before-commit','after-commit'] as $case) {
    $old=$processDb->name('User')->where('user_id',1)->select()->toArray()[0]['user_portrait'];
    $count=count($processDb->name('Annex')->select()->toArray());$worker=remoteWorker($case);$event=remoteReady($worker);
    $visible=$processDb->name('User')->where('user_id',1)->select()->toArray()[0]['user_portrait'];
    check($visible===($case==='after-commit'?$event['path']:$old),'A reader observed the wrong commit boundary');
    $rows=$processDb->name('StorageIntent')->where('local_path',$event['path'])->select()->toArray();
    check($case==='published'?$rows===[]:($rows[0]['reference_state']===($case==='after-commit'?'committed':'pending')),'Killed upload lost or prematurely committed its intent');
    proc_terminate($worker[0],9);proc_close($worker[0]);
    check($processDb->name('User')->where('user_id',1)->select()->toArray()[0]['user_portrait']===$visible
        && count($processDb->name('Annex')->select()->toArray())===$count+($case==='after-commit'?1:0),'SIGKILL split User/Annex commit');
    check(is_file($event['path'])&&is_file($event['stage'].'/manifest.json'),'SIGKILL lost its local candidate or recovery manifest');
    if($case!=='published')check(is_file('remote-fixture/'.$event['intent_id']),'SIGKILL pretended to undo an external object');
}
foreach(['throw-before','throw-after','permissions'] as $case) {
    $old=$processDb->name('User')->where('user_id',1)->select()->toArray()[0]['user_portrait'];$count=count($processDb->name('Annex')->select()->toArray());
    $worker=remoteWorker($case);check(proc_close($worker[0])===0,'Remote COMMIT/permission failure escaped controlled handling');
    $result=json_decode(file_get_contents($worker[1].'.out'),true,512,JSON_THROW_ON_ERROR);
    check($result['code']===0 && $result['calls']===($case==='permissions'?0:1),'Unknown COMMIT returned success or a permission failure reached SDK');
    $selected=$processDb->name('User')->where('user_id',1)->select()->toArray()[0]['user_portrait'];
    check($selected===($case==='throw-after'?$result['event']['path']:$old)
        && count($processDb->name('Annex')->select()->toArray())===$count+($case==='throw-after'?1:0),'COMMIT ambiguity split User/Annex persistence');
    if($case!=='permissions') {
        $manifest=json_decode(file_get_contents($result['event']['stage'].'/manifest.json'),true,512,JSON_THROW_ON_ERROR);
        check($manifest['state']==='commit_outcome_unknown' && is_file($result['event']['path']) && is_file('remote-fixture/'.$result['event']['intent_id']),'Unknown COMMIT deleted a possibly committed local/remote object');
    }
}

// While the first provider is waiting, a second request for the same owner must commit: no User/Annex lock crosses HTTP.
$count=count($processDb->name('Annex')->select()->toArray());$first=remoteWorker('provider');$one=remoteReady($first);
$second=remoteWorker('normal');check(proc_close($second[0])===0,'Second owner upload escaped its normal result');
$two=json_decode(file_get_contents($second[1].'.out'),true,512,JSON_THROW_ON_ERROR);
check($two['code']===1 && $processDb->name('User')->where('user_id',1)->select()->toArray()[0]['user_portrait']===$two['path'],'Network held the owner lock and blocked another request');
file_put_contents($first[1].'.release','continue');check(proc_close($first[0])===0,'First upload could not complete after another owner commit');
$last=json_decode(file_get_contents($first[1].'.out'),true,512,JSON_THROW_ON_ERROR);
check($last['code']===1 && $processDb->name('User')->where('user_id',1)->select()->toArray()[0]['user_portrait']===$last['path']
    && count($processDb->name('Annex')->select()->toArray())===$count+2,'Concurrent final pointer did not select the last complete transaction');
foreach([$last,$two] as $result) {
    $intent=$processDb->name('StorageIntent')->where('local_path',$result['path'])->select()->toArray()[0];
    check($intent['reference_state']==='committed' && !is_file($result['path']) && is_file('remote-fixture/'.$intent['intent_id']),'Concurrent upload lost a retained remote reference or skipped required cleanup');
}
