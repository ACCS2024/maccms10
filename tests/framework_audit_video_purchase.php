<?php
/** Real installation video schema, production routes, read policy and atomic purchase coordinator. */
declare(strict_types=1);
require __DIR__.'/fixtures/purchase_csrf.php';
use think\facade\Db;
use app\common\util\ContentPassword;

function videoPurchase(string $target,array $fields=[],array $cookies=[]):array{
    $result=purchaseCsrfRoute($target,purchaseCsrfBody($fields),[],$cookies,['Authorization'=>'Bearer '.purchaseCsrfBearer()]);
    $encoded=json_encode($result['data'],JSON_THROW_ON_ERROR);
    foreach(['fixture.invalid','VIDEO-','fixturepw','user_pwd','user_random','vod_play_url','vod_down_url']as $secret){
        check(!str_contains($encoded,$secret),'A purchase response cannot expose account credentials, content passwords or resource URLs');
    }
    return $result['data'];
}
function videoPolicy(string $flag='play',array $parameters=[]):array{
    $row=Db::name('Vod')->where('vod_id',17)->find();
    $row['vod_'.$flag.'_list']=mac_play_list($row['vod_'.$flag.'_from'],$row['vod_'.$flag.'_url'],$row['vod_'.$flag.'_server'],$row['vod_'.$flag.'_note'],$flag);
    $previous=$GLOBALS['user'];$user=Db::name('User')->where('user_id',1)->find();
    if((int)$user['group_id']>2&&(int)$user['user_end_time']<time())$user['group_id']=2;
    $GLOBALS['user']=$user;
    try{
        $controller=(new ReflectionClass(PurchaseCsrfIndex::class))->newInstanceWithoutConstructor();
        return (new ReflectionMethod($controller,'check_vod_resource_access'))->invoke($controller,$row,$flag,$parameters+['sid'=>2,'nid'=>3]);
    }finally{$GLOBALS['user']=$previous;}
}
function videoReject(string $target,array $fields=[],?int $code=null,array $cookies=[]):array{
    $state=purchaseCsrfState();$result=videoPurchase($target,$fields,$cookies);
    check($result['code']>1&&($code===null||$result['code']===$code)&&purchaseCsrfState()===$state,
        'A denied video purchase must preserve every account, ledger and receipt');return $result;
}
function videoGroup(array $permissions):void{
    Db::name('Group')->where('group_id',2)->update(['group_popedom'=>json_encode([1=>$permissions])]);
    $groups=(new \app\common\model\Group())->listData([],'group_id')['list'];
    \think\facade\Cache::set('purchase_csrf_group_list',$groups);
}

foreach(['user/ajax_buy_popedom','payment/buy_popedom']as $target){
    foreach([4=>'play',5=>'down']as $type=>$flag){
        foreach([0,1]as $whole){
            purchaseCsrfSeed();$GLOBALS['config']['user']['vod_points_type']=$whole;
            // Establish the actual permission decision before buying, then prove the same selected resource becomes readable.
            check(purchaseCsrfRoute('user/write_token',[],[],purchaseCsrfCookies(),[],'GET')['data']['code']===1,'Normal token GET initializes the content-password session');
            $before=videoPolicy($flag);check($before['code']===($type===4?3003:4003)&&$before['confirm']===1,'Actual read policy must request this purchase');
            $result=videoPurchase($target,['type'=>$type]);$points=$whole?40:($type===4?20:30);
            $receipt=Db::name('Ulog')->where('ulog_id','>',0)->find();
            check($receipt!==null,'Committed receipt missing for '.$target.' '.$flag.' whole='.$whole.': '.json_encode($result));
            check($result['code']===1&&(int)Db::name('User')->where('user_id',1)->value('user_points')===100-$points
                &&(int)$receipt['ulog_sid']===($whole?0:2)&&(int)$receipt['ulog_nid']===($whole?0:3)&&(int)$receipt['ulog_points']===$points,
                'A real purchase must debit the current server price and store only its canonical coordinates');
            check(videoPolicy($flag)['can_access']===true,'The actual read policy must recognize the committed receipt');
            $state=purchaseCsrfState();check(videoPurchase($target,['type'=>$type])['code']===1&&purchaseCsrfState()===$state,'A repeat actual purchase must return success without a second charge');
        }
    }
    foreach([['vod_status'=>0],['vod_recycle_time'=>time()],['vod_play_from'=>''],['vod_play_url'=>''],['vod_down_url'=>'']]as $changes){
        purchaseCsrfSeed();Db::name('Vod')->where('vod_id',17)->update($changes);videoReject($target,['type'=>isset($changes['vod_down_url'])?5:4],1002);
    }
    foreach([0,1]as $whole){
        purchaseCsrfSeed();$GLOBALS['config']['user']['vod_points_type']=$whole;
        foreach([['sid'=>0],['nid'=>0],['sid'=>3],['nid'=>4],['sid'=>256],['nid'=>65536]]as $bad)videoReject($target,$bad);
        Db::name('Vod')->where('vod_id',17)->update(['vod_play_url'=>'One$https://fixture.invalid/VIDEO-ONE$$$One$https://fixture.invalid/VIDEO-ONE##Three$https://fixture.invalid/VIDEO-THREE']);
        videoReject($target,['nid'=>2],1002);
    }
    purchaseCsrfSeed();$body=['mid'=>1,'id'=>17,'type'=>4];
    $result=purchaseCsrfRoute($target,$body,[],[],['Authorization'=>'Bearer '.purchaseCsrfBearer()]);
    check($result['data']['code']===1&&(int)Db::name('Ulog')->value('ulog_sid')===1&&(int)Db::name('Ulog')->value('ulog_nid')===1,'Omitted video coordinates follow the read API default 1/1');
    foreach(['free','vip','system_disabled']as $scenario){
        purchaseCsrfSeed();
        if($scenario==='free')Db::name('Vod')->where('vod_id',17)->update(['vod_points_play'=>0]);
        if($scenario==='vip')Db::name('User')->where('user_id',1)->update(['group_id'=>3,'user_end_time'=>time()+3600]);
        if($scenario==='system_disabled')$GLOBALS['config']['user']['status']=0;
        $state=purchaseCsrfState();check(videoPurchase($target)['code']===1&&purchaseCsrfState()===$state,'Already accessible '.$scenario.' content must not debit or create a fake entitlement');
    }
    purchaseCsrfSeed();videoGroup([3=>0,4=>0,5=>1]);videoReject($target,[],3001);videoReject($target,['type'=>5],3001);
    videoGroup([3=>0,4=>0,5=>0]);videoReject($target,[],3001);
    purchaseCsrfSeed();Db::name('Group')->where('group_id',2)->update(['group_status'=>0]);videoReject($target,[],3001);
    purchaseCsrfSeed();Db::name('Group')->where('group_id',2)->delete();videoReject($target,[],3001);
    purchaseCsrfSeed();Db::name('User')->where('user_id',1)->update(['group_id'=>3,'user_end_time'=>time()-60,'user_points'=>10]);
    videoReject($target,[],$target==='payment/buy_popedom'?1005:2002);
    check((int)Db::name('User')->where('user_id',1)->value('group_id')===3,'Expired VIP refusal must not persist a membership downgrade');
    foreach([4=>'play',5=>'down']as $type=>$flag){
        purchaseCsrfSeed();Db::name('Vod')->where('vod_id',17)->update(['vod_pwd_'.$flag=>'fixturepw']);
        videoReject($target,['type'=>$type],6001);
        $token=purchaseCsrfRoute('user/write_token',[],[],purchaseCsrfCookies(),[],'GET');
        $row=Db::name('Vod')->where('vod_id',17)->find();check(ContentPassword::verifyVod($row,$flag,'fixturepw')['code']===1,'Normal content password verification must establish a scoped session grant');
        $app->session->save();$cookies=['fixture_session'=>$token['session_id']];
        check(videoPurchase($target,['type'=>$type],$cookies)['code']===1,'A verified content password permits the ordinary paid purchase path');
        Db::name('Vod')->where('vod_id',17)->update(['vod_pwd_'.$flag=>'changedpw']);videoReject($target,['type'=>$type],6001,$cookies);
    }
    foreach(['user','plog','ulog']as $table){
        purchaseCsrfSeed();$event=$table==='user'?'UPDATE':'INSERT';
        $failure=$mysql?"FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='Isolated video failure'":"BEGIN SELECT RAISE(ABORT,'Isolated video failure'); END";
        Db::execute('CREATE TRIGGER audit_video_failure BEFORE '.$event.' ON audit_'.$table.' '.$failure);
        try{videoReject($target);}finally{Db::execute('DROP TRIGGER audit_video_failure');}
        check(videoPurchase($target)['code']===1,'A normal purchase remains retryable after removing its isolated storage failure');
    }
    purchaseCsrfSeed();$state=purchaseCsrfState();Db::startTrans();
    try{videoReject($target);check(Db::connect()->getPdo()->inTransaction(),'Rejecting a nested video purchase cannot close the caller transaction');}
    finally{Db::rollback();}
    check(purchaseCsrfState()===$state,'Nested video purchases are rejected with no hidden caller writes');
    foreach(['vod_points','vod_points_play','vod_points_down']as $field){
        purchaseCsrfSeed();$GLOBALS['config']['user']['vod_points_type']=$field==='vod_points'?1:0;
        if($mysql)Db::execute('ALTER TABLE audit_vod MODIFY '.$field.' VARCHAR(16) NOT NULL DEFAULT \'0\'');
        else Db::execute('PRAGMA ignore_check_constraints=ON');
        try{
            foreach([-1,65536,'bad','1.5']as $price){
                Db::execute('UPDATE audit_vod SET '.$field.'=? WHERE vod_id=17',[(string)$price]);
                check((string)Db::query('SELECT '.$field.' AS price FROM audit_vod WHERE vod_id=17')[0]['price']===(string)$price,'The legacy malformed price fixture must retain its actual stored bytes');
                videoReject($target,['type'=>$field==='vod_points_down'?5:4],1002);
            }
        }finally{
            Db::name('Vod')->where('vod_id',17)->update([$field=>0]);
            if($mysql)Db::execute('ALTER TABLE audit_vod MODIFY '.$field.' SMALLINT UNSIGNED NOT NULL DEFAULT 0');
            else Db::execute('PRAGMA ignore_check_constraints=OFF');
        }
    }
}
if($mysql){
    foreach(['user','group','vod','plog','ulog']as $table){
        purchaseCsrfSeed();Db::execute('ALTER TABLE audit_'.$table.' ENGINE=MyISAM');
        try{videoReject('user/ajax_buy_popedom');}finally{Db::execute('ALTER TABLE audit_'.$table.' ENGINE=InnoDB');}
    }
    $workerTemp=audit_temp_dir('video-purchase-workers');$workers=[];
    register_shutdown_function(static function()use($workerTemp,&$workers):void{
        foreach($workers as $worker){
            if(!is_resource($worker['process']))continue;
            if(proc_get_status($worker['process'])['running'])proc_terminate($worker['process'],9);
            foreach($worker['pipes']as $pipe)if(is_resource($pipe))fclose($pipe);
            proc_close($worker['process']);
        }
        audit_remove_temp($workerTemp);
    });
    function videoWorker(array $fields=[],string $target='user/ajax_buy_popedom'):int{
        global $workerTemp,$workers;
        $id=count($workers);$arguments=['ready'=>$workerTemp.'/'.$id.'.ready','barrier'=>$workerTemp.'/'.$id.'.go',
            'target'=>$target,'body'=>purchaseCsrfBody($fields),'bearer'=>purchaseCsrfBearer()];
        $process=proc_open([PHP_BINARY,__DIR__.'/fixtures/video_purchase_worker.php',json_encode($arguments,JSON_THROW_ON_ERROR)],
            [0=>['file','/dev/null','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);
        $workers[]=['process'=>$process,'pipes'=>$pipes,'arguments'=>$arguments];
        $deadline=microtime(true)+10;
        while(!is_file($arguments['ready'])){
            if(microtime(true)>$deadline||!proc_get_status($process)['running'])throw new RuntimeException('Video worker failed to initialize');usleep(10000);
        }
        $workers[$id]['thread']=(int)file_get_contents($arguments['ready']);file_put_contents($arguments['barrier'],'go');return $id;
    }
    function videoWaiting(int $id,string $table):void{
        global $workers;
        $deadline=microtime(true)+10;
        do{
            $sql=Db::query('SELECT INFO AS query FROM information_schema.PROCESSLIST WHERE ID=?',[$workers[$id]['thread']]);
            $sql=$sql[0]['query']??'';
            if(str_contains($sql,'audit_'.$table)&&str_contains(strtoupper($sql),'FOR UPDATE')){check(true,'The real buyer must wait for the held '.$table.' row lock');return;}
            if(!proc_get_status($workers[$id]['process'])['running'])throw new RuntimeException('Buyer exited before acquiring '.$table.' lock');usleep(10000);
        }while(microtime(true)<$deadline);
        throw new RuntimeException('Buyer did not wait on the expected '.$table.' lock');
    }
    function videoWorkerResult(int $id):array{
        global $workers;
        $worker=&$workers[$id];$deadline=microtime(true)+15;
        do{$status=proc_get_status($worker['process']);if(!$status['running'])break;if(microtime(true)>$deadline)throw new RuntimeException('Video worker completion timed out');usleep(10000);}while(true);
        $output=stream_get_contents($worker['pipes'][1]);$error=stream_get_contents($worker['pipes'][2]);
        foreach($worker['pipes']as $pipe)fclose($pipe);$code=proc_close($worker['process']);$worker['process']=null;
        check(($code===0||$status['exitcode']===0)&&$error==='','Real concurrent video buyer must finish without PHP diagnostics: '.$error);
        return json_decode($output,true,32,JSON_THROW_ON_ERROR);
    }
    foreach(['price','unpublish','recycle','source','episode','password','group_vip','group_deny','group_expired','permission','group_type','group_deleted','group_disabled','unrelated_permission','balance','random','disabled','vod_price']as $scenario){
        purchaseCsrfSeed();
        Db::name('Group')->insert(['group_id'=>4,'group_name'=>'Denied','group_status'=>1,'group_type'=>'1,','group_popedom'=>'{}']);
        if($scenario==='group_expired')Db::name('User')->where('user_id',1)->update(['group_id'=>3,'user_end_time'=>time()+3600]);
        $table=$scenario==='vod_price'?'Vod':'User';Db::startTrans();
        try{
            Db::name($table)->where(strtolower($table).'_id',$table==='Vod'?17:1)->lock(true)->find();
            $worker=videoWorker([],str_starts_with($scenario,'group_')?'payment/buy_popedom':'user/ajax_buy_popedom');
            videoWaiting($worker,strtolower($table));
            $vod=[];$user=[];
            switch($scenario){
                case 'price':case 'vod_price':$vod=['vod_points_play'=>35];break;
                case 'unpublish':$vod=['vod_status'=>0];break;
                case 'recycle':$vod=['vod_recycle_time'=>time()];break;
                case 'source':$vod=['vod_play_from'=>''];break;
                case 'episode':$vod=['vod_play_url'=>'One$https://fixture.invalid/VIDEO-ONE$$$One$https://fixture.invalid/VIDEO-ONE'];break;
                case 'password':$vod=['vod_pwd_play'=>'fixturepw'];break;
                case 'group_vip':$user=['group_id'=>3,'user_end_time'=>time()+3600];break;
                case 'group_deny':$user=['group_id'=>4,'user_end_time'=>time()+3600];break;
                case 'group_expired':$user=['user_end_time'=>time()-60];break;
                case 'permission':Db::name('Group')->where('group_id',2)->update(['group_popedom'=>'{}']);break;
                case 'group_type':Db::name('Group')->where('group_id',2)->update(['group_type'=>'']);break;
                case 'group_deleted':Db::name('Group')->where('group_id',2)->delete();break;
                case 'group_disabled':Db::name('Group')->where('group_id',2)->update(['group_status'=>0]);break;
                case 'unrelated_permission':Db::name('Group')->where('group_id',2)->update(['group_popedom'=>json_encode([1=>[3=>1,4=>0,5=>0]])]);break;
                case 'balance':$user=['user_points'=>10];break;
                case 'random':$user=['user_random'=>str_repeat('c',32)];break;
                case 'disabled':$user=['user_status'=>0];break;
            }
            if($vod)Db::name('Vod')->where('vod_id',17)->update($vod);
            if($user)Db::name('User')->where('user_id',1)->update($user);
            $before=purchaseCsrfState();Db::commit();
        }catch(Throwable $error){Db::rollback();throw $error;}
        $result=videoWorkerResult($worker);
        if(in_array($scenario,['price','vod_price','group_expired','unrelated_permission'],true)){
            $points=in_array($scenario,['group_expired','unrelated_permission'],true)?20:35;
            check($result['code']===1&&(int)Db::name('User')->where('user_id',1)->value('user_points')===100-$points
                &&Db::name('Ulog')->count()===1&&(int)Db::name('Ulog')->value('ulog_points')===$points,'A waiting buyer must charge the newly locked price/group in scenario '.$scenario);
            if($scenario==='group_expired')check((int)Db::name('User')->where('user_id',1)->value('group_id')===3,'Lock-wait expiry changes only effective permissions, never stored membership');
        }else{
            check(($scenario==='group_vip'?$result['code']===1:$result['code']>1)&&purchaseCsrfState()===$before,
                'A waiting buyer must honor current '.$scenario.' state with zero financial/account writes');
            if(in_array($scenario,['permission','group_type'],true))check(str_contains($result['msg'],'权限已更新'),'A stale relevant permission cache must prompt retry without charging');
        }
    }
    foreach(['same','limited']as $scenario){
        purchaseCsrfSeed();if($scenario==='limited')Db::name('User')->where('user_id',1)->update(['user_points'=>30]);
        Db::startTrans();$ids=[];
        try{
            Db::name('User')->where('user_id',1)->lock(true)->find();
            foreach([[1,1],[1,2],[2,1],[2,2]]as [$sid,$nid]){$id=videoWorker($scenario==='same'?[]:['sid'=>$sid,'nid'=>$nid]);videoWaiting($id,'user');$ids[]=$id;}
            Db::commit();
        }catch(Throwable $error){Db::rollback();throw $error;}
        $codes=[];foreach($ids as $id)$codes[]=videoWorkerResult($id)['code'];sort($codes);
        check($codes===($scenario==='same'?[1,1,1,1]:[1,2002,2002,2002])&&Db::name('Ulog')->count()===1&&Db::name('Plog')->count()===4
            &&(int)Db::name('User')->where('user_id',1)->value('user_points')===($scenario==='same'?80:10),
            'Concurrent real routes must grant only the affordable distinct resource and never double-charge a repeat');
    }
}
fwrite(STDOUT,'Video purchase resource audit passed ('.$checks.' checks; '.($mysql?'MySQL non-strict':'SQLite').")\n");
