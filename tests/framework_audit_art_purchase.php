<?php
/** Actual article installation schema, purchase routes, reading policy and shared financial transaction. */
declare(strict_types=1);
require __DIR__.'/fixtures/purchase_csrf.php';
use think\facade\Db;
use app\common\util\ContentPassword;
use app\common\util\ContentResource;

function artPurchaseBody(array $fields=[]):array{return $fields+['mid'=>2,'type'=>1,'id'=>17,'sid'=>2,'nid'=>0];}
function artPurchase(string $target,array $fields=[],array $cookies=[]):array{
    $result=purchaseCsrfRoute($target,artPurchaseBody($fields),[],$cookies,['Authorization'=>'Bearer '.purchaseCsrfBearer()])['data'];
    $encoded=json_encode($result,JSON_THROW_ON_ERROR);
    foreach(['CHAPTER-','fixturepw','art_content','art_pwd','user_pwd','user_random']as $secret){
        check(!str_contains($encoded,$secret),'Article purchase responses must not expose chapter bodies, passwords or account credentials');
    }
    return $result;
}
function artPurchaseReject(string $target,array $fields=[],?int $code=null,array $cookies=[]):array{
    $before=purchaseCsrfState();$result=artPurchase($target,$fields,$cookies);
    check($result['code']>1&&($code===null||$code===$result['code'])&&purchaseCsrfState()===$before,
        'A rejected article purchase must preserve every account, receipt and ledger');return $result;
}
function artPurchasePolicy(int $page=2):array{
    $row=Db::name('Art')->where('art_id',17)->find();$previous=$GLOBALS['user'];
    $user=Db::name('User')->where('user_id',1)->find();
    if(max(explode(',',(string)$user['group_id']))>2&&(int)$user['user_end_time']<time())$user['group_id']=2;
    $GLOBALS['user']=$user;
    try{
        $controller=(new ReflectionClass(PurchaseCsrfIndex::class))->newInstanceWithoutConstructor();
        return (new ReflectionMethod($controller,'check_art_resource_access'))->invoke($controller,$row,['id'=>17,'page'=>$page]);
    }finally{$GLOBALS['user']=$previous;}
}
function artPurchaseGroup(array $permissions,string $types='1,'):void{
    Db::name('Group')->where('group_id',2)->update(['group_type'=>$types,'group_popedom'=>json_encode([1=>$permissions])]);
    $groups=(new \app\common\model\Group())->listData([],'group_id')['list'];
    \think\facade\Cache::set('purchase_csrf_group_list',$groups);
}
foreach(['user/ajax_buy_popedom','payment/buy_popedom']as $target){
    foreach([0,1]as $whole){
        purchaseCsrfSeed();$GLOBALS['config']['user']['art_points_type']=$whole;
        purchaseCsrfRoute('user/write_token',[],[],purchaseCsrfCookies(),[],'GET');
        $permission=artPurchasePolicy();check($permission['code']===3003&&$permission['confirm']===1,'The actual chapter read policy requests this purchase');
        $result=artPurchase($target,['ulog_points'=>0,'user_id'=>999]);$points=$whole?40:20;
        $receipt=Db::name('Ulog')->where('ulog_id','>',0)->find();
        check($receipt!==null,'Article purchase did not commit its receipt: '.json_encode($result));
        check($result['code']===1&&(int)Db::name('User')->where('user_id',1)->value('user_points')===100-$points
            &&(int)$receipt['user_id']===1&&(int)$receipt['ulog_mid']===2&&(int)$receipt['ulog_sid']===($whole?0:2)
            &&(int)$receipt['ulog_nid']===0&&(int)$receipt['ulog_points']===$points&&Db::name('Plog')->count()===4,
            'The actual article route must debit its server quote and create the verified owner canonical receipt');
        check(artPurchasePolicy()['can_access']===true,'The newly purchased chapter must actually become readable');
        $state=purchaseCsrfState();check(artPurchase($target)['code']===1&&purchaseCsrfState()===$state,'A repeated article request must not debit or create another receipt');
    }
    purchaseCsrfSeed();
    $result=purchaseCsrfRoute($target,artPurchaseBody(),['mid'=>1,'id'=>999,'sid'=>1,'nid'=>8],[],['Authorization'=>'Bearer '.purchaseCsrfBearer()]);
    check($result['data']['code']===1&&(int)Db::name('Ulog')->value('ulog_sid')===2,'Query coordinates cannot override the actual article POST chapter');
    purchaseCsrfSeed();check(artPurchase($target,['sid'=>255])['code']===1&&(int)Db::name('Ulog')->value('ulog_sid')===3
        &&artPurchasePolicy(999)['can_access']===true,'Article last-page clamping must occur before both charging and receipt lookup');
    $state=purchaseCsrfState();check(artPurchase($target,['sid'=>3])['code']===1&&purchaseCsrfState()===$state,'An explicit actual last page must match the prior clamped receipt');
    purchaseCsrfSeed();$body=['mid'=>2,'type'=>1,'id'=>17];
    $result=purchaseCsrfRoute($target,$body,[],[],['Authorization'=>'Bearer '.purchaseCsrfBearer()]);
    check($result['data']['code']===1&&(int)Db::name('Ulog')->value('ulog_sid')===1,'Omitted article coordinates retain the default first real chapter');
    foreach([0,1]as $whole){
        purchaseCsrfSeed();$GLOBALS['config']['user']['art_points_type']=$whole;
        foreach([['sid'=>0],['sid'=>256],['nid'=>1],['sid'=>[]],['nid'=>[]],['type'=>4]]as $bad)artPurchaseReject($target,$bad);
        Db::name('Art')->where('art_id',17)->update(['art_content'=>'CHAPTER-ONE$$$$$$CHAPTER-THREE']);
        artPurchaseReject($target,[],1002);
        check(artPurchase($target,['sid'=>3])['code']===1,'A normal nonempty article chapter remains purchasable beside an empty chapter');
    }
    foreach([['art_status'=>0],['art_recycle_time'=>time()],['art_content'=>''],['art_content'=>'$$$$$$']]as $changes){
        purchaseCsrfSeed();Db::name('Art')->where('art_id',17)->update($changes);artPurchaseReject($target,[],1002);
    }
    purchaseCsrfSeed();Db::name('Art')->where('art_id',17)->delete();artPurchaseReject($target,[],1002);
    purchaseCsrfSeed();Db::name('Art')->where('art_id',17)->update(['art_points_detail'=>0]);
    check(artPurchase($target)['code']===1&&(int)Db::name('Ulog')->value('ulog_points')===40,'Detail price zero retains the established overall article price fallback');
    foreach(['free','vip','system_disabled']as $scenario){
        purchaseCsrfSeed();
        if($scenario==='free')Db::name('Art')->where('art_id',17)->update(['art_points'=>0,'art_points_detail'=>0]);
        if($scenario==='vip')Db::name('User')->where('user_id',1)->update(['group_id'=>3,'user_end_time'=>time()+3600]);
        if($scenario==='system_disabled')$GLOBALS['config']['user']['status']=0;
        $state=purchaseCsrfState();check(artPurchase($target)['code']===1&&purchaseCsrfState()===$state,
            'Already readable '.$scenario.' article content must not debit or create a meaningless receipt');
    }
    foreach(['permissions','category']as $scenario){
        purchaseCsrfSeed();artPurchaseGroup($scenario==='permissions'?[3=>0]:[3=>1],$scenario==='category'?'':'1,');
        check(artPurchase($target)['code']===1&&artPurchasePolicy()['can_access']===true,
            'An article member without '.$scenario.' access can still purchase and read that exact chapter');
        $state=purchaseCsrfState();check(artPurchase($target)['code']===1&&purchaseCsrfState()===$state,'A paid receipt also prevents repeat charging for a category-restricted member');
    }
    purchaseCsrfSeed();artPurchaseGroup([3=>0]);Db::name('Art')->where('art_id',17)->update(['art_points'=>0,'art_points_detail'=>0]);
    Db::name('Ulog')->insert(['user_id'=>1,'ulog_mid'=>2,'ulog_type'=>1,'ulog_rid'=>17,'ulog_sid'=>2,'ulog_nid'=>0,'ulog_points'=>0,'ulog_time'=>time()]);
    artPurchaseReject($target,[],3001);
    foreach([['user_id'=>2],['ulog_sid'=>1],['ulog_points'=>19]]as $different){
        purchaseCsrfSeed();Db::name('Ulog')->insert($different+['user_id'=>1,'ulog_mid'=>2,'ulog_type'=>1,'ulog_rid'=>17,'ulog_sid'=>2,'ulog_nid'=>0,'ulog_points'=>20,'ulog_time'=>time()]);
        check(artPurchase($target)['code']===1&&Db::name('Ulog')->count()===2
            &&(int)Db::name('User')->where('user_id',1)->value('user_points')===80,
            'Another owner, chapter or price receipt cannot substitute for the selected article entitlement');
    }
    foreach(['disabled','deleted']as $scenario){
        purchaseCsrfSeed();if($scenario==='deleted')Db::name('Group')->where('group_id',2)->delete();
        else Db::name('Group')->where('group_id',2)->update(['group_status'=>0]);
        artPurchaseReject($target,[],3001);
        purchaseCsrfSeed();Db::name('User')->where('user_id',1)->update(['group_id'=>'2,3','user_end_time'=>time()+3600]);
        if($scenario==='deleted')Db::name('Group')->where('group_id',3)->delete();
        else Db::name('Group')->where('group_id',3)->update(['group_status'=>0]);
        artPurchaseReject($target,[],3001);
    }
    purchaseCsrfSeed();Db::name('User')->where('user_id',1)->update(['group_id'=>3,'user_end_time'=>time()-60,'user_points'=>10]);
    artPurchaseReject($target,[],$target==='payment/buy_popedom'?1005:2002);
    check((int)Db::name('User')->where('user_id',1)->value('group_id')===3,'An expired article member refusal must not persist a group downgrade');
    purchaseCsrfSeed();Db::name('Art')->where('art_id',17)->update(['art_pwd'=>'fixturepw']);artPurchaseReject($target,[],6001);
    $session=purchaseCsrfRoute('user/write_token',[],[],purchaseCsrfCookies(),[],'GET');
    check(ContentPassword::verifyArt(Db::name('Art')->where('art_id',17)->find(),'fixturepw')['code']===1,'Normal content-password verification establishes a genuine article grant');
    $app->session->save();$cookies=['fixture_session'=>$session['session_id']];
    check(artPurchase($target,[],$cookies)['code']===1,'A normally verified article password enables the existing paid chapter flow');
    Db::name('Art')->where('art_id',17)->update(['art_pwd'=>'changedpw']);artPurchaseReject($target,[],6001,$cookies);
    foreach(['user','plog','ulog']as $table){
        purchaseCsrfSeed();$event=$table==='user'?'UPDATE':'INSERT';
        $failure=$mysql?"FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='Isolated article failure'":"BEGIN SELECT RAISE(ABORT,'Isolated article failure'); END";
        Db::execute('CREATE TRIGGER audit_art_failure BEFORE '.$event.' ON audit_'.$table.' '.$failure);
        try{artPurchaseReject($target);}finally{Db::execute('DROP TRIGGER audit_art_failure');}
        check(artPurchase($target)['code']===1,'A normal article purchase remains retryable after its isolated write fault is removed');
    }
    purchaseCsrfSeed();Db::startTrans();
    try{artPurchaseReject($target);check(Db::connect()->getPdo()->inTransaction(),'Rejecting nested article purchase preserves the caller transaction');}
    finally{Db::rollback();}
    foreach(['art_points','art_points_detail']as $field){
        purchaseCsrfSeed();$GLOBALS['config']['user']['art_points_type']=$field==='art_points'?1:0;
        if($mysql)Db::execute('ALTER TABLE audit_art MODIFY '.$field.' VARCHAR(16) NOT NULL DEFAULT \'0\'');
        else Db::execute('PRAGMA ignore_check_constraints=ON');
        try{foreach([-1,65536,'bad','1.5']as $price){
            Db::execute('UPDATE audit_art SET '.$field.'=? WHERE art_id=17',[(string)$price]);
            check((string)Db::query('SELECT '.$field.' AS price FROM audit_art WHERE art_id=17')[0]['price']===(string)$price,'The explicit legacy price fixture retains its actual invalid bytes');
            artPurchaseReject($target,[],1002);
        }}finally{
            Db::name('Art')->where('art_id',17)->update([$field=>0]);
            if($mysql)Db::execute('ALTER TABLE audit_art MODIFY '.$field.' SMALLINT UNSIGNED NOT NULL DEFAULT 0');
            else Db::execute('PRAGMA ignore_check_constraints=OFF');
        }
    }
    purchaseCsrfSeed();Db::name('User')->where('user_id',1)->update(['user_points'=>70000]);Db::name('Art')->where('art_id',17)->update(['art_points_detail'=>65535]);
    check(artPurchase($target)['code']===1&&(int)Db::name('User')->where('user_id',1)->value('user_points')===4465,'The actual receipt price upper bound remains purchasable without narrowing or overflow');
    purchaseCsrfSeed();$chapters=implode('$$$',array_fill(0,300,'CHAPTER-LONG'));Db::name('Art')->where('art_id',17)->update(['art_content'=>$chapters]);
    $row=Db::name('Art')->where('art_id',17)->find();$context=ContentResource::artContext($row,['page'=>300]);
    check($context['page']===300&&!$context['purchase_supported'],'A long individual chapter remains outside the sid storage limit');artPurchaseReject($target,['sid'=>300]);
    $GLOBALS['config']['user']['art_points_type']=1;$context=ContentResource::artContext($row,['page'=>300]);
    check($context['purchase_supported']&&$context['purchase_page']===1,'Whole-article purchase supplies a valid actual chapter even for a long article');
    check(artPurchase($target,['sid'=>$context['purchase_page']])['code']===1&&(int)Db::name('Ulog')->value('ulog_sid')===0
        &&artPurchasePolicy(300)['can_access']===true,'The frontend purchase_page convention buys a real chapter then grants the whole long article');
}
// A real cache refresh during policy evaluation must never turn the locked current group into a different fee decision.
foreach([false,true]as $allowed){
    purchaseCsrfSeed();Db::name('User')->where('user_id',1)->update(['group_id'=>3,'user_end_time'=>time()+3600]);
    Db::name('Group')->where('group_id',3)->update(['group_popedom'=>json_encode([1=>[3=>$allowed?1:0]])]);
    $groups=(new \app\common\model\Group())->listData([],'group_id')['list'];
    \think\facade\Cache::set('purchase_csrf_group_list',$groups);
    purchaseCsrfRoute('user/write_token',[],[],purchaseCsrfCookies(),[],'GET');$before=purchaseCsrfState();
    $result=\app\common\util\ArtPurchase::buy(Db::name('User')->where('user_id',1)->find(),artPurchaseBody(),
        static function(array $row,array $coordinates)use($groups,$allowed):array{
            $groups[3]['group_popedom'][1][3]=$allowed?0:1;
            \think\facade\Cache::set('purchase_csrf_group_list',$groups);
            $controller=(new ReflectionClass(PurchaseCsrfIndex::class))->newInstanceWithoutConstructor();
            return(new ReflectionMethod($controller,'check_art_resource_access'))->invoke($controller,$row,$coordinates);
        });
    check($result['code']===3001&&str_contains($result['msg'],'权限已更新')&&purchaseCsrfState()===$before,
        'A cache refresh during the real article policy callback must request a retry without a false grant or debit');
}
purchaseCsrfSeed();$before=purchaseCsrfState();
$result=\app\common\util\ContentPurchase::buyArt(1,static fn($user)=>['code'=>1,'record'=>[
    'ulog_mid'=>1,'ulog_type'=>4,'ulog_rid'=>17,'ulog_sid'=>2,'ulog_nid'=>3,'ulog_points'=>20]]);
check($result['code']===2003&&purchaseCsrfState()===$before,'The internal article quote cannot create a receipt for a different resource kind');
purchaseCsrfSeed();$GLOBALS['user']=['user_id'=>999,'fixture_context'=>'preserved'];$previous=$GLOBALS['user'];$before=purchaseCsrfState();
$result=\app\common\util\ArtPurchase::buy(Db::name('User')->where('user_id',1)->find(),artPurchaseBody(),
    static function(array $row,array $coordinates):array{throw new RuntimeException('Isolated policy interruption');});
check($result['code']===2003&&$GLOBALS['user']===$previous&&purchaseCsrfState()===$before,
    'A policy interruption must roll back the transaction and restore the original server identity context');
// The generic real-route worker is shared with video; its name is historical and it does not stub either resource.
if($mysql){
    foreach(['user','group','art','plog','ulog']as $table){
        purchaseCsrfSeed();Db::execute('ALTER TABLE audit_'.$table.' ENGINE=MyISAM');
        try{artPurchaseReject('user/ajax_buy_popedom');artPurchaseReject('payment/buy_popedom');}
        finally{Db::execute('ALTER TABLE audit_'.$table.' ENGINE=InnoDB');}
    }
    purchaseCsrfSeed();Db::execute('ALTER TABLE audit_vod ENGINE=MyISAM');
    try{check(artPurchase('user/ajax_buy_popedom')['code']===1,'An article transaction does not require an unrelated video table to be transactional');}
    finally{Db::execute('ALTER TABLE audit_vod ENGINE=InnoDB');}
    $artWorkerTemp=audit_temp_dir('article-purchase-workers');$artWorkers=[];
    register_shutdown_function(static function()use($artWorkerTemp,&$artWorkers):void{
        foreach($artWorkers as $worker){
            if(!is_resource($worker['process']))continue;
            if(proc_get_status($worker['process'])['running'])proc_terminate($worker['process'],9);
            foreach($worker['pipes']as $pipe)if(is_resource($pipe))fclose($pipe);
            proc_close($worker['process']);
        }
        audit_remove_temp($artWorkerTemp);
    });
    function artBuyer(array $fields=[],string $target='user/ajax_buy_popedom'):int{
        global $artWorkerTemp,$artWorkers;
        $id=count($artWorkers);$arguments=['ready'=>$artWorkerTemp.'/'.$id.'.ready','barrier'=>$artWorkerTemp.'/'.$id.'.go',
            'target'=>$target,'body'=>artPurchaseBody($fields),'bearer'=>purchaseCsrfBearer()];
        $process=proc_open([PHP_BINARY,__DIR__.'/fixtures/video_purchase_worker.php',json_encode($arguments,JSON_THROW_ON_ERROR)],
            [0=>['file','/dev/null','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);
        $artWorkers[]=['process'=>$process,'pipes'=>$pipes,'arguments'=>$arguments];
        $deadline=microtime(true)+10;
        while(!is_file($arguments['ready'])){
            if(microtime(true)>$deadline||!proc_get_status($process)['running'])throw new RuntimeException('Article buyer failed to initialize');usleep(10000);
        }
        $artWorkers[$id]['thread']=(int)file_get_contents($arguments['ready']);file_put_contents($arguments['barrier'],'go');return $id;
    }
    function artBuyerWaiting(int $id,string $table):void{
        global $artWorkers;
        $deadline=microtime(true)+10;
        do{
            $sql=Db::query('SELECT INFO AS query FROM information_schema.PROCESSLIST WHERE ID=?',[$artWorkers[$id]['thread']]);
            $sql=$sql[0]['query']??'';
            if(str_contains($sql,'audit_'.$table)&&str_contains(strtoupper($sql),'FOR UPDATE')){check(true,'The real article buyer must wait on the held '.$table.' lock');return;}
            if(!proc_get_status($artWorkers[$id]['process'])['running'])throw new RuntimeException('Article buyer exited before waiting on '.$table);usleep(10000);
        }while(microtime(true)<$deadline);
        throw new RuntimeException('Article buyer did not wait on '.$table);
    }
    function artBuyerResult(int $id):array{
        global $artWorkers;
        $worker=&$artWorkers[$id];$deadline=microtime(true)+15;
        do{$status=proc_get_status($worker['process']);if(!$status['running'])break;if(microtime(true)>$deadline)throw new RuntimeException('Article buyer completion timed out');usleep(10000);}while(true);
        $output=stream_get_contents($worker['pipes'][1]);$error=stream_get_contents($worker['pipes'][2]);
        foreach($worker['pipes']as $pipe)fclose($pipe);$code=proc_close($worker['process']);$worker['process']=null;
        check(($code===0||$status['exitcode']===0)&&$error==='','Concurrent real article buyer must finish without PHP diagnostics: '.$error);
        return json_decode($output,true,32,JSON_THROW_ON_ERROR);
    }
    foreach(['price','fallback','unpublish','recycle','empty','shorten','password','group_vip','group_denied','group_expired',
        'permission','group_type','group_deleted','group_disabled','unrelated_permission','balance','random','disabled','art_price']as $scenario){
        purchaseCsrfSeed();Db::name('Group')->insert(['group_id'=>4,'group_name'=>'Restricted','group_status'=>1,'group_type'=>'1,','group_popedom'=>'{}']);
        if($scenario==='group_expired')Db::name('User')->where('user_id',1)->update(['group_id'=>3,'user_end_time'=>time()+3600]);
        $table=$scenario==='art_price'?'Art':'User';Db::startTrans();
        try{
            Db::name($table)->where(strtolower($table).'_id',$table==='Art'?17:1)->lock(true)->find();
            $worker=artBuyer([],str_starts_with($scenario,'group_')?'payment/buy_popedom':'user/ajax_buy_popedom');
            artBuyerWaiting($worker,strtolower($table));$art=[];$user=[];
            switch($scenario){
                case 'price':case 'art_price':$art=['art_points_detail'=>35];break;
                case 'fallback':$art=['art_points_detail'=>0,'art_points'=>45];break;
                case 'unpublish':$art=['art_status'=>0];break;
                case 'recycle':$art=['art_recycle_time'=>time()];break;
                case 'empty':$art=['art_content'=>'CHAPTER-ONE$$$$$$CHAPTER-THREE'];break;
                case 'shorten':$art=['art_content'=>'CHAPTER-ONE'];break;
                case 'password':$art=['art_pwd'=>'fixturepw'];break;
                case 'group_vip':$user=['group_id'=>3,'user_end_time'=>time()+3600];break;
                case 'group_denied':$user=['group_id'=>4,'user_end_time'=>time()+3600];break;
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
            if($art)Db::name('Art')->where('art_id',17)->update($art);
            if($user)Db::name('User')->where('user_id',1)->update($user);
            $before=purchaseCsrfState();Db::commit();
        }catch(Throwable $error){Db::rollback();throw $error;}
        $result=artBuyerResult($worker);
        if(in_array($scenario,['price','art_price','fallback','shorten','group_denied','group_expired','unrelated_permission'],true)){
            $points=in_array($scenario,['price','art_price'],true)?35:($scenario==='fallback'?45:20);
            check($result['code']===1&&(int)Db::name('User')->where('user_id',1)->value('user_points')===100-$points
                &&Db::name('Ulog')->count()===1&&(int)Db::name('Ulog')->value('ulog_points')===$points
                &&(int)Db::name('Ulog')->value('ulog_sid')===($scenario==='shorten'?1:2),
                'A waiting article purchase must resolve the latest price, actual clamped chapter and effective member for '.$scenario);
            if($scenario==='group_expired')check((int)Db::name('User')->where('user_id',1)->value('group_id')===3,'Lock-wait expiry does not persist a membership downgrade');
        }else{
            check(($scenario==='group_vip'?$result['code']===1:$result['code']>1)&&purchaseCsrfState()===$before,
                'Waiting article requests must honor current '.$scenario.' state without financial/account writes');
            if(in_array($scenario,['permission','group_type'],true))check(str_contains($result['msg'],'权限已更新'),'Relevant permission cache mismatch must request a retry, never charge');
        }
    }
    foreach(['same','limited','clamped']as $scenario){
        purchaseCsrfSeed();if($scenario==='limited')Db::name('User')->where('user_id',1)->update(['user_points'=>30]);
        Db::startTrans();$ids=[];
        try{
            Db::name('User')->where('user_id',1)->lock(true)->find();
            foreach([1,2,3]as $page){
                $id=artBuyer(['sid'=>$scenario==='same'?2:($scenario==='clamped'?255-$page:$page)],$page===2?'payment/buy_popedom':'user/ajax_buy_popedom');
                artBuyerWaiting($id,'user');$ids[]=$id;
            }
            Db::commit();
        }catch(Throwable $error){Db::rollback();throw $error;}
        $codes=[];foreach($ids as $id)$codes[]=artBuyerResult($id)['code'];sort($codes);
        check(($scenario==='limited'?count(array_filter($codes,static fn($code)=>$code===1))===1&&count(array_filter($codes,static fn($code)=>in_array($code,[1005,2002],true)))===2:$codes===[1,1,1])
            &&Db::name('Ulog')->count()===1&&Db::name('Plog')->count()===4
            &&(int)Db::name('User')->where('user_id',1)->value('user_points')===($scenario==='limited'?10:80),
            'Concurrent article routes must charge only once for an affordable actual chapter in '.$scenario);
    }
}
if($mysql)require __DIR__.'/fixtures/art_purchase_replica.php';
fwrite(STDOUT,'Article purchase resource audit passed ('.$checks.' checks; '.($mysql?'MySQL non-strict':'SQLite').")\n");
