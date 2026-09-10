<?php
/** Actual manga installation schema, purchase routes, reading policy and shared financial transaction. */
declare(strict_types=1);
putenv('MANGA_PURCHASE_AUDIT=1');
require __DIR__.'/fixtures/purchase_csrf.php';
use think\facade\Db;
use app\common\util\ContentPassword;
use app\common\util\ContentResource;

function mangaPurchaseBody(array $fields=[]):array{return $fields+['mid'=>12,'type'=>1,'id'=>17,'sid'=>2,'nid'=>2];}
function mangaPurchase(string $target,array $fields=[],array $cookies=[]):array{
    $result=purchaseCsrfRoute($target,mangaPurchaseBody($fields),[],$cookies,['Authorization'=>'Bearer '.purchaseCsrfBearer()])['data'];
    $encoded=json_encode($result,JSON_THROW_ON_ERROR);
    foreach(['MANGA-','fixturepw','manga_chapter_url','manga_pwd','user_pwd','user_random']as $secret){
        check(!str_contains($encoded,$secret),'Manga purchase responses must not expose chapter bodies, passwords or account credentials');
    }
    return $result;
}
function mangaPurchaseReject(string $target,array $fields=[],?int $code=null,array $cookies=[]):array{
    $before=purchaseCsrfState();$result=mangaPurchase($target,$fields,$cookies);
    check($result['code']>1&&($code===null||$code===$result['code'])&&purchaseCsrfState()===$before,
        'A rejected manga purchase must preserve every account, receipt and ledger: '.json_encode([$fields,$code,$result]));return $result;
}
function mangaPurchasePolicy(int $sid=2,int $nid=2):array{
    $row=Db::name('Manga')->where('manga_id',17)->find();$previous=$GLOBALS['user'];
    $user=Db::name('User')->where('user_id',1)->find();
    if(max(explode(',',(string)$user['group_id']))>2&&(int)$user['user_end_time']<time())$user['group_id']=2;
    $GLOBALS['user']=$user;
    try{
        $controller=(new ReflectionClass(PurchaseCsrfIndex::class))->newInstanceWithoutConstructor();
        return (new ReflectionMethod($controller,'check_manga_resource_access'))->invoke($controller,$row,['id'=>17,'sid'=>$sid,'nid'=>$nid]);
    }finally{$GLOBALS['user']=$previous;}
}
function mangaPurchaseGroup(array $permissions,string $types='1,'):void{
    Db::name('Group')->where('group_id',2)->update(['group_type'=>$types,'group_popedom'=>json_encode([1=>$permissions])]);
    $groups=(new \app\common\model\Group())->listData([],'group_id')['list'];
    \think\facade\Cache::set('purchase_csrf_group_list',$groups);
}
foreach(['user/ajax_buy_popedom']as $target){
    foreach([0,1]as $whole){
        purchaseCsrfSeed();$GLOBALS['config']['user']['manga_points_type']=$whole;
        purchaseCsrfRoute('user/write_token',[],[],purchaseCsrfCookies(),[],'GET');
        $permission=mangaPurchasePolicy();check($permission['code']===3003&&$permission['confirm']===1,'The actual chapter read policy requests this purchase');
        $result=mangaPurchase($target,['ulog_points'=>0,'user_id'=>999]);$points=$whole?40:20;
        $receipt=Db::name('Ulog')->where('ulog_id','>',0)->find();
        check($receipt!==null,'Manga purchase did not commit its receipt: '.json_encode($result));
        check($result['code']===1&&(int)Db::name('User')->where('user_id',1)->value('user_points')===100-$points
            &&(int)$receipt['user_id']===1&&(int)$receipt['ulog_mid']===12&&(int)$receipt['ulog_sid']===($whole?0:2)
            &&(int)$receipt['ulog_nid']===($whole?0:2)&&(int)$receipt['ulog_points']===$points&&Db::name('Plog')->count()===4,
            'The actual manga route must debit its server quote and create the verified owner canonical receipt');
        check(mangaPurchasePolicy()['can_access']===true,'The newly purchased chapter must actually become readable');
        $state=purchaseCsrfState();check(mangaPurchase($target)['code']===1&&purchaseCsrfState()===$state,'A repeated manga request must not debit or create another receipt');
    }
    purchaseCsrfSeed();
    $result=purchaseCsrfRoute($target,mangaPurchaseBody(),['mid'=>1,'id'=>999,'sid'=>1,'nid'=>8],[],['Authorization'=>'Bearer '.purchaseCsrfBearer()]);
    check($result['data']['code']===1&&(int)Db::name('Ulog')->value('ulog_sid')===2,'Query coordinates cannot override the actual manga POST chapter');
    purchaseCsrfSeed();mangaPurchaseReject($target,['sid'=>255],1002);mangaPurchaseReject($target,['nid'=>65535],1002);
    purchaseCsrfSeed();$body=['mid'=>12,'type'=>1,'id'=>17];
    $result=purchaseCsrfRoute($target,$body,[],[],['Authorization'=>'Bearer '.purchaseCsrfBearer()]);
    check($result['data']['code']===1&&(int)Db::name('Ulog')->value('ulog_sid')===1&&(int)Db::name('Ulog')->value('ulog_nid')===1,'Omitted manga coordinates retain the default first real chapter');
    foreach([0,1]as $whole){
        purchaseCsrfSeed();$GLOBALS['config']['user']['manga_points_type']=$whole;
        foreach([['sid'=>0],['sid'=>256],['nid'=>0],['sid'=>[]],['nid'=>[]],['type'=>4]]as $bad)mangaPurchaseReject($target,$bad);
        Db::name('Manga')->where('manga_id',17)->update(['manga_chapter_url'=>'One$/images/one.jpg#$#Three$/images/three.jpg$$$One$/images/one.jpg#$#Three$/images/three.jpg']);
        mangaPurchaseReject($target,[],1002);
        check(mangaPurchase($target,['nid'=>3])['code']===1,'A normal nonempty manga chapter remains purchasable beside an empty chapter');
    }
    foreach([['manga_status'=>0],['manga_recycle_time'=>time()],['manga_chapter_url'=>''],['manga_chapter_url'=>'$$$$$$'],['manga_chapter_url'=>'One$#Two$https://$$$One$#Two$https://']]as $changes){
        purchaseCsrfSeed();Db::name('Manga')->where('manga_id',17)->update($changes);mangaPurchaseReject($target,[],1002);
    }
    purchaseCsrfSeed();Db::name('Manga')->where('manga_id',17)->delete();mangaPurchaseReject($target,[],1002);
    purchaseCsrfSeed();Db::name('Manga')->where('manga_id',17)->update(['manga_points_detail'=>0]);
    check(mangaPurchase($target)['code']===1&&(int)Db::name('Ulog')->value('ulog_points')===40,'Detail price zero retains the established overall manga price fallback');
    foreach(['free','vip','system_disabled']as $scenario){
        purchaseCsrfSeed();
        if($scenario==='free')Db::name('Manga')->where('manga_id',17)->update(['manga_points'=>0,'manga_points_detail'=>0]);
        if($scenario==='vip')Db::name('User')->where('user_id',1)->update(['group_id'=>3,'user_end_time'=>time()+3600]);
        if($scenario==='system_disabled')$GLOBALS['config']['user']['status']=0;
        $state=purchaseCsrfState();check(mangaPurchase($target)['code']===1&&purchaseCsrfState()===$state,
            'Already readable '.$scenario.' manga content must not debit or create a meaningless receipt');
    }
    foreach(['permissions','category']as $scenario){
        purchaseCsrfSeed();mangaPurchaseGroup($scenario==='permissions'?[3=>0]:[3=>1],$scenario==='category'?'':'1,');
        check(mangaPurchase($target)['code']===1&&mangaPurchasePolicy()['can_access']===true,
            'An manga member without '.$scenario.' access can still purchase and read that exact chapter');
        $state=purchaseCsrfState();check(mangaPurchase($target)['code']===1&&purchaseCsrfState()===$state,'A paid receipt also prevents repeat charging for a category-restricted member');
    }
    purchaseCsrfSeed();mangaPurchaseGroup([3=>0]);Db::name('Manga')->where('manga_id',17)->update(['manga_points'=>0,'manga_points_detail'=>0]);
    Db::name('Ulog')->insert(['user_id'=>1,'ulog_mid'=>12,'ulog_type'=>1,'ulog_rid'=>17,'ulog_sid'=>2,'ulog_nid'=>2,'ulog_points'=>0,'ulog_time'=>time()]);
    mangaPurchaseReject($target,[],3001);
    foreach([['user_id'=>2],['ulog_sid'=>1],['ulog_nid'=>1],['ulog_points'=>19]]as $different){
        purchaseCsrfSeed();Db::name('Ulog')->insert($different+['user_id'=>1,'ulog_mid'=>12,'ulog_type'=>1,'ulog_rid'=>17,'ulog_sid'=>2,'ulog_nid'=>2,'ulog_points'=>20,'ulog_time'=>time()]);
        check(mangaPurchase($target)['code']===1&&Db::name('Ulog')->count()===2
            &&(int)Db::name('User')->where('user_id',1)->value('user_points')===80,
            'Another owner, chapter or price receipt cannot substitute for the selected manga entitlement');
    }
    foreach(['disabled','deleted']as $scenario){
        purchaseCsrfSeed();if($scenario==='deleted')Db::name('Group')->where('group_id',2)->delete();
        else Db::name('Group')->where('group_id',2)->update(['group_status'=>0]);
        mangaPurchaseReject($target,[],3001);
        purchaseCsrfSeed();Db::name('User')->where('user_id',1)->update(['group_id'=>'2,3','user_end_time'=>time()+3600]);
        if($scenario==='deleted')Db::name('Group')->where('group_id',3)->delete();
        else Db::name('Group')->where('group_id',3)->update(['group_status'=>0]);
        mangaPurchaseReject($target,[],3001);
    }
    purchaseCsrfSeed();Db::name('User')->where('user_id',1)->update(['group_id'=>3,'user_end_time'=>time()-60,'user_points'=>10]);
    mangaPurchaseReject($target,[],2002);
    check((int)Db::name('User')->where('user_id',1)->value('group_id')===3,'An expired manga member refusal must not persist a group downgrade');
    purchaseCsrfSeed();Db::name('Manga')->where('manga_id',17)->update(['manga_pwd'=>'fixturepw']);mangaPurchaseReject($target,[],6001);
    $session=purchaseCsrfRoute('user/write_token',[],[],purchaseCsrfCookies(),[],'GET');
    check(ContentPassword::verifyManga(Db::name('Manga')->where('manga_id',17)->find(),'fixturepw')['code']===1,'Normal content-password verification establishes a genuine manga grant');
    $app->session->save();$cookies=['fixture_session'=>$session['session_id']];
    check(mangaPurchase($target,[],$cookies)['code']===1,'A normally verified manga password enables the existing paid chapter flow');
    Db::name('Manga')->where('manga_id',17)->update(['manga_pwd'=>'changedpw']);mangaPurchaseReject($target,[],6001,$cookies);
    foreach(['user','plog','ulog']as $table){
        purchaseCsrfSeed();$event=$table==='user'?'UPDATE':'INSERT';
        $failure=$mysql?"FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='Isolated manga failure'":"BEGIN SELECT RAISE(ABORT,'Isolated manga failure'); END";
        Db::execute('CREATE TRIGGER audit_manga_failure BEFORE '.$event.' ON audit_'.$table.' '.$failure);
        try{mangaPurchaseReject($target);}finally{Db::execute('DROP TRIGGER audit_manga_failure');}
        check(mangaPurchase($target)['code']===1,'A normal manga purchase remains retryable after its isolated write fault is removed');
    }
    foreach(['user'=>'user_points','plog'=>'plog_points','ulog'=>'ulog_points']as $table=>$field){
        purchaseCsrfSeed();$event=$table==='user'?'UPDATE':'INSERT';$id=$table.'_id';
        $body=$mysql?'FOR EACH ROW SET NEW.'.$field.'=19':'BEGIN UPDATE audit_'.$table.' SET '.$field.'=19 WHERE '.$id.'=NEW.'.$id.'; END';
        Db::execute('CREATE TRIGGER audit_manga_truncate '.($mysql?'BEFORE':'AFTER').' '.$event.' ON audit_'.$table.' '.$body);
        try{mangaPurchaseReject($target,[],2003);}finally{Db::execute('DROP TRIGGER audit_manga_truncate');}
        check(mangaPurchase($target)['code']===1,'Exact readback rejects silent '.$table.' mutation and the normal purchase remains retryable');
    }
    purchaseCsrfSeed();Db::startTrans();
    try{mangaPurchaseReject($target);check(Db::connect()->getPdo()->inTransaction(),'Rejecting nested manga purchase preserves the caller transaction');}
    finally{Db::rollback();}
    foreach(['manga_points','manga_points_detail']as $field){
        purchaseCsrfSeed();$GLOBALS['config']['user']['manga_points_type']=$field==='manga_points'?1:0;
        if($mysql)Db::execute('ALTER TABLE audit_manga MODIFY '.$field.' VARCHAR(16) NOT NULL DEFAULT \'0\'');
        else Db::execute('PRAGMA ignore_check_constraints=ON');
        try{foreach([-1,65536,'bad','1.5']as $price){
            Db::execute('UPDATE audit_manga SET '.$field.'=? WHERE manga_id=17',[(string)$price]);
            check((string)Db::query('SELECT '.$field.' AS price FROM audit_manga WHERE manga_id=17')[0]['price']===(string)$price,'The explicit legacy price fixture retains its actual invalid bytes');
            mangaPurchaseReject($target,[],1002);
        }}finally{
            Db::name('Manga')->where('manga_id',17)->update([$field=>0]);
            if($mysql)Db::execute('ALTER TABLE audit_manga MODIFY '.$field.' SMALLINT UNSIGNED NOT NULL DEFAULT 0');
            else Db::execute('PRAGMA ignore_check_constraints=OFF');
        }
    }
    purchaseCsrfSeed();Db::name('User')->where('user_id',1)->update(['user_points'=>70000]);Db::name('Manga')->where('manga_id',17)->update(['manga_points_detail'=>65535]);
    check(mangaPurchase($target)['code']===1&&(int)Db::name('User')->where('user_id',1)->value('user_points')===4465,'The actual receipt price upper bound remains purchasable without narrowing or overflow');
    purchaseCsrfSeed();$last=ContentResource::MANGA_MAX_CHAPTERS;
    $chapters='One$/images/MANGA-FIRST.jpg'.str_repeat('#',$last-1).'Last$/images/MANGA-LAST.jpg';
    Db::name('Manga')->where('manga_id',17)->update(['manga_chapter_from'=>'primary','manga_chapter_url'=>$chapters]);
    $row=Db::name('Manga')->where('manga_id',17)->find();$context=ContentResource::mangaContext($row,['sid'=>1,'nid'=>$last]);
    check($context['code']===1&&$context['nid']===$last&&$context['purchase_supported'],'An actual chapter at the accepted catalog budget retains its exact coordinate');
    check(mangaPurchase($target,['sid'=>1,'nid'=>$last])['code']===1&&(int)Db::name('Ulog')->value('ulog_nid')===$last
        &&mangaPurchasePolicy(1,$last)['can_access']===true,'An accepted long chapter is purchased and read with the same uncompressed coordinate');
    $GLOBALS['config']['user']['manga_points_type']=1;$context=ContentResource::mangaContext($row,['sid'=>1,'nid'=>$last]);
    check($context['purchase_supported']&&$context['purchase_sid']===1&&$context['purchase_nid']===1,'Whole Manga context supplies an actual first nonempty purchase entry');
    check(mangaPurchase($target,['sid'=>$context['purchase_sid'],'nid'=>$context['purchase_nid']])['code']===1
        &&Db::name('Ulog')->where(['ulog_sid'=>0,'ulog_nid'=>0,'ulog_points'=>40])->count()===1
        &&mangaPurchasePolicy(1,$last)['can_access']===true,'A purchase of a real chapter grants the whole Manga while preserving the actual read coordinate');
    Db::name('Manga')->where('manga_id',17)->update(['manga_chapter_url'=>$chapters.'#Extra$/images/extra.jpg']);
    mangaPurchaseReject($target,['sid'=>1,'nid'=>1],1002);
    $GLOBALS['config']['user']['manga_points_type']=0;mangaPurchaseReject($target,['sid'=>1,'nid'=>1],1002);
}
purchaseCsrfSeed();$cookies=purchaseCsrfCookies();$session=purchaseCsrfRoute('user/write_token',[],[],$cookies,[],'GET');
$cookies['fixture_session']=$session['session_id'];
$result=purchaseCsrfRoute('user/ajax_buy_popedom',mangaPurchaseBody(['csrf_token'=>$session['data']['info']['csrf_token']]),[],$cookies)['data'];
check($result['code']===1&&(int)Db::name('User')->where('user_id',1)->value('user_points')===80
    &&mangaPurchasePolicy()['can_access']===true,'An actual Cookie login and freshly issued session token complete a usable Manga purchase');
purchaseCsrfSeed();$before=purchaseCsrfState();
$result=purchaseCsrfRoute('payment/buy_popedom',mangaPurchaseBody(),[],[],['Authorization'=>'Bearer '.purchaseCsrfBearer()])['data'];
check($result['code']===1001&&purchaseCsrfState()===$before,'API Payment continues to reject unsupported Manga without creating any financial state');
purchaseCsrfSeed();Db::name('Manga')->where('manga_id',17)->update(['manga_chapter_url'=>'One$/images/one.jpg##Three$/images/three.jpg$$$One$/images/one.jpg##Three$/images/three.jpg']);
mangaPurchaseReject('user/ajax_buy_popedom',[],1002);
check(mangaPurchase('user/ajax_buy_popedom',['nid'=>3])['code']===1&&(int)Db::name('Ulog')->value('ulog_nid')===3
    &&mangaPurchasePolicy(2,3)['can_access']===true,'A sparse chapter key remains its own entitlement coordinate and never shifts into a missing chapter');
foreach([0,1]as $whole){
    purchaseCsrfSeed();$GLOBALS['config']['user']['manga_points_type']=$whole;
    Db::name('Manga')->where('manga_id',17)->update(['manga_chapter_url'=>'One$/images/one.jpg#Two$#Three$/images/three.jpg$$$One$/images/one.jpg#Two$#Three$/images/three.jpg']);
    mangaPurchaseReject('user/ajax_buy_popedom',[],1002);
}
purchaseCsrfSeed();$images=implode(',',array_fill(0,ContentResource::MANGA_MAX_IMAGES,'/images/normal.jpg'));
Db::name('Manga')->where('manga_id',17)->update(['manga_chapter_from'=>'primary','manga_chapter_url'=>'Images$'.$images]);
check(mangaPurchase('user/ajax_buy_popedom',['sid'=>1,'nid'=>1])['code']===1,'A chapter at the accepted image-count budget remains purchasable');
Db::name('Manga')->where('manga_id',17)->update(['manga_chapter_url'=>'Images$'.$images.',/images/extra.jpg']);
foreach([0,1]as $whole){$GLOBALS['config']['user']['manga_points_type']=$whole;mangaPurchaseReject('user/ajax_buy_popedom',['sid'=>1,'nid'=>1],1002);}
purchaseCsrfSeed();Db::name('Manga')->where('manga_id',17)->update(['manga_chapter_from'=>'primary',
    'manga_chapter_url'=>'Images$https://fixture.invalid/normal.jpg,/images/normal.jpg']);
check(mangaPurchase('user/ajax_buy_popedom',['sid'=>1,'nid'=>1])['code']===1,'A normal mixed HTTP and local image list remains purchasable');
Db::name('Manga')->where('manga_id',17)->update(['manga_chapter_url'=>'Images$/images/normal.jpg,https://']);
foreach([0,1]as $whole){$GLOBALS['config']['user']['manga_points_type']=$whole;mangaPurchaseReject('user/ajax_buy_popedom',['sid'=>1,'nid'=>1],1002);}
purchaseCsrfSeed();$description=str_repeat('A',ContentResource::MANGA_MAX_DESCRIPTION_BYTES);
Db::name('Manga')->where('manga_id',17)->update(['manga_content'=>$description]);
check(mangaPurchase('user/ajax_buy_popedom')['code']===1,'A synopsis at the accepted reader budget remains compatible with a normal chapter purchase');
Db::name('Manga')->where('manga_id',17)->update(['manga_content'=>$description.'A']);
foreach([0,1]as $whole){$GLOBALS['config']['user']['manga_points_type']=$whole;mangaPurchaseReject('user/ajax_buy_popedom',[],1002);}
foreach(['category','permission']as $restriction){
    purchaseCsrfSeed();Db::name('User')->where('user_id',1)->update(['group_id'=>3,'user_end_time'=>time()+3600]);
    Db::name('Group')->where('group_id',3)->update($restriction==='category'?['group_type'=>'']:['group_popedom'=>json_encode([1=>[3=>0]])]);
    $groups=(new \app\common\model\Group())->listData([],'group_id')['list'];
    \think\facade\Cache::set('purchase_csrf_group_list',$groups);
    check(mangaPurchase('user/ajax_buy_popedom')['code']===1&&(int)Db::name('User')->where('user_id',1)->value('user_points')===80
        &&mangaPurchasePolicy()['can_access']===true,'VIP without the current '.$restriction.' access still requires and can use a paid Manga receipt');
}
foreach(['02','2,02']as $groups){
    purchaseCsrfSeed();Db::name('User')->where('user_id',1)->update(['group_id'=>$groups]);
    Db::name('Manga')->where('manga_id',17)->update(['manga_points'=>0,'manga_points_detail'=>0]);
    purchaseCsrfRoute('user/write_token',[],[],purchaseCsrfCookies(),[],'GET');$before=purchaseCsrfState();
    check(mangaPurchase('user/ajax_buy_popedom')['code']===1&&purchaseCsrfState()===$before&&mangaPurchasePolicy()['can_access']===true,
        'Existing equivalent numeric Group representations must give the same free read and purchase result without rewriting the account');
}
foreach(['null','not-json']as $permissions){
    purchaseCsrfSeed();Db::name('Group')->where('group_id',2)->update(['group_popedom'=>$permissions]);
    mangaPurchaseReject('user/ajax_buy_popedom',[],3001);
}
foreach([false,true]as $allowed){
    purchaseCsrfSeed();Db::name('User')->where('user_id',1)->update(['group_id'=>3,'user_end_time'=>time()+3600]);
    Db::name('Group')->where('group_id',3)->update(['group_popedom'=>json_encode([1=>[3=>$allowed?1:0]])]);
    $cached=(new \app\common\model\Group())->getCache();$cached[3]['group_popedom'][1][3]=$allowed?0:1;
    \think\facade\Cache::set('purchase_csrf_group_list',$cached);
    $before=purchaseCsrfState();$result=mangaPurchase('user/ajax_buy_popedom');
    check($result['code']===1&&($allowed?purchaseCsrfState()===$before:(int)Db::name('User')->where('user_id',1)->value('user_points')===80)
        &&mangaPurchasePolicy()['can_access']===true,'A stale Group cache before the request cannot replace current writer permissions or prevent a valid Manga purchase');
}
// Manga read permissions use writer Group rows; unrelated cached permissions must not change the locked fee decision.
foreach([false,true]as $allowed){
    purchaseCsrfSeed();Db::name('User')->where('user_id',1)->update(['group_id'=>3,'user_end_time'=>time()+3600]);
    Db::name('Group')->where('group_id',3)->update(['group_popedom'=>json_encode([1=>[3=>$allowed?1:0]])]);
    $groups=(new \app\common\model\Group())->listData([],'group_id')['list'];
    \think\facade\Cache::set('purchase_csrf_group_list',$groups);
    purchaseCsrfRoute('user/write_token',[],[],purchaseCsrfCookies(),[],'GET');$before=purchaseCsrfState();
    $result=\app\common\util\MangaPurchase::buy(Db::name('User')->where('user_id',1)->find(),mangaPurchaseBody(),
        static function(array $row,array $coordinates)use($groups,$allowed):array{
            $groups[3]['group_popedom'][1][3]=$allowed?0:1;
            \think\facade\Cache::set('purchase_csrf_group_list',$groups);
            $controller=(new ReflectionClass(PurchaseCsrfIndex::class))->newInstanceWithoutConstructor();
            return(new ReflectionMethod($controller,'check_manga_resource_access'))->invoke($controller,$row,$coordinates);
        });
    check($result['code']===1&&($allowed?purchaseCsrfState()===$before:
        (int)Db::name('User')->where('user_id',1)->value('user_points')===80&&Db::name('Ulog')->count()===1&&Db::name('Plog')->count()===4)
        &&mangaPurchasePolicy()['can_access']===true,
        'A Group cache change during the actual writer policy must preserve the current free or paid entitlement decision');
}
purchaseCsrfSeed();$before=purchaseCsrfState();
$result=\app\common\util\ContentPurchase::buyManga(1,static fn($user)=>['code'=>1,'record'=>[
    'ulog_mid'=>1,'ulog_type'=>4,'ulog_rid'=>17,'ulog_sid'=>2,'ulog_nid'=>3,'ulog_points'=>20]]);
check($result['code']===2003&&purchaseCsrfState()===$before,'The internal manga quote cannot create a receipt for a different resource kind');
purchaseCsrfSeed();$GLOBALS['user']=['user_id'=>999,'fixture_context'=>'preserved'];$previous=$GLOBALS['user'];$before=purchaseCsrfState();
$result=\app\common\util\MangaPurchase::buy(Db::name('User')->where('user_id',1)->find(),mangaPurchaseBody(),
    static function(array $row,array $coordinates):array{throw new RuntimeException('Isolated policy interruption');});
check($result['code']===2003&&$GLOBALS['user']===$previous&&purchaseCsrfState()===$before,
    'A policy interruption must roll back the transaction and restore the original server identity context');
// Separate real-route workers share only installation/auth/session setup, with a dedicated Manga database.
if($mysql){
    foreach(['user','group','manga','plog','ulog']as $table){
        purchaseCsrfSeed();Db::execute('ALTER TABLE audit_'.$table.' ENGINE=MyISAM');
        try{mangaPurchaseReject('user/ajax_buy_popedom');}
        finally{Db::execute('ALTER TABLE audit_'.$table.' ENGINE=InnoDB');}
    }
    purchaseCsrfSeed();Db::execute('ALTER TABLE audit_vod ENGINE=MyISAM');
    try{check(mangaPurchase('user/ajax_buy_popedom')['code']===1,'A Manga transaction does not require an unrelated video table to be transactional');}
    finally{Db::execute('ALTER TABLE audit_vod ENGINE=InnoDB');}
    $mangaWorkerTemp=audit_temp_dir('manga-purchase-workers');$mangaWorkers=[];
    register_shutdown_function(static function()use($mangaWorkerTemp,&$mangaWorkers):void{
        foreach($mangaWorkers as $worker){
            if(!is_resource($worker['process']))continue;
            if(proc_get_status($worker['process'])['running'])proc_terminate($worker['process'],9);
            foreach($worker['pipes']as $pipe)if(is_resource($pipe))fclose($pipe);
            proc_close($worker['process']);
        }
        audit_remove_temp($mangaWorkerTemp);
    });
    function mangaBuyer(array $fields=[],string $target='user/ajax_buy_popedom'):int{
        global $mangaWorkerTemp,$mangaWorkers;
        $id=count($mangaWorkers);$arguments=['ready'=>$mangaWorkerTemp.'/'.$id.'.ready','barrier'=>$mangaWorkerTemp.'/'.$id.'.go',
            'target'=>$target,'body'=>mangaPurchaseBody($fields),'bearer'=>purchaseCsrfBearer(), 'whole'=>$GLOBALS['config']['user']['manga_points_type']];
        $process=proc_open([PHP_BINARY,__DIR__.'/fixtures/manga_purchase_worker.php',json_encode($arguments,JSON_THROW_ON_ERROR)],
            [0=>['file','/dev/null','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);
        $mangaWorkers[]=['process'=>$process,'pipes'=>$pipes,'arguments'=>$arguments];
        $deadline=microtime(true)+10;
        while(!is_file($arguments['ready'])){
            if(microtime(true)>$deadline||!proc_get_status($process)['running'])throw new RuntimeException('Manga buyer failed to initialize');usleep(10000);
        }
        $mangaWorkers[$id]['thread']=(int)file_get_contents($arguments['ready']);file_put_contents($arguments['barrier'],'go');return $id;
    }
    function mangaBuyerWaiting(int $id,string $table):void{
        global $mangaWorkers;
        $deadline=microtime(true)+10;
        do{
            $sql=Db::query('SELECT INFO AS query FROM information_schema.PROCESSLIST WHERE ID=?',[$mangaWorkers[$id]['thread']]);
            $sql=$sql[0]['query']??'';
            if(str_contains($sql,'audit_'.$table)&&str_contains(strtoupper($sql),'FOR UPDATE')){check(true,'The real manga buyer must wait on the held '.$table.' lock');return;}
            if(!proc_get_status($mangaWorkers[$id]['process'])['running'])throw new RuntimeException('Manga buyer exited before waiting on '.$table);usleep(10000);
        }while(microtime(true)<$deadline);
        throw new RuntimeException('Manga buyer did not wait on '.$table);
    }
    function mangaBuyerResult(int $id):array{
        global $mangaWorkers;
        $worker=&$mangaWorkers[$id];$deadline=microtime(true)+15;
        do{$status=proc_get_status($worker['process']);if(!$status['running'])break;if(microtime(true)>$deadline)throw new RuntimeException('Manga buyer completion timed out');usleep(10000);}while(true);
        $output=stream_get_contents($worker['pipes'][1]);$error=stream_get_contents($worker['pipes'][2]);
        foreach($worker['pipes']as $pipe)fclose($pipe);$code=proc_close($worker['process']);$worker['process']=null;
        check(($code===0||$status['exitcode']===0)&&$error==='','Concurrent real manga buyer must finish without PHP diagnostics: '.$error);
        return json_decode($output,true,32,JSON_THROW_ON_ERROR);
    }
    foreach(['price','fallback','unpublish','recycle','empty','shorten','password','group_vip','group_denied','group_expired',
        'permission','group_type','group_deleted','group_disabled','unrelated_permission','balance','random','disabled','manga_price']as $scenario){
        purchaseCsrfSeed();Db::name('Group')->insert(['group_id'=>4,'group_name'=>'Restricted','group_status'=>1,'group_type'=>'1,','group_popedom'=>'{}']);
        if($scenario==='group_expired')Db::name('User')->where('user_id',1)->update(['group_id'=>3,'user_end_time'=>time()+3600]);
        $table=$scenario==='manga_price'?'Manga':'User';Db::startTrans();
        try{
            Db::name($table)->where(strtolower($table).'_id',$table==='Manga'?17:1)->lock(true)->find();
            $worker=mangaBuyer([],'user/ajax_buy_popedom');
            mangaBuyerWaiting($worker,strtolower($table));$manga=[];$user=[];
            switch($scenario){
                case 'price':case 'manga_price':$manga=['manga_points_detail'=>35];break;
                case 'fallback':$manga=['manga_points_detail'=>0,'manga_points'=>45];break;
                case 'unpublish':$manga=['manga_status'=>0];break;
                case 'recycle':$manga=['manga_recycle_time'=>time()];break;
                case 'empty':$manga=['manga_chapter_url'=>'One$/images/one.jpg#$#Three$/images/three.jpg$$$One$/images/one.jpg#$#Three$/images/three.jpg'];break;
                case 'shorten':$manga=['manga_chapter_url'=>'One$/images/one.jpg$$$One$/images/one.jpg'];break;
                case 'password':$manga=['manga_pwd'=>'fixturepw'];break;
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
            if($manga)Db::name('Manga')->where('manga_id',17)->update($manga);
            if($user)Db::name('User')->where('user_id',1)->update($user);
            $before=purchaseCsrfState();Db::commit();
        }catch(Throwable $error){Db::rollback();throw $error;}
        $result=mangaBuyerResult($worker);
        if(in_array($scenario,['price','manga_price','fallback','group_denied','group_expired','unrelated_permission','permission','group_type'],true)){
            $points=in_array($scenario,['price','manga_price'],true)?35:($scenario==='fallback'?45:20);
            check($result['code']===1&&(int)Db::name('User')->where('user_id',1)->value('user_points')===100-$points
                &&Db::name('Ulog')->count()===1&&(int)Db::name('Ulog')->value('ulog_points')===$points
                &&(int)Db::name('Ulog')->value('ulog_sid')===2,
                'A waiting manga purchase must resolve the latest price, actual chapter and effective member for '.$scenario);
            if($scenario==='group_expired')check((int)Db::name('User')->where('user_id',1)->value('group_id')===3,'Lock-wait expiry does not persist a membership downgrade');
        }else{
            check(($scenario==='group_vip'?$result['code']===1:$result['code']>1)&&purchaseCsrfState()===$before,
                'Waiting manga requests must honor current '.$scenario.' state without financial/account writes');
        }
    }
    foreach(['same','limited','whole']as $scenario){
        purchaseCsrfSeed();if($scenario==='whole')$GLOBALS['config']['user']['manga_points_type']=1;if($scenario==='limited')Db::name('User')->where('user_id',1)->update(['user_points'=>30]);
        Db::startTrans();$ids=[];
        try{
            Db::name('User')->where('user_id',1)->lock(true)->find();
            foreach([1,2,3]as $page){
                $id=mangaBuyer(['nid'=>$scenario==='same'?2:$page], 'user/ajax_buy_popedom');
                mangaBuyerWaiting($id,'user');$ids[]=$id;
            }
            Db::commit();
        }catch(Throwable $error){Db::rollback();throw $error;}
        $codes=[];foreach($ids as $id)$codes[]=mangaBuyerResult($id)['code'];sort($codes);
        check(($scenario==='limited'?count(array_filter($codes,static fn($code)=>$code===1))===1&&count(array_filter($codes,static fn($code)=>in_array($code,[1005,2002],true)))===2:$codes===[1,1,1])
            &&Db::name('Ulog')->count()===1&&Db::name('Plog')->count()===4
            &&(int)Db::name('User')->where('user_id',1)->value('user_points')===($scenario==='limited'?10:($scenario==='whole'?60:80)),
            'Concurrent manga routes must charge only once for an affordable actual chapter in '.$scenario);
    }
}

if($mysql)require __DIR__.'/fixtures/manga_purchase_replica.php';
fwrite(STDOUT,'Manga purchase resource audit passed ('.$checks.' checks; '.($mysql?'MySQL non-strict':'SQLite').")\n");
