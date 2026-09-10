<?php
/** Actual ledger model and member/API actions; auth and display helpers are isolated. */
namespace app\admin\controller { class Base { public function error($message) { return ['code'=>0,'msg'=>$message]; } } }
namespace {
    require __DIR__.'/fixtures/security_audit_order_create.php';
    use think\facade\Db;
    use app\common\model\Plog;
    function mac_get_plog_type_text($type) { return 'type-'.$type; }
    function mac_array_rekey($rows,$key) { return array_column($rows,null,$key); }
    if (!$mysql) { Db::execute('ALTER TABLE audit_plog ADD COLUMN plog_user_hidden INTEGER NOT NULL DEFAULT 0'); }
    function ledgerSeed(): void {
        creationSeed();
        foreach ([[1,1,1,20],[2,1,8,10],[3,1,1,30],[4,2,1,40]] as [$id,$owner,$type,$points]) {
            Db::name('Plog')->insert(['plog_id'=>$id,'user_id'=>$owner,'plog_type'=>$type,'plog_points'=>$points,'plog_time'=>1700000000+$id,'plog_remarks'=>'original '.$id]);
        }
    }
    function originals(): array {
        return Db::name('Plog')->field('plog_id,user_id,plog_type,plog_points,plog_time,plog_remarks')->order('plog_id')->select()->toArray();
    }
    function ledgerAction($entry,$params,$method='POST') {
        $request = creationRequest($params,$entry==='api'?'del_plog':'plog_del',$entry==='api'?'/api.php':'/index.php',$method);
        $controller = creationController($entry==='api'?app\api\controller\User::class:app\index\controller\User::class);
        return $entry==='api' ? $controller->del_plog($request) : $controller->plog_del();
    }
    function ledgerApiRead($params=[]): array {
        $request = creationRequest($params,'get_plog','/api.php','GET');
        return creationController(app\api\controller\User::class)->get_plog($request);
    }
    foreach (['api','index'] as $entry) {
        ledgerSeed(); $before=originals(); $balances=Db::name('User')->order('user_id')->column('user_points');
        check(ledgerAction($entry,['ids'=>'1,4'])['code']===1,'Member hide action failed');
        check(originals()===$before && Db::name('User')->order('user_id')->column('user_points')===$balances,'Hiding changed original financial data');
        check(Db::name('Plog')->where('plog_user_hidden',1)->column('plog_id')===[1],'Member hid another owner’s record');
        $read=ledgerApiRead();
        check($read['code']===1 && $read['info']['total']===2 && array_column($read['info']['list'],'plog_id')===[3,2],'Member list/count includes hidden/foreign records');
        check(array_column(ledgerApiRead(['filter'=>'income'])['info']['list'],'plog_id')===[3],'Income filter ignored visibility');
        $page=ledgerApiRead(['page'=>2,'limit'=>1]);
        check($page['info']['total']===2 && array_column($page['info']['list'],'plog_id')===[2],'Visible pagination drifted');
        check((new Plog())->listData([],'plog_id asc')['total']===4,'Administrator lost original ledger rows');
        check(ledgerAction($entry,['all'=>'1'])['code']===1 && originals()===$before,'Hide-all erased financial rows');
        check(ledgerApiRead()['info']['total']===0 && Db::name('Plog')->where('user_id',2)->value('plog_user_hidden')===0,'Hide-all crossed account scope');
        check(ledgerAction($entry,['all'=>'1'])['code']===1 && originals()===$before,'Repeated hide changed original financial data');
        foreach ([[],['ids'=>[]],['ids'=>'-1'],['ids'=>'1x'],['ids'=>'1','all'=>[]]] as $bad) {
            $state=Db::name('Plog')->order('plog_id')->select()->toArray();
            check(ledgerAction($entry,$bad)['code']!==1 && Db::name('Plog')->order('plog_id')->select()->toArray()===$state,'Invalid hide changed visibility');
        }
        ledgerSeed();$before=Db::name('Plog')->order('plog_id')->select()->toArray();
        check(ledgerAction($entry,['ids'=>'1'],'GET')['code']!==1 && Db::name('Plog')->order('plog_id')->select()->toArray()===$before,'GET changed visibility');
    }
    ledgerSeed();$before=originals();
    $model=new Plog();
    check($model->delData([])['code']!==1 && $model->delData(['plog_id'=>1])['code']!==1 && originals()===$before,'Model physically deleted financial records');
    check($model->fieldData(['plog_id'=>1],'plog_points',999)['code']!==1 && originals()===$before,'Generic field update rewrote financial history');
    check($model->saveData(['plog_id'=>1,'user_id'=>1,'plog_type'=>1,'plog_points'=>999])['code']!==1 && originals()===$before,'Save updated existing history');
    foreach ([0,'',null] as $id) { check($model->saveData(['plog_id'=>$id,'user_id'=>1,'plog_type'=>1,'plog_points'=>5])['code']!==1 && originals()===$before,'Explicit primary key accepted on append'); }
    check(ledgerApiRead(['filter'=>[]])['code']===1001,'Malformed filter was not controlled');
    check($model->saveData(['user_id'=>1,'plog_type'=>1,'plog_points'=>5,'plog_user_hidden'=>1])['code']===1,'Normal ledger append failed');
    check(Db::name('Plog')->order('plog_id desc')->value('plog_user_hidden')===0,'Caller inserted an already-hidden ledger');
    check(creationController(app\admin\controller\Plog::class)->del()['code']!==1 && count(originals())===5,'Admin delete endpoint erased records');
    $GLOBALS['creation_logged_in']=false;
    check(ledgerAction('api',['all'=>'1'])['code']===1401 && Db::name('Plog')->where('plog_user_hidden',1)->count()===0,'Unauthenticated API changed visibility');
    $GLOBALS['creation_logged_in']=true;

    // Existing sites can still read and append before their explicit schema migration.
    if ($mysql) { Db::execute('ALTER TABLE audit_plog DROP INDEX user_visibility, DROP COLUMN plog_user_hidden'); }
    else { Db::execute('ALTER TABLE audit_plog DROP COLUMN plog_user_hidden'); }
    $manager->connect()->getSchemaInfo('audit_plog',true);
    $before=originals();
    check(ledgerApiRead()['info']['total']===4,'Legacy schema became unreadable');
    foreach (['api','index'] as $entry) { check(ledgerAction($entry,['all'=>'1'])['code']===1006 && originals()===$before,'Legacy schema silently deleted instead of hiding'); }
    check($model->saveData(['user_id'=>1,'plog_type'=>1,'plog_points'=>5])['code']===1,'Legacy schema stopped normal financial appends');
    echo "Ledger retention: $checks checks passed on PHP ".PHP_VERSION.' / '.($mysql?'MySQL':'SQLite')."\n";
}
