<?php
/** Real ORM split connections to different actual MySQL databases: no replacement database or query builder. */
use think\facade\Db;
$writer=Db::connect();$replica=$database.'_read';
$writer->execute('CREATE DATABASE `'.$replica.'` CHARACTER SET utf8mb4');
try {
    foreach($tables as $table){$writer->execute('CREATE TABLE `'.$replica.'`.`audit_unified_'.$table.'` LIKE `'.$database.'`.`audit_unified_'.$table.'`');$writer->execute('INSERT INTO `'.$replica.'`.`audit_unified_'.$table.'` SELECT * FROM `'.$database.'`.`audit_unified_'.$table.'`');}
    foreach($kinds as $kind)$writer->execute('ALTER TABLE `'.$replica.'`.`audit_unified_'.$kind.'` DROP COLUMN '.$kind.'_recycle_time');
    $split=$cfg;$split['connections']['fixture']=array_replace($cfg['connections']['fixture'],[
        'dsn'=>'','database'=>$database.','.$replica,'hostname'=>'localhost,localhost','socket'=>$socket,'deploy'=>1,'rw_separate'=>true,'master_num'=>1,'slave_no'=>1,
    ]);
    $fresh=static function()use($app,$split,&$sql):void{$manager=new think\DbManager();$manager->setConfig($split);$app->instance('think\\DbManager',$manager);Db::listen(static function($statement)use(&$sql):void{$sql[]=$statement;});};
    $fresh();check(Db::query('SELECT DATABASE() AS db',[],false)[0]['db']===$replica&&Db::query('SELECT DATABASE() AS db',[],true)[0]['db']===$database,'Fixture did not route reads/writes to different PDO databases');
    foreach(['index','suggest'] as $endpoint)foreach([false,true] as $meili){
        $reset();$fresh();$r=unifiedRequest($endpoint,['wd'=>'match'],$meili);
        foreach($kinds as $kind)check(($endpoint==='index'?$ids($r,$kind):$slimIds($r,$kind))===($meili?[10,20]:[20,10]),'Replica missing recycle metadata weakened writer publication guard');
        $writer->execute('UPDATE audit_unified_vod SET vod_status=0 WHERE vod_id=20');
        $fresh();$r=unifiedRequest($endpoint,['wd'=>'match'],$meili);check(!in_array(20,$endpoint==='index'?$ids($r,'vod'):$slimIds($r,'vod'),true),'Replica-lag cached visibility leaked a writer-hidden row');
        $writer->execute('UPDATE audit_unified_vod SET vod_status=1 WHERE vod_id=20');
    }
    // Metadata memoization belongs to one Request AND one actual connection, never just a module name.
    $reset();$fresh();$controller=new app\api\controller\Search();$method=new ReflectionMethod($controller,'publishedQuery');$sql=[];
    $method->invoke($controller,'vod')->count();$method->invoke($controller,'vod')->count();
    check(count(array_filter($sql,static fn($q)=>str_contains(strtolower($q),'information_schema.columns')))===1,'One request repeatedly probed the same writer schema');
    $request=(new think\Request())->withGet(['wd'=>'match']);$app->instance('request',$request);$sql=[];$method->invoke($controller,'vod')->count();
    check(count(array_filter($sql,static fn($q)=>str_contains(strtolower($q),'information_schema.columns')))===1,'Schema evidence leaked across requests');
    $other=$cfg;$other['connections']['fixture']['dsn']='mysql:unix_socket='.$socket.';dbname='.$replica.';charset=utf8mb4';$other['connections']['fixture']['database']=$replica;
    $otherManager=new think\DbManager();$otherManager->setConfig($other);$app->instance('think\DbManager',$otherManager);
    check(in_array(40,array_map('intval',$method->invoke($controller,'vod')->column('vod_id')),true),'Different actual connection reused the first database schema');
    $fresh();check(!in_array(40,array_map('intval',$method->invoke($controller,'vod')->column('vod_id')),true),'Returning to writer retained another database legacy schema');

    // Conversely, lagging replicas must not hide writer-visible hits in this endpoint.
    $writer->execute('UPDATE `'.$replica.'`.audit_unified_vod SET vod_status=0');
    foreach(['index','suggest'] as $endpoint){$reset();$fresh();$r=unifiedRequest($endpoint,['wd'=>'match'],true);check(($endpoint==='index'?$ids($r,'vod'):$slimIds($r,'vod'))===[10,20],'Source rows were still loaded from the stale replica');}
} finally {
    $app->instance('think\\DbManager',$manager);$writer->execute('DROP DATABASE `'.$replica.'`');
}
