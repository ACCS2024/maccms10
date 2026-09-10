<?php
/** Real split-connection reads use a separate ordinary-content database with delayed state. */
use think\facade\Db;
$writer=Db::connect();$replica=$database.'_read';
$writer->execute('CREATE DATABASE `'.$replica.'` CHARACTER SET utf8mb4');
try {
    foreach ($kinds as $kind) {
        $writer->execute('CREATE TABLE `'.$replica.'`.`audit_ai_'.$kind.'` LIKE `'.$database.'`.`audit_ai_'.$kind.'`');
        $writer->execute('INSERT INTO `'.$replica.'`.`audit_ai_'.$kind.'` SELECT * FROM `'.$database.'`.`audit_ai_'.$kind.'`');
    }
    foreach (['vod','art','manga'] as $kind) { $writer->execute('ALTER TABLE `'.$replica.'`.`audit_ai_'.$kind.'` DROP COLUMN '.$kind.'_recycle_time'); }
    $split=$cfg;$split['connections']['fixture']=array_replace($cfg['connections']['fixture'],[
        'dsn'=>'','database'=>$database.','.$replica,'hostname'=>'localhost,localhost','socket'=>$socket,'deploy'=>1,'rw_separate'=>true,'master_num'=>1,'slave_no'=>1,
    ]);
    $fresh=static function() use ($app,$split): void { $manager=new think\DbManager();$manager->setConfig($split);$app->instance('think\DbManager',$manager); };
    $fresh();
    check(Db::query('SELECT DATABASE() AS db',[],false)[0]['db']===$replica && Db::query('SELECT DATABASE() AS db',[],true)[0]['db']===$database,'Fixture routes did not use two actual PDO databases');
    foreach ($modules as $module) foreach ([false,true] as $meili) {
        $kind=$sourceKind($module);$clear();$fresh();
        check($payloadIds($build($module,$meili))===($meili?[10,20]:[20,10]),'Replica schema changed the actual writer public rows');
        $writer->execute('UPDATE audit_ai_'.$kind.' SET '.$kind.'_status=0 WHERE '.$kind.'_id=20');
        $fresh();check($payloadIds($build($module,$meili))===[10],'Delayed replica retained writer-withdrawn content');
        $writer->execute('UPDATE audit_ai_'.$kind.' SET '.$kind.'_status=1 WHERE '.$kind.'_id=20');
        // A reader that has not received a publication must not hide writer-visible index results.
        $writer->execute('UPDATE `'.$replica.'`.audit_ai_'.$kind.' SET '.$kind.'_status=0 WHERE '.$kind.'_id IN (10,20)');
        $clear();$fresh();check($payloadIds($build($module,$meili))===($meili?[10,20]:[20,10]),'Writer-visible content was omitted by the delayed reader');
        $writer->execute('UPDATE `'.$replica.'`.audit_ai_'.$kind.' SET '.$kind.'_status=1 WHERE '.$kind.'_id IN (10,20)');
    }
} finally { $app->instance('think\DbManager',$originalManager);$writer->execute('DROP DATABASE `'.$replica.'`'); }
