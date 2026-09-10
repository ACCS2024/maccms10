<?php
/** Real Annex persistence for image/upload regressions; no application initialization. */
$database = ['default'=>'image', 'auto_timestamp'=>false, 'connections'=>['image'=>[
    'type'=>'sqlite', 'database'=>':memory:', 'prefix'=>'image_audit_', 'trigger_sql'=>false, 'fields_cache'=>false,
]]];
$manager = new \think\DbManager(); $manager->setConfig($database);
$configuration = new \think\Config(); $configuration->set($database,'database');
\think\Container::getInstance()->instance('think\\DbManager',$manager);
\think\Container::getInstance()->instance('config',$configuration);
\think\facade\Db::execute('CREATE TABLE image_audit_annex (annex_id INTEGER PRIMARY KEY AUTOINCREMENT,
    annex_time INTEGER NOT NULL, annex_file TEXT NOT NULL, annex_size INTEGER NOT NULL, annex_type TEXT NOT NULL)');

\think\facade\Db::execute('CREATE TABLE image_audit_user (user_id INTEGER PRIMARY KEY, user_status INTEGER NOT NULL, user_portrait TEXT NOT NULL DEFAULT "")');
\think\facade\Db::name('User')->insert(['user_id'=>1, 'user_status'=>1, 'user_portrait'=>'']);
