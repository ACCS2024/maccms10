<?php
/** Test-only loopback router; private fixture root is supplied by its parent process. */
declare(strict_types=1);
require dirname(__DIR__,2).'/vendor/autoload.php';
set_error_handler(static function($level,$message,$file,$line){if(!(error_reporting()&$level))return false;throw new ErrorException($message,0,$level,$file,$line);});
define('ENTRANCE','admin');
$root=getenv('ADMIN_AUDIT_FIXTURE_ROOT');
if(!is_string($root)||$root===''||!is_file($root.'/audit.sqlite')){http_response_code(503);exit;}
function session($key){return \think\Container::getInstance()->make('session')->get($key);}
function mac_get_client_ip(){return '127.0.0.1';}
function config($key,$default=null){return \think\facade\Config::get($key,$default);}
$app=new \think\App($root.'/');
$database=['default'=>'audit','auto_timestamp'=>false,'connections'=>['audit'=>['type'=>'sqlite','database'=>$root.'/audit.sqlite','prefix'=>'audit_','fields_cache'=>false]]];
$app->config->set($database,'database');$db=new \think\DbManager();$db->setConfig($database);$app->instance('think\\DbManager',$db);
$request=\app\Request::__make($app)->setController('Vod')->setAction('save');$app->instance('request',$request);
$app->config->set(['type'=>'file','name'=>'fixture_session','expire'=>60,'path'=>$root.'/sessions'],'session');
$session=new \think\Session($app);$app->instance('session',$session);$session->init();
$session->set('admin_auth','1');$session->set('admin_info',['admin_id'=>2,'admin_name'=>'ordinary operator']);
$mode=$_GET['mode']??'';
$GLOBALS['config']['app']=['admin_audit_enabled'=>1,'admin_audit_get'=>0,'admin_audit_encrypt'=>in_array($mode,['encrypted','weak-key'],true)?1:0,
    'admin_audit_crypto_secret'=>$mode==='encrypted'?str_repeat('fixture-audit-key-',3):'short',
    'admin_audit_extra_redact'=>$mode==='bad-redaction'?[]:''];
$response=(new \app\middleware\AdminAudit())->handle($request,static fn()=>\think\Response::create('ordinary action completed','html',202));
$session->save();$response->send();
