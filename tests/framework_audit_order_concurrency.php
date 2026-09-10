<?php
/** Two independent callbacks begin together against one actual InnoDB order; dedicated audit database only. */
declare(strict_types=1);
if(getenv('MEMBERSHIP_AUDIT_MYSQL')!=='1'){throw new RuntimeException('This concurrency regression requires the isolated MySQL fixture');}
require __DIR__.'/fixtures/financial_before_begin.php';
$worker=($argv[1]??'')==='worker';
define('MEMBERSHIP_AUDIT_CONNECTION_CLASS',FinancialBeforeBeginMysql::class);
define('MEMBERSHIP_AUDIT_DATABASE','maccms_audit_order_parallel');
if($worker){define('MEMBERSHIP_AUDIT_EXISTING_DB',true);}
else{
    $server=new PDO('mysql:host='.(getenv('MEMBERSHIP_AUDIT_HOST')?:'127.0.0.1').';charset=utf8mb4','root',getenv('MEMBERSHIP_AUDIT_PASSWORD')?:'');
    $server->exec('CREATE DATABASE IF NOT EXISTS maccms_audit_order_parallel CHARACTER SET utf8mb4');
}
require __DIR__.'/fixtures/security_audit_membership_db.php';
use think\facade\Db;
use app\common\model\Order;
Db::execute("SET SESSION sql_mode=''");
if($worker){
    $directory=$argv[2];$id=$argv[3];
    $GLOBALS['member_groups']=json_decode(file_get_contents($directory.'/groups.json'),true,512,JSON_THROW_ON_ERROR);
    $GLOBALS['financial_before_begin']=static function()use($directory,$id):void {
        if(file_put_contents($directory.'/ready-'.$id,'ready')!==5){throw new RuntimeException('Worker readiness failed');}
        $deadline=microtime(true)+10;
        while(!is_file($directory.'/go')){
            if(microtime(true)>$deadline){throw new RuntimeException('Worker barrier timed out');}
            usleep(10000);clearstatcache();
        }
    };
    echo json_encode((new Order())->notify('member-once','weixin','10.00'),JSON_THROW_ON_ERROR)."\n";
    exit;
}
foreach([false,true]as $membership){
    membershipSeed();membershipOrderSeed();
    if(!$membership){Db::name('Order')->where('order_id',1)->update(['order_remarks'=>'']);}
    $directory=sys_get_temp_dir().'/maccms-order-parallel-'.bin2hex(random_bytes(12));
    if(!mkdir($directory,0700)){throw new RuntimeException('Cannot create callback barrier');}
    file_put_contents($directory.'/groups.json',json_encode($GLOBALS['member_groups'],JSON_THROW_ON_ERROR));
    $workers=[];
    try{
        for($id=0;$id<2;$id++){
            $process=proc_open([PHP_BINARY,__FILE__,'worker',$directory,(string)$id],
                [0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);
            if(!is_resource($process)){throw new RuntimeException('Cannot start payment worker');}
            fclose($pipes[0]);$workers[]=[$process,$pipes];
        }
        $deadline=microtime(true)+10;
        while(!is_file($directory.'/ready-0') || !is_file($directory.'/ready-1')){
            if(microtime(true)>$deadline){throw new RuntimeException('Callbacks did not reach their actual BEGIN barrier');}
            usleep(10000);clearstatcache();
        }
        check(file_put_contents($directory.'/go','go')===2,'Both independent callbacks are ready before concurrent release');
        foreach($workers as $index=>[$process,$pipes]){
            $output=stream_get_contents($pipes[1]);$error=stream_get_contents($pipes[2]);fclose($pipes[1]);fclose($pipes[2]);
            $status=proc_close($process);unset($workers[$index]);
            check($status===0 && $error==='', 'Independent callback exits cleanly: '.$error);
            check((json_decode($output,true,512,JSON_THROW_ON_ERROR)['code']??null)===1,'Both the winner and its paid replay are acknowledged');
        }
        check((int)Db::name('Order')->value('order_status')===1,'Concurrent settlement leaves one paid order');
        check(memberRow(1)['user_points']===($membership?100:120),'Concurrent callbacks charge or credit the buyer once');
        check(Db::name('Plog')->count()===($membership?5:1) && Db::name('Plog')->where('plog_type',1)->count()===1,'Concurrent callbacks create exactly one recharge receipt and one set of ledgers');
        check((int)Db::name('User')->where('user_id','>',1)->sum('user_points')===($membership?4:0),'Concurrent callbacks issue referrals exactly once');
        check((int)memberRow(1)['group_id']===($membership?3:2),'Concurrent callbacks apply the intended membership');
    }finally{
        foreach($workers as [$process,$pipes]){proc_terminate($process);fclose($pipes[1]);fclose($pipes[2]);proc_close($process);}
        audit_remove_temp($directory);
    }
}
printf("Concurrent order settlement: %d checks on PHP %s / MySQL non-strict (4 independent workers).\n",$checks,PHP_VERSION);
