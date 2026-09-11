<?php
/** Exact decimal quotes, payee preservation and actual storage effects, without payment-provider calls. */
declare(strict_types=1);
require __DIR__.'/fixtures/cash_owner_db.php';
use app\common\model\Cash;
use think\facade\Db;
if ($mysql && getenv('CASH_AUDIT_STRICT') === '1') { Db::execute("SET SESSION sql_mode='STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION'"); }
function cashStorageCreate($amount,array $changes=[]): array {
    return (new Cash())->saveData(array_replace(['cash_money'=>$amount,'cash_bank_name'=>'Bank + branch','cash_bank_no'=>'001234+567','cash_payee_name'=>"Ordinary O'Name"],$changes));
}
foreach([['0.29',100,29],['0.01',100,1],['655.35',100,65535],['20.00','0.5',10],[0.29,100,29],
    ['1.01',1,2],['0.01','0.5',1],['0.29',3,1],['10.01','0.33333333',4]] as [$amount,$rate,$points]) {
    cashOwnerSeed('reserve');Db::name('User')->where('user_id',1)->update(['user_points'=>100000]);
    $GLOBALS['config']['user']['cash_ratio']=$rate;$GLOBALS['config']['user']['cash_min']='0.01';
    check(cashStorageCreate($amount)['code']===1,'Exact decimal withdrawal rejected');
    $row=Db::name('Cash')->where('user_id',1)->find();$user=memberRow();
    check((int)$row['cash_points']===$points&&(int)$user['user_points']===100000-$points&&(int)$user['user_points_froze']===$points,'Floating-point multiplication changed the actual reserved points');
    check($row['cash_bank_name']==='Bank + branch'&&$row['cash_bank_no']==='001234+567'&&$row['cash_payee_name']==='Ordinary O&#039;Name','Decoded form value was decoded again or stored differently');
}
cashOwnerSeed('reserve');Db::name('User')->where('user_id',1)->update(['user_points'=>100000]);$before=cashRefundState();
check(cashStorageCreate('65535.01')['code']!==1&&cashRefundState()===$before,'Rounding up beyond the stored cash-point capacity must reject the reservation');
foreach(['1e2','20.001','20,00','-1','',true,[],INF,'10000000000.00'] as $amount) {
    cashOwnerSeed('reserve');$before=cashRefundState();
    check(cashStorageCreate($amount)['code']!==1&&cashRefundState()===$before,'Invalid monetary representation changed the reservation');
}
foreach(['cash_ratio','cash_min'] as $setting)foreach([[],true,'1e2','-1',INF] as $value) {
    cashOwnerSeed('reserve');$GLOBALS['config']['user'][$setting]=$value;$before=cashRefundState();
    check(cashStorageCreate('20.00')['code']!==1&&cashRefundState()===$before,'Malformed exchange/minimum configuration changed funds');
}
foreach(['cash_bank_name'=>60,'cash_bank_no'=>30,'cash_payee_name'=>30] as $field=>$limit) {
    foreach([str_repeat('a',$limit),str_repeat('中',$limit)] as $value) {
        cashOwnerSeed('reserve');check(cashStorageCreate('20.00',[$field=>$value])['code']===1,'Exact payee column capacity rejected');
        check(Db::name('Cash')->value($field)===$value,'Exact payee field was truncated');
    }
    foreach([str_repeat('a',$limit+1),str_repeat('&',intdiv($limit,5)+1),[],false,1.5,"ordinary\nname","\xff"] as $value) {
        cashOwnerSeed('reserve');$before=cashRefundState();
        check(cashStorageCreate('20.00',[$field=>$value])['code']!==1&&cashRefundState()===$before,'Invalid/oversized payee field changed funds: '.$field);
    }
}
cashOwnerSeed('reserve');check(cashStorageCreate('20.00',['cash_bank_name'=>'Bank%20Branch'])['code']===1&&Db::name('Cash')->value('cash_bank_name')==='Bank%20Branch','Literal percent sequence was interpreted as another URL encoding');
foreach([[],true,'1.0','1e0','4294967296'] as $owner) {
    cashOwnerSeed('reserve');$GLOBALS['user']['user_id']=$owner;$before=cashRefundState();
    check(cashStorageCreate('20.00')['code']!==1&&cashRefundState()===$before,'Malformed owner selected another account');
}
cashOwnerSeed('reserve');Db::name('User')->where('user_id',1)->update(['user_status'=>0]);$before=cashRefundState();
check(cashStorageCreate('20.00')['code']!==1&&cashRefundState()===$before,'User disabled after login still reserved funds');
$cases=[
 ['reserve','user','UPDATE','user_points','NEW.user_points+1'],['reserve','user','UPDATE','user_points_froze','NEW.user_points_froze+1'],
 ['reserve','cash','INSERT','user_id','2'],['reserve','cash','INSERT','cash_points','NEW.cash_points+1'],
 ['reserve','cash','INSERT','cash_money','NEW.cash_money+0.01'],['reserve','cash','INSERT','cash_status','1'],
 ['reserve','cash','INSERT','cash_time','0'],['reserve','cash','INSERT','cash_time_audit','1'],
 ['reserve','cash','INSERT','cash_bank_no',"'changed account'"],['reserve','cash','INSERT','cash_payee_name',"'changed payee'"],
 ['refund','user','UPDATE','user_points','NEW.user_points+1'],['refund','user','UPDATE','user_points_froze','NEW.user_points_froze+1'],
 ['settle','user','UPDATE','user_points','NEW.user_points+1'],['settle','user','UPDATE','user_points_froze','NEW.user_points_froze+1'],
 ['settle','cash','UPDATE','cash_status','0'],['settle','cash','UPDATE','cash_time_audit','0'],
 ['settle','plog','INSERT','user_id','2'],['settle','plog','INSERT','plog_type','8'],
 ['settle','plog','INSERT','plog_points','NEW.plog_points+1'],['settle','plog','INSERT','plog_time','0'],
];
foreach($cases as [$operation,$table,$event,$field,$expression]) {
    cashOwnerSeed($operation);$before=cashRefundState();
    $body=$mysql?'FOR EACH ROW SET NEW.'.$field.'='.$expression:'BEGIN UPDATE audit_'.$table.' SET '.$field.'='.$expression.' WHERE '.$table.'_id=NEW.'.$table.'_id; END';
    Db::execute('CREATE TRIGGER cash_storage_alter '.($mysql?'BEFORE':'AFTER').' '.$event.' ON audit_'.$table.' '.$body);
    try{check(cashOwnerRun($operation)['code']!==1&&cashRefundState()===$before,'Altered financial storage was acknowledged: '.$operation.'/'.$table.'/'.$field);}
    finally{Db::execute('DROP TRIGGER cash_storage_alter');}
}
cashOwnerSeed('refund');$before=cashRefundState();
Db::execute("CREATE TRIGGER cash_reappear AFTER DELETE ON audit_cash ".($mysql?'FOR EACH ROW ':'BEGIN ')."INSERT INTO audit_cash(cash_id,user_id,cash_points,cash_money) VALUES(OLD.cash_id,OLD.user_id,OLD.cash_points,OLD.cash_money)".($mysql?'':'; END'));
try{check(cashOwnerRun('refund')['code']!==1&&cashRefundState()===$before,'Refund returned success while a reservation remained available for a second refund');}
finally{Db::execute('DROP TRIGGER cash_reappear');}
cashOwnerSeed('settle');$before=cashRefundState();
foreach(['cash_status'=>1,'cash_points'=>1,'cash_money'=>'0.01','user_id'=>2] as $field=>$value) {
    check((new Cash())->fieldData(['cash_id'=>1],$field,$value)['code']!==1&&cashRefundState()===$before,'Generic setter bypassed the cash state transition');
}
echo 'Cash exact storage: '.$checks.' checks passed on PHP '.PHP_VERSION.' / '.($mysql?'MySQL':'SQLite')."\n";
