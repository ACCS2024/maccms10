<?php
/** Referral balances and ledgers must survive real non-strict storage and nested rollback contracts. */
require __DIR__.'/fixtures/security_audit_membership_db.php';
use think\facade\Db;
use app\common\model\User;
if ($mysql) { Db::execute("SET SESSION sql_mode=''"); }
function referralReject(string $message): void {
    $before=membershipState(); $failed=false;
    try { (new User())->reward(3000,1); } catch (RuntimeException $error) { $failed=true; }
    check($failed && membershipState()===$before,$message);
}
function referralAlterTrigger(string $table, string $field, string $value, int $type): void {
    global $mysql;
    $table='audit_'.$table;
    if ($mysql) {
        Db::execute('CREATE TRIGGER audit_referral_change BEFORE INSERT ON '.$table.' FOR EACH ROW BEGIN IF NEW.plog_type='.$type.' THEN SET NEW.'.$field.'='.$value.'; END IF; END');
    } else {
        Db::execute('CREATE TRIGGER audit_referral_change AFTER INSERT ON '.$table.' WHEN NEW.plog_type='.$type.' BEGIN UPDATE '.$table.' SET '.$field.'='.$value.' WHERE plog_id=NEW.plog_id; END');
    }
}
foreach ([4,5,6] as $type) {
    foreach (['user_id'=>'99','plog_type'=>'2','plog_points'=>'1','plog_remarks'=>"'Changed by isolated fixture'"] as $field=>$value) {
        membershipSeed();
        referralAlterTrigger('plog',$field,$value,$type);
        try { referralReject('A changed '.$field.' at referral tier '.$type.' must roll back earlier beneficiaries and all ledgers'); }
        finally { Db::execute('DROP TRIGGER audit_referral_change'); }
        check((new User())->reward(3000,1)['code']===1,'Unmodified full referral values must persist after removing the fixture fault');
    }
}
foreach ([2,3,4] as $recipient) {
    membershipSeed();
    if ($mysql) {
        Db::execute('CREATE TRIGGER audit_referral_change BEFORE UPDATE ON audit_user FOR EACH ROW BEGIN IF NEW.user_id='.$recipient.' THEN SET NEW.user_points=NEW.user_points+1; END IF; END');
    } else {
        Db::execute('CREATE TRIGGER audit_referral_change AFTER UPDATE ON audit_user WHEN NEW.user_id='.$recipient.' BEGIN UPDATE audit_user SET user_points=NEW.user_points+1 WHERE user_id=NEW.user_id; END');
    }
    try { referralReject('Changed stored balance at recipient '.$recipient.' must roll back the entire referral event'); }
    finally { Db::execute('DROP TRIGGER audit_referral_change'); }
}
membershipSeed();
$before=membershipState();
Db::startTrans();
Db::name('User')->where('user_id',1)->setDec('user_points',20);
check((new User())->reward(20,1)['code']===1,'Referral storage must participate in an already started purchase transaction');
Db::rollback();
check(membershipState()===$before,'Caller rollback must reverse buyer debit, all referral balances and ledgers');
if ($mysql) {
    foreach ([['user','user_points','TINYINT UNSIGNED NOT NULL DEFAULT 0','INT UNSIGNED NOT NULL DEFAULT 0'],
        ['plog','plog_points','TINYINT UNSIGNED NOT NULL DEFAULT 0','SMALLINT UNSIGNED NOT NULL DEFAULT 0'],
        ['plog','plog_remarks',"VARCHAR(3) NOT NULL DEFAULT ''","VARCHAR(255) NOT NULL DEFAULT ''"]] as [$table,$column,$narrow,$normal]) {
        membershipSeed();
        Db::execute('ALTER TABLE audit_'.$table.' MODIFY '.$column.' '.$narrow);
        try { referralReject('Real non-strict '.$table.'.'.$column.' clipping must never commit an incomplete reward'); }
        finally { Db::execute('ALTER TABLE audit_'.$table.' MODIFY '.$column.' '.$normal); }
        check((new User())->reward(3000,1)['code']===1,'Restored normal column must accept the original reward after clipping was rejected');
    }
    foreach (['user','plog'] as $table) {
        membershipSeed(); Db::execute('ALTER TABLE audit_'.$table.' ENGINE=MyISAM');
        try { referralReject('Nontransactional '.$table.' must be rejected before any referral write'); }
        finally { Db::execute('ALTER TABLE audit_'.$table.' ENGINE=InnoDB'); }
    }
}
printf("Referral exact storage: %d checks passed on PHP %s (%s).\n",$checks,PHP_VERSION,$mysql?'MySQL non-strict':'SQLite');
