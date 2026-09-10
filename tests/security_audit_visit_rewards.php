<?php
/** Daily visit quotas, bounded credit and checked ledgers must commit together. */
declare(strict_types=1);
require __DIR__ . '/fixtures/security_audit_visit_db.php';
use think\facade\Db;
use app\common\util\PointsBalance;

visitSeed();
check(visitCall()['code'] === 1 && memberRow()['user_points'] === 120
    && Db::name('Visit')->count() === 1 && Db::name('Plog')->count() === 1, 'A normal visit did not commit all three records');
$log = Db::name('Plog')->order('plog_id')->find();
check((int)$log['plog_points'] === 20 && (int)$log['plog_type'] === 3 && (int)$log['user_id'] === 1, 'Visit ledger changed its meaning');
$before = visitState();
check(visitCall()['code'] === 102 && visitState() === $before, 'A same-day replay changed balances or records');
$GLOBALS['visit_ip'] = '2130706434';
check(visitCall()['code'] === 1 && memberRow()['user_points'] === 140, 'Different addresses incorrectly shared a quota');
check(visitCall(['uid'=>2])['code'] === 1 && memberRow(2)['user_points'] === 20, 'Different beneficiaries incorrectly shared a quota');

foreach ([null, [], 'uid=1', ['uid'=>[]], ['uid'=>null], ['uid'=>false], ['uid'=>-1], ['uid'=>'1.0'],
    ['uid'=>'1e0'], ['uid'=>' 1'], ['uid'=>PointsBalance::MAX+1], ['uid'=>999]] as $input) {
    visitSeed(); $before = visitState();
    check(visitCall($input)['code'] === 101 && visitState() === $before, 'Invalid/missing beneficiary changed state');
}
foreach (['invite_visit_num','invite_visit_points'] as $key) {
    foreach ([[], false, -1, '1.2', '1e2', 'x', PointsBalance::MAX+1] as $value) {
        visitSeed(); $GLOBALS['config']['user'][$key] = $value; $before = visitState();
        check(visitCall()['code'] === 103 && visitState() === $before, 'Malformed visit configuration changed state: '.$key);
    }
}
foreach (['',0,'0',null] as $quota) {
    visitSeed(); $GLOBALS['config']['user']['invite_visit_num'] = $quota;
    check(visitCall()['code'] === 1 && visitCall()['code'] === 102, 'Historical empty quota no longer means one');
}
visitSeed(); $GLOBALS['config']['user']['invite_visit_num'] = '2';
check(visitCall()['code'] === 1 && visitCall()['code'] === 1 && visitCall()['code'] === 102
    && memberRow()['user_points'] === 140 && Db::name('Plog')->count() === 2, 'Configured quota was not enforced exactly');
visitSeed(); $GLOBALS['config']['user']['invite_visit_points'] = '0';
check(visitCall()['code'] === 1 && memberRow()['user_points'] === 100 && Db::name('Visit')->count() === 1
    && Db::name('Plog')->count() === 0 && visitCall()['code'] === 102, 'Zero reward should record a visit without a money movement');
visitSeed(); $GLOBALS['visit_ip'] = '0';
check(visitCall()['code'] === 1 && visitCall()['code'] === 102, 'Legacy unknown/IPv6 zero-address bucket was not bounded');
visitSeed(); $GLOBALS['visit_ip'] = [];
$before = visitState(); check(visitCall()['code'] === 103 && visitState() === $before, 'Malformed derived IP was accepted');

foreach ([strtotime('today')-1, strtotime('tomorrow'), strtotime('today')] as $time) {
    visitSeed();
    Db::name('Visit')->insert(['user_id'=>1,'visit_ip'=>$GLOBALS['visit_ip'],'visit_time'=>$time,'visit_ly'=>'fixture']);
    check(visitCall()['code'] === ($time === strtotime('today') ? 102 : 1), 'Daily interval mishandled midnight or future records');
}
visitSeed(); $GLOBALS['visit_referer'] = str_repeat('来源<&',100);
check(visitCall()['code'] === 1, 'A long normal referer failed');
$row = Db::name('Visit')->order('visit_id')->find();
check(mb_strlen($row['visit_ly'],'UTF-8') <= 100 && !str_contains($row['visit_ly'],'<')
    && mb_check_encoding($row['visit_ly'],'UTF-8'), 'Referer exceeded its column or lost escaping/UTF-8 integrity');

foreach ([PointsBalance::MAX-19, PointsBalance::MAX] as $balance) {
    visitSeed($balance); $before = visitState();
    check(visitCall()['code'] === 103 && visitState() === $before, 'Overflow clipped points or consumed the visit quota');
}
visitSeed(PointsBalance::MAX-20);
check(visitCall()['code'] === 1 && memberRow()['user_points'] === PointsBalance::MAX, 'Exact maximum credit was rejected');
visitSeed(0); $GLOBALS['config']['user']['invite_visit_points'] = (string)PointsBalance::MAX;
check(visitCall()['code'] === 1 && memberRow()['user_points'] === PointsBalance::MAX
    && (int)Db::name('Plog')->value('plog_points') === PointsBalance::MAX, 'Full installed INT UNSIGNED reward was truncated');

foreach (['member_fail_log_types','member_throw_log_types'] as $fault) {
    visitSeed(); $GLOBALS[$fault] = [3]; $before = visitState();
    check(visitCall()['code'] === 103 && visitState() === $before, 'Ledger failure left a visit or credit committed');
}
foreach (['visit','user','plog'] as $table) {
    visitSeed(); $operation = $table === 'user' ? 'UPDATE' : 'INSERT';
    Db::execute($mysql
        ? "CREATE TRIGGER visit_fixture_fail BEFORE $operation ON audit_$table FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='fixture failure'"
        : "CREATE TRIGGER visit_fixture_fail BEFORE $operation ON audit_$table BEGIN SELECT RAISE(FAIL,'fixture failure'); END");
    $before = visitState();
    check(visitCall()['code'] === 103 && visitState() === $before, 'Database write failure was not atomic: '.$table);
    Db::execute('DROP TRIGGER visit_fixture_fail');
}
visitSeed();
$manager->beforeStart = static function (): void { check(visitCall()['code'] === 1, 'The earlier competing visit failed'); };
check(visitCall()['code'] === 102 && memberRow()['user_points'] === 120
    && Db::name('Visit')->count() === 1 && Db::name('Plog')->count() === 1, 'Quota was read before the transaction');

if ($mysql) {
    foreach (['visit','user','plog'] as $table) {
        visitSeed(); Db::execute('ALTER TABLE audit_'.$table.' ENGINE=MyISAM'); $before = visitState();
        check(visitCall()['code'] === 103 && visitState() === $before, 'Nontransactional table accepted a reward: '.$table);
        Db::execute('ALTER TABLE audit_'.$table.' ENGINE=InnoDB');
    }
    visitSeed(); Db::execute('ALTER TABLE audit_plog MODIFY plog_points SMALLINT UNSIGNED NOT NULL DEFAULT 0');
    $GLOBALS['config']['user']['invite_visit_points'] = '65536'; $before = visitState();
    check(visitCall()['code'] === 103 && visitState() === $before, 'Legacy non-strict SMALLINT silently clipped the reward ledger');
    Db::execute('ALTER TABLE audit_plog MODIFY plog_points INT UNSIGNED NOT NULL DEFAULT 0');
    visitSeed();
    $peer = new PDO('mysql:host='.(getenv('MEMBERSHIP_AUDIT_HOST') ?: '127.0.0.1').';dbname=maccms_audit_membership;charset=utf8mb4',
        'root',getenv('MEMBERSHIP_AUDIT_PASSWORD') ?: '',[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);
    $peer->exec('SET SESSION innodb_lock_wait_timeout=1');
    $probed = false; $lockError = null;
    $manager->event('after_insert', static function ($query) use ($peer,&$probed,&$lockError): void {
        if ($probed || $query->getTable() !== 'audit_visit') { return; }
        $probed = true;
        try { $peer->exec('UPDATE audit_user SET user_points=user_points+1 WHERE user_id=1'); }
        catch (PDOException $error) { $lockError = $error->errorInfo[1] ?? 0; }
    });
    check(visitCall()['code'] === 1 && $probed && $lockError === 1205, 'Beneficiary row was not locked before storing the visit');
    check(memberRow()['user_points'] === 120 && Db::name('Visit')->count() === 1 && Db::name('Plog')->count() === 1,
        'Lock contention left a partial reward');
}
echo "visit reward audit: $checks checks passed on PHP ".PHP_VERSION.($mysql ? ' / MySQL non-strict' : ' / SQLite')."\n";
