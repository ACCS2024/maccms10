<?php
/** Real User/Plog models, isolated Visit tables and deterministic request metadata. */
declare(strict_types=1);
require __DIR__ . '/security_audit_membership_db.php';
use think\facade\Db;

function mac_get_ip_long() { return $GLOBALS['visit_ip']; }
function mac_get_refer() { return $GLOBALS['visit_referer']; }
if ($mysql) {
    Db::execute("SET SESSION sql_mode=''");
    if (!preg_match('/CREATE TABLE `mac_visit` \([\s\S]*?\) ENGINE[^;]*;/', $ddl, $match)) {
        throw new RuntimeException('Installation visit schema missing');
    }
    Db::execute('DROP TABLE IF EXISTS audit_visit');
    Db::execute(str_replace('`mac_visit`', '`audit_visit`', $match[0]));
} else {
    Db::execute('CREATE TABLE audit_visit (visit_id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER,
        visit_ip INTEGER NOT NULL, visit_time INTEGER NOT NULL, visit_ly TEXT NOT NULL CHECK(length(visit_ly)<=100))');
    Db::execute('DROP TABLE audit_plog');
    Db::execute('CREATE TABLE audit_plog (plog_id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, plog_type INTEGER,
        plog_points INTEGER CHECK(plog_points BETWEEN 0 AND 4294967295), plog_time INTEGER, plog_remarks TEXT)');
}
function visitSeed(int $balance = 100): void {
    membershipSeed($balance);
    Db::name('Visit')->delete(true);
    $GLOBALS['config']['user']['invite_visit_num'] = '1';
    $GLOBALS['config']['user']['invite_visit_points'] = '20';
    $GLOBALS['visit_ip'] = '2130706433';
    $GLOBALS['visit_referer'] = 'https://fixture.example/referral';
}
function visitState(): array {
    return [membershipState(), Db::name('Visit')->order('visit_id')->select()->toArray()];
}
function visitCall($param = ['uid'=>'1']): array { return (new app\common\model\User())->visit($param); }
