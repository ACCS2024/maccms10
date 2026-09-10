<?php
/** Isolated cash ledger using the installation DDL, never an application connection. */
declare(strict_types=1);
require __DIR__ . '/security_audit_membership_db.php';
use think\facade\Db;

if ($mysql) {
    // Exercise the deployment mode in which unsigned overflow otherwise only emits a warning.
    Db::execute("SET SESSION sql_mode=''");
    $ddl = file_get_contents(dirname(__DIR__, 2) . '/application/install/sql/install.sql');
    if (!preg_match('/CREATE TABLE `mac_cash` \([\s\S]*?\) ENGINE[^;]*;/', $ddl, $match)) {
        throw new RuntimeException('Installation cash schema missing');
    }
    Db::execute('DROP TABLE IF EXISTS audit_cash');
    Db::execute(str_replace('`mac_cash`', '`audit_cash`', $match[0]));
} else {
    Db::execute('ALTER TABLE audit_user ADD user_points_froze INTEGER NOT NULL DEFAULT 0
        CHECK(user_points_froze BETWEEN 0 AND 4294967295)');
    Db::execute('CREATE TABLE audit_cash (cash_id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL DEFAULT 0, cash_status INTEGER NOT NULL DEFAULT 0 CHECK(cash_status BETWEEN 0 AND 255),
        cash_points INTEGER NOT NULL DEFAULT 0 CHECK(cash_points BETWEEN 0 AND 65535),
        cash_money NUMERIC NOT NULL DEFAULT 0, cash_bank_name TEXT NOT NULL DEFAULT "",
        cash_bank_no TEXT NOT NULL DEFAULT "", cash_payee_name TEXT NOT NULL DEFAULT "",
        cash_time INTEGER NOT NULL DEFAULT 0, cash_time_audit INTEGER NOT NULL DEFAULT 0)');
}

function cashRefundSeed(int $available = 80, int $frozen = 20, int $points = 20, int $status = 0): void {
    Db::execute('DELETE FROM audit_cash');
    membershipSeed($available);
    Db::name('User')->where('user_id', 1)->update(['user_points_froze'=>$frozen]);
    Db::name('Cash')->insert(['cash_id'=>1, 'user_id'=>1, 'cash_status'=>$status,
        'cash_points'=>$points, 'cash_money'=>'20.00', 'cash_time'=>123]);
}
function cashRefundState(): array {
    return [Db::name('User')->order('user_id')->select()->toArray(),
        Db::name('Cash')->order('cash_id')->select()->toArray(),
        Db::name('Plog')->order('plog_id')->select()->toArray()];
}
function cashRefundSecondUser(int $available = 70, int $frozen = 30): void {
    Db::name('User')->where('user_id', 2)->update(['user_points'=>$available, 'user_points_froze'=>$frozen]);
    Db::name('Cash')->insert(['cash_id'=>2, 'user_id'=>2, 'cash_points'=>30, 'cash_money'=>'30.00']);
}
