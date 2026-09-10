<?php
/** Real installed card DDL plus the shared isolated financial fixture. */
require __DIR__ . '/security_audit_membership_db.php';
use think\facade\Db;
if ($mysql) {
    $ddl = file_get_contents(dirname(__DIR__, 2) . '/application/install/sql/install.sql');
    if (!preg_match('/CREATE TABLE `mac_card` \([\s\S]*?\) ENGINE[^;]*;/', $ddl, $match)) { throw new RuntimeException('Installation card schema missing'); }
    Db::execute('DROP TABLE IF EXISTS audit_card');
    Db::execute(str_replace('`mac_card`', '`audit_card`', $match[0]));
    Db::execute("SET SESSION sql_mode=''");
} else {
    Db::execute('CREATE TABLE audit_card (card_id INTEGER PRIMARY KEY AUTOINCREMENT, card_no TEXT, card_pwd TEXT,
        card_points INTEGER CHECK(card_points BETWEEN 0 AND 65535), card_money INTEGER DEFAULT 0,
        card_use_status INTEGER DEFAULT 0, card_sale_status INTEGER DEFAULT 0,
        card_use_time INTEGER DEFAULT 0, card_add_time INTEGER DEFAULT 0, user_id INTEGER DEFAULT 0)');
}
function cardSeed(int $balance = 100, int $points = 20): void {
    membershipSeed($balance);
    Db::execute('DELETE FROM audit_card');
    Db::name('Card')->insert(['card_id'=>1, 'card_no'=>'fixture-card', 'card_pwd'=>'fixture', 'card_points'=>$points]);
}
function cardState(): array {
    return [membershipState(), Db::name('Card')->order('card_id')->select()->toArray()];
}
