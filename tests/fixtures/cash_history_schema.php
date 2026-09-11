<?php
declare(strict_types=1);
function cashHistorySchema(bool $mysql): void
{
    \think\facade\Db::execute('DROP TABLE IF EXISTS audit_cash_history');
    if ($mysql) {
        $ddl=file_get_contents(dirname(__DIR__,2).'/application/install/sql/install.sql');
        if(!preg_match('/CREATE TABLE `mac_cash_history` \([\s\S]*?\) ENGINE[^;]*;/',$ddl,$match))throw new RuntimeException('Cash archive install DDL missing');
        \think\facade\Db::execute(str_replace('`mac_cash_history`','`audit_cash_history`',$match[0]));
    } else {
        \think\facade\Db::execute('CREATE TABLE audit_cash_history(cash_id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL,
            cash_status INTEGER NOT NULL, cash_time INTEGER NOT NULL, cash_time_archive INTEGER NOT NULL,
            cash_actor_type TEXT NOT NULL, cash_actor_id INTEGER NOT NULL, cash_payload TEXT NOT NULL, cash_payload_hash TEXT NOT NULL)');
    }
}
