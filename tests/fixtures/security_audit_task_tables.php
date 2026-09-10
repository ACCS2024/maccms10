<?php
/** Reward tables shared by the financial and authenticated API fixtures. */
use think\facade\Db;
if ($mysql) {
    $ddl = file_get_contents(dirname(__DIR__, 2) . '/application/install/sql/install.sql');
    foreach (['task', 'task_log', 'sign_log', 'sign_milestone', 'sign_milestone_log'] as $table) {
        if (!preg_match('/CREATE TABLE `mac_' . $table . '` \([\s\S]*?\) ENGINE[^;]*;/', $ddl, $match)) {
            throw new RuntimeException('Installation reward schema missing');
        }
        Db::execute('DROP TABLE IF EXISTS audit_' . $table);
        Db::execute(str_replace('`mac_' . $table . '`', '`audit_' . $table . '`', $match[0]));
    }
    Db::execute("SET SESSION sql_mode=''");
} else {
    Db::execute('CREATE TABLE audit_task (task_id INTEGER PRIMARY KEY, task_name TEXT DEFAULT "fixture task",
        task_type INTEGER DEFAULT 1, task_action TEXT UNIQUE, task_points INTEGER DEFAULT 0 CHECK(task_points BETWEEN 0 AND 4294967295),
        task_target INTEGER DEFAULT 1, task_sort INTEGER DEFAULT 0, task_status INTEGER DEFAULT 1)');
    Db::execute('CREATE TABLE audit_task_log (log_id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, task_id INTEGER,
        task_action TEXT, log_progress INTEGER DEFAULT 0 CHECK(log_progress BETWEEN 0 AND 4294967295), log_status INTEGER DEFAULT 0,
        log_points INTEGER DEFAULT 0, log_date TEXT, log_time INTEGER DEFAULT 0, log_claim_time INTEGER DEFAULT 0,
        UNIQUE(user_id, task_id, log_date))');
    Db::execute('CREATE TABLE audit_sign_log (sign_id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER,
        sign_date TEXT, sign_time INTEGER DEFAULT 0, sign_points INTEGER DEFAULT 0, sign_serial_days INTEGER DEFAULT 0,
        UNIQUE(user_id, sign_date))');
    Db::execute('CREATE TABLE audit_sign_milestone (milestone_id INTEGER PRIMARY KEY, milestone_name TEXT DEFAULT "fixture milestone",
        milestone_days INTEGER DEFAULT 1, milestone_points INTEGER DEFAULT 0 CHECK(milestone_points BETWEEN 0 AND 4294967295),
        milestone_status INTEGER DEFAULT 1)');
    Db::execute('CREATE TABLE audit_sign_milestone_log (log_id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER,
        milestone_id INTEGER, milestone_days INTEGER, log_points INTEGER, log_time INTEGER, UNIQUE(user_id, milestone_id))');
}
