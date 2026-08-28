<?php
/**
 * 共享:从站点 .env 建 PDO。各脚本 require 它。
 * 用法:$pdo = lb_pdo("/home/wwwroot/lebozy.com");
 */
function lb_pdo($root)
{
    $env = @parse_ini_file(rtrim($root, "/") . "/.env", false, INI_SCANNER_RAW);
    if (!$env || empty($env["DB_NAME"])) {
        fwrite(STDERR, "FATAL: 读不到 $root/.env 的 DB_* 配置\n");
        exit(1);
    }
    return new PDO(
        "mysql:host=" . ($env["DB_HOST"] ?: "127.0.0.1") . ";port=" . ($env["DB_PORT"] ?: "3306") . ";dbname=" . $env["DB_NAME"],
        $env["DB_USER"], $env["DB_PASS"],
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
    );
}
