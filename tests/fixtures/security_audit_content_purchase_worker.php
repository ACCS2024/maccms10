<?php
/** One trusted internal purchase operation using only the isolated MySQL fixture. */
declare(strict_types=1);
if (getenv('MEMBERSHIP_AUDIT_MYSQL')!=='1') { throw new RuntimeException('Purchase concurrency worker requires isolated MySQL'); }
define('MEMBERSHIP_AUDIT_EXISTING_DB',true);
require __DIR__.'/security_audit_membership_db.php';
$parameters=json_decode($argv[1],true,32,JSON_THROW_ON_ERROR);
$GLOBALS['user']=['user_id'=>999,'user_points'=>999999];
$deadline=microtime(true)+10;
while (!is_file($parameters['barrier'])) {
    if (microtime(true)>$deadline) { throw new RuntimeException('Purchase fixture barrier timeout'); }
    usleep(10000);
}
echo json_encode(app\common\util\ContentPurchase::buy($parameters['user_id'],$parameters['record']),JSON_THROW_ON_ERROR);
