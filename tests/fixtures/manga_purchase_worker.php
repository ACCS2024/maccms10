<?php
/** A separate real-route buyer for the dedicated local MySQL purchase fixture. */
declare(strict_types=1);
if(getenv('PURCHASE_CSRF_MYSQL')!=='1')throw new RuntimeException('The isolated purchase database is required');
putenv('MANGA_PURCHASE_AUDIT=1');
define('PURCHASE_CSRF_EXISTING_DB',true);
require __DIR__.'/purchase_csrf.php';
$arguments=json_decode($argv[1],true,32,JSON_THROW_ON_ERROR);
$GLOBALS['config']['user']['manga_points_type']=$arguments['whole'];
$thread=\think\facade\Db::query('SELECT CONNECTION_ID() AS id')[0]['id'];
file_put_contents($arguments['ready'],(string)$thread);
$deadline=microtime(true)+15;
while(!is_file($arguments['barrier'])){
    if(microtime(true)>$deadline)throw new RuntimeException('Manga purchase worker barrier timed out');usleep(10000);
}
$response=purchaseCsrfRoute($arguments['target'],$arguments['body'],[],[],['Authorization'=>'Bearer '.$arguments['bearer']]);
echo json_encode($response['data'],JSON_THROW_ON_ERROR);
