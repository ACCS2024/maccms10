<?php
/** Local HTTP fixture: actual PHP upload ownership and TP8 Request file conversion. */
declare(strict_types=1);
require dirname(__DIR__,2).'/vendor/autoload.php';
error_reporting(E_ALL);
set_error_handler(static function($severity,$message,$file,$line){throw new ErrorException($message,0,$severity,$file,$line);});
header('Content-Type: application/json');
try {
    $request=(new think\Request())->withFiles($_FILES);
    $upload=app\common\util\ImportUpload::inspect($request->file('file'),['csv','txt','xlsx'],app\common\util\BulkTableIo::MAX_IMPORT_BYTES);
    $parsed=app\common\util\BulkTableIo::parseFile($upload['path'],$upload['extension'],true);
    echo json_encode(['ok'=>true,'uploaded'=>is_uploaded_file($upload['path']),'rows'=>$parsed['rows'],'row_numbers'=>$parsed['row_numbers']],JSON_THROW_ON_ERROR);
} catch(Throwable $error) {echo json_encode(['ok'=>false]);}
