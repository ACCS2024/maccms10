<?php
/** A disposable loopback peer that accepts connections but cannot answer cache commands. */
declare(strict_types=1);
$port=filter_var($argv[1]??null,FILTER_VALIDATE_INT,['options'=>['min_range'=>1,'max_range'=>65535]]);
if(!$port)throw new RuntimeException('An isolated fixture port is required');
$server=stream_socket_server('tcp://127.0.0.1:'.$port,$error,$message);
if(!$server)throw new RuntimeException('Fixture listener failed');
$clients=[];$until=microtime(true)+10;
while(microtime(true)<$until){
    $client=@stream_socket_accept($server,0);if($client)$clients[]=$client;
    usleep(10000);
}
foreach($clients as $client)fclose($client);fclose($server);
