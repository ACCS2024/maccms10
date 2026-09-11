<?php
/** Bounded audit snapshots and actual HTTP middleware writing to a private SQLite audit table. */
declare(strict_types=1);
require dirname(__DIR__).'/vendor/autoload.php';
require __DIR__.'/fixtures/security_audit_test_helpers.php';
use app\common\util\AdminAuditPayload;
use app\common\util\SensitiveDataCrypto;
function auditPayload(array $data,array $config=[]):array {
    $json=AdminAuditPayload::encode($data,$config);
    check(strlen($json)<=16384&&mb_check_encoding($json,'UTF-8'),'Audit snapshot must be bounded valid UTF-8');
    return json_decode($json,true,512,JSON_THROW_ON_ERROR);
}
$ordinary=['id'=>17,'label'=>'Ordinary 中文','enabled'=>true,'optional'=>null,'ratio'=>0.25,'ids'=>[1,2,3]];
$encoded=auditPayload($ordinary);
check($encoded===['version'=>2,'data'=>$ordinary,'truncated'=>false],'Ordinary typed fields and nested lists must retain their values');
foreach(['中','🙂','é'] as $character) {
    $encoded=auditPayload(['label'=>str_repeat($character,2100)]);
    check($encoded['truncated']===true&&str_ends_with($encoded['data']['label'],'…')&&strlen($encoded['data']['label'])<=2003,'Long ordinary Unicode fields must truncate at complete characters');
}
foreach(['admin_pwd','user_pwd2','password_confirmation','PASSWORD','passwd','old_pwd','authorization','cookie','session_id','client_secret','api_key','ApiKey','__token__','access_key','private_key','credential','verify','sql','user_check','admin_check'] as $key) {
    $encoded=auditPayload(['outer'=>[$key=>['nested'=>'fixture-private-value'],'ordinary'=>'visible']]);
    check($encoded['data']['outer'][$key]==='[redacted]'&&$encoded['data']['outer']['ordinary']==='visible','Sensitive field names must redact the complete nested value without losing unrelated fields');
}
$encoded=auditPayload(['PersonalCard'=>'fixture-card','visible'=>'ordinary'],['admin_audit_extra_redact'=>'personal | DOB,Card']);
check($encoded['data']['PersonalCard']==='[redacted]'&&$encoded['data']['visible']==='ordinary','Bounded custom redaction words remain case-insensitive');
foreach([[],null,true,str_repeat('x',4097),str_repeat('x',65),implode(',',array_fill(0,65,'word')),"bad\xff"] as $extra) {
    $encoded=auditPayload(['private_custom'=>'fixture-private-value'],['admin_audit_extra_redact'=>$extra]);
    check(isset($encoded['redacted'])&&!isset($encoded['data']),'Malformed custom redaction configuration cannot fall back to logging unredacted payload');
}
$deep=['leaf'=>'ordinary'];for($i=0;$i<600;$i++)$deep=['next'=>$deep];
check(auditPayload($deep)['truncated']===true,'Deep payloads must stop before excessive recursion');
$cycle=[];$cycle['self']=&$cycle;
check(auditPayload($cycle)['truncated']===true,'Reference cycles from internal callers must remain bounded');unset($cycle);
check(auditPayload(array_fill(0,10000,'ordinary'))['truncated']===true,'Wide payloads must stop at the shared traversal budget');
$encoded=auditPayload(['ordinary'=>'preserved',str_repeat('key',1000)=>'omitted',"invalid\xff"=>'omitted','bad'=>"A\xffB"]);
check($encoded['truncated']===true&&$encoded['data']['ordinary']==='preserved','Malformed text and oversized keys must not invalidate the whole JSON record');
$object=new class implements JsonSerializable {public function jsonSerialize():mixed{throw new RuntimeException('Object serialization must not execute');}};
$encoded=auditPayload(['object'=>$object,'nan'=>NAN,'inf'=>INF]);
check($encoded['data']===['object'=>'[unsupported]','nan'=>'[unsupported]','inf'=>'[unsupported]'],'Objects and nonfinite numbers cannot invoke user code or break audit serialization');
$encoded=auditPayload(array_fill(0,10,str_repeat("\0",2000)));
check(isset($encoded['redacted'])&&$encoded['truncated']===true,'Worst-case JSON escaping must produce a valid omission record instead of cutting JSON bytes');

$temp=audit_temp_dir('admin-audit-payload');$process=null;
register_shutdown_function(static function()use($temp,&$process):void {
    if(is_resource($process)){proc_terminate($process);for($i=0;$i<50&&proc_get_status($process)['running'];$i++)usleep(20000);if(proc_get_status($process)['running'])proc_terminate($process,9);proc_close($process);}
    audit_remove_temp($temp);
});
$pdo=new PDO('sqlite:'.$temp.'/audit.sqlite');$pdo->setAttribute(PDO::ATTR_ERRMODE,PDO::ERRMODE_EXCEPTION);
$pdo->exec('CREATE TABLE audit_admin_audit_log (audit_id INTEGER PRIMARY KEY AUTOINCREMENT,admin_id INTEGER,admin_name TEXT,audit_time INTEGER,audit_ip TEXT,audit_method TEXT,audit_route TEXT,audit_uri TEXT,audit_http_code INTEGER,audit_payload TEXT)');
$socket=stream_socket_server('tcp://127.0.0.1:0',$error,$message);$address=stream_socket_get_name($socket,false);fclose($socket);
$process=proc_open([PHP_BINARY,'-d','display_errors=1','-d','error_reporting=-1','-S',$address,'-t',$temp,__DIR__.'/fixtures/admin_audit_payload_http.php'],
    [0=>['file','/dev/null','r'],1=>['file',$temp.'/server.log','a'],2=>['file',$temp.'/server.log','a']],$pipes,$temp,array_replace(getenv(),['ADMIN_AUDIT_FIXTURE_ROOT'=>$temp]));
check(is_resource($process),'Isolated audit HTTP fixture must start');
for($i=0;$i<100;$i++){$ready=@stream_socket_client('tcp://'.$address,$error,$message,0.02);if($ready){fclose($ready);break;}usleep(20000);}
check($i<100,'Isolated audit HTTP fixture must become ready');
function auditHttp(array $body,array $query=[]):array {
    global $address,$pdo;
    $before=(int)$pdo->query('SELECT COUNT(*) FROM audit_admin_audit_log')->fetchColumn();
    $curl=curl_init('http://'.$address.'/record'.($query?'?'.http_build_query($query):''));
    curl_setopt_array($curl,[CURLOPT_POST=>true,CURLOPT_POSTFIELDS=>http_build_query($body),CURLOPT_RETURNTRANSFER=>true,CURLOPT_TIMEOUT=>5]);
    $response=curl_exec($curl);$status=curl_getinfo($curl,CURLINFO_RESPONSE_CODE);curl_close($curl);
    check($status===202&&$response==='ordinary action completed','Actual HTTP audit middleware must preserve the completed action response');
    check((int)$pdo->query('SELECT COUNT(*) FROM audit_admin_audit_log')->fetchColumn()===$before+1,'Actual HTTP middleware must persist exactly one audit row');
    return $pdo->query('SELECT * FROM audit_admin_audit_log ORDER BY audit_id DESC LIMIT 1')->fetch(PDO::FETCH_ASSOC);
}
$row=auditHttp(['title'=>str_repeat('中',700),'password_confirmation'=>'fixture-password'],['token'=>'fixture-query-token']);
$payload=json_decode($row['audit_payload'],true,512,JSON_THROW_ON_ERROR);
check($payload['truncated']===true&&$payload['data']['password_confirmation']==='[redacted]'&&$payload['data']['token']==='[redacted]','The real HTTP middleware must store valid truncated Unicode and redact body/query secrets');
check($row['audit_method']==='POST'&&$row['audit_route']==='vod/save'&&(int)$row['audit_http_code']===202&&!str_contains($row['audit_uri'],'fixture-query-token'),'Actual stored metadata must preserve action identity without query credentials');
$crypto=['admin_audit_crypto_secret'=>str_repeat('fixture-audit-key-',3)];
$row=auditHttp(['title'=>'ordinary encrypted title','api_key'=>'fixture-secret'],['mode'=>'encrypted']);
check(SensitiveDataCrypto::isEncryptedPayload($row['audit_payload'])&&!str_contains($row['audit_payload'],'ordinary encrypted title'),'Enabled audit encryption must store ciphertext through the actual middleware');
$payload=json_decode(SensitiveDataCrypto::decryptString($row['audit_payload'],$crypto),true,512,JSON_THROW_ON_ERROR);
check($payload['data']['title']==='ordinary encrypted title'&&$payload['data']['api_key']==='[redacted]','Decrypted stored payload must preserve the redacted JSON snapshot');
$row=auditHttp(['title'=>'must not become plaintext'],['mode'=>'weak-key']);
check($row['audit_payload']==='{"redacted":"audit encryption unavailable"}','Encryption refusal must preserve the existing no-plaintext fallback');
$row=auditHttp(['title'=>'custom redaction unavailable'],['mode'=>'bad-redaction']);
check($row['audit_payload']==='{"redacted":"audit payload unavailable"}','Actual HTTP recording must safely omit payload under malformed custom redaction configuration');
$row=auditHttp([]);check($row['audit_payload']==='','An empty request keeps the established empty-payload representation');
check(!preg_match('/(?:Warning|Deprecated|Fatal error|Uncaught)/',file_get_contents($temp.'/server.log')),'Ordinary HTTP audit cases must not emit PHP diagnostics');
echo 'Administrator audit payload: '.$checks.' checks passed on PHP '.PHP_VERSION."\n";
