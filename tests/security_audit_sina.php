<?php
/** Actual client plus real TLS and loopback response faults; no external requests or credentials. */
namespace app\common\util {
    function curl_init($url = null) {
        $handle = \curl_init($url);
        $GLOBALS['sina_urls'][] = $url;
        return $handle;
    }
    function curl_setopt_array($handle, $options) {
        $GLOBALS['sina_options'] = $options;
        $root = $GLOBALS['sina_fixture'];
        $ports = json_decode(file_get_contents($root.'/ports.json'), true);
        $port = $ports[$GLOBALS['sina_tls'] === 'hostname' ? 'wrong' : 'good'];
        // Only alter fixture resolution/port/CA. The production peer/host, protocol, redirect,
        // timeout, credentials and response callbacks below go through real libcurl unchanged.
        $options[CURLOPT_PROXY] = '';
        $options[CURLOPT_PORT] = $port;
        $options[CURLOPT_RESOLVE] = ['login.sina.com.cn:'.$port.':127.0.0.1', 'picupload.service.weibo.com:'.$port.':127.0.0.1'];
        if ($GLOBALS['sina_tls'] !== 'untrusted') { $options[CURLOPT_CAINFO] = $root.'/ca.crt'; }
        return \curl_setopt_array($handle, $options);
    }
}
namespace {
    require dirname(__DIR__).'/vendor/autoload.php';
    require __DIR__.'/fixtures/security_audit_test_helpers.php';
    require dirname(__DIR__).'/application/common.php';
    $root = audit_temp_dir('sina-https');
    define('ROOT_PATH', $root.'/');
    define('APP_PATH', $root.'/application/');
    $GLOBALS['sina_fixture'] = $root;
    $GLOBALS['sina_urls'] = [];
    $GLOBALS['sina_tls'] = 'trusted';
    $GLOBALS['sina_config'] = ['upload'=>['api'=>['weibo'=>['old'=>'preserved']]], 'other'=>['sentinel'=>'unchanged']];
    function config($name) { return $GLOBALS['sina_config']; }
    function response(array $data = []): void {
        file_put_contents(ROOT_PATH.'response.json', json_encode($data + ['status'=>200, 'cookie'=>'SUB=fixture-session; Path=/; HttpOnly',
            'body'=>'{"data":{"pics":{"pic_1":{"pid":"Fixture123","width":40,"height":30}}}}']));
    }
    function received(): array {
        $rows = file_exists(ROOT_PATH.'received.jsonl') ? file(ROOT_PATH.'received.jsonl', FILE_IGNORE_NEW_LINES) : [];
        return array_map(static fn($row)=>json_decode($row,true),$rows);
    }
    $process = proc_open(['python3', __DIR__.'/fixtures/security_audit_sina_https.py', $root],
        [0=>['file','/dev/null','r'], 1=>['file',$root.'/server.log','a'], 2=>['file',$root.'/server.log','a']], $pipes);
    try {
        if (!is_resource($process)) { throw new RuntimeException('Cannot start TLS fixture'); }
        $until = microtime(true)+15;
        while (!is_file($root.'/ports.json') && microtime(true)<$until && proc_get_status($process)['running']) { usleep(50000); }
        check(is_file($root.'/ports.json'), 'TLS fixture did not start');
        file_put_contents($root.'/source.jpg', 'fixture upload bytes');
        $file = $root.'/source.jpg';
        response();
        $client = new \app\common\util\SinaUpload(['size'=>'large']);
        $user = 'fixture+user@example.invalid'; $password = 'fixture&a=b+c/%中文';
        check($client->login($user,$password) === 'SUB=fixture-session;', 'Trusted HTTPS login failed');
        $rows=received();parse_str($rows[0]['body'],$form);
        check($form['su']===base64_encode($user) && $form['sp']===$password && count($form)===16, 'Credentials changed or injected form parameters');
        $options=$GLOBALS['sina_options'];
        foreach ([CURLOPT_SSL_VERIFYPEER=>true,CURLOPT_SSL_VERIFYHOST=>2,CURLOPT_FOLLOWLOCATION=>false,
            CURLOPT_PROTOCOLS=>CURLPROTO_HTTPS,CURLOPT_REDIR_PROTOCOLS=>CURLPROTO_HTTPS,
            CURLOPT_CONNECTTIMEOUT=>5,CURLOPT_TIMEOUT=>30,CURLOPT_VERBOSE=>false] as $key=>$value) {
            check($options[$key]===$value,'Unsafe production transport option');
        }
        foreach (['untrusted','hostname'] as $mode) {
            $GLOBALS['sina_tls']=$mode;$before=count(received());
            check($client->login($user,$password)==='', 'TLS verification failure accepted a session');
            check($client->upload($file,false,'SUB=fixture;')['code']==='301','TLS verification failure accepted an upload');
            check(count(received())===$before,'Credentials reached an HTTP handler before TLS verification');
        }
        $GLOBALS['sina_tls']='trusted';
        $portsText=file_get_contents($root.'/ports.json');
        $ports=json_decode($portsText,true);$ports['good']=1;
        file_put_contents($root.'/ports.json',json_encode($ports));
        $before=count(received());
        check($client->login($user,$password)==='' && $client->upload($file,false,'SUB=fixture;')['code']==='301', 'Connection refusal did not return a controlled failure');
        check(count(received())===$before && is_file($file), 'Connection failure reached a handler or removed the source');
        file_put_contents($root.'/ports.json',$portsText);
        foreach ([false,true] as $multipart) {
            $result=$client->upload($file,$multipart,'SUB=fixture-session;');
            check($result['code']==='200' && $result['url']==='https://ws3.sinaimg.cn/large/Fixture123.jpg','Valid provider response failed');
            $rows=received();$last=end($rows);
            check($last['cookie']==='SUB=fixture-session;','Actual upload lost its verified cookie');
            check(str_contains($last['body'],$multipart?'fixture upload bytes':base64_encode('fixture upload bytes')),'Actual upload lost source bytes');
            check(is_file($file),'Client prematurely deleted its source');
        }
        foreach ([302,403,500] as $status) {
            response(['status'=>$status,'redirect'=>'http://127.0.0.1:1/must-not-follow']);$before=count(received());
            check($client->login($user,$password)==='', 'HTTP error/redirect supplied a session');
            check($client->upload($file,false,'SUB=fixture;')['code']==='301', 'HTTP error/redirect supplied an image');
            check(count(received())===$before+2,'Client followed an upstream redirect');
        }
        foreach ([['cookie'=>''], ['cookie'=>'SUB=;'], ['cookie'=>'SUB=bad value;'], ['cookie'=>'OTHER=token;'],
            ['body'=>str_repeat('x',1048577)], ['cookie'=>'SUB='.str_repeat('a',4097).';'], ['cookie'=>'SUB='.str_repeat('a',70000).';']] as $case) {
            response($case);check($client->login($user,$password)==='', 'Missing/invalid/oversized provider session accepted');
        }
        foreach (['', '{}', '[]', 'null', 'false', '{bad', '{"data":"wrong"}', '{"data":{"pics":{"pic_1":[]}}}',
            '{"data":{"pics":{"pic_1":{"pid":"../bad","width":1,"height":1}}}}',
            '{"data":{"pics":{"pic_1":{"pid":"ok","width":[],"height":1}}}}', str_repeat('x',1048577)] as $body) {
            response(['body'=>$body]);check($client->upload($file,false,'SUB=fixture;')['code']==='301','Malformed response accepted an object');
        }
        response();
        foreach ([null,[],false,1,'','SUB;','SUB=bad value;',"SUB=good;\r\nX-Test: injected",'SUB=ok; other=bad;'] as $cookie) {
            $before=count($GLOBALS['sina_urls']);
            check($client->upload($file,false,$cookie)['code']==='301','Invalid cookie accepted');
            check(count($GLOBALS['sina_urls'])===$before,'Invalid cookie started a transfer');
        }
        foreach ([null,[],false,1,''] as $value) {
            check($client->login($value,$password)==='' && $client->login($user,$value)==='', 'Invalid credential type accepted');
            check($client->upload($value,false,'SUB=fixture;')['code']==='301','Invalid file type accepted');
        }
        foreach (['http://login.sina.com.cn/sso/login.php','https://foreign.invalid/sso/login.php',
            'https://login.sina.com.cn:443/sso/login.php','https://user@login.sina.com.cn/sso/login.php',
            'https://login.sina.com.cn/sso/other.php','https://login.sina.com.cn/sso/login.php#fragment'] as $url) {
            $before=count($GLOBALS['sina_urls']);check($client->loginPost($url,['sp'=>$password])==='' && count($GLOBALS['sina_urls'])===$before,'Credentials routed to an unapproved endpoint');
        }
        check($client->loginPost('https://login.sina.com.cn/sso/login.php',['sp'=>[]])==='', 'Structured form value accepted');
        check($client->getSubstr('[ok]','[',']')==='ok' && $client->getSubstr(false,'[',']')==='', 'Legacy parser fails at position zero/transport failure');
        foreach (['bad/size',[],false] as $size) {
            $client->config(['size'=>$size]);check($client->upload($file,false,'SUB=fixture;')['code']==='301','Invalid rendition emitted a remote URL');
        }
        $client=new \app\common\util\SinaUpload(['user'=>$user,'pwd'=>$password]);
        mkdir(APP_PATH.'extra/maccms.php', 0700, true);
        check($client->check()['code']==='202' && !isset($client->_config['cookie']), 'Real legacy writer failure reported session success');
        check(is_dir(APP_PATH.'extra/maccms.php'), 'Write failure removed an unrelated target');
        rmdir(APP_PATH.'extra/maccms.php');
        check($client->check()['code']==='1' && $client->_config['cookie']==='SUB=fixture-session;', 'Session refresh did not persist');
        $stored = require APP_PATH.'extra/maccms.php';
        check($stored['other']===$GLOBALS['sina_config']['other'] && $stored['upload']['api']['weibo']['cookie']==='SUB=fixture-session;', 'Real session file lost its cookie or unrelated configuration');
        $before=count($GLOBALS['sina_urls']);check($client->check()['code']==='1' && count($GLOBALS['sina_urls'])===$before,'Valid cached session reauthenticates');
        foreach ([null,[],time()+100,0] as $time) {
            $client->config(['time'=>$time]);$before=count($GLOBALS['sina_urls']);
            check($client->check()['code']==='1' && count($GLOBALS['sina_urls'])===$before+1,'Invalid/expired timestamp skipped renewal');
        }
        $client->config(false);check($client->check()['code']==='203','Malformed provider configuration threw or reused old credentials');
        $GLOBALS['config']['upload']['api']['weibo']=['time'=>time(),'cookie'=>'SUB=fixture-session;'];
        $adapter=new \app\common\extend\upload\Weibo(['keep_local'=>true]);
        check($adapter->submit('source.jpg')==='https://ws3.sinaimg.cn/large/Fixture123.jpg' && is_file($file),'Real adapter success/keep_local failed');
        response(['body'=>'{}']);check($adapter->submit('source.jpg')==='source.jpg' && is_file($file),'Real adapter failure lost local fallback');
        $GLOBALS['config']['upload']['api']['weibo']=false;
        check($adapter->submit('source.jpg')==='source.jpg' && is_file($file),'Real adapter malformed configuration lost source');
        echo 'Sina HTTPS client: '.$checks.' checks passed on PHP '.PHP_VERSION."\n";
    } finally {
        if (is_resource($process)) { proc_terminate($process);proc_close($process); }
        audit_remove_temp($root);
    }
}
