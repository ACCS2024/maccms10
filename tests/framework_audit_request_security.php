<?php
/** RequestSecurity uses captured TP8 input, including an already merged param cache. */
declare(strict_types=1);
require dirname(__DIR__) . '/vendor/autoload.php';
error_reporting(E_ALL);
set_error_handler(static function ($severity, $message, $file, $line) {
    throw new ErrorException($message, 0, $severity, $file, $line);
});

if (($argv[1] ?? '') === '--case') {
    try {
        $case = json_decode(stream_get_contents(STDIN), true, 512, JSON_THROW_ON_ERROR);
        if ($case['entrance'] !== '') { define('ENTRANCE', $case['entrance']); }
        $GLOBALS['config'] = ['app'=>$case['config']];
        $_GET = $case['get'];
        $_POST = $case['json'] ? [] : $case['post'];
        $_SERVER = ['REQUEST_METHOD'=>$case['method'],'CONTENT_TYPE'=>$case['content_type']];
        $_REQUEST = array_merge($_GET, $_POST);
        $_COOKIE = ['untouched'=>'cookie<script>x</script>'];
        $_FILES = [];
        $app = new think\App(dirname(__DIR__));
        $request = think\Request::__make($app);
        $rawBody = $case['json'] ? json_encode($case['post'], JSON_THROW_ON_ERROR) : http_build_query($case['post']);
        if ($case['json']) { $request->withInput($rawBody); }
        $request->setRoute(['route_only'=>'route<script>x</script>', 'shared'=>'route']);
        if ($case['warm']) { $request->param(); }
        if (isset($case['server_after'])) { $_SERVER['CONTENT_TYPE'] = $case['server_after']; }
        $result = (new app\middleware\RequestSecurity())->handle($request, static function ($received) use ($request) {
            return ['same_request'=>$received === $request, 'get'=>$received->get(false),'post'=>$received->post(false),
                'param'=>$received->param(),'route'=>$received->route(false),'raw'=>$received->getInput(),
                'cookies'=>$received->cookie(), 'get_global'=>$_GET,'post_global'=>$_POST];
        });
        echo json_encode($result, JSON_THROW_ON_ERROR);
        exit;
    } catch (Throwable $error) {
        fwrite(STDERR, get_class($error).': '.$error->getMessage().PHP_EOL);
        exit(1);
    }
}
$checks = 0;
$failures = [];
function securityRequestExpect(bool $condition, string $message): void {
    global $checks, $failures;
    ++$checks;
    if (!$condition) { $failures[] = $message; }
}
function securityRequestCase(string $name, array $case, bool $filterGet, bool $filterPost): void {
    $process = proc_open([PHP_BINARY,'-d','error_reporting=-1','-d','display_errors=stderr',__FILE__,'--case'], [['pipe','r'],['pipe','w'],['pipe','w']], $pipes);
    if (!is_resource($process)) { throw new RuntimeException('Cannot start request fixture'); }
    fwrite($pipes[0], json_encode($case, JSON_THROW_ON_ERROR)); fclose($pipes[0]);
    $output = stream_get_contents($pipes[1]); fclose($pipes[1]);
    $errors = stream_get_contents($pipes[2]); fclose($pipes[2]);
    $exit = proc_close($process);
    $result = json_decode($output, true);
    securityRequestExpect($exit === 0 && $errors === '' && is_array($result), "$name process must succeed: $errors $output");
    if (!is_array($result)) { return; }
    $expectedGet = $filterGet ? ['query'=>'GET','nested'=>['value'=>'<b>ok</b>'], 'shared'=>'get'] : $case['get'];
    $expectedPost = $filterPost ? ['body'=>'POST','nested_body'=>['value'=>'<i>ok</i>'],'zero'=>0,'nil'=>null,'shared'=>'post'] : $case['post'];
    $expectedParam = array_merge(['route_only'=>'route<script>x</script>','shared'=>'route'], $expectedGet, $case['method'] === 'POST' ? $expectedPost : []);
    securityRequestExpect($result['same_request'] === true, "$name must forward the same Request");
    securityRequestExpect($result['get'] === $expectedGet, "$name captured GET must follow the configured filter");
    securityRequestExpect($result['post'] === $expectedPost, "$name captured POST must follow the configured filter");
    securityRequestExpect($result['param'] === $expectedParam, "$name merged param must preserve route/get/body priority and reflect current filtering");
    securityRequestExpect($result['route'] === ['route_only'=>'route<script>x</script>','shared'=>'route'], "$name route parameters are outside the legacy GET/POST filter");
    securityRequestExpect($result['cookies'] === ['untouched'=>'cookie<script>x</script>'], "$name must preserve cookies");
    securityRequestExpect($result['get_global'] === $expectedGet, "$name legacy GET readers stay consistent");
    securityRequestExpect($result['post_global'] === ($case['json'] ? [] : $expectedPost), "$name legacy POST remains a form body");
    if ($case['json']) { securityRequestExpect($result['raw'] === json_encode($case['post'], JSON_THROW_ON_ERROR), "$name must preserve exact raw JSON for signature verification"); }
}
try {
    $base = ['entrance'=>'index','method'=>'POST','json'=>false,'warm'=>false,'content_type'=>'application/x-www-form-urlencoded',
        'config'=>['security_xss_input'=>'1'],
        'get'=>['query'=>'GET<script>x</script>','nested'=>['value'=>"<b>ok</b>\0"],'shared'=>'get'],
        'post'=>['body'=>'POST<script>x</script>','nested_body'=>['value'=>"<i>ok</i>\0"],'zero'=>0,'nil'=>null,'shared'=>'post']];
    foreach ([false,true] as $warm) {
        $case = array_replace($base,['warm'=>$warm]);
        securityRequestCase('form cache '.(int)$warm, $case, true, true);
        securityRequestCase('GET cache '.(int)$warm, array_replace($case,['method'=>'GET']), true, true);
        securityRequestCase('no entrance cache '.(int)$warm, array_replace($case,['entrance'=>'']), true, true);
        securityRequestCase('disabled cache '.(int)$warm, array_replace($case,['config'=>['security_xss_input'=>'0']]), false, false);
        securityRequestCase('missing config cache '.(int)$warm, array_replace($case,['config'=>[]]), false, false);
        securityRequestCase('install cache '.(int)$warm, array_replace($case,['entrance'=>'install']), false, false);
        securityRequestCase('admin default cache '.(int)$warm, array_replace($case,['entrance'=>'admin']), false, false);
        securityRequestCase('admin enabled cache '.(int)$warm, array_replace($case,['entrance'=>'admin','config'=>['security_xss_input'=>1,'security_xss_admin'=>1]]), true, true);
        $json = array_replace($case,['entrance'=>'api','json'=>true,'content_type'=>'application/json; charset=utf-8']);
        securityRequestCase('JSON default skip cache '.(int)$warm, $json, true, false);
        securityRequestCase('JSON explicit skip cache '.(int)$warm, array_replace($json,['config'=>['security_xss_input'=>1,'security_xss_skip_json'=>1]]), true, false);
        securityRequestCase('JSON filtering enabled cache '.(int)$warm, array_replace($json,['config'=>['security_xss_input'=>1,'security_xss_skip_json'=>0]]), true, true);
        securityRequestCase('vendor JSON default skip cache '.(int)$warm, array_replace($json,['content_type'=>'application/problem+json']), true, false);
        securityRequestCase('captured JSON content type cache '.(int)$warm, array_replace($json,['server_after'=>'text/plain']), true, false);
        securityRequestCase('invalid main flag cache '.(int)$warm, array_replace($case,['config'=>['security_xss_input'=>['1']]]), false, false);
        securityRequestCase('invalid admin flag cache '.(int)$warm, array_replace($case,['entrance'=>'admin','config'=>['security_xss_input'=>1,'security_xss_admin'=>['1']]]), false, false);
        securityRequestCase('invalid skip flag cache '.(int)$warm, array_replace($json,['config'=>['security_xss_input'=>1,'security_xss_skip_json'=>['0']]]), true, false);
    }
    if ($failures) { throw new RuntimeException(implode(PHP_EOL, $failures)); }
    echo 'framework_audit_request_security: '.$checks.' checks passed on PHP '.PHP_VERSION.PHP_EOL;
} catch (Throwable $error) { fwrite(STDERR, $error->getMessage().PHP_EOL); exit(1); }
