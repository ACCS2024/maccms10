<?php
/** Real TP8 Request and Receive/common mapping boundary; collection is an isolated recorder. */
declare(strict_types=1);
namespace app\api\controller { class Base { public function __construct() {} } }
namespace app\common\model {
    class Type { public function getCache($name) { return $GLOBALS['receive_types']; } }
    class Collect {
        public function __call($method, $arguments) {
            if (!in_array($method, ['vod_data','art_data','actor_data','role_data','website_data','manga_data','comment_data'], true)
                || $arguments[0] !== [] || $arguments[2] !== 0 || count($arguments[1]['data']) !== 1) {
                throw new \RuntimeException('Unexpected collector protocol');
            }
            return ['code'=>1,'msg'=>'collected','method'=>$method,'payload'=>$arguments[1]['data'][0]];
        }
    }
}
namespace think\facade {
    class Cache {
        public static array $entries = [];
        public static function get($key) { return self::$entries[$key] ?? null; }
        public static function set($key, $value, $ttl = null) { self::$entries[$key] = $value; }
    }
}
namespace {
    require dirname(__DIR__) . '/vendor/autoload.php';
    require dirname(__DIR__) . '/application/common.php';
    error_reporting(E_ALL);
    set_error_handler(static function ($severity, $message, $file, $line) {
        throw new ErrorException($message, 0, $severity, $file, $line);
    });
    function lang($key, $vars = []) { return $key; }
    function config($name, $default = null) { return $name === 'maccms.interface' ? $GLOBALS['config']['interface'] : $default; }
    $secret = 'receive-fixture-password-only';
    $GLOBALS['config'] = ['app'=>['cache_flag'=>'receive-audit'], 'interface'=>[
        'status'=>1,'pass'=>$secret,'vodtype'=>"本地视频=remote\n备用视频=alternate",'arttype'=>'本地文章=remote',
        'actortype'=>'本地演员=remote','websitetype'=>'本地网站=remote','mangatype'=>'本地漫画=remote',
    ]];
    $GLOBALS['receive_types'] = [];
    foreach ([[10,1,'本地视频'],[11,1,'备用视频'],[20,2,'本地文章'],[80,8,'本地演员'],[110,11,'本地网站'],[120,12,'本地漫画']] as [$id,$mid,$name]) {
        $GLOBALS['receive_types'][$id] = ['type_id'=>$id,'type_mid'=>$mid,'type_name'=>$name,'type_pid'=>0];
    }
    if (($argv[1] ?? '') === '--case') {
        try {
            $case = json_decode(stream_get_contents(STDIN), true, 512, JSON_THROW_ON_ERROR);
            if (isset($case['interface'])) { $GLOBALS['config']['interface'] = $case['interface']; }
            if (isset($case['types'])) { $GLOBALS['receive_types'] = $case['types']; }
            $request = (new think\Request())->withGet($case['params'])->setController('Receive')->setAction($case['action']);
            $container = new think\Container();
            think\Container::setInstance($container);
            $container->instance('request', $request);
            $controller = new app\api\controller\Receive();
            $controller->{$case['action']}();
        } catch (Throwable $error) {
            fwrite(STDERR, get_class($error) . ': ' . $error->getMessage() . PHP_EOL);
            exit(1);
        }
        exit;
    }
    $checks = 0;
    $failures = [];
    function receiveExpect($condition, string $message): void {
        global $checks, $failures;
        ++$checks;
        if (!$condition) { $failures[] = $message; }
    }
    function receiveCase(string $name, array $params, string $action, int $code, array $extra = []): ?array {
        $process = proc_open([PHP_BINARY,'-d','error_reporting=-1','-d','display_errors=stderr',__FILE__,'--case'], [['pipe','r'],['pipe','w'],['pipe','w']], $pipes);
        if (!is_resource($process)) { throw new RuntimeException('Cannot start isolated case'); }
        fwrite($pipes[0], json_encode(['params'=>$params,'action'=>$action]+$extra, JSON_THROW_ON_ERROR)); fclose($pipes[0]);
        $output = stream_get_contents($pipes[1]); fclose($pipes[1]);
        $errors = stream_get_contents($pipes[2]); fclose($pipes[2]);
        $exit = proc_close($process);
        $result = json_decode($output, true);
        receiveExpect($exit === 0 && $errors === '' && is_array($result) && ($result['code'] ?? null) === $code,
            $name . ': expected ' . $code . ', exit=' . $exit . ', output=' . $output . ', errors=' . $errors);
        return is_array($result) ? $result : null;
    }
    try {
        receiveCase('missing password', [], 'vod', 3002);
        foreach ([[],['nested'],null,true,1234] as $bad) { receiveCase('non-string password', ['pass'=>$bad], 'vod', 3002); }
        receiveCase('wrong password', ['pass'=>'incorrect'], 'vod', 3002);
        receiveCase('disabled interface', [], 'vod', 3001, ['interface'=>['status'=>0]]);
        receiveCase('missing interface status', [], 'vod', 3001, ['interface'=>[]]);
        receiveCase('short matching password', ['pass'=>'short'], 'vod', 3003, ['interface'=>['status'=>1,'pass'=>'short']]);
        receiveCase('malformed configured password', ['pass'=>$secret], 'vod', 3002, ['interface'=>['status'=>1,'pass'=>[]]]);
        foreach (['vod'=>10,'art'=>20,'actor'=>80,'website'=>110,'manga'=>120] as $kind=>$id) {
            $base = ['pass'=>$secret,$kind.'_name'=>'合法名称'];
            if ($kind === 'actor') { $base['actor_sex'] = '女'; }
            $typeError = $kind === 'actor' ? 2003 : 2002;
            foreach ([[],['nested'],null,''] as $bad) {
                receiveCase($kind.' invalid name', array_replace($base, [$kind.'_name'=>$bad,'type_id'=>$id]), $kind, 2001);
            }
            receiveCase($kind.' missing category', $base, $kind, $typeError);
            foreach ([[],['remote'],'unknown'] as $bad) { receiveCase($kind.' invalid category name', $base+['type_name'=>$bad], $kind, $typeError); }
            foreach ([[10],'-1','1e1','10.5',str_repeat('9',40),999999] as $bad) { receiveCase($kind.' invalid category ID', $base+['type_id'=>$bad], $kind, $typeError); }
            $result = receiveCase($kind.' direct category', $base+['type_id'=>(string)$id,$kind.'_content'=>'<p>正文</p>'], $kind, 1);
            receiveExpect(($result['payload']['type_id'] ?? null) === $id && !isset($result['payload']['pass']) && ($result['payload'][$kind.'_content'] ?? null) === '<p>正文</p>', $kind.' must normalize category and preserve content without passing credentials to collector');
            $result = receiveCase($kind.' mapped category', $base+['type_name'=>'remote'], $kind, 1);
            receiveExpect(($result['payload']['type_id'] ?? null) === $id, $kind.' mapping must select the configured category');
            receiveExpect(($kind === 'vod') === isset($result['payload']['type_name']), $kind.' must retain only category metadata used by its collector');
            $result = receiveCase($kind.' optional scalar fields', $base+['type_id'=>$id,$kind.'_hits'=>0,$kind.'_blurb'=>null], $kind, 1);
            receiveExpect(($result['payload'][$kind.'_hits'] ?? null) === 0 && ($result['payload'][$kind.'_blurb'] ?? null) === '', $kind.' optional scalar and null values remain usable');
            receiveCase($kind.' optional nested field', $base+['type_id'=>$id,$kind.'_pic'=>['bad']], $kind, 1001);
            receiveCase($kind.' cross-module category', $base+['type_id'=>$id === 20 ? 10 : 20], $kind, $typeError);
        }
        $badMapping = $GLOBALS['config']['interface']; $badMapping['vodtype'] = ['invalid'];
        receiveCase('explicit ID ignores malformed optional mapping', ['pass'=>$secret,'vod_name'=>'视频','type_id'=>10], 'vod', 1, ['interface'=>$badMapping]);
        foreach (['reject','requireText','positiveId','requireCategory','requireRelation','collect'] as $helper) {
            receiveExpect((new ReflectionMethod(app\api\controller\Receive::class, $helper))->isPrivate(), 'Receive helper must not become a routable public action: '.$helper);
        }
        $actor = ['pass'=>$secret,'actor_name'=>'演员','type_id'=>80];
        receiveCase('actor missing sex', $actor, 'actor', 2002);
        receiveCase('actor array sex', $actor+['actor_sex'=>['女']], 'actor', 2002);
        $role = ['pass'=>$secret,'role_name'=>'角色','role_actor'=>'演员','vod_name'=>'视频'];
        receiveCase('role valid', $role, 'role', 1);
        foreach (['role_name'=>2001,'role_actor'=>2002,'vod_name'=>2003] as $field=>$code) { receiveCase('role array '.$field, array_replace($role,[$field=>['bad']]), 'role', $code); }
        receiveCase('role douban relation', array_diff_key($role,['vod_name'=>1])+['douban_id'=>'123456'], 'role', 1);
        receiveCase('role missing relation', array_diff_key($role,['vod_name'=>1]), 'role', 2003);
        receiveCase('role optional nested', $role+['role_pic'=>['bad']], 'role', 1001);
        $comment = ['pass'=>$secret,'comment_name'=>'昵称','comment_content'=>'正文','comment_mid'=>1,'rel_name'=>'视频'];
        receiveCase('comment valid', $comment, 'comment', 1);
        foreach (['comment_name'=>2001,'comment_content'=>2002,'comment_mid'=>2004,'rel_name'=>2003] as $field=>$code) { receiveCase('comment array '.$field, array_replace($comment,[$field=>['bad']]), 'comment', $code); }
        receiveCase('comment invalid module', array_replace($comment,['comment_mid'=>'invalid']), 'comment', 2004);
        receiveCase('comment missing relation', array_diff_key($comment,['rel_name'=>1]), 'comment', 2003);
        receiveCase('comment douban relation', array_diff_key($comment,['rel_name'=>1])+['douban_id'=>'123456'], 'comment', 1);
        receiveCase('comment optional nested', $comment+['comment_ip'=>['bad']], 'comment', 1001);
        // Exercise the real common helper with malformed rows, CR/LF input, stale and malformed cache.
        think\facade\Cache::$entries = [];
        $GLOBALS['config']['interface']['vodtype'] = "\r\n无等号\n =空来源\n本地视频=\n不存在=missing\r本地视频=remote\r\n备用视频=remote\n本地视频=remote=with=equals";
        $GLOBALS['config']['interface']['arttype'] = [];
        $GLOBALS['config']['interface']['actortype'] = '';
        $GLOBALS['config']['interface']['websitetype'] = null;
        unset($GLOBALS['config']['interface']['mangatype']);
        try {
            $mapping = mac_interface_type();
            receiveExpect($mapping['vodtype'] === ['remote'=>11,'remote=with=equals'=>10], 'mapping skips malformed/deleted targets and the last duplicate source wins');
            foreach (['arttype','actortype','websitetype','mangatype'] as $kind) { receiveExpect($mapping[$kind] === [], $kind.' empty/bad mapping must stay empty'); }
            unset($GLOBALS['receive_types'][11]);
            receiveExpect(!isset(mac_interface_type()['vodtype']['remote']), 'cached mapping must not resolve a deleted local category');
            think\facade\Cache::$entries['receive-audit_interface_type'] = ['vodtype'=>['remote'=>['bad']]];
            receiveExpect(mac_interface_type()['vodtype'] === [], 'malformed cache values must not become offsets');
        } catch (Throwable $error) { receiveExpect(false, 'mapping helper: '.get_class($error).': '.$error->getMessage()); }
        if ($failures) { throw new RuntimeException(implode("\n", $failures)); }
        echo 'framework_audit_receive: ' . $checks . ' checks passed on PHP ' . PHP_VERSION . PHP_EOL;
    } catch (Throwable $error) {
        fwrite(STDERR, $error->getMessage() . PHP_EOL);
        exit(1);
    }
}
