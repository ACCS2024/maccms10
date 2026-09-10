<?php
/** Real Order/Group ORM and router; authentication is a controlled fixture boundary. */
namespace app\common\model {
    class User {
        public function checkLogin() {
            return empty($GLOBALS['creation_logged_in']) ? ['code'=>1001] : ['code'=>1, 'info'=>\memberRow()];
        }
    }
}
namespace {
    require __DIR__ . '/security_audit_membership_db.php';
    if (!$mysql) { \think\facade\Db::execute('ALTER TABLE audit_order ADD COLUMN order_time INTEGER DEFAULT 0'); }
    function json($data) { return $data; }
    function request() { return \think\Container::getInstance()->make('request'); }
    function mac_get_uniqid_code() { return sprintf('FIXTURE%012d', ++$GLOBALS['creation_sequence']); }
    function mac_day($value) { return date('Y-m-d', (int)$value); }
    // Load only the actual compatibility wrapper, without application bootstrap.
    $source = file_get_contents(dirname(__DIR__, 2) . '/application/common.php');
    if (!preg_match("/if \\(!function_exists\\('url'\\)\\) \\{[\\s\\S]*?(?=\\nif \\(!function_exists\\('mac_ts'\\)\\))/", $source, $urlWrapper)) {
        throw new \RuntimeException('Project URL compatibility wrapper not found');
    }
    eval($urlWrapper[0]);
    $fixtureConfig = \think\Container::getInstance()->make('config');
    $app = new \think\App(sys_get_temp_dir() . '/maccms-order-create-' . bin2hex(random_bytes(8)));
    $app->instance('config', $fixtureConfig);
    $app->instance('think\\DbManager', $manager);
    $app->instance('cache', new \MembershipAuditCache());
    $app->bind('think\\route\\Url', \think\app\Url::class);
    $app->http->name('api')->setBind(true);
    $GLOBALS['creation_sequence'] = 0;
    $GLOBALS['creation_logged_in'] = true;
    class CreationHttpRequest extends \think\Request {
        public function isCli(): bool { return false; }
    }
    function creationSeed(array $pay = ['scale'=>'100', 'min'=>'0']): void {
        \membershipSeed();
        $GLOBALS['config']['pay'] = $pay;
        \think\facade\Config::set(['pay'=>$pay], 'maccms');
        $GLOBALS['creation_logged_in'] = true;
    }
    function creationRequest(array $parameters, string $action, string $script = '/api.php', string $method = 'POST'): \think\Request {
        $request = (new CreationHttpRequest())->withServer(['REQUEST_METHOD'=>$method, 'HTTP_HOST'=>'example.test',
            'SCRIPT_NAME'=>$script, 'SCRIPT_FILENAME'=>'/isolated' . $script,
            'REQUEST_URI'=>$script . '/user/' . $action]);
        $request->setAction($action)->setController('User');
        $request = $method === 'POST' ? $request->withPost($parameters) : $request->withGet($parameters);
        \think\Container::getInstance()->instance('request', $request);
        return $request;
    }
    function creationController(string $name): object {
        return (new \ReflectionClass($name))->newInstanceWithoutConstructor();
    }
}
