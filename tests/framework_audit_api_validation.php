<?php
/** API scene regressions using real validators/controllers/Request/ORM, SQLite only. */
declare(strict_types=1);
namespace { require dirname(__DIR__) . '/vendor/autoload.php'; }
namespace app\common\controller { class All {} }
namespace app\common\model {
    // Bound authentication independently of real session/JWT bootstrap; database access stays real.
    class User extends Base {
        protected $name = 'user';
        public function checkLogin() {
            return empty($GLOBALS['api_audit_logged_in']) ? ['code'=>1001] : ['code'=>1, 'info'=>['user_id'=>1]];
        }
    }
}
namespace {
    error_reporting(E_ALL);
    set_error_handler(static function ($severity, $message, $file, $line) {
        throw new ErrorException($message, 0, $severity, $file, $line);
    });
    function lang($key, $vars = []) { return $key . ($vars ? ': ' . implode(', ', $vars) : ''); }
    function config($name, $default = null) { return think\facade\Config::get($name, $default); }
    function json($data) { return new think\response\Json(new think\Cookie(think\Container::getInstance()->make('request')), $data); }
    function mac_validate($name) { $class = 'app\\common\\validate\\' . $name; return new $class(); }
    function mac_fe_write_throttle($name, $window, $limit) { return true; }
    function mac_get_uniqid_code() { return 'API-AUDIT-' . ++$GLOBALS['api_audit_order_seq']; }
    $container = new think\Container();
    think\Container::setInstance($container);
    $container->bind(think\Request::class, 'request');
    $configuration = ['default'=>'mysql', 'auto_timestamp'=>false, 'connections'=>['mysql'=>[
        'type'=>'sqlite', 'database'=>':memory:', 'prefix'=>'mac_', 'trigger_sql'=>false, 'fields_cache'=>false,
    ]]];
    $config = new think\Config();
    $config->set($configuration, 'database');
    $config->set(['pay'=>['min'=>5, 'scale'=>2]], 'maccms');
    $container->instance('config', $config);
    $manager = new think\DbManager();
    $manager->setConfig($configuration);
    $container->instance('think\\DbManager', $manager);
    $GLOBALS['config'] = ['app'=>['count_cache_sec'=>0]];
    $GLOBALS['api_audit_logged_in'] = true;
    $GLOBALS['api_audit_order_seq'] = 0;
    think\facade\Db::execute('CREATE TABLE mac_user (user_id INTEGER PRIMARY KEY, user_name TEXT)');
    think\facade\Db::name('User')->insert(['user_id'=>1, 'user_name'=>'audit']);
    think\facade\Db::execute('CREATE TABLE mac_order (order_id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, order_code TEXT, order_price REAL, order_points INTEGER, order_time INTEGER, order_status INTEGER DEFAULT 0)');
    think\facade\Db::execute('CREATE TABLE mac_link (link_id INTEGER PRIMARY KEY, link_type INTEGER, link_time INTEGER, link_name TEXT, link_logo TEXT, link_url TEXT)');
    think\facade\Db::name('Link')->insertAll([
        ['link_id'=>1, 'link_type'=>1, 'link_time'=>300, 'link_name'=>'First', 'link_logo'=>'one.png', 'link_url'=>'https://example.test/one'],
        ['link_id'=>2, 'link_type'=>1, 'link_time'=>100, 'link_name'=>'Second', 'link_logo'=>'two.png', 'link_url'=>'https://example.test/two'],
    ]);
    $checks = 0;
    function validationExpect($condition, string $message): void {
        global $checks;
        ++$checks;
        if (!$condition) { throw new RuntimeException($message); }
    }
    function validationCall(string $name, string $action, array $params, ?string $method = null): array {
        $request = (new think\Request())->setController($name)->setAction($action);
        $request = $method === 'POST' || ($name === 'Order' && $action === 'create')
            ? $request->withServer(['REQUEST_METHOD'=>'POST'])->withPost($params)
            : $request->withServer(['REQUEST_METHOD'=>'GET'])->withGet($params);
        $container = think\Container::getInstance();
        $container->instance('request', $request);
        $controller = (new ReflectionClass('app\\api\\controller\\' . $name))->newInstanceWithoutConstructor();
        return $container->invokeMethod([$controller, $action])->getData();
    }
    $cases = [
        ['Actor','get_list',['orderby'=>'bad']], ['Actor','get_detail',[]],
        ['Art','get_list',['orderby'=>'bad']], ['Art','get_detail',[]], ['Art','get_read_page',[]],
        ['Cash','get_list',['limit'=>0]], ['Cash','get_detail',[]], ['Cash','create',[]], ['Cash','del',['ids'=>str_repeat('1',201)]],
        ['Comment','get_list',['orderby'=>'bad']], ['Gbook','get_list',['orderby'=>'bad']],
        ['Link','get_list',['limit'=>0]], ['Live','get_list',['orderby'=>'bad']], ['Live','get_detail',[]],
        ['Manga','get_list',['order'=>'bad']], ['Manga','get_detail',[]], ['Manga','get_chapter',[]],
        ['Order','create',['price'=>0]], ['Order','get_list',['limit'=>0]], ['Order','get_detail',['order_id'=>0]], ['Order','check_status',['order_code'=>str_repeat('a',31)]],
        ['Payment','gopay',[]], ['Payment','use_card',[]], ['Payment','buy_popedom',[]], ['Payment','upgrade',[]], ['Payment','get_cards',['limit'=>0]],
        ['Role','get_list',['orderby'=>'bad']], ['Role','get_detail',[]],
        ['Topic','get_list',['orderby'=>'bad']], ['Topic','get_detail',[]], ['Type','get_list',['type_id'=>0]],
        ['User','get_list',['orderby'=>'bad']], ['User','get_detail',[]], ['User','get_invite_list',['limit'=>0]],
        ['Vod','get_list',['orderby'=>'bad']], ['Vod','get_detail',[]], ['Vod','get_year',[]], ['Vod','get_class',[]], ['Vod','get_area',[]],
        ['Website','get_list',['orderby'=>'bad']], ['Website','get_detail',[]],
    ];
    try {
        $failures = [];
        foreach ($cases as [$name, $action, $params]) {
            try {
                $class = 'app\\api\\validate\\' . $name;
                validationExpect((new $class())->hasScene($action), "$name::$action must have an explicit scene");
                $data = validationCall($name, $action, $params);
                validationExpect($data['code'] === 1001 && !isset($data['info']), "$name::$action must reject invalid input through its JSON branch");
            } catch (Throwable $error) { $failures[] = "$name::$action: " . $error->getMessage(); }
        }
        validationExpect($failures === [], implode("\n", $failures));
        validationExpect(count($cases) === 41, 'Every original short-helper action must be exercised');

        // Real rule acceptance matters: an always-failing validator could otherwise pass the rejection matrix.
        foreach ($cases as [$name, $action, $params]) {
            $valid = ['actor_id'=>1, 'art_id'=>1, 'cash_id'=>1, 'cash_money'=>'1.25', 'cash_bank_name'=>'bank',
                'cash_bank_no'=>'123', 'cash_payee_name'=>'audit', 'live_id'=>1, 'id'=>1, 'price'=>'10.25',
                'order_code'=>'PAY1', 'order_id'=>1, 'payment'=>'alipay', 'card_no'=>'1234', 'card_pwd'=>'1234',
                'mid'=>1, 'type'=>4, 'group_id'=>3, 'long'=>'month', 'role_id'=>1, 'topic_id'=>1, 'type_id'=>1,
                'vod_id'=>1, 'type_id_1'=>1, 'website_id'=>1];
            if ($name === 'Link') { $valid['type'] = 1; }
            $class = 'app\\api\\validate\\' . $name;
            $v = new $class();
            validationExpect($v->scene($action)->check($valid), "$name::$action must accept its valid field set: " . $v->getError());
        }
        foreach ([['User',['group_id'=>3,'orderby'=>'points']], ['Website',['orderby'=>'time','time_start'=>1]], ['Link',['offset'=>0,'limit'=>10]]] as [$name,$params]) {
            $class = 'app\\api\\validate\\' . $name;
            validationExpect((new $class())->scene('get_list')->check($params), "$name valid optional filters must remain usable");
        }
        foreach (['Actor','Gbook','User','Website'] as $name) {
            $class = 'app\\api\\validate\\' . $name;
            validationExpect(!(new $class())->scene('get_list')->check(['time_start'=>['bad']]), "$name time filters must use the declared numeric rules");
        }
        foreach (['0','-1','1.001','1e2','10000000000','bad', [1]] as $price) {
            validationExpect(validationCall('Order','create',['price'=>$price])['code'] === 1001, 'Invalid money must be rejected before coercion and insertion');
        }
        validationExpect(think\facade\Db::name('Order')->count() === 0, 'Invalid amounts must never create an order');
        validationExpect(validationCall('Order','create',['price'=>'4.99'])['code'] === 1002, 'The configured minimum must still reject a valid low amount');
        $getRequest = (new think\Request())->withServer(['REQUEST_METHOD'=>'GET'])->withGet(['price'=>'10.50'])
            ->setController('Order')->setAction('create');
        $container->instance('request', $getRequest);
        $getController = (new ReflectionClass(app\api\controller\Order::class))->newInstanceWithoutConstructor();
        validationExpect($getController->create($getRequest)->getData()['code'] === 1001
            && think\facade\Db::name('Order')->count() === 0, 'GET must never create a recharge order');
        $order = validationCall('Order','create',['price'=>'10.25']);
        validationExpect($order['code'] === 1, 'Valid order must succeed: ' . json_encode($order));
        $stored = think\facade\Db::name('Order')->where('user_id', 1)->find();
        validationExpect($order['code'] === 1 && (float)$stored['order_price'] === 10.25 && $stored['order_points'] === 20, 'A valid amount must preserve configured scale and actually persist');
        foreach ([['time',[1,2]], ['id',[2,1]]] as [$sort,$ids]) {
            $data = validationCall('Link','get_list',['orderby'=>$sort]);
            validationExpect($data['code'] === 1 && array_column($data['info']['rows'],'link_id') === $ids, 'Validated ordering must reach the real list query');
        }
        $GLOBALS['api_audit_logged_in'] = false;
        foreach (['Cash'=>'create','Order'=>'create','Payment'=>'gopay'] as $name=>$action) {
            validationExpect(validationCall($name,$action,[],'POST')['code'] === 1401, 'A permitted HTTP method must authenticate before validating fields for ' . $name);
        }
        echo 'framework_audit_api_validation: ' . $checks . ' checks passed (41 controller actions) on PHP ' . PHP_VERSION . PHP_EOL;
    } catch (Throwable $error) {
        fwrite(STDERR, get_class($error) . ': ' . $error->getMessage() . PHP_EOL . $error->getTraceAsString() . PHP_EOL);
        exit(1);
    }
}
