<?php
/** Actual ORM ownership checks, with only the controller view and payment transport replaced. */
namespace app\index\controller {
    class Base {
        public array $assigned = [];
        protected function error($message) { return ['error' => $message]; }
        protected function assign($name, $value) { $this->assigned[$name] = $value; }
        protected function fetch($template) { return ['template' => $template, 'data' => $this->assigned]; }
    }
}
namespace app\common\extend\pay {
    class Weixin {
        public function submit($user, $order, $param) {
            $GLOBALS['checkout_calls'][] = [$user, $order, $param];
            if (($GLOBALS['checkout_mode'] ?? '') === 'throw') { throw new \TypeError('private fixture upstream details'); }
            return $GLOBALS['checkout_result'] ?? false;
        }
    }
    class Fixture extends Weixin {}
    class Nosubmit {}
}
namespace {
    $frameworkAuditTables = ['user', 'group', 'order', 'plog'];
    require __DIR__ . '/fixtures/framework_audit_db.php';
    require dirname(__DIR__) . '/application/index/controller/User.php';
    seed(); orderSeed();
    $GLOBALS['user'] = ['user_id' => 1];
    $GLOBALS['config']['pay'] = array_fill_keys(['weixin', 'fixture', 'missing', 'nosubmit'], ['appid' => 'fixture']);
    $GLOBALS['config']['pay']['disabled'] = ['appid' => ''];
    $base = ['order_id' => '1', 'order_code' => 'once', 'payment' => 'weixin'];
    function checkout(array $input, string $action = 'gopay') {
        $request = new think\Request();
        $request->withGet($input)->setMethod('GET');
        think\Container::getInstance()->instance('request', $request);
        $controller = (new ReflectionClass(app\index\controller\User::class))->newInstanceWithoutConstructor();
        return $controller->$action();
    }
    $GLOBALS['checkout_calls'] = [];
    foreach (['order_id', 'order_code', 'payment'] as $field) {
        $input = $base; unset($input[$field]);
        expect(isset(checkout($input)['error']), 'Missing checkout field must return a controlled error');
        foreach ([[], new stdClass(), '', false] as $bad) {
            expect(isset(checkout(array_replace($base, [$field => $bad]))['error']), 'Malformed checkout field accepted');
        }
    }
    foreach ([['order_id' => '1e0'], ['order_id' => '-1'], ['order_id' => '4294967296'],
        ['order_code' => str_repeat('x', 31)], ['payment' => '../weixin'], ['payment' => 'missing'],
        ['payment' => 'nosubmit'], ['payment' => 'disabled'], ['paytype' => []], ['type' => []]] as $patch) {
        expect(isset(checkout(array_replace($base, $patch))['error']), 'Invalid payment dispatch accepted');
    }
    expect($GLOBALS['checkout_calls'] === [], 'Invalid input reached a payment provider');
    expect(isset(checkout(array_replace($base, ['order_code' => 'another']))['error']), 'Mismatched order code accepted');
    $GLOBALS['user']['user_id'] = 2;
    expect(isset(checkout($base)['error']), 'Another user could submit the order');
    $GLOBALS['user']['user_id'] = 1;
    think\facade\Db::name('Order')->where('order_id', 1)->update(['order_status' => 1]);
    expect(isset(checkout($base)['error']), 'Paid order could be submitted again');
    think\facade\Db::name('Order')->where('order_id', 1)->update(['order_status' => 0]);
    expect($GLOBALS['checkout_calls'] === [], 'Unowned or paid order reached a provider');
    foreach ([false, [], ['code_url' => []], ['code_url' => 'javascript:bad']] as $result) {
        $GLOBALS['checkout_result'] = $result;
        expect(isset(checkout($base)['error']), 'Invalid WeChat response rendered a payment page');
    }
    $GLOBALS['checkout_mode'] = 'throw';
    expect(checkout($base) === ['error' => 'index/payment_status'], 'Upstream Throwable was not contained');
    $GLOBALS['checkout_mode'] = '';
    $GLOBALS['checkout_result'] = ['code_url' => 'weixin://fixture', 'total_fee' => '10.00'];
    $result = checkout(array_replace($base, ['payment' => 'WEIXIN']));
    expect($result['template'] === 'user/payment_weixin' && $result['data']['payment'] === $GLOBALS['checkout_result'],
        'Valid WeChat checkout no longer renders the payment page');
    $GLOBALS['checkout_result'] = 'fixture redirect response';
    expect(checkout(array_replace($base, ['payment' => 'fixture'])) === 'fixture redirect response', 'Provider return value was lost');
    foreach ([[], ['order_code' => []], ['order_code' => ''], ['order_code' => str_repeat('x', 31)]] as $input) {
        expect(isset(checkout($input, 'pay')['error']), 'Malformed pay-page input was not rejected');
    }
    finishFrameworkAudit('framework_audit_checkout');
}
