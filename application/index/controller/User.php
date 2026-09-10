<?php
namespace app\index\controller;
use think\facade\Db;
use think\facade\Request;
use login\ThinkOauth;
use app\index\event\LoginEvent;
use app\common\util\QrResponse;
use app\common\util\OAuthState;

class User extends Base
{
    public function __construct()
    {
        if (in_array(strtolower(request()->action()), ['write_token', 'ajax_buy_popedom'], true)) {
            $this->persistExpiredMemberGroup = false;
        }
        parent::__construct();

        if (!defined('THIRD_LOGIN_CALLBACK')) {
            $installDir = '/' . trim((string) ($GLOBALS['config']['site']['install_dir'] ?? '/'), '/');
            define('THIRD_LOGIN_CALLBACK', request()->domain() . rtrim($installDir, '/') . '/index.php/user/logincallback/type/');
        }

        //判断用户登录状态
        $ac = request()->action();
        $guestAllowedActions = ['login', 'logout', 'ajax_login', 'reg', 'regcheck', 'findpass', 'findpass_msg', 'findpass_reset', 'reg_msg', 'oauth', 'logincallback', 'visit', 'index', 'ajax_upgrade', 'write_token', 'ajax_buy_popedom'];
        $guestAllowedGetActions = ['buy', 'plays', 'upgrade', 'checkin'];
        if (in_array($ac, $guestAllowedActions) || (in_array($ac, $guestAllowedGetActions) && !Request()->isPost())) {
            // 游客可访问的页面也注入 obj，避免模板判断分支缺少变量
            $this->assign('obj', $GLOBALS['user']);
        } else {
            if ($GLOBALS['user']['user_id'] < 1) {
                (new \app\common\model\User())->logout();
                redirect(url('user/login'))->send();
                exit;
            }
            $this->assign('obj', $GLOBALS['user']);
        }
    }

    public function ajax_login()
    {
        return $this->fetch('user/ajax_login');
    }

    public function ajax_info()
    {
        return $this->fetch('user/ajax_info');
    }

    public function ajax_ulog()
    {
        $param = \think\facade\Request::param();
        if (($param['ac'] ?? '') == 'set') {
            $data = [];
            $data['ulog_mid'] = intval($param['mid']);
            $data['ulog_rid'] = intval($param['id']);
            $data['ulog_type'] = intval($param['type']);
            $data['ulog_sid'] = intval($param['sid']);
            $data['ulog_nid'] = intval($param['nid']);
            $data['user_id'] = $GLOBALS['user']['user_id'];

            if ($data['ulog_mid'] == 1 && $data['ulog_type'] > 3) {
                $where2 = [];
                $where2['vod_id'] = $data['ulog_rid'];
                $res = (new \app\common\model\Vod())->infoData($where2);
                if ($res['code'] > 1) {
                    return $res;
                }
                $flag = $data['ulog_type'] == 4 ? 'play' : 'down';
                $data['ulog_points'] = $res['info']['vod_points_' . $flag];
            }
            $data['ulog_points'] = intval($data['ulog_points']);

            $res = (new \app\common\model\Ulog())->infoData($data);
            if ($res['code'] == 1) {
                $r = (new \app\common\model\Ulog())->where($data)->update(['ulog_time'=>time()]);
                return json($res);
            }
            if ($data['ulog_points'] == 0) {
                $res = (new \app\common\model\Ulog())->saveData($data);
            } else {
                $res = ['code' => 2001, 'msg' => lang('index/ulog_fee')];
            }
        } else {
            $where = [];
            $where['user_id'] = $GLOBALS['user']['user_id'];
            $param['page'] = intval($param['page'] ?? 1) < 1 ? 1 : intval($param['page'] ?? 1);
            $param['limit'] = intval($param['limit'] ?? 10) < 1 ? 10 : intval($param['limit'] ?? 10);
            if(intval($param['mid'] ?? 0)>0){
                $where['ulog_mid'] = intval($param['mid'] ?? 0);
            }
            if(intval($param['id'] ?? 0)>0){
                $where['ulog_rid'] = intval($param['id'] ?? 0);
            }
            if(intval($param['type'] ?? 0)>0){
                $where['ulog_type'] = intval($param['type'] ?? 0);
            }
            $order = 'ulog_time desc';
            $res = (new \app\common\model\Ulog())->listData($where, $order, $param['page'], $param['limit']);
        }
        return json($res);
    }

    public function ajax_buy_popedom()
    {
        $identity = \app\common\util\MemberWrite::authorize(request());
        if ($identity['code'] !== 1) { return json($identity); }
        $param = \app\common\util\ContentPurchase::parameters(Request::post());
        if ($param === null) { return json(['code'=>2001, 'msg'=>lang('param_err')]); }
        $data = [];
        $data['ulog_mid'] = intval($param['mid']) <=0 ? 1: intval($param['mid']);
        $data['ulog_rid'] = intval($param['id']);
        $data['ulog_sid'] = intval($param['sid']);
        $data['ulog_nid'] = intval($param['nid']);

        if (!in_array($param['mid'], ['1','2','12']) || !in_array($param['type'], ['1','4','5']) || empty($data['ulog_rid']) ) {
            return json(['code' => 2001, 'msg' => lang('param_err')]);
        }
        $data['ulog_type'] = $param['type'];
        $data['user_id'] = $identity['info']['user_id'];

        $where = [];
        if($param['mid']=='12'){
            // 漫画购买（扣费额与 check_user_popedom 一致）
            $where['manga_id'] = $data['ulog_rid'];
            $res = (new \app\common\model\Manga())->infoData($where);
            if ($res['code'] > 1) {
                return json($res);
            }
            $data['ulog_points'] = mac_content_read_points_amount('manga', $res['info']);
            if($GLOBALS['config']['user']['manga_points_type']=='1'){
                $data['ulog_sid']=0;
                $data['ulog_nid']=0;
            }
        }
        elseif($param['type']=='1'){
            // 文章购买
            $where['art_id'] = $data['ulog_rid'];
            $res = (new \app\common\model\Art())->infoData($where);
            if ($res['code'] > 1) {
                return json($res);
            }
            $data['ulog_points'] = mac_content_read_points_amount('art', $res['info']);
            if($GLOBALS['config']['user']['art_points_type']=='1'){
                $data['ulog_sid']=0;
                $data['ulog_nid']=0;
            }
        }
        else{
            // 视频播放/下载购买
            $where['vod_id'] = $data['ulog_rid'];
            $res = (new \app\common\model\Vod())->infoData($where);
            if ($res['code'] > 1) {
                return json($res);
            }
            $col = 'vod_points_' . ($param['type'] == '4' ? 'play' : 'down');
            if($GLOBALS['config']['user']['vod_points_type']=='1'){
                $col='vod_points';
                $data['ulog_sid']=0;
                $data['ulog_nid']=0;
            }
            $data['ulog_points'] = intval($res['info'][$col]);
        }

        return json(\app\common\util\ContentPurchase::buy($identity['info']['user_id'], $data));
    }

    /** Same-origin clients fetch this after login; it is never embedded in a cached public page. */
    public function write_token()
    {
        if (request()->method(true) !== 'GET' || request()->method() !== 'GET') {
            $result = ['code'=>1001, 'msg'=>lang('param_err')];
        } else {
            $identity = \app\common\util\MemberWrite::identity();
            $result = $identity['code'] === 1
                ? ['code'=>1, 'info'=>['csrf_token'=>\app\common\util\SessionCsrf::issue()]] : $identity;
        }
        return json($result)->header(['Cache-Control'=>'private, no-store', 'Pragma'=>'no-cache',
            'X-Content-Type-Options'=>'nosniff', 'Vary'=>'Cookie, Authorization']);
    }

    public function index()
    {
        return $this->fetch('user/index');
    }

    public function login()
    {
        if (Request()->isPost()) {
            $param = \think\facade\Request::post();
            $res = (new \app\common\model\User())->login($param);
            return json($res);
        }
        if (\app\common\util\PointsBalance::amount($GLOBALS['user']['user_id'] ?? null) !== null) {
            return redirect('user/index');
        }
        return $this->fetch('user/login');
    }

    public function logout()
    {
        $res = (new \app\common\model\User())->logout();
        if (request()->isAjax()) {
            return json($res);
        } else {
            return redirect('user/login');
        }
    }

    public function oauth($type = '')
    {
        if (!OAuthState::supports($type)) {
            return $this->error(lang('param_err'));
        }
        //加载ThinkOauth类并实例化一个对象
        $sns = ThinkOauth::getInstance($type);
        //跳转到授权页面
        $state = OAuthState::issue($type, (int) ($GLOBALS['user']['user_id'] ?? 0));
        return redirect($sns->getRequestCodeURL($state));
    }

    //授权回调地址
    public function logincallback($type = '', $code = '')
    {
        if (!OAuthState::supports($type) || !is_string($code) || $code === ''
            || !OAuthState::consume($type, request()->get('state'), (int) ($GLOBALS['user']['user_id'] ?? 0))) {
            return $this->error(lang('param_err'));
        }
        //加载ThinkOauth类并实例化一个对象
        $sns = ThinkOauth::getInstance($type);
        $extend = null;

        //请妥善保管这里获取到的Token信息，方便以后API调用
        $token = $sns->getAccessToken($code, $extend);
        //获取当前登录用户信息
        if (is_array($token)) {
            $loginEvent = new LoginEvent();
            $res = $loginEvent->$type($token);
            if ($res['code'] == 1) {
                $openid = $res['info']['openid'] ?? null;
                if (!is_string($openid) || $openid === '') {
                    return $this->error(lang('index/logincallback2'));
                }
                $col = 'user_openid_' . $type;
                //如果已登录,是否需要重新绑定
                $check = (new \app\common\model\User())->checkLogin();
                if ($check['code'] == 1) {

                    if ($check['info'][$col] == $openid) {
                        //无需再次绑定
                        return json(['code' => 1001, 'msg' => lang('index/bind_haved')]);
                    } else {
                        //解除原有绑定
                        $where = [];
                        $where[$col] = $openid;
                        $update = [];
                        $update[$col] = '';
                        (new \app\common\model\User())->where($where)->update($update);
                        //新绑定
                        $where = [];
                        $where['user_id'] = $GLOBALS['user']['user_id'];
                        $update = [];
                        $update[$col] = $openid;
                        (new \app\common\model\User())->where($where)->update($update);
                        return json(['code' => 1, 'msg' => lang('index/bind_ok')]);
                    }
                }

                $where = [];
                $where[$col] = $openid;
                $res2 = (new \app\common\model\User())->infoData($where);
                //未绑定的需要先创建用户并绑定
                if ($res2['code'] > 1) {
                    $data = [];
                    $data['user_name'] = substr($openid, 0, 10);
                    $data['user_nick_name'] = htmlspecialchars(urldecode(trim($res['info']['name'])));
                    $pwd = bin2hex(random_bytes(24));
                    $data['user_pwd'] = $pwd;
                    $data['user_pwd2'] = $pwd;
                    $data[$col] = $openid;
                    $reg = (new \app\common\model\User())->register($data, true);
                    if ($reg['code'] > 1) {
                        //注册失败
                        return $this->error(lang('index/logincallback1'));
                    }
                }
                //直接登录。。。
                $login = (new \app\common\model\User())->login(['col' => $col, 'openid' => $openid], ['trusted_oauth' => true]);
                if ($login['code'] > 1) {
                    return $this->error($login['msg']);
                }
                return redirect((string) url('user/index'));
            } else {
                return $this->error($res['msg']);
            }
        } else {
            return $this->error(lang('index/logincallback2'));
        }
    }

    public function bindmsg()
    {
        if (!Request()->isPost()) { return json(['code'=>9001, 'msg'=>lang('param_err')]); }
        $param = \think\facade\Request::post();
        $res = (new \app\common\model\User())->bindmsg($param);
        return json($res);
    }

    public function bind()
    {
        if (Request()->isPost()) {
            $param = \think\facade\Request::post();
            $res = (new \app\common\model\User())->bind($param);
            return json($res);
        }
        $param = \think\facade\Request::get();
        $ac = $param['ac'] ?? 'email';
        if (!in_array($ac, ['email', 'phone'], true)) { return $this->error(lang('param_err')); }
        $bind_readonly = ($ac === 'email' && !empty($GLOBALS['user']['user_email']))
            || ($ac === 'phone' && !empty($GLOBALS['user']['user_phone']));
        $this->assign('ac', $ac);
        $this->assign('bind_readonly', $bind_readonly ? 1 : 0);
        return $this->fetch('user/bind');
    }

    public function unbind()
    {
        if (Request()->isPost()) {
            $param = \think\facade\Request::post();
            $res = (new \app\common\model\User())->unbind($param);
            return json($res);
        }
        $param = \think\facade\Request::get();
        $ac = $param['ac'] ?? 'email';
        if (!in_array($ac, ['email', 'phone'], true)) { return $this->error(lang('param_err')); }
        $this->assign('ac', $ac);
        $this->assign('contact', (string)($GLOBALS['user']['user_'.$ac] ?? ''));
        return $this->fetch('user/unbind');
    }

    public function info()
    {
        $param = \think\facade\Request::param();
        if (Request()->isPost()) {
            $res = (new \app\common\model\User())->info($param);
            if ($res['code'] == 1) {
                $this->success($res['msg']);
                exit;
            }
            $this->error($res['msg']);
            exit;
        }
        $this->assign('param',$param);
        return $this->fetch('user/info');
    }

    /** HTTP form fields are text; reject structured values before legacy string operations. */
    private function userFormParameters(array $param, array $fields): ?array
    {
        $data = [];
        foreach ($fields as $field) {
            $value = array_key_exists($field, $param) ? $param[$field] : '';
            if (!is_string($value) && !is_int($value)) {
                return null;
            }
            $data[$field] = (string)$value;
        }
        return $data;
    }

    private function userMessageTargetIsValid(array $param): bool
    {
        if ($param['ac'] === 'email') {
            return filter_var(trim($param['to']), FILTER_VALIDATE_EMAIL) !== false;
        }
        return $param['ac'] === 'phone' && preg_match('/^1[0-9]{10}$/D', trim($param['to'])) === 1;
    }

    public function regcheck()
    {
        $param = $this->userFormParameters(Request::param(), ['t', 'str']);
        if ($param === null || !in_array($param['t'], ['user_name', 'user_email', 'verify'], true)
            || trim($param['str']) === '') {
            return json(['code' => 1001, 'msg' => lang('param_err')]);
        }
        $t = $param['t'];
        $str = htmlspecialchars(urldecode(trim($param['str'])));
        return json((new \app\common\model\User())->regcheck($t, $str));
    }

    public function reg()
    {
        if (request()->isPost()) {
            $param = Request::post();
            if (!array_key_exists('uid', $param)) {
                $referral = cookie('uid');
                if ($referral !== null && $referral !== '') {
                    $referral = \app\common\util\PointsBalance::amount($referral);
                    if ($referral === null) { return json(['code'=>1001, 'msg'=>lang('param_err')]); }
                    $param['uid'] = $referral;
                }
            }
            $res = (new \app\common\model\User())->register($param);
            if ($res['code'] > 1) { return json($res); }
            if ((int)$GLOBALS['config']['user']['reg_status'] !== 1) {
                return json(['code'=>1, 'msg'=>lang('index/reg_ok'), 'pending_approval'=>1]);
            }
            $GLOBALS['config']['user']['login_verify'] = '0';
            $res = (new \app\common\model\User())->login($param);
            $res['msg'] = lang('index/reg_ok').'，' . $res['msg'];
            return json($res);
        }
        if (!request()->isGet()) { return json(['code'=>1001, 'msg'=>lang('param_err')]); }
        $query = Request::get();
        $code = $query['invite_code'] ?? '';
        $uid = array_key_exists('uid', $query) ? \app\common\util\PointsBalance::amount($query['uid']) : null;
        if (!is_string($code) || !preg_match('/^[A-Za-z0-9]{0,20}$/D', $code)
            || (array_key_exists('uid', $query) && $uid === null)) {
            return json(['code'=>1001, 'msg'=>lang('param_err')]);
        }
        if ($uid !== null) { cookie('uid', (string)$uid); }
        $this->assign('user_config', $GLOBALS['config']['user']);
        $this->assign('param', ['wd'=>'', 'sid'=>0, 'nid'=>0, 'invite_code'=>$code, 'uid'=>$uid ?? 0]);
        return $this->fetch('user/reg');
    }

    public function reg_msg()
    {
        $param = $this->userFormParameters(Request::post(), ['ac', 'to', 'code', 'verify']);
        if (!request()->isPost() || $param === null
            || !$this->userMessageTargetIsValid($param)) {
            return json(['code' => 9001, 'msg' => lang('param_err')]);
        }
        $res = (new \app\common\model\User())->reg_msg($param);
        return json($res);
    }


    public function portrait()
    {
        if(request()->isPost()){
            if ($GLOBALS['config']['user']['portrait_status'] == 0) {
                return json(['code' => 0, 'msg' => lang('index/portrait_tip1')]);
            }
            $param=[];
            $param['input'] = 'file';
            $param['flag'] = 'user';
            $param['user_id'] = $GLOBALS['user']['user_id'];
            $res = (new \app\common\model\Upload())->upload($param);
            return json($res);
        }
        return $this->fetch('user/portrait');
    }

    public function findpass()
    {
        $param = $this->userFormParameters(Request::param(), [
            'user_name', 'user_question', 'user_answer', 'user_pwd', 'user_pwd2', 'verify',
        ]);
        if ($param === null) {
            return json(['code' => 1001, 'msg' => lang('param_err')]);
        }
        if (request()->isPost()) {
            $res = (new \app\common\model\User())->findpass($param);
            return json($res);
        }
        $this->assign('param', $param);
        return $this->fetch('user/findpass');
    }

    public function findpass_msg()
    {
        $raw = Request::param();
        $param = $this->userFormParameters($raw, ['ac', 'to', 'code', 'verify']);
        if ($param === null) {
            return json(['code' => 9001, 'msg' => lang('param_err')]);
        }
        if (!request()->isPost() && !array_key_exists('ac', $raw)) {
            // Templates use the selected channel in links and form fields.
            return redirect(url('user/findpass_msg', ['ac' => 'email']));
        }
        if (!in_array($param['ac'], ['email', 'phone'], true)
            || (request()->isPost() && !$this->userMessageTargetIsValid($param))) {
            return json(['code' => 9001, 'msg' => lang('param_err')]);
        }
        if (request()->isPost()) {
            $res = (new \app\common\model\User())->findpass_msg($param);
            return json($res);
        }
        $param['ac_text'] = $param['ac'] === 'phone' ? lang('mobile') : lang('email');
        $this->assign('param', $param);
        return $this->fetch('user/findpass_msg');
    }

    public function findpass_reset()
    {
        $param = $this->userFormParameters(Request::param(), [
            'ac', 'to', 'user_email', 'code', 'user_pwd', 'user_pwd2',
        ]);
        if (!request()->isPost() || $param === null
            || !in_array($param['ac'], ['email', 'phone'], true)
            || !$this->userMessageTargetIsValid($param) || trim($param['code']) === '') {
            return json(['code' => 9001, 'msg' => lang('param_err')]);
        }
        $res = (new \app\common\model\User())->findpass_reset($param);
        return json($res);
    }

    public function buy()
    {
        $param = \think\facade\Request::param();
        if (Request()->isPost()) {
            $flag = \think\facade\Request::param('flag');
            if ($flag == 'card') {
                $card_no = htmlspecialchars(urldecode(trim($param['card_no'])));
                $card_pwd = htmlspecialchars(urldecode(trim($param['card_pwd'])));

                $res = (new \app\common\model\Card())->useData($card_no, $card_pwd, $GLOBALS['user']);
                return json($res);
            } else {
                $price = \think\facade\Request::param('price');
                $minor = \app\common\util\OrderAmount::minorUnits($price);
                $minimum = \app\common\util\OrderAmount::minimum($GLOBALS['config']['pay']['min'] ?? null);
                if ($minor === null || $minimum === null) {
                    return json(['code' => 1001, 'msg' => lang('param_err')]);
                }

                if ($minor < $minimum) {
                    return json(['code' => 1002, 'msg' =>lang('index/min_pay',[$GLOBALS['config']['pay']['min']])]);
                }
                $quote = \app\common\util\OrderAmount::recharge($price, $GLOBALS['config']['pay']['scale'] ?? null);
                if ($quote === null) {
                    return json(['code' => 1003, 'msg' => '当前充值金额不可用，请调整金额或联系管理员']);
                }

                $data = [];
                $data['user_id'] = $GLOBALS['user']['user_id'];
                $data['order_code'] = 'PAY' . mac_get_uniqid_code();
                $data['order_price'] = $quote['order_price'];
                $data['order_time'] = time();
                $data['order_points'] = $quote['order_points'];
                $res = (new \app\common\model\Order())->saveData($data);
                if ($res['code'] == 1) {
                    $orderInfo = (new \app\common\model\Order())->infoData(['order_code' => $data['order_code'], 'user_id' => $data['user_id']]);
                    if ($orderInfo['code'] == 1) {
                        $data['order_id'] = $orderInfo['info']['order_id'];
                    }
                }
                $res['data'] = $data;
                return json($res);
            }
        }
        $this->assign('param',$param);
        $this->assign('config', $GLOBALS['config']['pay']);
        $extends = mac_extends_list('pay');
        $this->assign('ext_list', $extends['ext_list']);
        return $this->fetch('user/buy');
    }

    public function pay()
    {
        $param = \think\facade\Request::param();
        $order_code = $param['order_code'] ?? null;
        if (!is_string($order_code) || !preg_match('/^[A-Za-z0-9_-]{1,30}$/D', $order_code)) {
            return $this->error(lang('param_err'));
        }
        $where = [];
        $where['order_code'] = $order_code;
        $where['user_id'] = $GLOBALS['user']['user_id'];
        $res = (new \app\common\model\Order())->infoData($where);
        if ($res['code'] > 1) {
            return $this->error($res['msg']);
        }
        $this->assign('param',$param);
        $this->assign('config', $GLOBALS['config']['pay']);
        $this->assign('info', $res['info']);

        $extends = mac_extends_list('pay');
        $this->assign('extends',$extends);
        $this->assign('ext_list',$extends['ext_list']);

        return $this->fetch('user/pay');
    }

    public function gopay()
    {
        $param = \think\facade\Request::param();

        $order_code = $param['order_code'] ?? null;
        $order_id = $param['order_id'] ?? null;
        $payment = $param['payment'] ?? null;
        if (!is_string($order_code) || !preg_match('/^[A-Za-z0-9_-]{1,30}$/D', $order_code)
            || (!is_int($order_id) && !is_string($order_id))
            || !preg_match('/^[1-9][0-9]{0,9}$/D', (string)$order_id) || (float)$order_id > 4294967295
            || !is_string($payment) || !preg_match('/^[A-Za-z][A-Za-z0-9_]{0,9}$/D', $payment)) {
            return $this->error(lang('param_err'));
        }
        $order_id = (int)$order_id;
        $payment = strtolower($payment);
        foreach (['paytype', 'type'] as $option) {
            if (isset($param[$option]) && !is_string($param[$option]) && !is_int($param[$option])) {
                return $this->error(lang('param_err'));
            }
        }
        $provider = $GLOBALS['config']['pay'][$payment] ?? null;
        $cp = 'app\\common\\extend\\pay\\' . ucfirst($payment);
        if (!is_array($provider) || !is_scalar($provider['appid'] ?? null)
            || trim((string)$provider['appid']) === '' || !class_exists($cp) || !method_exists($cp, 'submit')) {
            return $this->error(lang('index/payment_status'));
        }

        //核实订单
        $where['order_id'] = $order_id;
        $where['order_code'] = $order_code;
        $where['user_id'] = $GLOBALS['user']['user_id'];
        $res = (new \app\common\model\Order())->infoData($where);
        if ($res['code'] > 1) {
            return $this->error(lang('index/order_not'));
        }
        if ($res['info']['order_status'] == 1) {
            return $this->error(lang('index/order_payed'));
        }

        $this->assign('order', $res['info']);
        //跳转到相应页面
        $this->assign('param',$param);

        try {
            $payment_res = (new $cp())->submit($GLOBALS['user'], $res['info'], $param);
        } catch (\Throwable $e) {
            return $this->error(lang('index/payment_status'));
        }
        if ($payment === 'weixin') {
            if (!is_array($payment_res) || !is_string($payment_res['code_url'] ?? null)
                || !str_starts_with($payment_res['code_url'], 'weixin://')) {
                return $this->error(lang('index/payment_status'));
            }
            $this->assign('payment', $payment_res);
            return $this->fetch('user/payment_weixin');
        }
        if ($payment_res === false) {
            return $this->error(lang('index/payment_status'));
        }
        return $payment_res;
    }

    public function qrcode()
    {
        $data = \think\facade\Request::param('data');
        if (!is_string($data) || !str_starts_with($data, 'weixin://') || strlen($data) <= 9) {
            return json(['code' => 1001, 'msg' => lang('param_err')], 400);
        }
        return QrResponse::png($data, QrResponse::LOW, 10, 4);
    }

    public function upgrade()
    {
        $param = \think\facade\Request::param();
        if (Request()->isPost()) {
            $res = (new \app\common\model\User())->upgrade($param);
            return json($res);
        }

        $group_list = (new \app\common\model\Group())->getCache();
        $this->assign('group_list', $group_list);
        $this->assign('pay_config', $GLOBALS['config']['pay']);
        $this->assign('param',$param);
        return $this->fetch('user/upgrade');
    }

    /**
     * 会员权益说明页（需登录）
     */
    public function benefits()
    {
        return $this->fetch('user/benefits');
    }

    /**
     * 每日签到（当前为前端展示页，业务逻辑待接入）
     */
    public function checkin()
    {
        return $this->fetch('user/checkin');
    }

    /**
     * 弹窗用：返回升级会员表单 HTML（需登录）
     */
    public function ajax_upgrade()
    {
        $group_list = (new \app\common\model\Group())->getCache();
        $this->assign('group_list', $group_list);
        $this->assign('pay_config', $GLOBALS['config']['pay']);
        $this->assign('param', \think\facade\Request::param());
        $html = $this->fetch('user/ajax_upgrade');
        return json($html);
    }

    public function popedom()
    {
        $type_tree = (new \app\common\model\Type())->getCache('type_tree');
        $this->assign('type_tree', $type_tree);

        $n = 1;
        $ids = [1 => lang('index/page_type'), 2 => lang('index/page_detail'), 3 => lang('index/page_play'), 4 => lang('index/page_down'), '5' => lang('index/try_see')];
        foreach ($type_tree as $k1 => $v1) {
            unset($type_tree[$k1]['type_extend']);
            $max_a = ($v1['type_mid'] == 1) ? 5 : (in_array($v1['type_mid'], [2, 12]) ? 3 : 2);
            foreach ($ids as $a => $b) {
                if ($a > $max_a) break;
                $n++;
                $type_tree[$k1]['popedom'][$b] = (new \app\common\model\User())->popedom($v1['type_id'], $a, $GLOBALS['user']['group_id']);
            }
            foreach ($v1['child'] as $k2 => $v2) {
                unset($type_tree[$k1]['child'][$k2]['type_extend']);
                $max_a = ($v2['type_mid'] == 1) ? 5 : (in_array($v2['type_mid'], [2, 12]) ? 3 : 2);
                foreach ($ids as $a => $b) {
                    if ($a > $max_a) break;
                    $n++;
                    $type_tree[$k1]['child'][$k2]['popedom'][$b] = (new \app\common\model\User())->popedom($v2['type_id'], $a, $GLOBALS['user']['group_id']);
                }
            }
        }

        $this->assign('type_tree', $type_tree);

        return $this->fetch('user/popedom');
    }

    public function plays()
    {
        $param = \think\facade\Request::param();
        $param['page'] = intval($param['page'] ?? 1) < 1 ? 1 : intval($param['page'] ?? 1);
        $param['limit'] = intval($param['limit'] ?? 20) < 20 ? 20 : intval($param['limit'] ?? 20);
        $param['mid'] = intval($param['mid'] ?? 0);

        $where = [];
        $where['user_id'] = $GLOBALS['user']['user_id'];
        $where['ulog_type'] = 4;
        if (in_array($param['mid'], [1, 2, 3, 8, 12])) {
            $where['ulog_mid'] = $param['mid'];
        }
        $order = 'ulog_time desc';
        $res = (new \app\common\model\Ulog())->listData($where, $order, $param['page'], $param['limit']);

        $this->assign('param', array_merge(mac_param_url(), $param));
        $this->assign('list', $res['list']);
        $page_url = url('user/plays', ['mid' => $param['mid'], 'page' => 'PAGELINK']);
        $pages = mac_page_param($res['total'], $param['limit'], $param['page'], $page_url);
        $this->assign('__PAGING__', $pages);
        return $this->fetch('user/plays');
    }

    public function downs()
    {
        $param = \think\facade\Request::param();
        $param['page'] = intval($param['page'] ?? 1) < 1 ? 1 : intval($param['page'] ?? 1);
        $param['limit'] = intval($param['limit'] ?? 20) < 20 ? 20 : intval($param['limit'] ?? 20);

        $where = [];
        $where['user_id'] = $GLOBALS['user']['user_id'];
        $where['ulog_mid'] = 1;
        $where['ulog_type'] = 5;
        $order = 'ulog_time desc';
        $res = (new \app\common\model\Ulog())->listData($where, $order, $param['page'], $param['limit']);

        $this->assign('param', array_merge(mac_param_url(), $param));
        $this->assign('list', $res['list']);
        $pages = mac_page_param($res['total'], $param['limit'], $param['page'], url('user/downs', ['page' => 'PAGELINK']));
        $this->assign('__PAGING__', $pages);
        return $this->fetch('user/downs');
    }

    public function favs()
    {
        $param = \think\facade\Request::param();
        $param['page'] = intval($param['page'] ?? 1) < 1 ? 1 : intval($param['page'] ?? 1);
        $param['limit'] = intval($param['limit'] ?? 20) < 20 ? 20 : intval($param['limit'] ?? 20);
        $param['mid'] = intval($param['mid'] ?? 0);

        $where = [];
        $where['user_id'] = $GLOBALS['user']['user_id'];
        if (in_array($param['mid'], [1, 2, 3, 8, 12])) {
            $where['ulog_mid'] = $param['mid'];
        }
        $where['ulog_type'] = 2;
        $order = 'ulog_time desc';
        $res = (new \app\common\model\Ulog())->listData($where, $order, $param['page'], $param['limit']);

        $this->assign('param', array_merge(mac_param_url(), $param));
        $this->assign('list', $res['list']);
        $page_url = url('user/favs', ['mid' => $param['mid'], 'page' => 'PAGELINK']);
        $pages = mac_page_param($res['total'], $param['limit'], $param['page'], $page_url);
        $this->assign('__PAGING__', $pages);
        return $this->fetch('user/favs');
    }

    public function ulog()
    {
        if (!\think\facade\View::engine()->exists('user/ulog')) {
            throw new \think\exception\HttpException(404, lang('page_not_found'));
        }
        $param = array_merge(['mid' => 0, 'type' => 0], \think\facade\Request::param());
        $param['page'] = intval($param['page'] ?? 1) < 1 ? 1 : intval($param['page'] ?? 1);
        $param['limit'] = intval($param['limit'] ?? 20) < 20 ? 20 : intval($param['limit'] ?? 20);

        $where = [];
        $where['user_id'] = $GLOBALS['user']['user_id'];
        if(in_array($param['mid'],['1','2','3','8'])){
            $where['ulog_mid'] = $param['mid'];
        }
        if(in_array($param['type'],['1','2','3','4','5'])){
            $where['ulog_type'] = $param['type'];
        }

        $order = 'ulog_time desc';
        $res = (new \app\common\model\Ulog())->listData($where, $order, $param['page'], $param['limit']);

        $this->assign('param', array_merge(mac_param_url(), $param));
        $this->assign('list', $res['list']);
        $pages = mac_page_param($res['total'], $param['limit'], $param['page'], url('user/ulog', ['page' => 'PAGELINK']));
        $this->assign('__PAGING__', $pages);
        return $this->fetch('user/ulog');
    }

    public function ulog_del()
    {
        $param = \think\facade\Request::post();
        $ids = $this->logDeletionIds($param);
        $type = $param['type'] ?? null;
        if ($ids === null || (!is_int($type) && !is_string($type))
            || !in_array((string)$type, ['1', '2', '3', '4', '5'], true)) {
            return json(['code' => 1001, 'msg' => lang('param_err')]);
        }
        $where = ['user_id' => $GLOBALS['user']['user_id'], 'ulog_type' => $type];
        if ($ids !== []) { $where[] = ['ulog_id', 'in', $ids]; }
        return json((new \app\common\model\Ulog())->delData($where));
    }

    public function plog()
    {
        $param = \think\facade\Request::param();
        $param['page'] = intval($param['page'] ?? 1) < 1 ? 1 : intval($param['page'] ?? 1);
        $param['limit'] = intval($param['limit'] ?? 20) < 20 ? 20 : intval($param['limit'] ?? 20);
        $param['filter'] = is_scalar($param['filter'] ?? '') ? trim((string)($param['filter'] ?? '')) : '';

        $where = [];
        $where['user_id'] = $GLOBALS['user']['user_id'];
        // 筛选：income=收入(1-6 与任务/里程碑奖励 10-11), expense=支出(7-9)
        if ($param['filter'] == 'income') {
            $where['plog_type'] = [1, 2, 3, 4, 5, 6, 10, 11];
        } elseif ($param['filter'] == 'expense') {
            $where['plog_type'] = [7, 8, 9];
        }
        $order = 'plog_id desc';
        $res = (new \app\common\model\Plog())->listForUser($GLOBALS['user']['user_id'], $where, $order, $param['page'], $param['limit']);

        $this->assign('param', array_merge(mac_param_url(), $param));
        $this->assign('list', $res['list']);
        $page_url = url('user/plog', ['filter' => $param['filter'], 'page' => 'PAGELINK']);
        $pages = mac_page_param($res['total'], $param['limit'], $param['page'], $page_url);
        $this->assign('__PAGING__', $pages);
        return $this->fetch('user/plog');
    }

    public function plog_del()
    {
        $ids = $this->logDeletionIds(\think\facade\Request::post());
        if ($ids === null) {
            return json(['code' => 1001, 'msg' => lang('param_err')]);
        }
        return json((new \app\common\model\Plog())->hideForUser($GLOBALS['user']['user_id'], $ids));
    }

    /** Null rejects the request; [] means an explicit delete-all within the owner's scope. */
    private function logDeletionIds(array $param): ?array
    {
        if (!request()->isPost() || (int)($GLOBALS['user']['user_id'] ?? 0) < 1) { return null; }
        return \app\common\util\LogSelection::ids($param);
    }

    public function cash()
    {
        $param = \think\facade\Request::param();
        if (Request()->isPost()) {
            $param['user_id'] = $GLOBALS['user']['user_id'];
            $res = (new \app\common\model\Cash())->saveData($param);
            return json($res);
        }

        $param['page'] = intval($param['page'] ?? 1) < 1 ? 1 : intval($param['page'] ?? 1);
        $param['limit'] = intval($param['limit'] ?? 20) < 20 ? 20 : intval($param['limit'] ?? 20);

        $where = [];
        $where['user_id'] = $GLOBALS['user']['user_id'];
        $order = 'cash_id desc';
        $res = (new \app\common\model\Cash())->listData($where, $order, $param['page'], $param['limit']);

        $this->assign('param', array_merge(mac_param_url(), $param));
        $this->assign('list', $res['list']);
        $pages = mac_page_param($res['total'], $param['limit'], $param['page'], url('user/cash', ['page' => 'PAGELINK']));
        $this->assign('__PAGING__', $pages);
        return $this->fetch('user/cash');
    }

    public function cash_del()
    {
        $param = \think\facade\Request::param();
        $ids = htmlspecialchars(urldecode(trim($param['ids'])));
        $type = $param['type'];
        $all = $param['all'];

        if (empty($ids) && empty($all)) {
            return json(['code' => 1001, 'msg' => lang('param_err')]);
        }

        $arr = [];
        $ids = explode(',', $ids);
        foreach ($ids as $k => $v) {
            $v = abs(intval($v));
            $arr[$v] = $v;
        }

        $where = [];
        $where['user_id'] = $GLOBALS['user']['user_id'];
        if ($all != '1') {
            $where['cash_id'] = array('in', array_values($arr));
        }
        $return = (new \app\common\model\Cash())->delData($where);
        return json($return);
    }

    public function reward()
    {
        $param = array_merge(['level' => 1], \think\facade\Request::param());

        $param['page'] = intval($param['page'] ?? 1) < 1 ? 1 : intval($param['page'] ?? 1);
        $param['limit'] = intval($param['limit'] ?? 20) < 20 ? 20 : intval($param['limit'] ?? 20);

        $where = [];
        if($param['level']=='2'){
            $where['user_pid_2'] = $GLOBALS['user']['user_id'];
        }
        elseif($param['level']=='3'){
            $where['user_pid_3'] = $GLOBALS['user']['user_id'];
        }
        else{
            $where['user_pid'] = $GLOBALS['user']['user_id'];
        }

        $order = 'user_id desc';
        $userModel = (new \app\common\model\User());
        $res = $userModel->listData($where, $order, $param['page'], $param['limit']);
        // 安全加固:listData 走 SELECT *,剥离 user_pwd / user_random 等敏感字段后再传模板,
        // 防止自定义主题循环输出 $list 时泄露下线用户凭证(user_random 泄露可伪造会话)。
        if (!empty($res['list']) && is_array($res['list'])) {
            foreach ($res['list'] as $k => $row) {
                $res['list'][$k] = $userModel->stripSensitiveFields($row);
            }
        }

        $this->assign('param', array_merge(mac_param_url(), $param));
        $this->assign('list', $res['list']);
        $pages = mac_page_param($res['total'], $param['limit'], $param['page'], url('user/reward', ['level'=>$param['level'], 'page' => 'PAGELINK']));
        $this->assign('__PAGING__', $pages);
        return $this->fetch('user/reward');
    }

    public function orders()
    {
        $param = \think\facade\Request::param();
        $param['page'] = intval($param['page'] ?? 1) < 1 ? 1 : intval($param['page'] ?? 1);
        $param['limit'] = intval($param['limit'] ?? 20) < 20 ? 20 : intval($param['limit'] ?? 20);

        $where = [];
        $where['o.user_id'] = $GLOBALS['user']['user_id'];

        $order = 'o.order_id desc';
        $res = (new \app\common\model\Order())->listData($where, $order, $param['page'], $param['limit']);

        $pages = mac_page_param($res['total'], $param['limit'], $param['page'], url('user/orders', ['page' => 'PAGELINK']));
        $this->assign('__PAGING__', $pages);
        $this->assign('param', array_merge(mac_param_url(), $param));
        $this->assign('list', $res['list']);
        return $this->fetch('user/orders');
    }

    public function order_info()
    {
        $param = \think\facade\Request::param();
        $where = [];
        $where['order_id'] = intval($param['order_id']);
        // 安全加固(CVE-2026-4563):订单详情必须绑定当前登录用户,防止越权遍历他人订单
        $where['user_id'] = $GLOBALS['user']['user_id'];
        $res = (new \app\common\model\Order())->infoData($where);
        if (request()->isAjax()) {
            return json($res);
        }
        $this->assign('param',$param);
        return $this->fetch('user/order_info');
    }


    public function cards()
    {
        $param = \think\facade\Request::param();
        $param['page'] = intval($param['page'] ?? 1) < 1 ? 1 : intval($param['page'] ?? 1);
        $param['limit'] = intval($param['limit'] ?? 20) < 20 ? 20 : intval($param['limit'] ?? 20);

        $where = [];
        $where['user_id'] = $GLOBALS['user']['user_id'];
        $where['card_use_status'] = 1;

        $order = 'card_id desc';
        $res = (new \app\common\model\Card())->listData($where, $order, $param['page'], $param['limit']);

        $pages = mac_page_param($res['total'], $param['limit'], $param['page'], url('user/cards', ['page' => 'PAGELINK']));
        $this->assign('__PAGING__', $pages);
        $this->assign('param', array_merge(mac_param_url(), $param));
        $this->assign('list', $res['list']);
        return $this->fetch('user/cards');
    }

    public function comment()
    {
        $param = \think\facade\Request::param();
        $this->assign('param',$param);
        return $this->fetch('user/comment');
    }

    public function gbook()
    {
        $param = \think\facade\Request::param();
        $this->assign('param',$param);
        return $this->fetch('user/gbook');
    }

    /**
     * 邀请推广页面：展示邀请码、邀请链接及下线列表
     */
    public function invite()
    {
        $param = \think\facade\Request::param();
        $param['page']  = intval($param['page'] ?? 1)  < 1 ? 1  : intval($param['page'] ?? 1);
        $param['limit'] = intval($param['limit'] ?? 20) < 1 ? 20 : intval($param['limit'] ?? 20);

        $user_id     = $GLOBALS['user']['user_id'];
        $invite_code = $GLOBALS['user']['user_invite_code'];

        $base_url         = $GLOBALS['http_type'] . $_SERVER['HTTP_HOST'] ?? '';
        $reg_path         = mac_url('user/reg');
        $invite_link_uid  = $base_url . $reg_path . '?uid=' . $user_id;
        $invite_link_code = !empty($invite_code)
            ? $base_url . $reg_path . '?invite_code=' . $invite_code
            : '';

        $total = (new \app\common\model\User())->where('user_pid', $user_id)->count();

        $invitees_raw = (new \app\common\model\User())
            ->field('user_id,user_name,user_nick_name,user_invite_code,user_invite_count,user_reg_time')
            ->where('user_pid', $user_id)
            ->order('user_id desc')
            ->page($param['page'])
            ->limit($param['limit'])
            ->select();

        $invitees = is_array($invitees_raw)
            ? $invitees_raw
            : (is_object($invitees_raw) ? $invitees_raw->toArray() : []);

        if (!empty($invitees)) {
            $level1_ids = array_column($invitees, 'user_id');

            $sub_raw  = (new \app\common\model\User())
                ->field('user_id,user_name,user_nick_name,user_invite_count,user_reg_time,user_pid')
                ->where('user_pid', 'in', $level1_ids)
                ->order('user_id desc')
                ->select();
            $sub_list = is_array($sub_raw)
                ? $sub_raw
                : (is_object($sub_raw) ? $sub_raw->toArray() : []);

            $sub_map = [];
            foreach ($sub_list as $sub) {
                $sub_map[$sub['user_pid']][] = $sub;
            }
            foreach ($invitees as &$invitee) {
                $invitee['sub_invitees'] = isset($sub_map[$invitee['user_id']]) ? $sub_map[$invitee['user_id']] : [];
                $invitee['sub_count']    = count($invitee['sub_invitees']);
            }
            unset($invitee);
        }

        $this->assign('invite_code',      $invite_code);
        $this->assign('invite_link_uid',  $invite_link_uid);
        $this->assign('invite_link_code', $invite_link_code);
        $this->assign('total',            intval($total));
        $this->assign('list',             $invitees);
        $this->assign('param', array_merge(mac_param_url(), $param));

        $pages = mac_page_param($total, $param['limit'], $param['page'], url('user/invite', ['page' => 'PAGELINK']));
        $this->assign('__PAGING__', $pages);

        return $this->fetch('user/invite');
    }

    private static function visitReturnLocation($value, string $origin): string
    {
        if (!is_string($value) || $value === '' || strlen($value) > 4096
            || preg_match('/[\\x00-\\x20\\x7f\\\\]/', $value)) { return '/'; }
        if ($value[0] === '/') { return str_starts_with($value, '//') ? '/' : $value; }
        $target = parse_url($value); $site = parse_url($origin);
        if (!is_array($target) || !is_array($site) || isset($target['user']) || isset($target['pass'])
            || !in_array(strtolower($target['scheme'] ?? ''), ['http','https'], true)
            || strcasecmp($target['scheme'], $site['scheme'] ?? '') !== 0
            || strcasecmp($target['host'] ?? '', $site['host'] ?? '') !== 0
            || ($target['port'] ?? (strtolower($target['scheme']) === 'https' ? 443 : 80))
                !== ($site['port'] ?? (strtolower($site['scheme'] ?? '') === 'https' ? 443 : 80))) { return '/'; }
        $path = $target['path'] ?? '/';
        if ($path === '' || $path[0] !== '/' || str_starts_with($path, '//')) { return '/'; }
        // A same-origin absolute input becomes a local path, so Host never chooses the destination origin.
        return $path.(isset($target['query']) ? '?'.$target['query'] : '').(isset($target['fragment']) ? '#'.$target['fragment'] : '');
    }

    public function visit()
    {
        $param = \think\facade\Request::param();
        (new \app\common\model\User())->visit($param);
        return redirect(self::visitReturnLocation($param['url'] ?? null, \think\facade\Request::domain()));
    }

}
