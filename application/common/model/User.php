<?php
namespace app\common\model;

use app\common\util\JwtService;
use think\facade\Db;
use think\View;
use app\common\validate\User as UserValidate;

class User extends Base
{
    // 设置数据表（不含前缀）
    protected $name = 'user';

    // 定义时间戳字段名
    protected $createTime = '';
    protected $updateTime = '';

    // 自动完成
    protected $auto = [];
    protected $insert = [];
    protected $update = [];

    public $_guest_group = 1;
    public $_def_group = 2;

    // Only a successful INSERT in this model instance can authorize one invitation event.
    private ?int $pendingRegistrationSourceId = null;
    private ?int $pendingInvitationRewardUserId = null;

    /** 禁止通过前台 / 公开 API 输出的用户字段（含会话伪造所需 user_random） */
    private static $sensitiveFields = [
        'user_pwd',
        'user_random',
        'user_answer',
        'user_question',
        'user_reg_ip',
        'user_login_ip',
        'user_last_login_ip',
        'user_openid_qq',
        'user_openid_weixin',
    ];

    /**
     * 公开 API 用户详情允许返回的字段（白名单）。
     *
     * @return string
     */
    public function publicApiDetailFields()
    {
        // 安全加固(V8):移除 user_phone/user_qq/user_email 等PII,防止未授权遍历泄露
        return 'user_id,user_name,user_nick_name,group_id,user_points,user_exp,user_integral,user_invite_code,user_invite_count,user_reg_time,user_status';
    }

    /**
     * 剥离会话/凭证相关字段，避免公开接口泄露后可伪造 user_check / JWT。
     *
     * @param array|null $row
     *
     * @return array|null
     */
    public function stripSensitiveFields($row)
    {
        if (!is_array($row)) {
            return $row;
        }
        foreach (self::$sensitiveFields as $key) {
            unset($row[$key]);
        }

        return $row;
    }

    public function countData($where)
    {
        $total = $this->where($where)->count();
        return $total;
    }

    public function listData($where, $order, $page = 1, $limit = 20, $start = 0)
    {
        $page = $page > 0 ? (int)$page : 1;
        $limit = $limit ? (int)$limit : 20;
        $start = $start ? (int)$start : 0;
        $total = $this->where($where)->count();
        $list = Db::name('User')->where($where)->order($order)->page($page)->limit($limit)->select()->toArray();
        return ['code' => 1, 'msg' => lang('data_list'), 'page' => $page, 'pagecount' => ceil($total / $limit), 'limit' => $limit, 'total' => $total, 'list' => $list];
    }

    public function infoData($where, $field='*')
    {
        if (empty($where) || !is_array($where)) {
            return ['code' => 1001, 'msg'=>lang('param_err')];
        }
        $info = $this->field($field)->where($where)->find();
        if (empty($info)) {
            return ['code' => 1002, 'msg' => lang('obtain_err')];
        }
        $info = $info->toArray();

        //用户组
        $group_list = (new \app\common\model\Group())->getCache('group_list');
        $group_ids = explode(',', $info['group_id']);
        $info['group'] = $group_list[$group_ids[0]];
        $info['groups'] = [];
        foreach($group_ids as $gid){
            if(isset($group_list[$gid])){
                $info['groups'][] = $group_list[$gid];
            }
        }


        $info['user_pwd'] = '';
        $info = $this->stripSensitiveFields($info);
        return ['code' => 1, 'msg' =>lang('obtain_ok'), 'info' => $info];
    }

    public function saveData($data)
    {
        if (!is_array($data) || (array_key_exists('user_pwd', $data) && !is_string($data['user_pwd']))) {
            return ['code'=>1001, 'msg'=>lang('param_err')];
        }
        $validate = mac_validate('User');

        if (isset($data['user_start_time']) && !is_numeric($data['user_start_time'])) {
            $data['user_start_time'] = strtotime($data['user_start_time']);
        }
        if (isset($data['user_end_time']) && !is_numeric($data['user_end_time'])) {
            $data['user_end_time'] = strtotime($data['user_end_time']);
        }

        // 选择VIP会员组（group_id > 2）时，包时截止时间必须大于当前时间
        $check_group_id = isset($data['group_id']) ? $data['group_id'] : 0;
        // 支持多组逗号分隔，取最大值判断
        $max_group_id = 0;
        if (!empty($check_group_id)) {
            $group_ids_arr = explode(',', $check_group_id);
            $max_group_id = max(array_map('intval', $group_ids_arr));
        }
        if ($max_group_id > 2) {
            $end_time_val = isset($data['user_end_time']) ? intval($data['user_end_time']) : 0;
            if ($end_time_val <= time()) {
                return ['code' => 1001, 'msg' => lang('model/user/vip_end_time_must_future')];
            }
        }

        if (!empty($data['user_id'])) {
            if (!$validate->scene('edit')->check($data)) {
                return ['code' => 1001, 'msg' => lang('param_err').'：' . $validate->getError()];
            }

            $changePassword = isset($data['user_pwd']) && trim($data['user_pwd']) !== '';
            try {
                if (!$changePassword) {
                    unset($data['user_pwd']);
                } else {
                    $credentials = $this->passwordCredentials($data['user_pwd']);
                    if ($credentials === null) { return ['code'=>1001, 'msg'=>lang('model/user/pass_length_err')]; }
                    $data = array_replace($data, $credentials);
                }
                $where = ['user_id'=>$data['user_id']];
                $data = $this->filterFields($data);
                $res = $this->where($where)->update($data);
                if ($changePassword && $res !== 1) { return ['code'=>1003, 'msg'=>lang('save_err')]; }
            } catch (\Throwable $error) {
                return ['code'=>1003, 'msg'=>lang('save_err')];
            }
        } else {
            if (!$validate->scene('edit')->check($data)) {
                return ['code' => 1002, 'msg' => lang('param_err').'：' . $validate->getError()];
            }

            $data['user_pwd'] = mac_password_hash($data['user_pwd']);
            $data = $this->filterFields($data);
            $res = $this->insert($data);
            // 新增用户后自动生成邀请码
            if ($res !== false) {
                $nid = $this->getLastInsID();
                if ($nid > 0) {
                    $invite_code = $this->generateUniqueInviteCode($nid);
                    $this->where('user_id', $nid)->update(['user_invite_code' => $invite_code]);
                }
            }
        }
        if (false === $res) {
            return ['code' => 1003, 'msg' => '' . $this->getError()];
        }
        return ['code' => 1, 'msg' =>lang('save_ok')];
    }

    public function delData($where)
    {
        $res = $this->where($where)->delete();
        if ($res < 1) {
            return ['code' => 1001, 'msg' => lang('del_err')];
        }
        return ['code' => 1, 'msg'=>lang('del_ok')];
    }

    public function fieldData($where, $col, $val)
    {
        if (!isset($col) || !isset($val)) {
            return ['code' => 1001, 'msg'=>lang('param_err')];
        }
        $data = [];
        $data[$col] = $val;
        $res = $this->where($where)->update($data);
        if ($res < 1) {
            return ['code' => 1002, 'msg' => lang('set_err')];
        }
        return ['code' => 1, 'msg' =>lang('set_ok')];
    }

    public function register($param, bool $trustedOauth = false)
    {
        return $this->createAccount($param, $trustedOauth, 6, false);
    }

    /** Internal mode is selected by server code, never by request flags. */
    private function createAccount($param, bool $trustedOauth, int $minimumNameLength, bool $autoLogin)
    {
        if (!is_array($param)) {
            return ['code' => 1001, 'msg' => lang('param_err')];
        }
        foreach (['user_name', 'user_pwd', 'user_pwd2', 'verify', 'ac', 'to', 'code', 'invite_code',
            'user_openid_qq', 'user_openid_weixin'] as $key) {
            if (array_key_exists($key, $param) && !is_string($param[$key])) {
                return ['code' => 1001, 'msg' => lang('param_err')];
            }
            $param[$key] = $param[$key] ?? '';
            if (!in_array($key, ['user_pwd', 'user_pwd2'], true)
                && (!mb_check_encoding($param[$key], 'UTF-8') || str_contains($param[$key], "\0"))) {
                return ['code'=>1001, 'msg'=>lang('param_err')];
            }
        }
        $rawUid = array_key_exists('uid', $param) ? $param['uid'] : '';
        if (array_key_exists('uid', $param) && !is_int($rawUid) && !is_string($rawUid)) {
            return ['code'=>1001, 'msg'=>lang('param_err')];
        }
        $rawUid = is_string($rawUid) ? trim($rawUid) : $rawUid;
        $uid = \app\common\util\PointsBalance::amount($rawUid === '' ? 0 : $rawUid, true);
        $invite_code_param = trim($param['invite_code']);
        if ($uid === null || !preg_match('/^[A-Za-z0-9]{0,20}$/D', $invite_code_param)) {
            return ['code'=>1001, 'msg'=>lang('param_err')];
        }
        foreach (['verify'=>255, 'ac'=>5, 'to'=>30, 'code'=>6, 'user_openid_qq'=>40, 'user_openid_weixin'=>40] as $key=>$limit) {
            $value = in_array($key, ['ac','to','code'], true) ? trim($param[$key]) : $param[$key];
            if (strlen($value) > $limit || (str_starts_with($key, 'user_openid_')
                && preg_match('/[\x{10000}-\x{10ffff}]/u', $value))) {
                return ['code'=>1001, 'msg'=>lang('param_err')];
            }
        }
        // Only the server-side callback, after verifying state and the provider token,
        // may register an OAuth identity or bypass normal registration challenges.
        if (!$trustedOauth) {
            $param['user_openid_qq'] = $param['user_openid_weixin'] = '';
        }
        // 安全加固:注册按 IP 温和限流(默认开启,失败开放),防注册刷量/暴力触发 bcrypt 打满 CPU。
        // 既有逻辑仅限制"每 IP 当日成功注册数",不限请求频率;此处补齐请求级限流。
        if (!mac_fe_write_throttle('fe_reg', 120, 10)) {
            return ['code' => 1429, 'msg' => lang('frequently')];
        }
        $config = config('maccms');
        if (!is_array($config) || !is_array($config['user'] ?? null)) {
            return ['code'=>1001, 'msg'=>lang('param_err')];
        }
        foreach (['status', 'reg_open', 'reg_verify'] as $key) {
            if (!in_array($config['user'][$key] ?? null, [0, 1, '0', '1'], true)) {
                return ['code'=>1001, 'msg'=>lang('param_err')];
            }
        }

        $data = [];
        $password_raw = trim($param['user_pwd']);
        $data['user_name'] = htmlspecialchars(urldecode(trim($param['user_name'])));
        $data['user_pwd'] = $password_raw;
        $data['user_pwd2'] = trim($param['user_pwd2']);
        $data['verify'] = $param['verify'];
        $is_from_3rdparty = !empty($param['user_openid_qq']) || !empty($param['user_openid_weixin']);


        if ($config['user']['status'] == 0 || $config['user']['reg_open'] == 0) {
            return ['code' => 1001, 'msg' => lang('model/user/not_open_reg')];
        }
        if (empty($data['user_name']) || empty($data['user_pwd']) || empty($data['user_pwd2'])) {
            return ['code' => 1002, 'msg' => lang('model/user/input_require')];
        }
        if (!$is_from_3rdparty && $config['user']['reg_verify'] == 1 && !captcha_check($data['verify'])) {
            return ['code' => 1003, 'msg' => lang('verify_err')];
        }
        if ($data['user_pwd'] !== $data['user_pwd2']) {
            return ['code' => 1004, 'msg' => lang('model/user/pass_not_pass2')];
        }
        if (strlen($password_raw) < 6 || strlen($password_raw) > 72
            || str_contains($param['user_pwd'], "\0") || str_contains($param['user_pwd2'], "\0")) {
            return ['code'=>1007, 'msg'=>lang('model/user/pass_length_err')];
        }
        if (strlen($data['user_name']) > 30) { return ['code'=>1006, 'msg'=>lang('model/user/name_contain')]; }
        try { $row = $this->where('user_name', $data['user_name'])->find(); }
        catch (\think\db\exception\DbException | \PDOException $error) { return ['code'=>1010, 'msg'=>lang('model/user/reg_err')]; }
        if (!empty($row)) {
            return ['code' => 1005, 'msg' => lang('model/user/haved_reg')];
        }
        if (!preg_match("/^[a-zA-Z\d]*$/i", $data['user_name'])) {
            return ['code' => 1006, 'msg' => lang('model/user/name_contain')];
        }

        $validate = mac_validate('User');
        $validate->scene('add')->rule('user_name', 'require|min:'.$minimumNameLength);
        if (!$validate->check($data)) {
            return ['code'=>1007, 'msg'=>lang('param_err').'：'.$validate->getError()];
        }
        if ($autoLogin && ($config['user']['login_verify'] ?? 0) == 1 && $config['user']['reg_verify'] == 0
            && !captcha_check($data['verify'])) { return ['code'=>1003, 'msg'=>lang('verify_err')]; }

        foreach (['reg_status', 'reg_phone_sms', 'reg_email_sms'] as $key) {
            if (!in_array($config['user'][$key] ?? null, [0, 1, '0', '1'], true)) {
                return ['code'=>1001, 'msg'=>lang('param_err')];
            }
        }
        foreach (['reg_points', 'reg_num', 'invite_reg_points', 'invite_reg_num'] as $key) {
            $value = array_key_exists($key, $config['user']) ? $config['user'][$key] : (str_starts_with($key, 'invite_reg_') ? 0 : null);
            $config['user'][$key] = \app\common\util\PointsBalance::amount($value, true);
            if ($config['user'][$key] === null) { return ['code'=>1001, 'msg'=>lang('param_err')]; }
        }
        $group = \app\common\util\PointsBalance::amount($this->_def_group, true);
        $filter = array_key_exists('filter_words', $config['user']) ? $config['user']['filter_words'] : '';
        if ($group === null || $group < 1 || $group > 32767 || !is_string($filter) || !mb_check_encoding($filter, 'UTF-8')) {
            return ['code'=>1001, 'msg'=>lang('param_err')];
        }
        if(!empty($filter)) {
            $filter_arr = explode(',', $filter);
            $f_name = str_replace($filter_arr, '', $data['user_name']);
            if ($f_name != $data['user_name']) {
                return ['code' => 1008, 'msg' =>lang('model/user/name_filter',[$filter])];
            }
        }

        $ip = \app\common\util\PointsBalance::amount(mac_get_ip_long(), true);
        $registeredAt = \app\common\util\PointsBalance::amount(time(), true);
        if ($ip === null || $registeredAt === null) { return ['code'=>1001, 'msg'=>lang('param_err')]; }
        if( $config['user']['reg_num'] > 0){
            $where2=[];
            $where2['user_reg_ip'] = $ip;
            $where2[] = ['user_reg_time', '>', strtotime('today')];
            try { $cc = $this->where($where2)->count(); }
            catch (\think\db\exception\DbException | \PDOException $error) { return ['code'=>1010, 'msg'=>lang('model/user/reg_err')]; }
            if($cc >= $config['user']['reg_num']){
                return ['code' => 1009, 'msg' => lang('model/user/ip_limit',[$config['user']['reg_num']])];
            }
        }

        $fields = ['user_name'=>$data['user_name'], 'group_id'=>(string)$group,
            'user_points'=>0, 'user_status'=>(int)$config['user']['reg_status'],
            'user_reg_time'=>$registeredAt, 'user_reg_ip'=>$ip,
            'user_openid_qq'=>$param['user_openid_qq'], 'user_openid_weixin'=>$param['user_openid_weixin']];
        $locks = [];
        $started = false;
        try {
            $tiers = \app\common\util\InvitationRewardPlan::tiers($config['user']);
            if (!$this->registrationTransactionsAvailable()) { throw new \RuntimeException('Registration requires transactional tables'); }
            $this->registrationGroups($tiers, $group);
            $fields['user_pwd'] = mac_password_hash($password_raw);
            $fields['user_random'] = bin2hex(random_bytes(16));
            $message = null;
            if (!$is_from_3rdparty && ($config['user']['reg_phone_sms'] || $config['user']['reg_email_sms'])) {
                $channel = $config['user']['reg_phone_sms'] ? 'phone' : 'email';
                $param['type'] = 3;
                $message = $this->messageParameters($param, true);
                if ($message === null || $message['ac'] !== $channel) { return ['code'=>9001, 'msg'=>lang('param_err')]; }
                $fields['user_'.$channel] = $message['to'];
            }
            // Every advisory lock precedes row locks. The pool serializes code allocation on legacy schemas.
            $locks[] = $this->acquireContactLock('registration-pool', 'codes');
            $locks[] = $this->acquireContactLock('registration-name', $fields['user_name']);
            if ($config['user']['reg_num'] > 0) { $locks[] = $this->acquireContactLock('registration-ip', (string)$ip); }
            foreach (['qq','weixin'] as $provider) {
                if ($fields['user_openid_'.$provider] !== '') {
                    $locks[] = $this->acquireContactLock('registration-'.$provider, $fields['user_openid_'.$provider]);
                }
            }
            if ($message !== null) { $locks[] = $this->acquireContactLock($message['ac'], $message['to']); }
            Db::startTrans();
            $started = true;
            $registeredAt = time();
            $fields['user_reg_time'] = $registeredAt;
            $unique = ['user_name'];
            if ($message !== null) { $unique[] = 'user_'.$message['ac']; }
            foreach (['user_openid_qq','user_openid_weixin'] as $field) { if ($fields[$field] !== '') { $unique[] = $field; } }
            foreach ($unique as $field) {
                if (Db::name('User')->master()->where($field, $fields[$field])->count() > 0) {
                    throw new \RuntimeException('Registration identity is already used');
                }
            }
            if ($config['user']['reg_num'] > 0 && Db::name('User')->master()->where('user_reg_ip', $ip)
                ->where('user_reg_time', '>=', strtotime('today'))->where('user_reg_time', '<', strtotime('tomorrow'))
                ->count() >= $config['user']['reg_num']) { throw new \RuntimeException('Registration address quota exceeded'); }
            if ($invite_code_param !== '') {
                $inviters = Db::name('User')->master()->where('user_invite_code', $invite_code_param)->limit(2)->column('user_id');
                if (count($inviters) !== 1) { throw new \RuntimeException('Invitation code is unavailable or ambiguous'); }
                $uid = (int)$inviters[0];
            }
            if ($uid > 0) {
                $inviter = Db::name('User')->where('user_id', $uid)->lock(true)->find();
                if (!$inviter || (int)$inviter['user_status'] !== 1) { throw new \RuntimeException('Inviter is unavailable'); }
                $ancestry = [$uid];
                foreach (['user_pid','user_pid_2'] as $field) {
                    $ancestor = \app\common\util\PointsBalance::amount($inviter[$field], true);
                    if ($ancestor === null || ($ancestor > 0 && (in_array($ancestor, $ancestry, true)
                        || !Db::name('User')->master()->where('user_id', $ancestor)->find()))) {
                        throw new \RuntimeException('Invalid referral ancestry');
                    }
                    if ($ancestor > 0) { $ancestry[] = $ancestor; }
                }
                $fields += ['user_pid'=>$uid, 'user_pid_2'=>(int)$inviter['user_pid'], 'user_pid_3'=>(int)$inviter['user_pid_2']];
            }
            if ($message !== null) {
                // Registration codes belong to a guest even if the request carries an existing login cookie.
                $verified = $this->checkMessageForUser($message, 0);
                if (($verified['code'] ?? null) !== 1 || Db::name('Msg')->where('msg_id', $verified['msg_id'])
                    ->where('msg_status', 0)->update(['msg_status'=>1]) !== 1) { throw new \RuntimeException('Registration code is unavailable'); }
                if ((int)Db::name('Msg')->master()->where('msg_id', $verified['msg_id'])->value('msg_status') !== 1) {
                    throw new \RuntimeException('Registration code was not consumed');
                }
            }
            // Bounded allocation fails closed rather than returning an unchecked fallback collision.
            $fields['user_invite_code'] = '';
            for ($attempt = 0; $attempt < 20; ++$attempt) {
                $candidate = strtoupper(bin2hex(random_bytes(5)));
                if (!Db::name('User')->master()->where('user_invite_code', $candidate)->count()) {
                    $fields['user_invite_code'] = $candidate; break;
                }
            }
            if ($fields['user_invite_code'] === '' || $this->insert($fields) !== 1) { throw new \RuntimeException('Registration insert failed'); }
            $nid = \app\common\util\PointsBalance::amount($this->getLastInsID());
            if ($nid === null) { throw new \RuntimeException('Registration id is invalid'); }
            $this->assertRegistrationFields($nid, $fields);
            $this->registrationCredit($nid, $config['user']['reg_points'], '注册赠分');
            if ($uid > 0) {
                $this->pendingRegistrationSourceId = $nid;
                $invitation = $this->addInviteCount($uid, $nid);
                if (($invitation['code'] ?? null) !== 1) { throw new \RuntimeException('Invitation registration failed'); }
            }
            $created = Db::name('User')->master()->where('user_id', $nid)->find();
            if ($autoLogin && (int)$created['user_status'] === 1) { $created = $this->writeAccountLogin($created); }
            $cookieGroup = $autoLogin && (int)$created['user_status'] === 1 ? $this->loginCookieGroup($created) : [];
            Db::commit();
            $started = false;
            if (!$autoLogin) { return ['code'=>1, 'msg'=>lang('model/user/reg_ok')]; }
            $result = ['code'=>1, 'msg'=>lang('model/user/reg_ok'), 'action'=>'register'];
            if ((int)$created['user_status'] !== 1) { $result['msg'] = '注册成功，请等待管理员审核'; return $result + ['pending_approval'=>1]; }
            $this->_setLoginCookie($created, $created['user_random'], $cookieGroup);
            return $result + ['info'=>$this->stripSensitiveFields($created)];
        } catch (\Throwable $error) {
            if ($started) { Db::rollback(); }
            return ['code'=>1010, 'msg'=>lang('model/user/reg_err')];
        } finally {
            $this->pendingRegistrationSourceId = null;
            foreach (array_reverse($locks) as $lock) { $this->releaseContactLock($lock); }
        }
    }

    private function registrationTransactionsAvailable(): bool
    {
        $type = Db::connect()->getConfig('type');
        if ($type === 'sqlite') { return true; }
        if ($type !== 'mysql') { return false; }
        $tables = [$this->getTable(), (new Msg())->getTable(), (new Plog())->getTable(), Db::name('Group')->getTable()];
        $rows = Db::query('SELECT TABLE_NAME AS name, ENGINE AS engine FROM information_schema.TABLES '
            .'WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME IN (?,?,?,?)', $tables, true);
        foreach ($rows as $row) {
            $index = array_search($row['name'], $tables, true);
            if ($index !== false && strtoupper((string)$row['engine']) === 'INNODB') { unset($tables[$index]); }
        }
        return $tables === [];
    }

    private function registrationGroups(array $tiers, ?int $defaultGroup = null): array
    {
        $ids = $defaultGroup === null ? [] : [$defaultGroup];
        foreach ($tiers as $tier) { if ($tier['group_id'] >= 2) { $ids[] = $tier['group_id']; } }
        $groups = [];
        foreach (array_unique($ids) as $id) {
            $row = Db::name('Group')->master()->where('group_id', $id)->find();
            if (!$row || (int)$row['group_status'] !== 1) { throw new \RuntimeException('Registration group is unavailable'); }
            $groups[$id] = $row;
        }
        return $groups;
    }

    /** Read back exact business values: non-strict legacy columns may silently clip successful writes. */
    private function assertRegistrationFields(int $userId, array $expected): void
    {
        $actual = Db::name('User')->master()->where('user_id', $userId)->find();
        foreach ($expected as $field=>$value) {
            if (!$actual || (string)$actual[$field] !== (string)$value) { throw new \RuntimeException('Registration state was not stored exactly'); }
        }
    }

    private function registrationCredit(int $userId, int $points, string $remarks): void
    {
        $balance = \app\common\util\PointsBalance::amount(Db::name('User')->master()->where('user_id', $userId)->value('user_points'), true);
        if ($balance === null || $points > \app\common\util\PointsBalance::MAX - $balance
            || ($points > 0 && !\app\common\util\PointsBalance::credit($userId, $points))) {
            throw new \RuntimeException('Registration credit failed');
        }
        $this->assertRegistrationFields($userId, ['user_points'=>$balance + $points]);
        $ledger = new Plog();
        $expected = ['user_id'=>$userId, 'plog_type'=>2, 'plog_points'=>$points, 'plog_remarks'=>$remarks];
        $result = $ledger->saveData($expected);
        if (($result['code'] ?? null) !== 1) { throw new \RuntimeException('Registration ledger failed'); }
        $stored = Db::name('Plog')->master()->where('plog_id', $ledger->getLastInsID())->find();
        foreach ($expected as $field=>$value) {
            if (!$stored || (string)$stored[$field] !== (string)$value) { throw new \RuntimeException('Registration ledger was not stored exactly'); }
        }
    }

    public function regcheck($t, $str)
    {
        $where = [];
        if ($t == 'user_name') {
            $where['user_name'] = $str;
            $row = $this->where($where)->find();
            if (!empty($row)) {
                return ['code' => 1001, 'msg' => lang('registered')];
            }
        } elseif ($t == 'user_email') {
            $where['user_email'] = $str;
            $row = $this->where($where)->find();
            if (!empty($row)) {
                return ['code' => 1001, 'msg' =>  lang('registered')];
            }
        } elseif ($t == 'verify') {
            if (!captcha_check((string)($str ?? ''))) {
                return ['code' => 1002, 'msg' => lang('verify_err')];
            }
        }
        return ['code' => 1, 'msg' => 'ok'];
    }

    /** Password replacement always changes the hash and invalidates existing sessions together. */
    private function passwordCredentials($value): ?array
    {
        if (!is_string($value)) { return null; }
        $password = trim($value);
        if (strlen($password) < 6 || strlen($password) > 72 || str_contains($password, "\0")) {
            return null;
        }
        return ['user_pwd'=>mac_password_hash($password), 'user_random'=>bin2hex(random_bytes(16))];
    }

    /** Only legacy MD5 rows may use the historical request-format transformation. */
    private function passwordMatches(string $password, string $hash): bool
    {
        if (mac_password_verify($password, $hash)) { return true; }
        return strlen($hash) === 32 && ctype_xdigit($hash)
            && mac_password_verify(htmlspecialchars(urldecode($password)), $hash);
    }

    /** Shared by the authenticated frontend and API profile forms. */
    public function updateAccountProfile($userId, array $profile, $oldPassword = null, $newPassword = null): array
    {
        if ((!is_int($userId) && !is_string($userId)) || !preg_match('/^[1-9][0-9]{0,9}$/D', (string)$userId)
            || (int)$userId > 4294967295) {
            return ['code'=>1002, 'msg'=>lang('model/user/not_login')];
        }
        if (array_key_exists('user_email', $profile) || array_key_exists('user_phone', $profile)) {
            return ['code'=>1001, 'msg'=>'请通过联系方式绑定页面验证邮箱或手机'];
        }
        $lengths = ['user_nick_name'=>30, 'user_qq'=>16, 'user_question'=>255, 'user_answer'=>255];
        $profile = array_intersect_key($profile, $lengths);
        foreach ($profile as $field=>$value) {
            if (!is_string($value) || !mb_check_encoding($value, 'UTF-8') || mb_strlen($value, 'UTF-8') > $lengths[$field]) {
                return ['code'=>1001, 'msg'=>lang('param_err')];
            }
        }
        $changePassword = $oldPassword !== null || $newPassword !== null;
        if ($changePassword && (!is_string($oldPassword) || !is_string($newPassword) || trim($oldPassword) === '')) {
            return ['code'=>1001, 'msg'=>lang('model/user/input_old_pass')];
        }
        try {
            $current = Db::name('User')->where('user_id', (int)$userId)->field('user_pwd')->find();
            if (!$current) { return ['code'=>1002, 'msg'=>lang('model/user/not_login')]; }
            $where = ['user_id'=>(int)$userId];
            if ($changePassword) {
                if (!$this->passwordMatches(trim($oldPassword), $current['user_pwd'])) {
                    return ['code'=>1012, 'msg'=>lang('model/user/old_pass_err')];
                }
                $credentials = $this->passwordCredentials($newPassword);
                if ($credentials === null) { return ['code'=>1003, 'msg'=>lang('model/user/pass_length_err')]; }
                $profile = array_replace($profile, $credentials);
                // A concurrent password change must not be overwritten using an already checked old hash.
                $where['user_pwd'] = $current['user_pwd'];
            }
            if ($profile === []) { return ['code'=>1001, 'msg'=>lang('api/no_update_needed')]; }
            $affected = Db::name('User')->where($where)->update($profile);
            if ($affected === false || ($changePassword && $affected !== 1)) {
                return ['code'=>1003, 'msg'=>lang('update_err')];
            }
            return ['code'=>1, 'msg'=>lang('update_ok')];
        } catch (\Throwable $error) {
            return ['code'=>1003, 'msg'=>lang('update_err')];
        }
    }

    public function info($param)
    {
        if (!is_array($param)) { return ['code'=>1001, 'msg'=>lang('param_err')]; }
        foreach (['user_pwd', 'user_pwd1', 'user_pwd2', 'user_nick_name', 'user_qq', 'user_question', 'user_answer'] as $field) {
            if (array_key_exists($field, $param) && !is_string($param[$field]) && !is_int($param[$field])) {
                return ['code'=>1001, 'msg'=>lang('param_err')];
            }
        }
        $old = trim((string)($param['user_pwd'] ?? ''));
        $first = trim((string)($param['user_pwd1'] ?? ''));
        $second = trim((string)($param['user_pwd2'] ?? ''));
        $changePassword = $old !== '' || $first !== '' || $second !== '';
        if ($changePassword && ($first === '' || $second === '')) {
            return ['code'=>1003, 'msg'=>lang('model/user/input_require')];
        }
        if ($changePassword && $first !== $second) {
            return ['code'=>1004, 'msg'=>lang('model/user/pass_not_same_pass2')];
        }
        $profile = [];
        foreach (['user_nick_name', 'user_qq', 'user_question', 'user_answer'] as $field) {
            if (array_key_exists($field, $param)) {
                $value = urldecode(trim((string)$param[$field]));
                if (!mb_check_encoding($value, 'UTF-8')) { return ['code'=>1001, 'msg'=>lang('param_err')]; }
                $profile[$field] = htmlspecialchars($value);
            }
        }
        $result = $this->updateAccountProfile($GLOBALS['user']['user_id'] ?? null, $profile,
            $changePassword ? $old : null, $changePassword ? $first : null);
        if ($result['code'] === 1012) { $result['code'] = 1002; }
        return $result;
    }

    /**
     * 登录注册一体化：帐号存在则校验密码登录，不存在则自动注册并登录
     * @param array $param [user_name, user_pwd, invite_code(可选)]
     * @return array
     */
    public function loginOrRegister($param)
    {
        if (!is_array($param)) { return ['code'=>1001, 'msg'=>lang('param_err')]; }
        foreach (['user_name','user_pwd','verify','invite_code'] as $field) {
            if (array_key_exists($field, $param) && !is_string($param[$field])) { return ['code'=>1001, 'msg'=>lang('param_err')]; }
            $param[$field] = $param[$field] ?? '';
        }
        $configuration = config('maccms')['user'] ?? null;
        if (!is_array($configuration)) { return ['code'=>1001, 'msg'=>lang('param_err')]; }
        foreach (['status','reg_open','reg_verify','reg_phone_sms','reg_email_sms'] as $field) {
            if (!in_array($configuration[$field] ?? null, [0,1,'0','1'], true)) { return ['code'=>1001, 'msg'=>lang('param_err')]; }
        }
        if (!in_array(array_key_exists('login_verify', $configuration) ? $configuration['login_verify'] : 0, [0,1,'0','1'], true)) { return ['code'=>1001, 'msg'=>lang('param_err')]; }
        if ((int)$configuration['status'] !== 1) { return ['code'=>1005, 'msg'=>lang('model/user/user_feature_closed')]; }
        if (!mb_check_encoding($param['user_name'], 'UTF-8') || str_contains($param['user_name'], "\0")
            || strlen($param['user_name']) > 1024 || strlen($param['user_pwd']) > 4096) { return ['code'=>1001, 'msg'=>lang('param_err')]; }
        $name = htmlspecialchars(urldecode(trim($param['user_name'])));
        try {
            $existing = $this->where('user_name', $name)->find();
            if ($existing) {
                $result = $this->login($param, ['return_info'=>true, 'identity_field'=>'user_name']);
                return ($result['code'] ?? null) === 1 ? $result + ['action'=>'login'] : $result;
            }
            if ((int)$configuration['reg_open'] !== 1) { return ['code'=>1001, 'msg'=>lang('model/user/not_open_reg')]; }
            if (!preg_match('/^[A-Za-z0-9]{3,30}$/D', $name)) { return ['code'=>1006, 'msg'=>lang('model/user/name_alnum_3_30')]; }
            if ($configuration['reg_verify'] || $configuration['reg_phone_sms'] || $configuration['reg_email_sms']) {
                return ['code'=>1013, 'msg'=>'请前往注册页面完成验证', 'registration_required'=>1];
            }
            // This one-password UI intentionally confirms its own original bytes; no external OAuth exemption.
            $param['user_pwd2'] = $param['user_pwd'];
            return $this->createAccount($param, false, 3, true);
        } catch (\Throwable $error) { return ['code'=>1010, 'msg'=>lang('model/user/reg_err')]; }
    }

    /**
     * 设置登录 Cookie（loginOrRegister / login 共用）
     */
    private function loginCookieGroup(array $row): array
    {
        $groups = (new \app\common\model\Group())->getCache('group_list');
        if (!is_array($groups)) { throw new \RuntimeException('Login membership metadata is unavailable'); }
        foreach (explode(',', $row['group_id']) as $id) {
            if (isset($groups[$id]) && isset($groups[$id]['group_id'], $groups[$id]['group_name'])) { return $groups[$id]; }
        }
        throw new \RuntimeException('Login membership metadata is unavailable');
    }

    private function _setLoginCookie(array $row, string $random, array $group): void
    {
        // user_id / user_name 是展示型标识(非凭据),前台主题的 JS 会读它们来决定
        // 显示「登录」还是用户名(例:template/default/asset/js/foot-expand.js 的
        // $.cookie("user_id")),所以单独放开 HttpOnly;真正的登录令牌 user_check
        // 沿用 config/cookie.php 的 httponly=true,JS 读不到。
        cookie('user_id', $row['user_id'], ['expire' => 2592000, 'httponly' => false]);
        cookie('user_name', $row['user_name'], ['expire' => 2592000, 'httponly' => false]);
        cookie('group_id', !empty($group['group_id']) ? $group['group_id'] : $this->_def_group, ['expire' => 2592000]);
        cookie('group_name', !empty($group['group_name']) ? $group['group_name'] : '', ['expire' => 2592000]);
        cookie('user_check', md5($random . '-' . $row['user_name'] . '-' . $row['user_id'] . '-'), ['expire' => 2592000]);
        cookie('user_portrait', mac_get_user_portrait($row['user_id']), ['expire' => 2592000]);
    }

    public function login($param, array $options = [])
    {
        if (!is_array($param)) { return ['code'=>1001, 'msg'=>lang('param_err')]; }
        $userConfiguration = $GLOBALS['config']['user'] ?? [];
        if (!is_array($userConfiguration)) { return ['code'=>1001, 'msg'=>lang('param_err')]; }
        $enabled = array_key_exists('status', $userConfiguration) ? $userConfiguration['status'] : 1;
        if (!in_array($enabled, [0,1,'0','1'], true)) { return ['code'=>1001, 'msg'=>lang('param_err')]; }
        if ((int)$enabled !== 1) { return ['code'=>1005, 'msg'=>lang('model/user/user_feature_closed')]; }
        foreach (['user_name','user_pwd','verify','openid','col'] as $field) {
            if (array_key_exists($field, $param) && !is_string($param[$field])) { return ['code'=>1001, 'msg'=>lang('param_err')]; }
            $param[$field] = $param[$field] ?? '';
        }
        if (($options['trusted_oauth'] ?? false) !== true) { $param['openid'] = $param['col'] = ''; }
        if (!mac_fe_write_throttle('fe_login', 120, 20)) { return ['code'=>1429, 'msg'=>lang('frequently')]; }
        $password = trim($param['user_pwd']);
        if (strlen($param['user_name']) > 1024 || strlen($param['user_pwd']) > 4096 || strlen($param['verify']) > 255
            || !mb_check_encoding($param['user_name'], 'UTF-8') || str_contains($param['user_name'], "\0")
            || str_contains($param['user_pwd'], "\0")) { return ['code'=>1001, 'msg'=>lang('param_err')]; }
        $name = htmlspecialchars(urldecode(trim($param['user_name'])));
        $oauth = $param['openid'] !== '';
        $where = ['user_status'=>1];
        if ($oauth) {
            if (!in_array($param['col'], ['user_openid_qq','user_openid_weixin'], true) || strlen($param['openid']) > 40
                || !mb_check_encoding($param['openid'], 'UTF-8') || str_contains($param['openid'], "\0")) { return ['code'=>1001, 'msg'=>lang('param_err')]; }
            $where[$param['col']] = $param['openid'];
        } else {
            if ($name === '' || $password === '') { return ['code'=>1001, 'msg'=>lang('model/user/input_require')]; }
            $verify = array_key_exists('login_verify', $userConfiguration) ? $userConfiguration['login_verify'] : 0;
            if (!in_array($verify, [0,1,'0','1'], true)) { return ['code'=>1001, 'msg'=>lang('param_err')]; }
            if ((int)$verify === 1 && !captcha_check($param['verify'])) { return ['code'=>1002, 'msg'=>lang('verify_err')]; }
            $identity = $options['identity_field'] ?? (filter_var($name, FILTER_VALIDATE_EMAIL) !== false ? 'user_email' : 'user_name');
            if (!in_array($identity, ['user_name','user_email','user_phone'], true)) { return ['code'=>1001, 'msg'=>lang('param_err')]; }
            $where[$identity] = $name;
        }
        $started = false;
        try {
            // Resolve via the normal model boundary first; duplicate identities are rejected below under locks.
            if (!$this->where($where)->find()) { return ['code'=>1003, 'msg'=>lang('model/user/not_found')]; }
            if (!$this->accountTransactionsAvailable()) { throw new \RuntimeException('Transactional account table required'); }
            Db::startTrans(); $started = true;
            $rows = Db::name('User')->where($where)->limit(2)->lock(true)->select()->toArray();
            if (count($rows) !== 1) { throw new \RuntimeException('Login identity is unavailable or ambiguous'); }
            $row = $rows[0];
            $hash = null;
            if (!$oauth) {
                $legacy = strlen($row['user_pwd']) === 32 && ctype_xdigit($row['user_pwd']);
                if ((!$legacy && strlen($password) > 72) || !$this->passwordMatches($password, $row['user_pwd'])) {
                    Db::rollback(); $started = false;
                    return ['code'=>1003, 'msg'=>lang('model/user/not_found')];
                }
                // Preserve unusually long legacy MD5 passwords until an explicit password change; bcrypt truncates after 72 bytes.
                if (strlen($password) <= 72 && mac_password_need_rehash($row['user_pwd'])) { $hash = mac_password_hash($password); }
            }
            $row = $this->writeAccountLogin($row, $hash);
            $cookieGroup = ($options['set_cookie'] ?? true) !== false ? $this->loginCookieGroup($row) : [];
            Db::commit(); $started = false;
            if (($options['set_cookie'] ?? true) !== false) { $this->_setLoginCookie($row, $row['user_random'], $cookieGroup); }
            $out = ['code'=>1, 'msg'=>lang('model/user/login_ok')];
            if (!empty($options['return_meta'])) {
                $out['meta'] = ['user_id'=>(int)$row['user_id'], 'user_name'=>$row['user_name'], 'user_random'=>$row['user_random']];
            }
            if (!empty($options['return_info'])) { $out['info'] = $this->stripSensitiveFields($row); }
            return $out;
        } catch (\Throwable $error) {
            if ($started) { Db::rollback(); }
            return ['code'=>1004, 'msg'=>lang('model/user/update_login_err')];
        }
    }

    private function accountTransactionsAvailable(): bool
    {
        $type = Db::connect()->getConfig('type');
        if ($type === 'sqlite') { return true; }
        if ($type !== 'mysql') { return false; }
        $rows = Db::query('SELECT ENGINE AS engine FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=?', [$this->getTable()], true);
        return count($rows) === 1 && strtoupper((string)$rows[0]['engine']) === 'INNODB';
    }

    /** Caller owns the User row lock and transaction; password and session rotate in one exact UPDATE. */
    private function writeAccountLogin(array $row, ?string $hash = null): array
    {
        $userId = \app\common\util\PointsBalance::amount($row['user_id'] ?? null);
        $ip = \app\common\util\PointsBalance::amount(mac_get_ip_long(), true);
        $now = \app\common\util\PointsBalance::amount(time());
        $count = \app\common\util\PointsBalance::amount($row['user_login_num'] ?? null, true);
        $lastTime = \app\common\util\PointsBalance::amount($row['user_login_time'] ?? null, true);
        $lastIp = \app\common\util\PointsBalance::amount($row['user_login_ip'] ?? null, true);
        $end = \app\common\util\PointsBalance::amount($row['user_end_time'] ?? null, true);
        if ($userId === null || $ip === null || $now === null || $count === null || $count === \app\common\util\PointsBalance::MAX
            || $lastTime === null || $lastIp === null || $end === null || !is_string($row['group_id'] ?? null)
            || !preg_match('/^[0-9]+(?:,[0-9]+)*$/D', $row['group_id'])) { throw new \RuntimeException('Invalid login state'); }
        $groups = explode(',', $row['group_id']);
        foreach ($groups as $group) {
            $id = \app\common\util\PointsBalance::amount($group);
            if ($id === null || $id > 32767) { throw new \RuntimeException('Invalid login group'); }
        }
        $fields = ['user_random'=>bin2hex(random_bytes(16)), 'user_login_ip'=>$ip, 'user_login_time'=>$now,
            'user_login_num'=>$count + 1, 'user_last_login_time'=>$lastTime, 'user_last_login_ip'=>$lastIp];
        if (max($groups) > 2 && $end < $now) { $fields['group_id'] = '2'; }
        if ($hash !== null) { $fields['user_pwd'] = $hash; }
        if (Db::name('User')->where('user_id', $userId)->update($fields) !== 1) { throw new \RuntimeException('Login write failed'); }
        $this->assertRegistrationFields($userId, $fields);
        return array_replace($row, $fields);
    }

    public function expire()
    {
        $where=[];
        // 只处理VIP会员组（group_id > 2）且 user_end_time 已过期（排除 user_end_time=0 的普通用户）
        $where[] = ['group_id', '>', 2];
        $where[] = ['user_end_time', 'between', [1, time()]];

        $update=[];
        $update['group_id'] = '2';

        $res = $this->where($where)->update($update);
        if ($res < 1) {
            return ['code' => 101, 'msg' => lang('model/user/update_expire_err')];
        }
        return ['code' => 1, 'msg' => lang('model/user/update_expire_ok')];
    }

    public function logout()
    {
        cookie('user_id', null);
        cookie('user_name', null);
        cookie('group_id', null);
        cookie('group_name', null);
        cookie('user_check', null);
        cookie('user_portrait', null);
        return ['code' => 1, 'msg' =>lang('model/user/logout_ok')];
    }

    public function checkLogin(bool $persistExpiredGroup = true)
    {
        $jwt = JwtService::bearerFromRequest();
        if ($jwt !== '' && JwtService::isEnabled()) {
            $pl = JwtService::decodeAndVerify($jwt);
            if (!is_array($pl)) {
                return ['code' => 1003, 'msg' => lang('model/user/not_login')];
            }
            $uid = (int)($pl['sub'] ?? 0);
            $rnd = (string)($pl['rnd'] ?? '');
            if ($uid < 1 || $rnd === '') {
                return ['code' => 1003, 'msg' => lang('model/user/not_login')];
            }
            $whereJwt = ['user_id' => $uid, 'user_status' => 1];
            $rowJwt = $this->field('*')->where($whereJwt)->find();
            if (empty($rowJwt)) {
                return ['code' => 1002, 'msg' => lang('model/user/not_login')];
            }
            $info = $rowJwt->toArray();
            if (!isset($info['user_random']) || !hash_equals((string)$info['user_random'], $rnd)) {
                return ['code' => 1003, 'msg' => lang('model/user/not_login')];
            }

            return $this->finalizeUserLoginPayload($info, $whereJwt, $persistExpiredGroup);
        }

        $user_id = cookie('user_id');
        $user_name = cookie('user_name');
        $user_check = cookie('user_check');

        // Cookies may be absent or parsed as arrays. Reject malformed credentials before string operations.
        if ((!is_string($user_id) && !is_int($user_id)) || !is_string($user_name) || !is_string($user_check)
            || strlen((string)$user_id) > 128 || strlen($user_name) > 1024 || strlen($user_check) > 256) {
            return ['code' => 1001, 'msg' => lang('model/user/not_login')];
        }
        $user_id = \app\common\util\PointsBalance::amount(urldecode(trim((string)$user_id)));
        $user_name = htmlspecialchars(urldecode(trim($user_name)));
        $user_check = urldecode(trim($user_check));

        if ($user_id === null || $user_name === '' || !preg_match('/^[a-f0-9]{32}$/D', $user_check)) {
            return ['code' => 1001, 'msg' => lang('model/user/not_login')];
        }

        $where = [];
        $where['user_id'] = $user_id;
        $where['user_name'] = $user_name;
        $where['user_status'] = 1;

        $info = $this->field('*')->where($where)->find();
        if(empty($info)) {
            return ['code' => 1002, 'msg' => lang('model/user/not_login')];
        }
        $info = $info->toArray();
        $login_check = md5($info['user_random'] . '-' . $info['user_name']. '-' . $info['user_id'] .'-' );
        // 安全加固:登录态 cookie 校验改用常量时间比较(与上方 JWT 分支的 hash_equals 一致),
        // 杜绝对 user_check 的计时侧信道伪造;功能等价,零回归。
        if(!hash_equals($login_check, (string)$user_check)) {
            return ['code' => 1003, 'msg' => lang('model/user/not_login')];
        }

        return $this->finalizeUserLoginPayload($info, $where, $persistExpiredGroup);
    }

    /**
     * 组装已校验用户（Cookie 或 JWT）的会员组与过期处理。
     *
     * @param array $info        用户行
     * @param array $whereUpdate VIP 过期等更新时用于 where()
     *
     * @return array
     */
    private function finalizeUserLoginPayload(array $info, array $whereUpdate, bool $persistExpiredGroup = true)
    {
        $group_list = (new \app\common\model\Group())->getCache('group_list');
        $group_ids = explode(',', $info['group_id']);
        $user_groups = [];
        $user_group_types = [];
        foreach($group_ids as $gid){
            if(isset($group_list[$gid])){
                $user_groups[] = $group_list[$gid];
                if (!empty($group_list[$gid]['group_type'])) {
                    $user_group_types = array_merge($user_group_types, explode(',', $group_list[$gid]['group_type']));
                }
            }
        }

        if (!empty($user_groups)) {
            $info['group'] = $user_groups[0];
            $info['group']['group_type'] = implode(',', array_unique(array_filter($user_group_types)));
            $info['groups'] = $user_groups;

            $all_names = [];
            foreach($user_groups as $g){
                $all_names[] = $g['group_name'];
            }
            $info['group']['group_name'] = implode(',', $all_names);

        } else {
            $info['group'] = $group_list[1];
        }

        //会员截止日期
        if (max($group_ids) > 2 && $info['user_end_time'] < time()) {
            //用户组
            $info['group'] = $group_list[2];

            $update = [];
            $update['group_id'] = 2;

            if ($persistExpiredGroup) {
                $res = $this->where($whereUpdate)->update($update);
                if ($res < 1) {
                    return ['code' => 1004, 'msg' => lang('model/user/update_expire_err')];
                }
            }

            $info['group_id'] = 2;
            $info['groups'] = [$group_list[2]];
            if ($persistExpiredGroup) {
                cookie('group_id', $info['group']['group_id'], ['expire'=>2592000] );
                cookie('group_name', $info['group']['group_name'],['expire'=>2592000] );
            }
        }

        return ['code' => 1, 'msg' => lang('model/user/haved_login'), 'info' => $info];
    }

    public function resetPwd()
    {

    }

    public function findpass($param)
    {
        if (!is_array($param)) { return ['code'=>1001, 'msg'=>lang('param_err')]; }
        foreach (['user_name', 'user_question', 'user_answer', 'user_pwd', 'user_pwd2', 'verify'] as $field) {
            if (!is_string($param[$field] ?? null) || trim($param[$field]) === '') {
                return ['code'=>1001, 'msg'=>lang('param_err')];
            }
        }
        if (!captcha_check($param['verify'])) { return ['code'=>1002, 'msg'=>lang('verify_err')]; }
        if (trim($param['user_pwd']) !== trim($param['user_pwd2'])) {
            return ['code'=>1003, 'msg'=>lang('model/user/pass_not_same_pass2')];
        }
        $where = [];
        foreach (['user_name', 'user_question', 'user_answer'] as $field) {
            $where[$field] = htmlspecialchars(urldecode(trim($param[$field])));
        }
        try {
            $users = Db::name('User')->where($where)->limit(2)->select()->toArray();
            if (count($users) !== 1) { return ['code'=>1004, 'msg'=>lang('model/user/findpass_not_found')]; }
            $credentials = $this->passwordCredentials($param['user_pwd']);
            if ($credentials === null) { return ['code'=>1001, 'msg'=>lang('model/user/pass_length_err')]; }
            $where['user_id'] = $users[0]['user_id'];
            $where['user_pwd'] = $users[0]['user_pwd'];
            if (Db::name('User')->where($where)->update($credentials) !== 1) {
                return ['code'=>1005, 'msg'=>lang('model/user/pass_reset_err')];
            }
            return ['code'=>1, 'msg'=>lang('model/user/findpass_ok')];
        } catch (\Throwable $error) {
            return ['code'=>1005, 'msg'=>lang('model/user/pass_reset_err')];
        }
    }

    public function popedom($type_id, $popedom, $group_ids = 1)
    {
        $group_list = (new \app\common\model\Group())->getCache();
        $group_ids = explode(',', $group_ids);
        
        foreach($group_ids as $group_id) {
            if(!isset($group_list[$group_id])) {
                continue;
            }
            $group_info = $group_list[$group_id];
            
            if (strpos(',' . $group_info['group_type'], ',' . $type_id . ',') !== false && !empty($group_info['group_popedom'][$type_id][$popedom]) !== false) {
                return true;
            }
        }
        return false;
    }

    public function upgrade($param)
    {
        $group_id = self::membershipInteger($param['group_id'] ?? null);
        $long = $param['long'] ?? null;
        $points_long = ['day'=>86400,'week'=>86400*7,'month'=>86400*30,'year'=>86400*365];
        if (!is_string($long) || !isset($points_long[$long]) || $group_id === null || $group_id < 3) {
            return ['code'=>1001,'msg'=>lang('model/user/upgrade_param_invalid')];
        }
        $group_list = (new \app\common\model\Group())->getCache();
        $group_info = $group_list[$group_id] ?? [];
        if (!$group_info || (int)($group_info['group_status'] ?? 0) !== 1) {
            return ['code'=>1003,'msg'=>lang('model/user/group_not_found')];
        }
        // The default upgrade UI explicitly offers configured zero-point plans as free.
        $point = self::membershipInteger($group_info['group_points_' . $long] ?? null, true);
        $user_id = self::membershipInteger($GLOBALS['user']['user_id'] ?? null);
        if ($point === null || $user_id === null) {
            return ['code'=>1001,'msg'=>lang('model/user/upgrade_param_invalid')];
        }
        $result = $this->applyMembershipUpgrade($user_id, $group_id, $point, $points_long[$long]);
        if ($result['code'] !== 1) {
            return $result;
        }
        cookie('group_id', $group_id, ['expire'=>2592000]);
        cookie('group_name', $group_info['group_name'] ?? '', ['expire'=>2592000]);
        return $result;
    }

    /** Internal payment step; Order::notify owns payment-order idempotency. */
    public function upgradeByPaidOrder($order, $user)
    {
        $remarks = json_decode((string)($order['order_remarks'] ?? ''), true);
        if (!is_array($remarks) || ($remarks['biz'] ?? '') !== 'member_upgrade') {
            return ['code'=>1001,'msg'=>lang('model/user/order_not_member_upgrade')];
        }
        $group_id = self::membershipInteger($remarks['group_id'] ?? null);
        $point = self::membershipInteger($remarks['upgrade_points'] ?? null);
        $user_id = self::membershipInteger($user['user_id'] ?? null);
        $long = $remarks['long'] ?? null;
        $points_long = ['day'=>86400,'week'=>86400*7,'month'=>86400*30,'year'=>86400*365];
        if ($group_id === null || $group_id < 3 || $point === null || $user_id === null
            || !is_string($long) || !isset($points_long[$long])
            || (int)($order['user_id'] ?? 0) !== $user_id) {
            return ['code'=>1002,'msg'=>lang('model/user/upgrade_param_invalid')];
        }
        $group_list = (new \app\common\model\Group())->getCache();
        $group_info = $group_list[$group_id] ?? [];
        if (!$group_info || (int)($group_info['group_status'] ?? 0) !== 1) {
            return ['code'=>1003,'msg'=>lang('model/user/group_not_found')];
        }
        $result = $this->applyMembershipUpgrade($user_id, $group_id, $point, $points_long[$long],
            '支付后自动升级会员：' . ($group_info['group_name'] ?? ''));
        if ($result['code'] !== 1) {
            return $result;
        }
        cookie('group_id', $group_id, ['expire'=>2592000]);
        cookie('group_name', $group_info['group_name'] ?? '', ['expire'=>2592000]);
        return $result;
    }

    private static function membershipInteger($value, bool $allowZero = false): ?int
    {
        if ((!is_int($value) && !is_string($value)) || !preg_match('/^[0-9]{1,10}$/D', (string)$value)
            || (int)$value < ($allowZero ? 0 : 1) || (int)$value > 4294967295) {
            return null;
        }
        return (int)$value;
    }

    /** Deduction, membership and every associated ledger entry share one transaction. */
    private function applyMembershipUpgrade(int $user_id, int $group_id, int $point, int $seconds, string $remark = ''): array
    {
        Db::startTrans();
        try {
            $current = $this->where('user_id', $user_id)->lock(true)->find();
            if (!$current || (int)$current['user_points'] < $point) {
                Db::rollback();
                return ['code'=>1005,'msg'=>lang('model/user/potins_not_enough')];
            }
            $end_time = max(time(), (int)($current['user_end_time'] ?? 0)) + $seconds;
            if ($point > 0) {
                $affected = $this->where('user_id', $user_id)->where('user_points', '>=', $point)
                    ->setDec('user_points', $point);
                if ($affected !== 1) {
                    Db::rollback();
                    return ['code'=>1005,'msg'=>lang('model/user/potins_not_enough')];
                }
            }
            $updated = $this->where('user_id', $user_id)->update(['user_end_time'=>$end_time, 'group_id'=>$group_id]);
            if ($updated !== 1) {
                throw new \RuntimeException('membership update failed');
            }
            $log = (new \app\common\model\Plog())->saveData([
                'user_id'=>$user_id, 'plog_type'=>7, 'plog_points'=>$point, 'plog_remarks'=>$remark,
            ]);
            if (($log['code'] ?? null) !== 1) {
                throw new \RuntimeException('membership ledger failed');
            }
            $this->reward($point, $user_id);
            Db::commit();
            return ['code'=>1,'msg'=>lang('model/user/update_group_ok')];
        } catch (\Throwable $e) {
            Db::rollback();
            return ['code'=>1009,'msg'=>lang('model/user/update_group_err')];
        }
    }

    /** Match the same decoded HTTP text that is stored and later used for the account. */
    private function messageParameters($param, bool $requireCode): ?array
    {
        if (!is_array($param)) { return null; }
        foreach (['ac', 'to'] as $key) {
            if (!is_string($param[$key] ?? null)) { return null; }
            $param[$key] = trim($param[$key]);
        }
        if (!in_array($param['type'] ?? null, [1, 2, 3, '1', '2', '3'], true)
            || !in_array($param['ac'], ['email', 'phone'], true)
            || $param['to'] === '' || strlen($param['to']) > 30) { return null; }
        $param['type'] = (int)$param['type'];
        if ($param['ac'] === 'email') {
            if (filter_var($param['to'], FILTER_VALIDATE_EMAIL) === false) { return null; }
        } elseif (preg_match('/^1[0-9]{10}$/D', $param['to']) !== 1) { return null; }
        if ($requireCode) {
            if (!is_string($param['code'] ?? null)) { return null; }
            $param['code'] = trim($param['code']);
            if (preg_match('/^[0-9]{6}$/D', $param['code']) !== 1) { return null; }
        }
        return $param;
    }

    private function messageCutoff(string $channel): int
    {
        $minutes = filter_var($GLOBALS['config']['email']['time'] ?? 5, FILTER_VALIDATE_INT,
            ['options'=>['min_range'=>1, 'max_range'=>1440]]);
        return time() - 60 * ($channel === 'email' && $minutes !== false ? $minutes : 5);
    }

    public function check_msg($param)
    {
        return $this->checkMessageForUser($param, (int)($GLOBALS['user']['user_id'] ?? 0));
    }

    private function checkMessageForUser($param, int $userId)
    {
        $param = $this->messageParameters($param, true);
        if ($param === null) { return ['code'=>9001, 'msg'=>lang('param_err')]; }
        if ($param['ac'] === 'email' && in_array($param['type'], [1, 3], true)) {
            $result = UserValidate::validateEmail($param['to']);
            if ($result['code'] > 1) { return $result; }
        }
        $where = [
            'user_id'=>$userId,
            'msg_to'=>$param['to'], 'msg_code'=>$param['code'],
            'msg_type'=>$param['type'], 'msg_status'=>0,
            ['msg_time', '>', $this->messageCutoff($param['ac'])],
            ['msg_time', '<=', time()],
        ];
        try { $res = (new Msg())->infoData($where); }
        catch (\Throwable $error) { return ['code'=>9002, 'msg'=>lang('model/user/msg_not_found')]; }
        if (($res['code'] ?? null) !== 1) {
            return ['code'=>9002, 'msg'=>lang('model/user/msg_not_found')];
        }
        return ['code'=>1, 'msg'=>'ok', 'msg_id'=>(int)$res['info']['msg_id'], 'to'=>$param['to']];
    }

    public function send_msg($param)
    {
        return $this->sendMessageForUser($param, (int)($GLOBALS['user']['user_id'] ?? 0),
            (string)($GLOBALS['user']['user_name'] ?? ''));
    }

    private function sendMessageForUser($param, int $userId, string $userName)
    {
        $param = $this->messageParameters($param, false);
        if ($param === null) { return ['code'=>9001, 'msg'=>lang('param_err')]; }
        if (!mac_fe_write_throttle('fe_sendmsg', 300, 8)) {
            return ['code'=>9002, 'msg'=>lang('model/user/do_not_send_frequently')];
        }
        if ($param['ac'] === 'email' && in_array($param['type'], [1, 3], true)) {
            $result = UserValidate::validateEmail($param['to']);
            if ($result['code'] > 1) { return $result; }
        }
        $types = [1=>['bind', 'bind'], 2=>['findpass', 'findpass'], 3=>['register', 'reg']];
        [$description, $flag] = $types[$param['type']];
        $description = lang($description);
        $where = ['user_id'=>$userId,
            'msg_type'=>$param['type'], 'msg_to'=>$param['to'],
            ['msg_time', '>', $this->messageCutoff($param['ac'])]];
        try {
            $existing = (new Msg())->infoData($where);
            if (($existing['code'] ?? null) === 1) {
                return ['code'=>9002, 'msg'=>lang('model/user/do_not_send_frequently')];
            }
            $code = (string)random_int(100000, 999999);
            if ($param['ac'] === 'email') {
                $templates = $GLOBALS['config']['email']['tpl'] ?? [];
                $title = $templates['user_'.$flag.'_title'] ?? null;
                $body = $templates['user_'.$flag.'_body'] ?? null;
                if (!is_string($title) || !is_string($body)) { throw new \RuntimeException('Missing message template'); }
                \think\facade\View::assign(['code'=>$code, 'time'=>$GLOBALS['config']['email']['time'] ?? 5]);
                $title = \think\facade\View::display($title);
                $body = htmlspecialchars_decode(\think\facade\View::display($body));
                $delivery = mac_send_mail($param['to'], $title, $body);
            } else {
                $body = $GLOBALS['config']['sms']['content'] ?? null;
                if (!is_string($body)) { throw new \RuntimeException('Missing message template'); }
                $body = str_replace(['[用户]','[类型]','[时长]','[验证码]'],
                    [$userName, $description, '5', $code], $body);
                $delivery = mac_send_sms($param['to'], $code, $flag, $description, $body);
            }
            if (!is_array($delivery) || !in_array($delivery['code'] ?? null, [1, '1'], true)) {
                return ['code'=>9009, 'msg'=>lang('model/user/msg_send_err')];
            }
            $saved = (new Msg())->saveData([
                'user_id'=>$where['user_id'], 'msg_type'=>$param['type'], 'msg_status'=>0,
                'msg_to'=>$param['to'], 'msg_code'=>$code,
                // The message table is an audit record, not a copy of an arbitrarily long HTML template.
                'msg_content'=>mb_substr(strip_tags($body), 0, 255, 'UTF-8'), 'msg_time'=>time(),
            ]);
            if (($saved['code'] ?? null) !== 1) { throw new \RuntimeException('Cannot record message'); }
        } catch (\Throwable $error) {
            return ['code'=>9009, 'msg'=>lang('model/user/msg_send_err')];
        }
        return ['code'=>1, 'msg'=>lang('model/user/msg_send_ok')];
    }

    public function bind($param)
    {
        if (!is_array($param)) { return ['code'=>9001, 'msg'=>lang('param_err')]; }
        $param['type'] = 1;
        $param = $this->messageParameters($param, true);
        if ($param === null) { return ['code'=>9001, 'msg'=>lang('param_err')]; }
        $started = false;
        $lock = null;
        try {
            $user = $this->authenticatedContactUser($param);
            if ($user === null) { return ['code'=>1002, 'msg'=>lang('model/user/not_login')]; }
            if (!mac_fe_write_throttle('fe_bind', 600, 10)) {
                return ['code'=>2003, 'msg'=>lang('index/pwd_frequently')];
            }
            if (!$this->messageTransactionsAvailable()) { throw new \RuntimeException('Transactional account tables required'); }
            $lock = $this->acquireContactLock($param['ac'], $param['to']);
            Db::startTrans(); $started = true;
            $current = Db::name('User')->where('user_id', $user['user_id'])->lock(true)->find();
            $column = $param['ac'] === 'email' ? 'user_email' : 'user_phone';
            if (!$current || $current['user_random'] !== $user['user_random'] || (int)$current['user_status'] !== 1) {
                throw new \RuntimeException('Authentication changed');
            }
            if ((string)$current[$column] !== '') { throw new \RuntimeException('Unbind existing contact first'); }
            if (Db::name('User')->where($column, $param['to'])->where('user_id', '<>', $user['user_id'])->lock(true)->find()) {
                throw new \RuntimeException('Contact already bound');
            }
            $verified = $this->checkMessageForUser($param, (int)$user['user_id']);
            if ($verified['code'] !== 1) { Db::rollback(); $started = false; return $verified; }
            if (Db::name('Msg')->where('msg_id', $verified['msg_id'])->where('msg_status', 0)
                ->update(['msg_status'=>1]) !== 1) { throw new \RuntimeException('Verification already used'); }
            if (Db::name('User')->where('user_id', $user['user_id'])->where($column, '')
                ->where('user_random', $user['user_random'])
                ->update([$column=>$param['to'], 'user_random'=>bin2hex(random_bytes(16))]) !== 1) {
                throw new \RuntimeException('Contact update failed');
            }
            Db::commit(); $started = false;
            return ['code'=>1, 'msg'=>lang('model/user/update_bind_ok').'，请重新登录', 'reauthenticate'=>1];
        } catch (\Throwable $error) {
            if ($started) { Db::rollback(); }
            return ['code'=>2003, 'msg'=>'绑定失败，请确认联系方式尚未绑定，并重新获取验证码'];
        } finally {
            $this->releaseContactLock($lock);
        }
    }

    public function unbind($param)
    {
        if (!is_array($param) || !in_array($param['ac'] ?? null, ['email', 'phone'], true)
            || !is_string($param['user_pwd'] ?? null) || trim($param['user_pwd']) === '') {
            return ['code'=>2001, 'msg'=>lang('param_err')];
        }
        $started = false;
        try {
            $user = $this->authenticatedContactUser($param);
            if ($user === null) { return ['code'=>1002, 'msg'=>lang('model/user/not_login')]; }
            if (!mac_fe_write_throttle('fe_unbind', 600, 10)) {
                return ['code'=>2002, 'msg'=>lang('index/pwd_frequently')];
            }
            if (!$this->messageTransactionsAvailable()) { throw new \RuntimeException('Transactional account tables required'); }
            Db::startTrans(); $started = true;
            $current = Db::name('User')->where('user_id', $user['user_id'])->lock(true)->find();
            if (!$current || $current['user_random'] !== $user['user_random'] || (int)$current['user_status'] !== 1
                || !$this->passwordMatches(trim($param['user_pwd']), $current['user_pwd'])) {
                Db::rollback(); $started = false;
                return ['code'=>2002, 'msg'=>lang('model/user/old_pass_err')];
            }
            $column = $param['ac'] === 'email' ? 'user_email' : 'user_phone';
            if ((string)$current[$column] === '') {
                Db::commit(); $started = false;
                return ['code'=>1, 'msg'=>lang('model/user/update_unbind_ok'), 'reauthenticate'=>0];
            }
            if (Db::name('User')->where('user_id', $user['user_id'])->where($column, $current[$column])
                ->where('user_random', $user['user_random'])
                ->update([$column=>'', 'user_random'=>bin2hex(random_bytes(16))]) !== 1) {
                throw new \RuntimeException('Contact update failed');
            }
            Db::commit(); $started = false;
            return ['code'=>1, 'msg'=>lang('model/user/update_unbind_ok').'，请重新登录', 'reauthenticate'=>1];
        } catch (\Throwable $error) {
            if ($started) { Db::rollback(); }
            return ['code'=>2002, 'msg'=>lang('model/user/update_bind_err')];
        }
    }

    public function bindmsg($param)
    {
        if (!is_array($param)) { return ['code'=>9001, 'msg'=>lang('param_err')]; }
        $param['type'] = 1;
        $param = $this->messageParameters($param, false);
        if ($param === null) { return ['code'=>9001, 'msg'=>lang('param_err')]; }
        try {
            $user = $this->authenticatedContactUser($param);
            if ($user === null) { return ['code'=>1002, 'msg'=>lang('model/user/not_login')]; }
            $column = $param['ac'] === 'email' ? 'user_email' : 'user_phone';
            if (!$this->messageTransactionsAvailable() || (string)$user[$column] !== ''
                || Db::name('User')->where($column, $param['to'])->where('user_id', '<>', $user['user_id'])->find()) {
                return ['code'=>2003, 'msg'=>'请先解除原绑定，并使用尚未绑定的联系方式'];
            }
            return $this->sendMessageForUser($param, (int)$user['user_id'], (string)$user['user_name']);
        } catch (\Throwable $error) {
            return ['code'=>9009, 'msg'=>lang('model/user/msg_send_err')];
        }
    }

    private function authenticatedContactUser(array $param): ?array
    {
        $authenticated = $this->checkLogin();
        if (($authenticated['code'] ?? null) !== 1 || empty($authenticated['info']['user_id'])) { return null; }
        // Browser cookies are sent automatically; explicit, verified Bearer credentials are not.
        if (JwtService::bearerFromRequest() === '' || !JwtService::isEnabled()) {
            $expected = \think\facade\Session::get('__csrf_token__');
            $provided = $param['csrf_token'] ?? request()->header('X-CSRF-Token');
            if (!is_string($expected) || $expected === '' || !is_string($provided)
                || !hash_equals($expected, $provided)) { return null; }
        }
        return $authenticated['info'];
    }

    /** Serialize this binding flow on legacy schemas until contact uniqueness is migrated. */
    private function acquireContactLock(string $channel, string $recipient): ?string
    {
        if (Db::connect()->getConfig('type') !== 'mysql') { return null; }
        $name = hash('sha256', (string)Db::connect()->getConfig('database').'|'.$this->getTable().'|'.$channel.'|'.strtolower($recipient));
        $result = Db::query('SELECT GET_LOCK(?, 5) AS acquired', [$name], true);
        if ((int)($result[0]['acquired'] ?? 0) !== 1) { throw new \RuntimeException('Contact is busy'); }
        return $name;
    }

    private function releaseContactLock(?string $name): void
    {
        if ($name === null) { return; }
        try { Db::query('SELECT RELEASE_LOCK(?) AS released', [$name], true); }
        catch (\Throwable $error) { /* Disconnecting also releases connection-owned locks. */ }
    }

    public function findpass_msg($param)
    {
        if (!is_array($param)) { return ['code'=>9001, 'msg'=>lang('param_err')]; }
        $param['type'] = 2;
        return $this->send_msg($param);
    }

    public function reg_msg($param)
    {
        if (!is_array($param)) { return ['code'=>9001, 'msg'=>lang('param_err')]; }
        $param['type'] = 3;
        return $this->sendMessageForUser($param, 0, '');
    }


    /** Password and verification state must commit together, including on upgraded old installations. */
    private function messageTransactionsAvailable(): bool
    {
        $type = Db::connect()->getConfig('type');
        if ($type === 'sqlite') { return true; }
        if ($type !== 'mysql') { return false; }
        $tables = [$this->getTable(), (new Msg())->getTable()];
        foreach (Db::query('SHOW TABLE STATUS') as $row) {
            $index = array_search($row['Name'], $tables, true);
            if ($index !== false && strtoupper((string)$row['Engine']) === 'INNODB') { unset($tables[$index]); }
        }
        return $tables === [];
    }

    public function findpass_reset($param)
    {
        if (!is_array($param)) { return ['code'=>9001, 'msg'=>lang('param_err')]; }
        foreach (['user_pwd', 'user_pwd2'] as $key) {
            if (!is_string($param[$key] ?? null)) { return ['code'=>9001, 'msg'=>lang('param_err')]; }
        }
        if (array_key_exists('user_email', $param)) {
            if (!is_string($param['user_email'])) { return ['code'=>9001, 'msg'=>lang('param_err')]; }
            $alias = trim($param['user_email']);
            if ($alias !== '' && (!is_string($param['to'] ?? null) || trim($param['to']) !== $alias)) {
                return ['code'=>9001, 'msg'=>lang('param_err')];
            }
        }
        $param['type'] = 2;
        $param = $this->messageParameters($param, true);
        if ($param === null) { return ['code'=>9001, 'msg'=>lang('param_err')]; }
        // Login currently trims passwords; preserve all other original bytes without a second URL decode.
        $password = trim($param['user_pwd']);
        if (strlen($password) < 6 || strlen($password) > 72 || str_contains($password, "\0")) {
            return ['code'=>2002, 'msg'=>lang('model/user/pass_length_err')];
        }
        if ($password !== trim($param['user_pwd2'])) {
            return ['code'=>2003, 'msg'=>lang('model/user/pass_not_same_pass2')];
        }
        if (!mac_fe_write_throttle('fe_findpass', 600, 10)) {
            return ['code'=>2001, 'msg'=>lang('index/pwd_frequently')];
        }
        $started = false;
        try {
            if (!$this->messageTransactionsAvailable()) { throw new \RuntimeException('Transactional account tables required'); }
            $hash = mac_password_hash($password);
            $random = bin2hex(random_bytes(16));
            Db::startTrans(); $started = true;
            $verified = $this->check_msg($param);
            if ($verified['code'] !== 1) { Db::rollback(); return $verified; }
            $column = $param['ac'] === 'email' ? 'user_email' : 'user_phone';
            $users = Db::name('User')->where($column, $param['to'])->lock(true)->limit(2)->select()->toArray();
            if (count($users) !== 1) {
                Db::rollback();
                return ['code'=>$param['ac'] === 'email' ? 2006 : 2008, 'msg'=>lang('model/user/'.($param['ac'] === 'email' ? 'email_err' : 'phone_err'))];
            }
            if (Db::name('Msg')->where('msg_id', $verified['msg_id'])->where('msg_status', 0)->update(['msg_status'=>1]) !== 1) {
                throw new \RuntimeException('Verification already used');
            }
            if (Db::name('User')->where('user_id', $users[0]['user_id'])->where($column, $param['to'])
                ->update(['user_pwd'=>$hash, 'user_random'=>$random]) !== 1) {
                throw new \RuntimeException('Password update failed');
            }
            Db::commit();
            return ['code'=>1, 'msg'=>lang('model/user/pass_reset_ok')];
        } catch (\Throwable $error) {
            if ($started) { Db::rollback(); }
            return ['code'=>2009, 'msg'=>lang('model/user/pass_reset_err')];
        }
    }

    private function visitTransactionsAvailable(): bool
    {
        $type = Db::connect()->getConfig('type');
        if ($type === 'sqlite') { return true; }
        if ($type !== 'mysql') { return false; }
        $tables = [$this->getTable(), (new Visit())->getTable(), (new Plog())->getTable()];
        $rows = Db::query('SELECT TABLE_NAME AS name, ENGINE AS engine FROM information_schema.TABLES '
            . 'WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME IN (?,?,?)', $tables, true);
        foreach ($rows as $row) {
            $index = array_search($row['name'], $tables, true);
            if ($index !== false && strtoupper((string)$row['engine']) === 'INNODB') { unset($tables[$index]); }
        }
        return $tables === [];
    }

    public function visit($param)
    {
        $userId = is_array($param) ? \app\common\util\PointsBalance::amount($param['uid'] ?? null) : null;
        if ($userId === null) { return ['code'=>101, 'msg'=>lang('model/user/id_err')]; }
        $configuration = $GLOBALS['config']['user'] ?? [];
        $quota = $configuration['invite_visit_num'] ?? 1;
        // Historical zero/empty configuration means one visit per address per day.
        if ($quota === '' || $quota === 0 || $quota === '0' || $quota === null) { $quota = 1; }
        $quota = \app\common\util\PointsBalance::amount($quota);
        $points = \app\common\util\PointsBalance::amount($configuration['invite_visit_points'] ?? 0, true);
        $ip = \app\common\util\PointsBalance::amount(mac_get_ip_long(), true);
        if ($quota === null || $points === null || $ip === null) {
            return ['code'=>103, 'msg'=>lang('model/user/visit_err')];
        }
        $started = false;
        try {
            if (!$this->visitTransactionsAvailable()) { throw new \RuntimeException('Transactional visit tables required'); }
            Db::startTrans(); $started = true;
            // All requests for this beneficiary acquire the same lock before reading the quota.
            if (!$this->where('user_id', $userId)->lock(true)->find()) {
                Db::rollback(); return ['code'=>101, 'msg'=>lang('model/user/id_err')];
            }
            $now = time(); $day = strtotime('today', $now); $nextDay = strtotime('+1 day', $day);
            $count = Db::name('Visit')->where('user_id', $userId)->where('visit_ip', $ip)
                ->where('visit_time', '>=', $day)->where('visit_time', '<', $nextDay)->lock(true)->count();
            if ($count >= $quota) { Db::rollback(); return ['code'=>102, 'msg'=>lang('model/user/visit_tip')]; }
            $referer = mac_get_refer();
            if (!is_string($referer)) { $referer = ''; }
            $referer = mb_substr(htmlspecialchars($referer, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'), 0, 100, 'UTF-8');
            if (Db::name('Visit')->insert(['user_id'=>$userId, 'visit_ip'=>$ip, 'visit_time'=>$now, 'visit_ly'=>$referer]) !== 1) {
                throw new \RuntimeException('Visit insert failed');
            }
            if ($points > 0) {
                if (!\app\common\util\PointsBalance::credit($userId, $points)) { throw new \RuntimeException('Visit credit failed'); }
                $log = (new Plog())->saveData(['user_id'=>$userId, 'plog_type'=>3, 'plog_points'=>$points]);
                if (($log['code'] ?? null) !== 1) { throw new \RuntimeException('Visit ledger failed'); }
                // Legacy SMALLINT ledgers can silently clip values under non-strict MySQL.
                $stored = Db::name('Plog')->where('plog_id', Db::name('Plog')->getLastInsID())->lock(true)->find();
                if (!$stored || (int)$stored['user_id'] !== $userId || (int)$stored['plog_type'] !== 3
                    || (int)$stored['plog_points'] !== $points) { throw new \RuntimeException('Visit ledger amount mismatch'); }
            }
            Db::commit();
            return ['code'=>1, 'msg'=>lang('model/user/visit_ok')];
        } catch (\Throwable $error) {
            if ($started) { Db::rollback(); }
            return ['code'=>103, 'msg'=>lang('model/user/visit_err')];
        }
    }

    /** Failures throw so callers cannot commit a charge with incomplete reward ledgers. */
    public function reward($fee_points=0, $source_user_id=null)
    {
        $configuration = $GLOBALS['config']['user'] ?? [];
        if (($configuration['reward_status'] ?? '0') != '1' || $fee_points === 0 || $fee_points === '0') {
            return ['code'=>1,'msg'=>lang('model/user/reward_ok')];
        }
        $fee_points = self::membershipInteger($fee_points);
        $source_user_id = self::membershipInteger($source_user_id ?? $GLOBALS['user']['user_id'] ?? null);
        if ($fee_points === null || $source_user_id === null) {
            throw new \RuntimeException('invalid reward parameters');
        }
        $type = Db::connect()->getConfig('type');
        if ($type === 'mysql') {
            $tables = [Db::name('User')->getTable(), Db::name('Plog')->getTable()];
            $rows = Db::query('SELECT TABLE_NAME AS name, ENGINE AS engine FROM information_schema.TABLES '
                .'WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME IN (?,?)', $tables, true);
            foreach ($rows as $row) {
                $index = array_search($row['name'], $tables, true);
                if ($index !== false && strtoupper((string)$row['engine']) === 'INNODB') { unset($tables[$index]); }
            }
            if ($tables !== []) { throw new \RuntimeException('reward requires transactional tables'); }
        } elseif ($type !== 'sqlite') { throw new \RuntimeException('unsupported reward storage'); }
        Db::startTrans();
        try {
            $source = $this->where('user_id', $source_user_id)->find();
            if (!$source) {
                throw new \RuntimeException('reward source missing');
            }
            $recipients = [];
            foreach (['' => 4, '_2' => 5, '_3' => 6] as $suffix => $log_type) {
                $ratio = $configuration['reward_ratio' . $suffix] ?? 0;
                if (!is_numeric($ratio) || !is_finite((float)$ratio) || (float)$ratio < 0) {
                    throw new \RuntimeException('invalid reward ratio');
                }
                $recipient = self::membershipInteger($source['user_pid' . $suffix] ?? null);
                $points = floor($fee_points / 100 * (float)$ratio);
                if ($points <= 0 || $recipient === null) {
                    continue;
                }
                if (!is_finite($points) || $points > 4294967295 || $recipient === $source_user_id || isset($recipients[$recipient])) {
                    throw new \RuntimeException('invalid reward recipient or amount');
                }
                $recipients[$recipient] = true;
                $points = (int)$points;
                $before = \app\common\util\PointsBalance::amount(Db::name('User')->master()
                    ->where('user_id', $recipient)->lock(true)->value('user_points'), true);
                if ($before === null || !\app\common\util\PointsBalance::credit($recipient, $points)) {
                    throw new \RuntimeException('reward credit rejected');
                }
                $after = Db::name('User')->master()->where('user_id', $recipient)->value('user_points');
                if ((string)$after !== (string)($before + $points)) {
                    throw new \RuntimeException('reward balance was not stored exactly');
                }
                $expected = [
                    'user_id'=>$recipient, 'plog_type'=>$log_type, 'plog_points'=>$points,
                    'plog_remarks'=>lang('model/user/reward_tip', [$source_user_id, $source['user_name'], $fee_points, $points]),
                ];
                $ledger = new Plog();
                $log = $ledger->saveData($expected);
                if (($log['code'] ?? null) !== 1) { throw new \RuntimeException('reward ledger failed'); }
                $stored = Db::name('Plog')->master()->where('plog_id', $ledger->getLastInsID())->find();
                foreach ($expected as $field=>$value) {
                    if (!$stored || (string)$stored[$field] !== (string)$value) {
                        throw new \RuntimeException('reward ledger was not stored exactly');
                    }
                }
            }
            Db::commit();
            return ['code'=>1,'msg'=>lang('model/user/reward_ok')];
        } catch (\Throwable $e) {
            Db::rollback();
            throw new \RuntimeException('reward transaction failed', 0, $e);
        }
    }

    /**
     * 根据用户ID生成邀请码
     * @param int $user_id
     * @return string
     */
    public function generateInviteCode($user_id)
    {
        $chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
        $code = '';
        $charsLength = strlen($chars);
        for ($i = 0; $i < 5; $i++) {
            $code .= $chars[random_int(0, $charsLength - 1)];
        }
        return $code;
    }
    
    /**
     * 检查邀请码是否已存在
     * @param string $code
     * @return bool
     */
    public function checkInviteCodeExists($code)
    {
        $count = $this->where('user_invite_code', $code)->count();
        return $count > 0;
    }
    
    /**
     * 生成唯一的不重复邀请码
     * @param int $user_id
     * @return string
     */
    public function generateUniqueInviteCode($user_id)
    {
        $max_attempts = 10;
        for ($i = 0; $i < $max_attempts; $i++) {
            $code = $this->generateInviteCode($user_id);
            if (!$this->checkInviteCodeExists($code)) {
                return $code;
            }
        }
        
        $fallback_code = strtoupper(substr(bin2hex(random_bytes(4)), 0, 5));
        if ($this->checkInviteCodeExists($fallback_code)) {
            $fallback_code = strtoupper(substr(bin2hex(random_bytes(4)), 0, 5));
        }
        
        return $fallback_code;
    }

    /**
     * 根据邀请码获取用户ID
     * @param string $invite_code
     * @return int
     */
    public function getUserIdByInviteCode($invite_code)
    {
        $info = $this->where('user_invite_code', $invite_code)->find();
        return $info ? $info['user_id'] : 0;
    }

    /** Internal continuation; ordinary calls cannot replay rewards for an existing account. */
    public function processInviteReward($user_id)
    {
        $userId = \app\common\util\PointsBalance::amount($user_id);
        if ($userId === null || $this->pendingInvitationRewardUserId !== $userId) {
            return ['code'=>1010, 'msg'=>lang('model/user/reg_err')];
        }
        $this->pendingInvitationRewardUserId = null;
        $configuration = config('maccms')['user'] ?? null;
        if (!is_array($configuration)) { throw new \RuntimeException('Invalid invitation configuration'); }
        $tiers = \app\common\util\InvitationRewardPlan::tiers($configuration);
        if ($tiers === []) { return ['code'=>1, 'msg'=>'ok']; }
        $groups = $this->registrationGroups($tiers);
        $user = Db::name('User')->where('user_id', $userId)->lock(true)->find();
        $now = time();
        $plan = \app\common\util\InvitationRewardPlan::calculate($user ?: [], $tiers, $groups, $now);
        foreach ($plan['events'] as $event) {
            $this->registrationCredit($userId, $event['points'], '邀请阶梯：'.$event['threshold']);
        }
        if ($plan['events'] !== []) {
            $fields = ['group_id'=>$plan['group_id'], 'user_end_time'=>$plan['user_end_time'],
                'user_invite_reward_level'=>$plan['user_invite_reward_level'], 'user_invite_reward_time'=>$now];
            if (Db::name('User')->where('user_id', $userId)->update($fields) !== 1) { throw new \RuntimeException('Invitation membership update failed'); }
            $this->assertRegistrationFields($userId, $fields);
        }
        return ['code'=>1, 'msg'=>'ok'];
    }

    /** A newly inserted child authorizes exactly one count, receipt, direct credit and tier transition. */
    public function addInviteCount($user_id, $source_user_id = null)
    {
        $userId = \app\common\util\PointsBalance::amount($user_id);
        $sourceId = \app\common\util\PointsBalance::amount($source_user_id);
        $authorized = $sourceId !== null && $sourceId === $this->pendingRegistrationSourceId;
        $this->pendingRegistrationSourceId = null;
        if (!$authorized || $userId === null || $userId === $sourceId) { return ['code'=>1010, 'msg'=>lang('model/user/reg_err')]; }
        $started = false;
        try {
            if (!$this->registrationTransactionsAvailable()) { throw new \RuntimeException('Invitation requires transactional tables'); }
            $configuration = config('maccms')['user'] ?? null;
            $points = is_array($configuration) ? \app\common\util\PointsBalance::amount($configuration['invite_reg_points'] ?? 0, true) : null;
            if ($points === null) { throw new \RuntimeException('Invalid direct invitation amount'); }
            $this->registrationGroups(\app\common\util\InvitationRewardPlan::tiers($configuration));
            Db::startTrans(); $started = true;
            $rows = Db::name('User')->whereIn('user_id', [$userId, $sourceId])->order('user_id')->lock(true)->select()->toArray();
            $users = array_column($rows, null, 'user_id');
            if (!isset($users[$userId], $users[$sourceId]) || (int)$users[$sourceId]['user_pid'] !== $userId
                || (int)$users[$userId]['user_status'] !== 1) { throw new \RuntimeException('Registration source does not match the inviter'); }
            $receipt = '注册推荐确认：'.$userId;
            if (Db::name('Plog')->master()->where('user_id', $sourceId)->where('plog_type', 2)
                ->where('plog_remarks', 'like', '注册推荐确认：%')->count() > 0) { throw new \RuntimeException('Invitation was already confirmed'); }
            $this->registrationCredit($sourceId, 0, $receipt);
            $count = \app\common\util\PointsBalance::amount($users[$userId]['user_invite_count'], true);
            if ($count === null || $count === \app\common\util\PointsBalance::MAX
                || Db::name('User')->where('user_id', $userId)->where('user_invite_count', $count)
                ->update(['user_invite_count'=>$count + 1]) !== 1) { throw new \RuntimeException('Invitation count failed'); }
            $this->assertRegistrationFields($userId, ['user_invite_count'=>$count + 1]);
            $this->registrationCredit($userId, $points, '注册推荐积分：'.$sourceId);
            $this->pendingInvitationRewardUserId = $userId;
            $result = $this->processInviteReward($userId);
            if (($result['code'] ?? null) !== 1) { throw new \RuntimeException('Invitation tier failed'); }
            Db::commit(); $started = false;
            return ['code'=>1, 'msg'=>'ok'];
        } catch (\Throwable $error) {
            if ($started) { Db::rollback(); }
            return ['code'=>1010, 'msg'=>lang('model/user/reg_err')];
        } finally { $this->pendingInvitationRewardUserId = null; }
    }

}
