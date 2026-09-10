<?php
namespace app\common\util;

use app\common\model\Gbook;
use app\common\model\User;
use think\facade\Db;
use think\Request;

/** Build a new public message from its content and the server's current account/configuration. */
final class GbookSubmission
{
    public static function submit(Request $request, bool $legacy = false): array
    {
        $settings = $GLOBALS['config']['gbook'] ?? [];
        if (!$request->isPost() || ($settings['status'] ?? '0') != '1') {
            return ['code'=>1001, 'msg'=>lang('close')];
        }
        $input = $request->post();
        if (($settings['verify'] ?? '0') == '1') {
            $verify = $input['verify'] ?? '';
            if (!is_string($verify) || !captcha_check($verify)) { return ['code'=>1002, 'msg'=>lang('verify_err')]; }
        }
        if (!mac_fe_write_throttle('fe_gbook', 60, 30) || !empty(cookie('gbook_timespan'))) {
            return ['code'=>1005, 'msg'=>lang('frequently')];
        }
        $content = $input['gbook_content'] ?? null;
        if (!is_string($content) || trim($content) === '' || !mb_check_encoding($content, 'UTF-8')) {
            return ['code'=>1004, 'msg'=>lang('index/require_content')];
        }
        $content = htmlentities(mac_filter_words(trim($content)), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        if (mb_strlen($content, 'UTF-8') > 255) { return ['code'=>1001, 'msg'=>lang('param_err')]; }
        $rid = $input['gbook_rid'] ?? 0;
        $rid = PointsBalance::amount($rid === '' ? 0 : $rid, true);
        if ($rid === null) { return ['code'=>1001, 'msg'=>lang('param_err')]; }
        try {
            $check = (new User())->checkLogin();
            $user = ($check['code'] ?? null) === 1 ? $check['info'] : null;
            if (!$user && ($settings['login'] ?? '0') == '1') {
                return ['code'=>1003, 'msg'=>lang('index/require_login')];
            }
            $name = $user ? ($user['user_nick_name'] ?: $user['user_name'])
                : ($legacy ? lang('controller/visitor') : ($input['gbook_name'] ?? lang('controller/visitor')));
            if (!is_string($name) || !mb_check_encoding($name, 'UTF-8')) {
                return ['code'=>1001, 'msg'=>lang('param_err')];
            }
            $name = htmlentities(trim($name) === '' ? lang('controller/visitor') : trim($name), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
            if (mb_strlen($name, 'UTF-8') > 60) { return ['code'=>1001, 'msg'=>lang('param_err')]; }
            if ($rid > 0) {
                // gbook_rid is a video report target; administrator replies stay on the original message.
                $target = Db::name('Vod')->where('vod_id', $rid)->where('vod_status', 1);
                if (in_array('vod_recycle_time', $target->getTableFields(), true)) { $target->where('vod_recycle_time', 0); }
                if (!$target->find()) { return ['code'=>1001, 'msg'=>lang('param_err')]; }
            }
            $result = (new Gbook())->saveData([
                'gbook_content'=>$content, 'gbook_name'=>$name, 'gbook_rid'=>$rid,
                'user_id'=>$user ? (int)$user['user_id'] : 0,
                'gbook_status'=>($settings['audit'] ?? '0') == '1' ? 0 : 1,
                'gbook_reply'=>'', 'gbook_reply_time'=>0, 'gbook_ip'=>mac_get_ip_long(), 'gbook_time'=>time(),
            ]);
        } catch (\Throwable $error) { return ['code'=>1002, 'msg'=>lang('save_err')]; }
        if (($result['code'] ?? null) === 1) {
            $seconds = PointsBalance::amount($settings['timespan'] ?? 30, true);
            cookie('gbook_timespan', 't', min($seconds ?? 30, 86400));
            $result['msg'] = lang(($settings['audit'] ?? '0') == '1' ? 'index/thanks_msg_audit' : 'index/thanks_msg');
        }
        return $result;
    }
}
