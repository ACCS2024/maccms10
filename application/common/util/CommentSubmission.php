<?php
namespace app\common\util;

use app\common\model\Comment;
use app\common\model\User;
use think\facade\Db;
use think\Request;

/** The public comment endpoints may create a comment, never select an existing row to edit. */
final class CommentSubmission
{
    public static function submit(Request $request, bool $legacy = false): array
    {
        if (!$request->isPost()) {
            return ['code'=>1001, 'msg'=>lang('param_err')];
        }
        $settings = $GLOBALS['config']['comment'] ?? [];
        if (($settings['status'] ?? '0') != '1') {
            return ['code'=>1001, 'msg'=>lang('close')];
        }
        if (!mac_fe_write_throttle('fe_comment', 60, 30) || !empty(cookie('comment_timespan'))) {
            return ['code'=>1005, 'msg'=>lang('frequently')];
        }
        $input = $request->post();
        if (($settings['verify'] ?? '0') == '1') {
            $verify = $input['verify'] ?? '';
            if (!is_string($verify) || !captcha_check($verify)) {
                return ['code'=>1002, 'msg'=>lang('verify_err')];
            }
        }
        $mid = $input['comment_mid'] ?? null;
        $rid = $input['comment_rid'] ?? null;
        if ($legacy) {
            // Old templates may submit an empty canonical field alongside the populated alias.
            if (in_array($mid, [null, '', 0, '0'], true)) { $mid = $input['mid'] ?? $mid; }
            if (in_array($rid, [null, '', 0, '0'], true)) { $rid = $input['rid'] ?? $rid; }
        }
        if ($legacy && (is_string($mid) || is_int($mid))) {
            $aliases = ['vod'=>1, 'art'=>2, 'topic'=>3, 'actor'=>8, 'role'=>9, 'website'=>11, 'manga'=>12];
            $mid = $aliases[strtolower(trim((string)$mid))] ?? $mid;
            if ((string)$mid === '4') { $mid = $input['mid'] ?? $mid; }
        }
        $mid = PointsBalance::amount($mid);
        $rid = PointsBalance::amount($rid);
        $pid = $input['comment_pid'] ?? 0;
        $pid = PointsBalance::amount($pid === '' ? 0 : $pid, true);
        $targets = [1=>'Vod', 2=>'Art', 3=>'Topic', 8=>'Actor', 9=>'Role', 11=>'Website', 12=>'Manga'];
        if ($mid === null || !isset($targets[$mid]) || $rid === null || $pid === null) {
            return ['code'=>1006, 'msg'=>lang('index/mid_err')];
        }
        $content = $input['comment_content'] ?? '';
        if (!is_string($content) || trim($content) === '' || !mb_check_encoding($content, 'UTF-8')) {
            return ['code'=>1004, 'msg'=>lang('index/require_content')];
        }
        $content = htmlentities(mac_filter_words(trim($content)), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        if (mb_strlen($content, 'UTF-8') > 255) {
            return ['code'=>1001, 'msg'=>lang('param_err')];
        }

        $user = self::authenticatedUser($request);
        if (!$user && ($settings['login'] ?? '0') == '1') {
            return ['code'=>1003, 'msg'=>lang('index/require_login')];
        }
        $name = $user ? ($user['user_nick_name'] ?: $user['user_name'])
            : (!$legacy ? ($input['comment_name'] ?? lang('controller/visitor')) : lang('controller/visitor'));
        if (!is_string($name) || !mb_check_encoding($name, 'UTF-8')) {
            return ['code'=>1001, 'msg'=>lang('param_err')];
        }
        $name = htmlentities(trim($name), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        if ($name === '' || mb_strlen($name, 'UTF-8') > 60) {
            return ['code'=>1001, 'msg'=>lang('param_err')];
        }
        $ip = mac_get_ip_long();
        $blacks = config('blacks', []);
        foreach ((array)($blacks['black_keyword_list'] ?? []) as $word) {
            if (is_string($word) && $word !== '' && strpos($content, $word) !== false) {
                return ['code'=>1007, 'msg'=>lang('index/blacklist_keyword')];
            }
        }
        if (in_array(long2ip((int)$ip), (array)($blacks['black_ip_list'] ?? []), true)) {
            return ['code'=>1008, 'msg'=>lang('index/blacklist_ip')];
        }

        // Only these fields cross the public write boundary. Identity, moderation and time are server-owned.
        $data = [
            'comment_mid'=>$mid, 'comment_rid'=>$rid, 'comment_pid'=>$pid,
            'comment_content'=>$content, 'comment_name'=>$name, 'user_id'=>$user ? (int)$user['user_id'] : 0,
            'comment_status'=>($settings['audit'] ?? '0') == '1' ? 0 : 1,
            'comment_ip'=>$ip, 'comment_time'=>time(),
        ];
        try {
            $target = strtolower($targets[$mid]);
            $targetQuery = Db::name($targets[$mid])->where($target . '_id', $rid)->where($target . '_status', 1);
            if (in_array($mid, [1, 2, 12], true)
                && in_array($target . '_recycle_time', $targetQuery->getTableFields(), true)) {
                $targetQuery->where($target . '_recycle_time', 0);
            }
            if (!$targetQuery->field($target . '_id')->find()) {
                return ['code'=>1001, 'msg'=>lang('param_err')];
            }
            if ($pid > 0 && !Db::name('Comment')->where([
                'comment_id'=>$pid, 'comment_mid'=>$mid, 'comment_rid'=>$rid, 'comment_status'=>1,
            ])->find()) {
                return ['code'=>1001, 'msg'=>lang('param_err')];
            }
            $result = (new Comment())->saveData($data, true);
        } catch (\Throwable $e) {
            return ['code'=>1002, 'msg'=>lang('save_err')];
        }
        if (($result['code'] ?? null) === 1) {
            cookie('comment_timespan', 't', max(1, (int)($settings['timespan'] ?? 30)));
            if ($legacy) {
                $result['msg'] = lang(($settings['audit'] ?? '0') == '1' ? 'index/thanks_msg_audit' : 'index/thanks_msg');
            }
        }
        return $result;
    }

    private static function authenticatedUser(Request $request): ?array
    {
        $hasCookies = true;
        foreach (['user_id', 'user_name', 'user_check'] as $key) {
            $value = cookie($key);
            if (!is_string($value) || $value === '') { $hasCookies = false; }
        }
        // Do not send malformed cookie containers through the legacy string-based login checker.
        if (!is_string($request->header('Authorization', ''))) { return null; }
        $bearer = JwtService::isEnabled() && JwtService::bearerFromRequest($request) !== '';
        if (!$hasCookies && !$bearer) { return null; }
        $check = (new User())->checkLogin();
        return ($check['code'] ?? null) === 1 && is_array($check['info'] ?? null) ? $check['info'] : null;
    }
}
