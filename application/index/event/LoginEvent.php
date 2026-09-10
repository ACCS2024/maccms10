<?php
namespace app\index\event;

use login\ThinkOauth;

class LoginEvent
{
    public function qq($token)
    {
        return $this->profile('qq', $token);
    }

    public function weixin($token)
    {
        return $this->profile('weixin', $token);
    }

    /** Normalize provider responses before any identity can reach local login/registration. */
    private function profile(string $provider, $token): array
    {
        $failure = ['code' => 0, 'msg' => $provider === 'qq' ? '获取腾讯QQ用户信息失败' : '获取微信用户信息失败'];
        try {
            if (!is_array($token) || !is_string($token['access_token'] ?? null) || $token['access_token'] === '') {
                return $failure;
            }
            $sdk = ThinkOauth::getInstance($provider, $token);
            $data = $sdk->call($provider === 'qq' ? 'user/get_user_info' : 'sns/userinfo');
            if (!is_array($data)) { return $failure; }
            // QQ has an explicit ret; WeChat successful userinfo can omit errcode.
            $status = $provider === 'qq' ? ($data['ret'] ?? null) : ($data['errcode'] ?? 0);
            if (!in_array($status, [0, '0'], true) || !is_string($data['nickname'] ?? null)) {
                return $failure;
            }
            $openid = $sdk->openid();
            if (!is_string($openid) || $openid === ''
                || (isset($data['openid']) && $data['openid'] !== $openid)) {
                return $failure;
            }
            $head = $data[$provider === 'qq' ? 'figureurl_2' : 'headimgurl'] ?? '';
            if (!is_string($head)) { return $failure; }
            return ['code' => 1, 'msg' => 'ok', 'info' => [
                'type' => strtoupper($provider), 'name' => $data['nickname'], 'nick' => $data['nickname'],
                'head' => $head, 'openid' => $openid,
            ]];
        } catch (\Throwable $e) {
            return $failure;
        }
    }
}
