<?php
namespace app\index\controller;

class Verify
{
    /**
     * 输出验证码图片。
     *
     * TP5 时代的写法是 new Captcha((array)Config::get('captcha')) 再调 entry()；
     * TP8 的 think\captcha\Captcha 构造函数签名改成了 (Config $config, Session $session)
     * ——由容器注入、配置自己读，且 entry() 已不存在。旧写法在 PHP 8 下直接
     * TypeError: Argument #1 ($config) must be of type think\Config, array given，
     * 表现为后台登录页验证码 500、无法登录。
     * 这里改用 think-captcha 提供的 captcha() 助手，它返回 Response。
     */
    public function index($id = '')
    {
        // 清掉可能已存在的输出缓冲，避免图片二进制被前置内容污染
        while (ob_get_level() > 0) {
            ob_end_clean();
        }

        return captcha($id !== '' ? $id : null);
    }

    public function check($verify, $id = '')
    {
        return captcha_check($verify) ? 1 : 0;
    }
}
