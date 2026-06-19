<?php
namespace app\index\controller;
use think\captcha\Captcha;
use think\facade\Config;

class Verify
{
    public function index($id='')
    {
        ob_end_clean();
        $captcha = new Captcha((array)Config::get('captcha'));
        return $captcha->entry($id);
    }

    public function check($verify,$id='')
    {
        if(!captcha_check($verify)){
            return 0;
        }
        else{
            return 1;
        }
    }

}
