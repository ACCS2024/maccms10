<?php
namespace app\index\controller;

use app\common\util\Qrcode as QR;

class Qrcode
{
    public function index()
    {
        $param = \think\facade\Request::param();
        $url = $param['url'];
        if(!empty($url) && filter_var($url, FILTER_VALIDATE_URL)){
            ob_end_clean();
            header('Content-Type:image/png;');
            QR::png($url, false, QR_ECLEVEL_M, 10, 2);
        }
        die;
    }
}
