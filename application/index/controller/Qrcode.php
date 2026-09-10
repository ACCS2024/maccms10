<?php
namespace app\index\controller;

use app\common\util\QrResponse;
use think\facade\Request;
use think\Response;

class Qrcode
{
    public function index(): Response
    {
        $url = Request::param('url');
        if (!is_string($url) || $url === '' || !filter_var($url, FILTER_VALIDATE_URL)) {
            return Response::create(['code' => 1001, 'msg' => '二维码地址无效'], 'json', 400);
        }

        return QrResponse::png($url, QrResponse::MEDIUM, 10, 2);
    }
}
