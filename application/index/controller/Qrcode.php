<?php
namespace app\index\controller;

use app\common\util\QRcode as QR;
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

        $bufferLevel = ob_get_level();
        $contentTypes = array_values(array_filter(headers_list(),
            static fn(string $header): bool => stripos($header, 'Content-Type:') === 0));
        try {
            ob_start();
            QR::png($url, false, QR_ECLEVEL_M, 10, 2);
            $png = ob_get_contents();
            if (!is_string($png) || !str_starts_with($png, "\x89PNG\r\n\x1a\n")) {
                throw new \RuntimeException('QR encoder produced no PNG');
            }
            return Response::create($png)->header(['Content-Type' => 'image/png']);
        } catch (\InvalidArgumentException $e) {
            return Response::create(['code' => 1001, 'msg' => '二维码内容超出支持范围'], 'json', 400);
        } catch (\Throwable $e) {
            return Response::create(['code' => 1002, 'msg' => '二维码生成失败'], 'json', 500);
        } finally {
            while (ob_get_level() > $bufferLevel) {
                ob_end_clean();
            }
            // The legacy encoder sets a native header. Let the completed Response own its type.
            if (!headers_sent()) {
                header_remove('Content-Type');
                foreach ($contentTypes as $contentType) { header($contentType); }
            }
        }
    }
}
