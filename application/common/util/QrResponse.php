<?php
namespace app\common\util;

use think\Response;

/** Buffer legacy QR output so failed encodes never leave partial image responses. */
final class QrResponse
{
    public const LOW = 0;
    public const MEDIUM = 1;
    public static function png(string $text, int $level, int $size = 10, int $margin = 4): Response
    {
        $bufferLevel = ob_get_level();
        $contentTypes = array_values(array_filter(headers_list(),
            static fn(string $header): bool => stripos($header, 'Content-Type:') === 0));
        try {
            ob_start();
            QRcode::png($text, false, $level, $size, $margin);
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
