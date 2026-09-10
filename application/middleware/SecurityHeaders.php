<?php
namespace app\middleware;

class SecurityHeaders
{
    public function handle($request, \Closure $next)
    {
        // Cache markers belong to this request, including under a reused application container.
        unset($GLOBALS['_mac_page_cacheable']);
        $contentEntrance = defined('ENTRANCE') && in_array(ENTRANCE, ['index', 'api'], true);
        $privateContext = $contentEntrance && \app\common\util\ContentCachePolicy::hasPrivateContext($request);
        $response = $next($request);

        // 采集进度页用 mac_echo() 边跑边 flush(见 common.php),响应头此刻早已发出。
        // 再调 header_remove()/header() 只会刷 "headers already sent" 告警
        // (一次采集刷 27 条),头是设不上去的。直接放行,语义不变。
        if (headers_sent()) {
            return $response;
        }

        // 消除 PHP/框架版本指纹（防技术栈探测）
        if (function_exists('header_remove')) {
            header_remove('X-Powered-By');
        }

        $app = isset($GLOBALS['config']['app']) && is_array($GLOBALS['config']['app'])
            ? $GLOBALS['config']['app']
            : [];

        $base = !empty($app['security_headers_base']) && (string)$app['security_headers_base'] === '0'
            ? []
            : [
                'X-Content-Type-Options' => 'nosniff',
                'Referrer-Policy'        => 'strict-origin-when-cross-origin',
                'X-DNS-Prefetch-Control' => 'off',
                'X-Powered-By'           => '',   // 覆盖为空字符串，彻底隐藏 PHP/框架版本
            ];
        if ($base !== []) {
            $response->header($base);
        }

        // This middleware wraps SessionInit, whose outgoing Session Cookie is queued after the controller.
        $cookieEffects = $contentEntrance && (\think\facade\Cookie::getCookie() !== [] || $response->getHeader('Set-Cookie'));
        $cacheControl = strtolower((string)$response->getHeader('Cache-Control'));
        if ($contentEntrance && ($privateContext || $cookieEffects || \app\common\util\ContentCachePolicy::requiresPrivateResponse($request))) {
            unset($GLOBALS['_mac_page_cacheable']);
            $response->header(['Cache-Control' => 'private, no-store']);
        } elseif (!empty($GLOBALS['_mac_page_cacheable']) && mac_page_cache_eligible()
            && !str_contains($cacheControl, 'private') && !str_contains($cacheControl, 'no-store')) {
            $response->header(['Cache-Control' => 'public, max-age=' . (int)$GLOBALS['_mac_page_cacheable']]);
        }

        if (defined('ENTRANCE') && ENTRANCE === 'install') {
            return $response;
        }

        $cspMode = isset($app['security_csp']) ? (string)$app['security_csp'] : '0';
        if ($cspMode === '' || $cspMode === '0') {
            return $response;
        }

        $policy = isset($app['security_csp_policy']) ? trim((string)$app['security_csp_policy']) : '';
        if ($policy === '') {
            $policy = self::defaultCspPolicy();
        }

        $report = isset($app['security_csp_report_uri']) ? trim((string)$app['security_csp_report_uri']) : '';
        if ($report !== '') {
            $policy .= (substr(rtrim($policy), -1) === ';' ? ' ' : '; ') . 'report-uri ' . $report;
        }

        if ($cspMode === '2') {
            $response->header(['Content-Security-Policy-Report-Only' => $policy]);
        } else {
            $response->header(['Content-Security-Policy' => $policy]);
        }

        return $response;
    }

    public static function defaultCspPolicy(): string
    {
        return implode(' ', [
            "default-src 'self'",
            "base-uri 'self'",
            "object-src 'none'",
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https: http:",
            "style-src 'self' 'unsafe-inline' https: http:",
            "img-src 'self' data: blob: https: http:",
            "font-src 'self' data: https: http:",
            "connect-src 'self' https: http: ws: wss:",
            "media-src 'self' blob: https: http:",
            "frame-src 'self' https: http:",
            "worker-src 'self' blob:",
            "form-action 'self' https: http:",
        ]);
    }
}
