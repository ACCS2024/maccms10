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
        // Collection progress and legacy controllers may flush or exit inside $next.
        // Set the mandatory policy before invoking them, while headers can still be sent.
        $earlyApp = [];
        if (class_exists(\think\facade\Config::class)) {
            $earlyApp = \think\facade\Config::get('maccms.app', []);
        } elseif (isset($GLOBALS['config']['app'])) {
            $earlyApp = $GLOBALS['config']['app'];
        }
        if (!headers_sent()) {
            header('Content-Security-Policy: ' . self::scriptCspPolicy(is_array($earlyApp) ? $earlyApp : []));
        }
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

        // Always enforce the local-script boundary, including installation and legacy sites
        // whose optional CSP switch is still 0. Additional policies may only tighten it.
        $baseline = self::scriptCspPolicy($app);
        $response->header(['Content-Security-Policy' => $baseline]);

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
            $response->header(['Content-Security-Policy' => $baseline . ', ' . $policy]);
        }

        return $response;
    }

    public static function defaultCspPolicy(): string
    {
        return implode('; ', [
            "default-src 'self'",
            "base-uri 'self'",
            "object-src 'none'",
            // The separate mandatory script policy narrows these to self/approved origins.
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https:",
            "style-src 'self' 'unsafe-inline' https: http:",
            "img-src 'self' data: blob: https: http:",
            "font-src 'self' data: https: http:",
            "connect-src 'self' https: http: ws: wss:",
            "media-src 'self' blob: https: http:",
            "frame-src 'self' https: http:",
            "worker-src 'self' blob:",
            "form-action 'self' https: http:",
        ]) . ';';
    }

    /** Explicitly approved HTTPS asset origins only; never wildcard hosts, keywords or paths. */
    public static function scriptCspPolicy(array $app): string
    {
        $sources = $app['security_script_sources'] ?? [];
        if (is_string($sources)) { $sources = preg_split('/\s+/', trim($sources)); }
        $allowed = [];
        foreach (is_array($sources) ? array_slice($sources, 0, 32) : [] as $source) {
            if (!is_string($source) || strlen($source) > 300 || preg_match('/[\x00-\x20\x7f\\\\]/', $source)) { continue; }
            $parts = parse_url($source);
            if (!is_array($parts) || strtolower($parts['scheme'] ?? '') !== 'https'
                || empty($parts['host'])
                || isset($parts['user']) || isset($parts['pass']) || isset($parts['query']) || isset($parts['fragment'])
                || !in_array($parts['path'] ?? '', ['', '/'], true)) { continue; }
            $host = rtrim(strtolower($parts['host']), '.');
            if (!preg_match('/^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*$/D', $host)) { continue; }
            $origin = 'https://' . $host . (isset($parts['port']) ? ':' . $parts['port'] : '');
            if (function_exists('mac_is_official_url') && mac_is_official_url($origin)) { continue; }
            $allowed[$origin] = true;
        }
        return "script-src 'self' 'unsafe-inline' 'unsafe-eval'" . ($allowed ? ' ' . implode(' ', array_keys($allowed)) : '')
            . "; object-src 'none'; base-uri 'self'; worker-src 'self' blob:;";
    }
}
