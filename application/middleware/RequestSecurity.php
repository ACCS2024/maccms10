<?php
namespace app\middleware;

use app\common\util\RequestXssSanitizer;

class RequestSecurity
{
    public function handle($request, \Closure $next)
    {
        $app = isset($GLOBALS['config']['app']) && is_array($GLOBALS['config']['app'])
            ? $GLOBALS['config']['app']
            : [];
        $enabled = $app['security_xss_input'] ?? '0';
        if (!is_scalar($enabled) || empty($enabled) || (string)$enabled === '0'
            || (defined('ENTRANCE') && ENTRANCE === 'install')) {
            return $next($request);
        }
        $admin = $app['security_xss_admin'] ?? '0';
        if (defined('ENTRANCE') && ENTRANCE === 'admin' && (!is_scalar($admin) || (string)$admin !== '1')) {
            return $next($request);
        }

        $skipJson = $app['security_xss_skip_json'] ?? '1';
        $skipJson = !is_scalar($skipJson) || (string)$skipJson !== '0';
        // Match the framework's JSON body parsing, including vendor +json media types.
        $isJson = str_contains(strtolower($request->contentType()), 'json');

        // TP8 captures input before middleware runs; changing only superglobals
        // leaves controllers reading the original Request data.
        $request->withGet(RequestXssSanitizer::sanitizeDeep($request->get(false)));
        $_GET = RequestXssSanitizer::sanitizeDeep($_GET);
        if (!$skipJson || !$isJson) {
            $request->withPost(RequestXssSanitizer::sanitizeDeep($request->post(false)));
            $_POST = RequestXssSanitizer::sanitizeDeep($_POST);
        }
        // withGet/withPost do not invalidate TP8's merged param cache. setRoute
        // merges an empty update, retaining the route while forcing a fresh merge.
        $request->setRoute([]);

        return $next($request);
    }
}
