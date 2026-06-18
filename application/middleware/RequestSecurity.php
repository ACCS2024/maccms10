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

        if (!empty($app['security_xss_input']) && (string)$app['security_xss_input'] !== '0') {
            if (!defined('ENTRANCE') || ENTRANCE !== 'install') {
                $skipAdmin = defined('ENTRANCE') && ENTRANCE === 'admin'
                    && (empty($app['security_xss_admin']) || (string)$app['security_xss_admin'] !== '1');

                if (!$skipAdmin) {
                    $skipJson = !isset($app['security_xss_skip_json']) || (string)$app['security_xss_skip_json'] !== '0';
                    $isJson   = !empty($_SERVER['CONTENT_TYPE'])
                        && stripos((string)$_SERVER['CONTENT_TYPE'], 'application/json') !== false;

                    if ($skipJson && $isJson) {
                        $_GET = RequestXssSanitizer::sanitizeDeep($_GET);
                    } else {
                        $_GET  = RequestXssSanitizer::sanitizeDeep($_GET);
                        $_POST = RequestXssSanitizer::sanitizeDeep($_POST);
                    }
                }
            }
        }

        return $next($request);
    }
}
