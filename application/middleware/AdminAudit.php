<?php
namespace app\middleware;

use app\common\model\AdminAuditLog;
use app\common\util\SensitiveDataCrypto;

class AdminAudit
{
    public function handle($request, \Closure $next)
    {
        $response = $next($request);

        if (PHP_SAPI === 'cli') {
            return $response;
        }
        if (!defined('ENTRANCE') || ENTRANCE !== 'admin') {
            return $response;
        }
        $app = isset($GLOBALS['config']['app']) && is_array($GLOBALS['config']['app'])
            ? $GLOBALS['config']['app']
            : [];
        if (empty($app['admin_audit_enabled']) || (string)$app['admin_audit_enabled'] !== '1') {
            return $response;
        }
        if (session('admin_auth') !== '1') {
            return $response;
        }
        $admin = session('admin_info');
        if (!is_array($admin) || empty($admin['admin_id'])) {
            return $response;
        }

        $method = strtoupper($request->method());
        $logGet = !empty($app['admin_audit_get']) && (string)$app['admin_audit_get'] === '1';
        if (!$logGet && !in_array($method, ['POST', 'PUT', 'PATCH', 'DELETE'], true)) {
            return $response;
        }

        $ctl   = strtolower((string)$request->controller());
        $act   = strtolower((string)$request->action());
        $route = $ctl . '/' . $act;

        $skip = [
            'index/login', 'upload/upload', 'upload/ueditorai',
            'upload/ueditor_ai', 'assistant/chat',
        ];
        if (in_array($route, $skip, true) || $ctl === 'adminaudit') {
            return $response;
        }

        $payload = array_merge($request->param(), $request->post());
        $json = '';
        if ($payload !== []) {
            $json = \app\common\util\AdminAuditPayload::encode($payload, $app);
            if (!empty($app['admin_audit_encrypt']) && (string)$app['admin_audit_encrypt'] === '1') {
                try {
                    $enc = SensitiveDataCrypto::encryptString($json, $app);
                } catch (\Throwable $error) {
                    $enc = false;
                }
                $json = SensitiveDataCrypto::isEncryptedPayload($enc)
                    ? $enc : '{"redacted":"audit encryption unavailable"}';
            }
        }

        $code = (int)$response->getCode();
        if ($code < 100 || $code > 599) {
            $code = 0;
        }

        AdminAuditLog::insertRow([
            'admin_id'        => (int)$admin['admin_id'],
            'admin_name'      => isset($admin['admin_name']) ? (string)$admin['admin_name'] : '',
            'audit_time'      => time(),
            'audit_ip'        => (string)mac_get_client_ip(),
            'audit_method'    => $method,
            'audit_route'     => $route,
            // Query parameters are recorded through the redacted payload above.
            'audit_uri'       => substr(explode('?', (string)$request->url(true), 2)[0], 0, 2048),
            'audit_http_code' => $code,
            'audit_payload'   => $json,
        ]);

        return $response;
    }

}
