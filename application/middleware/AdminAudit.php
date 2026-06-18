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

        $denyContains = self::buildDenyContainsList($app);
        $payload      = self::sanitizePayload(array_merge($request->param(), $request->post()), $denyContains);
        $json         = '';
        if ($payload !== []) {
            $json = json_encode($payload, JSON_UNESCAPED_UNICODE);
            if (strlen($json) > 16384) {
                $json = substr($json, 0, 16300) . '…(truncated)';
            }
            if (!empty($app['admin_audit_encrypt']) && (string)$app['admin_audit_encrypt'] === '1' && $json !== '') {
                $enc = SensitiveDataCrypto::encryptString($json, $app);
                if (SensitiveDataCrypto::isEncryptedPayload($enc)) {
                    $json = $enc;
                }
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
            'audit_uri'       => substr((string)$request->url(true), 0, 2048),
            'audit_http_code' => $code,
            'audit_payload'   => $json,
        ]);

        return $response;
    }

    private static function buildDenyContainsList(array $app): array
    {
        $denyContains = [
            'secret', 'apikey', 'api_key', 'token', 'access_key', 'private_key',
        ];
        $extra = isset($app['admin_audit_extra_redact']) ? trim((string)$app['admin_audit_extra_redact']) : '';
        if ($extra !== '') {
            foreach (preg_split('/[\s,|]+/', $extra, -1, PREG_SPLIT_NO_EMPTY) ?: [] as $word) {
                $w = strtolower(trim((string)$word));
                if ($w !== '' && strlen($w) <= 64) {
                    $denyContains[] = $w;
                }
            }
        }
        return array_values(array_unique($denyContains));
    }

    private static function sanitizePayload(array $data, array $denyContains): array
    {
        $denyExact = [
            'admin_pwd', 'user_pwd', 'user_pwd2', 'password', 'verify',
            '__token__', 'user_check', 'admin_check', 'sql',
        ];
        $out = [];
        foreach ($data as $k => $v) {
            $lk = strtolower((string)$k);
            if (in_array($lk, $denyExact, true)
                || substr($lk, -4) === '_pwd'
                || substr($lk, -8) === '_password') {
                $out[$k] = '[redacted]';
                continue;
            }
            $redacted = false;
            foreach ($denyContains as $kw) {
                if ($kw !== '' && strpos($lk, $kw) !== false) {
                    $out[$k] = '[redacted]';
                    $redacted = true;
                    break;
                }
            }
            if ($redacted) {
                continue;
            }
            if (is_array($v)) {
                $out[$k] = self::sanitizePayload($v, $denyContains);
            } elseif (is_string($v) && strlen($v) > 2000) {
                $out[$k] = substr($v, 0, 2000) . '…';
            } else {
                $out[$k] = $v;
            }
        }
        return $out;
    }
}
