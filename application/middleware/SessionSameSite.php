<?php
namespace app\middleware;

class SessionSameSite
{
    public function handle($request, \Closure $next)
    {
        if (PHP_SAPI !== 'cli'
            && PHP_VERSION_ID >= 70300
            && !headers_sent()
            && session_status() !== PHP_SESSION_ACTIVE
        ) {
            $cfg = function_exists('config') ? config('session') : [];
            if (!is_array($cfg)) {
                $cfg = [];
            }

            $ss = isset($cfg['samesite']) ? trim((string)$cfg['samesite']) : '';
            if ($ss !== '' && $ss !== '0') {
                $lifetime = isset($cfg['expire']) ? (int)$cfg['expire'] : 0;
                if ($lifetime < 1) {
                    $lifetime = (int)ini_get('session.cookie_lifetime');
                }

                $path = '/';
                $p = ini_get('session.cookie_path');
                if ($p !== false && $p !== '') {
                    $path = (string)$p;
                }

                $domain = '';
                if (isset($cfg['domain'])) {
                    $domain = (string)$cfg['domain'];
                } else {
                    $d = ini_get('session.cookie_domain');
                    if ($d !== false && $d !== '') {
                        $domain = (string)$d;
                    }
                }

                $secure   = isset($cfg['secure'])   ? (bool)$cfg['secure']   : (bool)ini_get('session.cookie_secure');
                $httponly = isset($cfg['httponly'])  ? (bool)$cfg['httponly'] : (bool)ini_get('session.cookie_httponly');

                session_set_cookie_params([
                    'lifetime' => $lifetime,
                    'path'     => $path,
                    'domain'   => $domain,
                    'secure'   => $secure,
                    'httponly' => $httponly,
                    'samesite' => $ss,
                ]);
            }
        }

        return $next($request);
    }
}
