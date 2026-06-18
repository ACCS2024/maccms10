<?php
namespace app\middleware;

class Begin
{
    private static $allowedExtraFiles = [
        'addons.php', 'bind.php', 'blacks.php', 'captcha.php',
        'domain.php', 'maccms.php', 'queue.php', 'quickmenu.php',
        'timming.php', 'version.php', 'voddowner.php', 'vodplayer.php',
        'vodserver.php',
        'mctheme.php', 'type_synonyms.php', 'resource_sites_custom.php',
    ];

    public function handle($request, \Closure $next)
    {
        $extraDir = APP_PATH . 'extra' . DIRECTORY_SEPARATOR;
        if (is_dir($extraDir)) {
            $files = scandir($extraDir);
            foreach ($files as $f) {
                if ($f === '.' || $f === '..') {
                    continue;
                }
                if (!in_array($f, self::$allowedExtraFiles)) {
                    @file_put_contents(
                        RUNTIME_PATH . 'security_alert.log',
                        date('Y-m-d H:i:s') . " [ALERT] Suspicious file in extra/: {$f} from " . ($_SERVER['REMOTE_ADDR'] ?? 'CLI') . "\n",
                        FILE_APPEND | LOCK_EX
                    );
                    @unlink($extraDir . $f);
                }
            }

            $addonsFile = $extraDir . 'addons.php';
            if (is_file($addonsFile)) {
                $c = (string)@file_get_contents($addonsFile);
                if (strlen($c) > 2048 || preg_match('/eval|assert|\bsystem\b|\bexec\b|passthru|shell_exec|popen|proc_open|base64_decode|gzinflate|gzuncompress|str_rot13|create_function|call_user_func|file_put_contents|fwrite|fopen|curl_exec|\$_(GET|POST|REQUEST|COOKIE|SERVER)/i', $c)) {
                    @file_put_contents(
                        RUNTIME_PATH . 'security_alert.log',
                        date('Y-m-d H:i:s') . " [ALERT] addons.php tampered (size=" . strlen($c) . ") from " . ($_SERVER['REMOTE_ADDR'] ?? 'CLI') . "\n",
                        FILE_APPEND | LOCK_EX
                    );
                    @rename($addonsFile, $addonsFile . '.quarantine.' . date('YmdHis'));
                    @file_put_contents($addonsFile, "<?php\n\nreturn array (\n  'autoload' => false,\n  'hooks' => \n  array (\n  ),\n  'route' => \n  array (\n  ),\n);\n");
                }
            }
        }

        // TP8 multi-app: module = app name (set via $http->name())
        if (defined('ENTRANCE') && ENTRANCE === 'admin') {
            $pi = trim((string)$request->pathinfo(), '/');
            if ($pi === '' || $pi === 'admin') {
                $entryFile = defined('IN_FILE') ? IN_FILE : '/admin.php';
                header('Location: ' . $entryFile . '/index/index');
                exit;
            }
        }

        return $next($request);
    }
}
