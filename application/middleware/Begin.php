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
        // Config loaders parse literal arrays with DataConfig before this middleware runs.
        // These additional inventory signals preserve evidence and never execute extra files.
        $extraDir = APP_PATH . 'extra' . DIRECTORY_SEPARATOR;
        if (is_dir($extraDir)) {
            $files = scandir($extraDir);
            foreach ($files ?: [] as $f) {
                if ($f === '.' || $f === '..') {
                    continue;
                }
                if (!in_array($f, self::$allowedExtraFiles, true)) {
                    @file_put_contents(
                        RUNTIME_PATH . 'security_alert.log',
                        date('Y-m-d H:i:s') . " [REVIEW] Unrecognized extra/ entry: " . json_encode($f) . "\n",
                        FILE_APPEND | LOCK_EX
                    );
                }
            }

            $addonsFile = $extraDir . 'addons.php';
            if (is_file($addonsFile)) {
                $c = (string)@file_get_contents($addonsFile);
                if (strlen($c) > 2048 || preg_match('/eval|assert|\bsystem\b|\bexec\b|passthru|shell_exec|popen|proc_open|base64_decode|gzinflate|gzuncompress|str_rot13|create_function|call_user_func|file_put_contents|fwrite|fopen|curl_exec|\$_(GET|POST|REQUEST|COOKIE|SERVER)/i', $c)) {
                    @file_put_contents(
                        RUNTIME_PATH . 'security_alert.log',
                        date('Y-m-d H:i:s') . " [REVIEW] addons.php requires inspection (size=" . strlen($c) . "). File preserved.\n",
                        FILE_APPEND | LOCK_EX
                    );

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
