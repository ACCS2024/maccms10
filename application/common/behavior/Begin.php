<?php
namespace app\common\behavior;

class Begin
{
    // 已知的合法 extra 配置文件白名单
    private static $allowedExtraFiles = [
        'addons.php', 'bind.php', 'blacks.php', 'captcha.php',
        'domain.php', 'maccms.php', 'queue.php', 'quickmenu.php',
        'timming.php', 'version.php', 'voddowner.php', 'vodplayer.php',
        'vodserver.php',
        // 本 fork 合法新增的配置文件(V16:避免被清扫器误删)
        'mctheme.php', 'type_synonyms.php', 'resource_sites_custom.php',
    ];

    public function run(&$params)
    {
        // 安全加固：检查 application/extra/ 目录是否存在可疑文件
        $extraDir = APP_PATH . 'extra' . DIRECTORY_SEPARATOR;
        if(is_dir($extraDir)){
            $files = scandir($extraDir);
            foreach($files as $f){
                if($f === '.' || $f === '..') continue;
                if(!in_array($f, self::$allowedExtraFiles)){
                    // 发现未知文件，记录日志并阻止加载
                    @file_put_contents(RUNTIME_PATH . 'security_alert.log',
                        date('Y-m-d H:i:s') . " [ALERT] Suspicious file in extra/: {$f} from " . ($_SERVER['REMOTE_ADDR'] ?? 'CLI') . "\n",
                        FILE_APPEND | LOCK_EX
                    );
                    // 删除可疑文件
                    @unlink($extraDir . $f);
                }
            }
            // 安全加固(N2):白名单文件 addons.php 体积/内容校验,
            // 防止被篡改为 20-30KB 后门(文件名在白名单内,清扫器不会删,故需校验内容)
            $addonsFile = $extraDir . 'addons.php';
            if (is_file($addonsFile)) {
                $c = (string)@file_get_contents($addonsFile);
                if (strlen($c) > 2048 || preg_match('/eval|assert|\bsystem\b|\bexec\b|passthru|shell_exec|popen|proc_open|base64_decode|gzinflate|gzuncompress|str_rot13|create_function|call_user_func|file_put_contents|fwrite|fopen|curl_exec|\$_(GET|POST|REQUEST|COOKIE|SERVER)/i', $c)) {
                    @file_put_contents(RUNTIME_PATH . 'security_alert.log',
                        date('Y-m-d H:i:s') . " [ALERT] addons.php tampered (size=" . strlen($c) . ") from " . ($_SERVER['REMOTE_ADDR'] ?? 'CLI') . "\n",
                        FILE_APPEND | LOCK_EX
                    );
                    // 隔离篡改文件留证,并还原为干净的空配置
                    @rename($addonsFile, $addonsFile . '.quarantine.' . date('YmdHis'));
                    @file_put_contents($addonsFile, "<?php\n\nreturn array (\n  'autoload' => false,\n  'hooks' => \n  array (\n  ),\n  'route' => \n  array (\n  ),\n);\n");
                }
            }
        }

        $module = '';
        $dispatch = request()->dispatch();

        if (isset($dispatch['module'])) {
            $module = $dispatch['module'][0];
        }

        if( $module =='install'){
            return;
        }

        if(defined('ENTRANCE') && ENTRANCE == 'admin') {

            if ($module == '') {
                header('Location: '.url('admin/index/index'));
                exit;
            }

            if ($module != 'admin' ) {
                header('Location: '.url('admin/index/index'));
                exit;
            }
        }

    }
}