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