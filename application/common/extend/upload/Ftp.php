<?php
namespace app\common\extend\upload;

use app\common\util\Ftp as ftpOper;

class Ftp
{
    public $name = 'FTP存储';
    public $ver = '1.0';
    private $config = [];
    private static $connections = [];
    private static $failedConnections = [];

    public function __construct($config = []) {
        $this->config = $config;
    }

    public function submit($file_path)
    {
        $settings = $GLOBALS['config']['upload']['api']['ftp'];
        $ftp_config = [
            'ftp_host'=>$settings['host'],
            'ftp_port'=>$settings['port'],
            'ftp_user'=>$settings['user'],
            'ftp_pwd' =>$settings['pwd'],
            'ftp_dir'=>$settings['path'],
            'ftp_timeout'=>max(3, (int)($settings['timeout'] ?? 30)),
        ];

        $connectionKey = hash('sha256', serialize($ftp_config));
        if (isset(self::$failedConnections[$connectionKey])) {
            return $file_path;
        }

        if (!isset(self::$connections[$connectionKey])) {
            $ftp = new ftpOper($ftp_config);
            if ($ftp->connect() !== $ftp) {
                self::$failedConnections[$connectionKey] = true;
                return $file_path;
            }
            self::$connections[$connectionKey] = $ftp;
        }

        $ftp = self::$connections[$connectionKey];
        try {
            $uploaded = $ftp->put(ROOT_PATH . $file_path, $file_path);
        } catch (\Throwable $e) {
            $uploaded = false;
        }
        if (!$uploaded) {
            self::$failedConnections[$connectionKey] = true;
            unset(self::$connections[$connectionKey]);
            return $file_path;
        }

        $filePath = ROOT_PATH . $file_path;
        empty($this->config['keep_local']) && @unlink($filePath);
        return $settings['url'] . '/' . $file_path;
    }
}
