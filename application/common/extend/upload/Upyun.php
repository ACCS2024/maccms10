<?php
namespace app\common\extend\upload;

use Upyun\Upyun as upOper;
use Upyun\Config;

class Upyun
{
    public $name = '又拍云存储';
    public $ver = '1.0';
    private $config = [];

    public function __construct($config = []) {
        $this->config = $config;
    }

    public function submit($file_path)
    {
        $bucket = $GLOBALS['config']['upload']['api']['upyun']['bucket'];
        $username = $GLOBALS['config']['upload']['api']['upyun']['username'];
        $pwd = $GLOBALS['config']['upload']['api']['upyun']['pwd'];

        require_once ROOT_PATH . 'extend/upyun/vendor/autoload.php';
        $bucketConfig = new Config($bucket, $username, $pwd);
        $client = new upOper($bucketConfig);
        $filePath = ROOT_PATH . $file_path;
        if (!is_file($filePath) || !is_readable($filePath)) { return $file_path; }
        $_file = fopen($filePath, 'rb');
        if ($_file === false) { return $file_path; }
        try {
            $result = $client->write($file_path, $_file);
        } catch (\Throwable $e) {
            return $file_path;
        } finally {
            if (is_resource($_file)) { fclose($_file); }
        }
        if ($result === false) { return $file_path; }
        $baseUrl = $GLOBALS['config']['upload']['api']['upyun']['url'] ?? '';
        return StorageResult::complete($file_path, rtrim($baseUrl, '/') . '/' . $file_path, $this->config);
    }
}
