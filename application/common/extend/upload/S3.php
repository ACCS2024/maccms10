<?php
namespace app\common\extend\upload;

use Aws\S3\S3Client;

class S3
{
    public $name = 'S3';
    public $ver = '1.0';
    private $config = [];

    public function __construct($config = []) {
        $this->config = $config;
    }

    public function submit($file_path)
    {
        $bucket = $GLOBALS['config']['upload']['api']['s3']['bucket'];
        $accessKey = $GLOBALS['config']['upload']['api']['s3']['accesskey'];
        $secretKey = $GLOBALS['config']['upload']['api']['s3']['secretkey'];
        $region = $GLOBALS['config']['upload']['api']['s3']['region'];
        $endpoint = !empty($GLOBALS['config']['upload']['api']['s3']['endpoint']) ? $GLOBALS['config']['upload']['api']['s3']['endpoint'] : '';
        $basepath = !empty($GLOBALS['config']['upload']['api']['s3']['basepath']) ? $GLOBALS['config']['upload']['api']['s3']['basepath'] : '';
        $domain = !empty($GLOBALS['config']['upload']['api']['s3']['domain']) ? $GLOBALS['config']['upload']['api']['s3']['domain'] : '';

        $options = [
            'region'  => $region,
            'version' => '2006-03-01',
            'credentials' => [
                'key'    => $accessKey,
                'secret' => $secretKey
            ]
        ];
        if (!empty($endpoint)) {
            $options['endpoint'] = $endpoint;
            $options['use_path_style_endpoint'] = true;
        }
        $filePath = ROOT_PATH . $file_path;
        if (!is_file($filePath) || !is_readable($filePath)) { return $file_path; }
        $body = fopen($filePath, 'rb');
        if ($body === false) { return $file_path; }
        try {
            $s3 = new S3Client($options);
            $key = !empty($basepath) ? rtrim($basepath, '/') . '/' . ltrim($file_path, '/') : $file_path;
            $result = $s3->putObject([
                'Bucket' => $bucket,
                'Key'    => $key,
                'Body'   => $body,
                'ACL'    => 'public-read'
            ]);
        } catch (\Throwable $e) {
            return $file_path;
        } finally {
            if (is_resource($body)) { fclose($body); }
        }

        if (!empty($domain)) {
            $url = rtrim($domain, '/') . '/' . $bucket . '/' . $key;
        } else {
            $url = $result['ObjectURL'] ?? '';
        }
        return StorageResult::complete($file_path, $url, $this->config);
    }
}
