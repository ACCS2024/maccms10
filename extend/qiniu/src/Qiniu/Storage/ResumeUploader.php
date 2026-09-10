<?php
namespace Qiniu\Storage;

use Qiniu\Config;
use Qiniu\Http\Client;
use Qiniu\Http\Error;

/**
 * 断点续上传类, 该类主要实现了断点续上传中的分块上传,
 * 以及相应地创建块和创建文件过程.
 *
 * @link http://developer.qiniu.com/docs/v6/api/reference/up/mkblk.html
 * @link http://developer.qiniu.com/docs/v6/api/reference/up/mkfile.html
 */
final class ResumeUploader
{
    private $upToken;
    private $key;
    private $inputStream;
    private $size;
    private $params;
    private $mime;
    private $contexts;
    private $host;
    private $currentUrl;
    private $config;

    /**
     * 上传二进制流到七牛
     *
     * @param $upToken    上传凭证
     * @param $key        上传文件名
     * @param $inputStream 上传二进制流
     * @param $size       上传流的大小
     * @param $params     自定义变量
     * @param $mime       上传数据的mimeType
     *
     * @link http://developer.qiniu.com/docs/v6/api/overview/up/response/vars.html#xvar
     */
    public function __construct(
        $upToken,
        $key,
        $inputStream,
        $size,
        $params,
        $mime,
        $config
    ) {

        $this->upToken = $upToken;
        $this->key = $key;
        $this->inputStream = $inputStream;
        $this->size = $size;
        $this->params = $params;
        $this->mime = $mime;
        $this->contexts = array();
        $this->config = $config;

        list($accessKey, $bucket, $err) = \Qiniu\explodeUpToken($upToken);
        if ($err != null) {
            throw new \InvalidArgumentException($err);
        }

        if (!is_resource($inputStream) || get_resource_type($inputStream) !== 'stream' ||
            !is_int($size) || $size < 0) {
            throw new \InvalidArgumentException('Invalid upload stream or size');
        }
        $upHost = $config->getUpHost($accessKey, $bucket);
        $this->host = $upHost;
    }

    /**
     * 上传操作
     */
    public function upload($fname)
    {
        $uploaded = 0;
        while ($uploaded < $this->size) {
            $blockSize = $this->blockSize($uploaded);
            $data = '';
            while (strlen($data) < $blockSize) {
                $chunk = fread($this->inputStream, $blockSize - strlen($data));
                if ($chunk === false || $chunk === '') {
                    throw new \RuntimeException('file can not be read completely');
                }
                $data .= $chunk;
            }
            $crc = \Qiniu\crc32_data($data);
            $response = $this->makeBlock($data, $blockSize);
            $ret = $response->json();
            if ($response->statusCode < 0) {
                list($accessKey, $bucket, $err) = \Qiniu\explodeUpToken($this->upToken);
                if ($err != null) {
                    return array(null, $err);
                }

                $upHostBackup = $this->config->getUpBackupHost($accessKey, $bucket);
                $this->host = $upHostBackup;
            }
            if ($response->needRetry() || ($response->ok() && !self::validBlock($ret, $crc, $blockSize))) {
                $response = $this->makeBlock($data, $blockSize);
                $ret = $response->json();
            }

            if (!$response->ok() || !self::validBlock($ret, $crc, $blockSize)) {
                if ($response->ok()) {
                    $response->error = 'Invalid block upload response';
                }
                return array(null, new Error($this->currentUrl, $response));
            }
            array_push($this->contexts, $ret['ctx']);
            $uploaded += $blockSize;
        }
        return $this->makeFile($fname);
    }

    /**
     * 创建块
     */
    private function makeBlock($block, $blockSize)
    {
        $url = $this->host . '/mkblk/' . $blockSize;
        return $this->post($url, $block);
    }

    private function fileUrl($fname)
    {
        $url = $this->host . '/mkfile/' . $this->size;
        $url .= '/mimeType/' . \Qiniu\base64_urlSafeEncode($this->mime);
        if ($this->key != null) {
            $url .= '/key/' . \Qiniu\base64_urlSafeEncode($this->key);
        }
        $url .= '/fname/' . \Qiniu\base64_urlSafeEncode($fname);
        if (!empty($this->params)) {
            foreach ($this->params as $key => $value) {
                $val = \Qiniu\base64_urlSafeEncode($value);
                $url .= "/$key/$val";
            }
        }
        return $url;
    }

    /**
     * 创建文件
     */
    private function makeFile($fname)
    {
        $url = $this->fileUrl($fname);
        $body = implode(',', $this->contexts);
        $response = $this->post($url, $body);
        if ($response->needRetry()) {
            $response = $this->post($url, $body);
        }
        if (!$response->ok()) {
            return array(null, new Error($this->currentUrl, $response));
        }
        return array($response->json(), null);
    }

    private function post($url, $data)
    {
        $this->currentUrl = $url;
        $headers = array('Authorization' => 'UpToken ' . $this->upToken,
            'Content-Type' => 'application/octet-stream');
        return Client::post($url, $data, $headers);
    }

    private static function validBlock($data, $crc, $blockSize)
    {
        return is_array($data) && isset($data['crc32'], $data['ctx'], $data['offset']) &&
            (is_int($data['crc32']) || is_string($data['crc32'])) &&
            (string)$data['crc32'] === $crc &&
            is_string($data['ctx']) && $data['ctx'] !== '' &&
            !preg_match('/[\x00-\x20,\x7f]/', $data['ctx']) &&
            (is_int($data['offset']) || is_string($data['offset'])) &&
            (string)$data['offset'] === (string)$blockSize;
    }

    private function blockSize($uploaded)
    {
        if ($this->size < $uploaded + Config::BLOCK_SIZE) {
            return $this->size - $uploaded;
        }
        return Config::BLOCK_SIZE;
    }
}
