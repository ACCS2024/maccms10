<?php
namespace Upyun;

use Upyun\Api\Rest;
use Upyun\Api\Form;
use GuzzleHttp\Psr7;

class Uploader
{
    /**
     * @var Config
     */
    protected $config;

    protected $useBlock = false;


    public function __construct(Config $config)
    {
        $this->config = $config;
    }

    public function upload($path, $file, $params, $withAsyncProcess)
    {
        $stream = Psr7\Utils::streamFor($file);
        $size = $stream->getSize();
        $useBlock = $this->needUseBlock($size);

        if ($withAsyncProcess) {
            $req = new Form($this->config);
            return $req->upload($path, $stream, $params);
        }

        if (! $useBlock) {
            $req = new Rest($this->config);
            return $req->request('PUT', $path)
                       ->withHeaders($params)
                       ->withFile($stream)
                       ->send();
        } else {
            return $this->pointUpload($path, $stream, $params);
        }
    }

    /**
     *  断点续传
     * @param $path
     * @param $stream
     * @param $params
     *
     * @return mixed|\Psr\Http\Message\ResponseInterface
     * @throws \Exception
     */
    private function pointUpload($path, $stream, $params)
    {
        $size = $stream->getSize();
        if (!is_int($size) || $size <= 0) {
            throw new \InvalidArgumentException('Block upload requires a known positive stream size');
        }
        $req = new Rest($this->config);
        $headers = array();
        if (is_array($params)) {
            foreach ($params as $key => $val) {
                $headers['X-Upyun-Meta-' . $key] = $val;
            }
        }
        $res = $req->request('PUT', $path)
            ->withHeaders(array_merge(array(
                'X-Upyun-Multi-Stage' => 'initiate',
                'X-Upyun-Multi-Type' => Psr7\MimeType::fromFilename($path),
                'X-Upyun-Multi-Length' => $size,
            ), $headers))
            ->send();
        if ($res->getStatusCode() !== 204) {
            throw new \Exception('init request failed when poinit upload!');
        }

        $uuid = $res->getHeaderLine('X-Upyun-Multi-Uuid');
        if ($uuid === '' || !preg_match('/^[A-Za-z0-9_-]+$/D', $uuid) ||
            ($res->hasHeader('X-Upyun-Next-Part-Id') && $res->getHeaderLine('X-Upyun-Next-Part-Id') !== '0')) {
            throw new \RuntimeException('Invalid block upload initialization response');
        }
        $blockSize = 1024 * 1024;
        $uploaded = 0;
        for ($partId = 0; $uploaded < $size; ++$partId) {
            $expectedLength = min($blockSize, $size - $uploaded);
            $fileBlock = '';
            while (strlen($fileBlock) < $expectedLength) {
                $chunk = $stream->read($expectedLength - strlen($fileBlock));
                if ($chunk === '') {
                    throw new \RuntimeException('Upload stream ended before its declared size');
                }
                $fileBlock .= $chunk;
            }
            $req = new Rest($this->config);
            $res = $req->request('PUT', $path)
                ->withHeaders(array(
                    'X-Upyun-Multi-Stage' => 'upload',
                    'X-Upyun-Multi-Uuid' => $uuid,
                    'X-Upyun-Part-Id' => $partId
                ))
                ->withFile(Psr7\Utils::streamFor($fileBlock))
                ->send();

            if ($res->getStatusCode() !== 204) {
                throw new \Exception('upload request failed when poinit upload!');
            }
            $uploaded += $expectedLength;
            $expectedNext = $uploaded === $size ? '-1' : (string)($partId + 1);
            if ($res->getHeaderLine('X-Upyun-Next-Part-Id') !== $expectedNext ||
                ($res->hasHeader('X-Upyun-Multi-Uuid') && $res->getHeaderLine('X-Upyun-Multi-Uuid') !== $uuid)) {
                throw new \RuntimeException('Invalid block upload progress response');
            }
        }

        // A fresh request must not carry the previous block's stream/body or ID.
        $req = new Rest($this->config);
        $res = $req->request('PUT', $path)
            ->withHeaders(array(
                'X-Upyun-Multi-Uuid' => $uuid,
                'X-Upyun-Multi-Stage' => 'complete'
            ))
            ->send();

        if ($res->getStatusCode() != 204 && $res->getStatusCode() != 201) {
            throw new \Exception('end request failed when poinit upload!');
        }
        return $res;
    }

    private function needUseBlock($fileSize)
    {
        if ($this->config->uploadType === 'BLOCK') {
            return true;
        } elseif ($this->config->uploadType === 'AUTO' &&
                  $fileSize >= $this->config->sizeBoundary) {
            return true;
        } else {
            return false;
        }
    }
}
