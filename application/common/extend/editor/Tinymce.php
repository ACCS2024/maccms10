<?php
namespace app\common\extend\editor;

class Tinymce {

    public $name = 'Tinymce';
    public $ver = '1.0';

    public function front($param)
    {

    }

    public function back($info='',$status=0,$data=[])
    {
        $location = is_array($data) ? ($data['file'] ?? null) : null;
        $success = in_array($status, [1, '1'], true) && is_string($location)
            && trim($location) !== '' && strlen($location) <= 8192
            && preg_match('//u', $location) === 1 && !preg_match('/[\x00-\x1f\x7f]/', $location);
        if ($success) {
            $httpStatus = 200;
            $payload = ['location' => $location];
        } else {
            // A declared failure is a rejected upload; malformed internal success data is a server error.
            $httpStatus = in_array($status, [0, '0', false], true) ? 400 : 500;
            $message = is_string($info) && $info !== '' && strlen($info) <= 4096 ? $info : 'Upload failed.';
            $payload = ['error' => ['message' => $message]];
        }
        if (!headers_sent()) {
            http_response_code($httpStatus);
            header('Content-Type: application/json; charset=utf-8');
            header('X-Content-Type-Options: nosniff');
        }
        echo json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
        exit;
    }
}
