<?php
namespace app\common\util;

/** Legacy provider protocol; credentials are sent only to its fixed HTTPS endpoints. */
class SinaUpload
{
    public $_config = [];
    private const LOGIN_URL = 'https://login.sina.com.cn/sso/login.php';
    private const UPLOAD_URL = 'https://picupload.service.weibo.com/interface/pic_upload.php';
    private const MAX_RESPONSE = 1048576;

    public function __construct($config = []) { $this->config($config); }

    public function config($config = [])
    {
        $this->_config = is_array($config) ? array_merge($this->_config, $config) : [];
    }

    public function check()
    {
        $now = time();
        $stamp = $this->_config['time'] ?? null;
        $cookie = $this->_config['cookie'] ?? null;
        if ((is_int($stamp) || is_string($stamp) && preg_match('/^[0-9]{1,10}$/D', $stamp))
            && (int)$stamp <= $now && $now - (int)$stamp < 20 * 3600 && self::validCookie($cookie)) {
            return ['code'=>'1', 'msg'=>'ok'];
        }
        $cookie = $this->login($this->_config['user'] ?? null, $this->_config['pwd'] ?? null);
        if ($cookie === '') {
            return ['code'=>'203', 'msg'=>'获取新浪微博cookie失败，请检查账号状态或重新配置'];
        }
        try {
            $config = config('maccms');
            if (!is_array($config) || !is_array($config['upload'] ?? null)
                || !is_array($config['upload']['api'] ?? null)) {
                throw new \RuntimeException('Invalid upload configuration');
            }
            $updated = array_replace($this->_config, ['cookie'=>$cookie, 'time'=>$now]);
            $config['upload']['api']['weibo'] = $updated;
            $path = APP_PATH . 'extra/maccms.php';
            mac_arr2file($path, $config);
            // The legacy helper returns void even when its underlying write fails.
            $expected = "<?php\nreturn " . var_export($config, true) . ';';
            if (!is_file($path) || @file_get_contents($path) !== $expected) {
                throw new \RuntimeException('Provider session did not persist');
            }
            $this->_config = $updated;
            return ['code'=>'1', 'msg'=>'ok'];
        } catch (\Throwable $error) {
            return ['code'=>'202', 'msg'=>'写入微博登录状态失败'];
        }
    }

    public function login($user, $password)
    {
        if (!is_string($user) || $user === '' || strlen($user) > 1024
            || !is_string($password) || $password === '' || strlen($password) > 4096) { return ''; }
        return $this->loginPost(self::LOGIN_URL . '?client=ssologin.js(v1.4.15)', [
            'entry'=>'sso', 'gateway'=>'1', 'from'=>'null', 'savestate'=>'30', 'useticket'=>'0',
            'pagerefer'=>'', 'vsnf'=>'1', 'su'=>base64_encode($user), 'service'=>'sso', 'sp'=>$password,
            'sr'=>'1920*1080', 'encoding'=>'UTF-8', 'cdult'=>'3', 'domain'=>'sina.com.cn',
            'prelt'=>'0', 'returntype'=>'TEXT',
        ]);
    }

    public function loginPost($url, $data)
    {
        if (!is_string($url) || !is_array($data)) { return ''; }
        $parts = parse_url($url);
        if (!is_array($parts) || ($parts['scheme'] ?? '') !== 'https'
            || ($parts['host'] ?? '') !== 'login.sina.com.cn' || ($parts['path'] ?? '') !== '/sso/login.php'
            || isset($parts['user']) || isset($parts['pass']) || isset($parts['port']) || isset($parts['fragment'])
            || preg_match('/[\\\\\x00-\x20\x7f]/', $url)) { return ''; }
        foreach ($data as $value) { if (!is_string($value)) { return ''; } }
        $response = self::transfer($url, http_build_query($data, '', '&', PHP_QUERY_RFC3986));
        if ($response === null) { return ''; }
        if (preg_match('/^Set-Cookie:\s*(SUB=[^;\r\n]+)(?:;|\r?$)/mi', $response['headers'], $match)
            && self::validCookie($match[1])) { return $match[1] . ';'; }
        return '';
    }

    public function getSubstr($text, $left, $right)
    {
        if (!is_string($text) || !is_string($left) || $left === '' || !is_string($right) || $right === '') { return ''; }
        $start = strpos($text, $left);
        if ($start === false) { return ''; }
        $start += strlen($left);
        $end = strpos($text, $right, $start);
        return $end === false ? '' : substr($text, $start, $end - $start);
    }

    public function upload($file, $multipart, $cookie)
    {
        $failure = ['code'=>'301', 'msg'=>'上传错误'];
        if (!is_string($file) || $file === '' || str_contains($file, "\0") || !is_bool($multipart)
            || !self::validCookie($cookie) || !is_file($file) || !is_readable($file)) { return $failure; }
        try {
            $size = $this->_config['size'] ?? 'large';
            if ($size === '') { $size = 'large'; }
            if (!is_string($size) || !preg_match('/^[a-zA-Z0-9_-]{1,32}$/D', $size)) { return $failure; }
            $bytes = @filesize($file);
            if (!is_int($bytes) || $bytes <= 0 || $bytes > ImageProcessor::MAX_BYTES) { return $failure; }
            if ($multipart) {
                $post = ['pic1'=>new \CURLFile(realpath($file))];
            } else {
                $source = @file_get_contents($file);
                if (!is_string($source) || strlen($source) !== $bytes) { return $failure; }
                $post = ['b64_data'=>base64_encode($source)];
            }
            $url = self::UPLOAD_URL . '?mime=image%2Fjpeg&data=base64&url=0&markpos=1&logo=&nick=0&marks=1&app=miniblog';
            if ($multipart) { $url .= '&cb=' . rawurlencode('https://weibo.com/aj/static/upimgback.html?_wv=5&callback=STK_ijax_' . time()); }
            $response = self::transfer($url, $post, $cookie);
            if ($response === null) { return $failure; }
            $start = strpos($response['body'], '{'); $end = strrpos($response['body'], '}');
            if ($start === false || $end === false || $end <= $start) { return $failure; }
            $decoded = json_decode(substr($response['body'], $start, $end - $start + 1), true);
            $picture = is_array($decoded) ? ($decoded['data']['pics']['pic_1'] ?? null) : null;
            if (!is_array($picture) || !is_string($picture['pid'] ?? null)
                || !preg_match('/^[a-zA-Z0-9_-]{1,128}$/D', $picture['pid'])
                || PointsBalance::amount($picture['width'] ?? null) === null
                || PointsBalance::amount($picture['height'] ?? null) === null) { return $failure; }
            return ['code'=>'200', 'width'=>$picture['width'], 'height'=>$picture['height'], 'size'=>$size,
                'pid'=>$picture['pid'], 'url'=>'https://ws3.sinaimg.cn/' . $size . '/' . $picture['pid'] . '.jpg'];
        } catch (\Throwable $error) { return $failure; }
    }

    private static function validCookie($cookie): bool
    {
        return is_string($cookie) && preg_match('/^SUB=[\x21\x23-\x2b\x2d-\x3a\x3c-\x5b\x5d-\x7e]{1,4096};?$/D', $cookie) === 1;
    }

    private static function transfer(string $url, $post, string $cookie = ''): ?array
    {
        $handle = null;
        try {
            $handle = curl_init($url);
            if ($handle === false) { return null; }
            $body = ''; $headers = '';
            $options = [
                CURLOPT_POST=>true, CURLOPT_POSTFIELDS=>$post, CURLOPT_RETURNTRANSFER=>true,
                CURLOPT_SSL_VERIFYPEER=>true, CURLOPT_SSL_VERIFYHOST=>2,
                CURLOPT_PROTOCOLS=>CURLPROTO_HTTPS, CURLOPT_REDIR_PROTOCOLS=>CURLPROTO_HTTPS,
                CURLOPT_FOLLOWLOCATION=>false, CURLOPT_CONNECTTIMEOUT=>5, CURLOPT_TIMEOUT=>30,
                CURLOPT_VERBOSE=>false, CURLOPT_NOSIGNAL=>true,
                CURLOPT_WRITEFUNCTION=>static function ($handle, string $chunk) use (&$body): int {
                    if (strlen($body) + strlen($chunk) > self::MAX_RESPONSE) { return 0; }
                    $body .= $chunk; return strlen($chunk);
                },
                CURLOPT_HEADERFUNCTION=>static function ($handle, string $chunk) use (&$headers): int {
                    if (strlen($headers) + strlen($chunk) > 65536) { return 0; }
                    $headers .= $chunk; return strlen($chunk);
                },
            ];
            if ($cookie !== '') { $options[CURLOPT_HTTPHEADER] = ['Cookie: ' . $cookie]; }
            if (!curl_setopt_array($handle, $options) || curl_exec($handle) === false
                || curl_getinfo($handle, CURLINFO_HTTP_CODE) !== 200) { return null; }
            return ['body'=>$body, 'headers'=>$headers];
        } catch (\Throwable $error) {
            return null;
        } finally {
            if ($handle !== null && $handle !== false) { curl_close($handle); }
        }
    }
}
