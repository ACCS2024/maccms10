<?php
namespace app\common\extend\urlsend;

class Baidu
{
    public $name = '百度推送普通';
    public $ver = '1.0';
    private const ENDPOINT = 'https://data.zz.baidu.com/urls';
    private const MAX_URLS = 2000;

    public function submit($data)
    {
        if (!is_array($data) || !is_array($data['urls'] ?? null) || $data['urls'] === []
            || count($data['urls']) > self::MAX_URLS) {
            return ['code' => 100, 'msg' => '推送参数错误：每批需要 1 至 2000 条完整网址。'];
        }
        $token = $GLOBALS['config']['urlsend']['baidu']['token'] ?? null;
        $site = $GLOBALS['config']['site']['site_url'] ?? null;
        if (!is_string($token) || $token === '' || strlen($token) > 256 || preg_match('/[\x00-\x20\x7f]/', $token)
            || !is_string($site) || $site === '') {
            return ['code' => 100, 'msg' => '百度普通推送配置不完整，请检查站点地址和 Token。'];
        }
        // Some installations already store an absolute URL. Do not prepend a second scheme.
        if (!preg_match('~^https?://~i', $site)) {
            $scheme = $GLOBALS['http_type'] ?? null;
            if (!in_array($scheme, ['http://', 'https://'], true)) {
                return ['code' => 100, 'msg' => '百度普通推送站点协议配置无效。'];
            }
            $site = $scheme . $site;
        }
        $siteParts = self::urlParts($site);
        if ($siteParts === false || !in_array($siteParts['path'] ?? '', ['', '/'], true)
            || isset($siteParts['query']) || isset($siteParts['fragment'])) {
            return ['code' => 100, 'msg' => '百度普通推送站点地址无效，请填写已验证的 HTTP(S) 站点根地址。'];
        }
        $site = rtrim($site, '/');
        $urls = [];
        foreach ($data['urls'] as $url) {
            if (self::urlParts($url) === false) {
                return ['code' => 100, 'msg' => '推送网址格式无效，请检查协议、换行和嵌套输入。'];
            }
            $urls[$url] = $url;
        }
        // One request per submit call. A response count does not identify which URLs were accepted.
        $count = count($urls);
        $api = self::ENDPOINT . '?' . http_build_query(['site' => $site, 'token' => $token], '', '&', PHP_QUERY_RFC3986);
        $response = self::request($api, implode("\n", $urls));
        if (isset($response['code'])) { return $response; }
        $status = $response['status'];
        $json = json_decode($response['body'], true);
        if ($status !== 200) {
            return ['code' => 102, 'msg' => self::failureMessage($status, $json)];
        }
        if (isset($json['error']) && $json['error'] !== 0) {
            return ['code' => 102, 'msg' => self::failureMessage($status, $json)];
        }
        if (!is_array($json) || !is_int($json['success'] ?? null) || !is_int($json['remain'] ?? null)
            || $json['success'] < 0 || $json['success'] > $count || $json['remain'] < 0) {
            return ['code' => 101, 'msg' => '百度普通推送返回了无效统计，结果尚未确认。请在平台核对后再决定是否重试。'];
        }
        $rejected = [];
        foreach (['not_same_site', 'not_valid'] as $field) {
            $values = array_key_exists($field, $json) ? $json[$field] : [];
            if (!is_array($values) || !array_is_list($values)) {
                return ['code' => 101, 'msg' => '百度普通推送返回了无效拒绝列表，请在平台核对结果。'];
            }
            foreach ($values as $value) {
                if (!is_string($value)) {
                    return ['code' => 101, 'msg' => '百度普通推送返回了无效拒绝列表，请在平台核对结果。'];
                }
            }
            $rejected[$field] = count($values);
        }
        if ($json['success'] + array_sum($rejected) > $count) {
            return ['code' => 101, 'msg' => '百度普通推送返回的统计不一致，请在平台核对结果。'];
        }
        $result = ['code' => 1, 'msg' => '推送成功' . $json['success'] . '条；当天剩余可推' . $json['remain'] . '条。',
            'success' => $json['success'], 'remain' => $json['remain'], 'submitted' => $count] + $rejected;
        if ($json['success'] < $count || $json['remain'] === 0) {
            // Existing admin/cron callers stop on non-1 codes; retain confirmed counts without replaying anything.
            $result['code'] = 103;
            $result['msg'] .= $json['remain'] === 0 ? '当天配额已用尽，已停止后续推送。' : '本批存在未确认成功的网址，已停止后续推送。';
            $result['msg'] .= '请在百度平台核对结果，勿按成功数量推断网址顺序或整批重发。';
        }
        return $result;
    }

    private static function urlParts($url)
    {
        if (!is_string($url) || $url === '' || strlen($url) > 8192 || preg_match('/[\x00-\x20\x7f\\\\]/', $url)
            || filter_var($url, FILTER_VALIDATE_URL) === false) { return false; }
        $parts = parse_url($url);
        return is_array($parts) && in_array(strtolower($parts['scheme'] ?? ''), ['http', 'https'], true)
            && !empty($parts['host']) && !isset($parts['user']) && !isset($parts['pass']) ? $parts : false;
    }

    /** Fixed trusted service only; never follow redirects carrying a token or retry an uncertain POST. */
    private static function request(string $api, string $body): array
    {
        $curl = curl_init($api);
        if ($curl === false) { return ['code' => 101, 'msg' => '百度普通推送渠道暂不可用：无法初始化 HTTPS 请求。']; }
        $response = '';
        $headerBytes = 0;
        try {
            $options = [
                CURLOPT_POST => true,
                CURLOPT_POSTFIELDS => $body,
                CURLOPT_HTTPHEADER => ['Content-Type: text/plain', 'Accept: application/json'],
                CURLOPT_FOLLOWLOCATION => false,
                CURLOPT_PROXY => '',
                CURLOPT_NOPROXY => '*',
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_SSL_VERIFYHOST => 2,
                CURLOPT_CONNECTTIMEOUT_MS => 5000,
                CURLOPT_TIMEOUT_MS => 15000,
                CURLOPT_HEADERFUNCTION => static function ($handle, $line) use (&$headerBytes) {
                    $headerBytes += strlen($line);
                    return $headerBytes <= 16384 ? strlen($line) : 0;
                },
                CURLOPT_WRITEFUNCTION => static function ($handle, $chunk) use (&$response) {
                    if (strlen($response) + strlen($chunk) > 65536) { return 0; }
                    $response .= $chunk;
                    return strlen($chunk);
                },
            ];
            if (defined('CURLOPT_PROTOCOLS_STR')) { $options[CURLOPT_PROTOCOLS_STR] = 'https'; }
            else { $options[CURLOPT_PROTOCOLS] = CURLPROTO_HTTPS; }
            if (!curl_setopt_array($curl, $options) || curl_exec($curl) === false) {
                $tlsFailure = in_array(curl_errno($curl), [CURLE_SSL_CACERT, CURLE_SSL_CONNECT_ERROR, CURLE_SSL_CACERT_BADFILE], true);
                return ['code' => 101, 'msg' => $tlsFailure
                    ? '百度普通推送渠道暂不可用：HTTPS 证书或安全连接校验失败。请通过百度搜索资源平台手动提交，或在平台确认安全接口恢复后重试。'
                    : '百度普通推送请求未能完成，结果尚未确认。请在平台核对结果后再决定是否重试。'];
            }
            return ['status' => (int)curl_getinfo($curl, CURLINFO_RESPONSE_CODE), 'body' => $response];
        } catch (\Throwable $error) {
            return ['code' => 101, 'msg' => '百度普通推送请求异常，结果尚未确认。请在平台核对结果后再决定是否重试。'];
        } finally {
            curl_close($curl);
        }
    }

    private static function failureMessage(int $status, $json): string
    {
        $known = [
            'site error' => '站点尚未验证或站点地址不匹配，请在百度平台核对。',
            'site init fail' => '站点初始化失败，请在百度平台核对已验证的站点地址。',
            'token is not valid' => 'Token 未被接受，请在百度平台核对或重新获取。',
            'empty content' => '平台未接受推送内容。',
            'only 2000 urls are allowed once' => '每次最多推送 2000 条网址，请调整批次大小。',
            'over quota' => '当天推送配额已用尽，已停止后续推送。',
            'not found' => '推送接口暂不可用，请在百度平台核对。',
            'internal error, please try later' => '百度推送服务暂时异常，请先在平台核对本次结果。',
        ];
        $message = is_array($json) && is_string($json['message'] ?? null) ? $json['message'] : '';
        if (isset($known[$message])) { return '百度普通推送失败：' . $known[$message]; }
        if ($status >= 300 && $status < 400) { return '百度普通推送渠道发生重定向，已停止发送。请在百度平台核对接口。'; }
        return '百度普通推送未获有效确认（HTTP ' . $status . '），请在百度平台核对接口和本次结果。';
    }
}
