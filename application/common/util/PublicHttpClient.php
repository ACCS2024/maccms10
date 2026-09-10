<?php
namespace app\common\util;

/** HTTP transport for untrusted public URLs. Trusted internal services use their own clients. */
final class PublicHttpClient
{
    public const MAX_RESPONSE_BYTES = 20971520;

    public static function isPublicIp($ip): bool
    {
        if (!is_string($ip) || filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_GLOBAL_RANGE) === false) {
            return false;
        }
        $packed = inet_pton($ip);
        if (strlen($packed) === 4) {
            // Multicast is globally scoped in FILTER_FLAG_GLOBAL_RANGE, but is not a unicast HTTP target.
            return ord($packed[0]) < 224;
        }
        // Accept global unicast only; reject transition mechanisms with embedded IPv4 addresses.
        return (ord($packed[0]) & 0xe0) === 0x20 && substr($packed, 0, 2) !== "\x20\x02";
    }

    /** @return array{url:string,host:string,port:int,scheme:string,ips:array,resolve:array}|null */
    public static function resolve($url): ?array
    {
        if (!is_string($url) || $url === '' || strlen($url) > 8192 || preg_match('/[\x00-\x20\x7f\\\\]/', $url)) {
            return null;
        }
        $parts = parse_url($url);
        if (!is_array($parts) || empty($parts['host']) || empty($parts['scheme'])
            || isset($parts['user']) || isset($parts['pass'])) {
            return null;
        }
        $scheme = strtolower($parts['scheme']);
        if (!in_array($scheme, ['http', 'https'], true)) {
            return null;
        }
        $host = rtrim(strtolower(trim($parts['host'], '[]')), '.');
        $isIp = filter_var($host, FILTER_VALIDATE_IP) !== false;
        if (!$isIp && !preg_match('/^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/D', $host)) {
            return null;
        }
        $port = $parts['port'] ?? ($scheme === 'https' ? 443 : 80);
        if ($port < 1 || $port > 65535) {
            return null;
        }
        $authority = str_contains($host, ':') ? '[' . $host . ']' : $host;
        if (isset($parts['port'])) {
            $authority .= ':' . $port;
        }
        $url = $scheme . '://' . $authority . ($parts['path'] ?? '/')
            . (isset($parts['query']) ? '?' . $parts['query'] : '');
        if (function_exists('mac_is_official_url') && mac_is_official_url($url)) {
            return null;
        }
        $ips = [];
        if ($isIp) {
            $ips[] = $host;
        } else {
            $records = @dns_get_record($host, DNS_A | DNS_AAAA);
            foreach (is_array($records) ? $records : [] as $record) {
                if (isset($record['ip'])) { $ips[] = $record['ip']; }
                if (isset($record['ipv6'])) { $ips[] = $record['ipv6']; }
            }
            if ($ips === []) {
                $ips = @gethostbynamel($host) ?: [];
            }
        }
        if ($ips === []) {
            return null;
        }
        foreach ($ips as $ip) {
            if (!self::isPublicIp($ip)) {
                return null;
            }
        }
        $ips = array_values(array_unique($ips));
        $addresses = array_map(static fn($ip) => str_contains($ip, ':') ? '[' . $ip . ']' : $ip, $ips);
        return ['url' => $url, 'host' => $host, 'port' => $port, 'scheme' => $scheme, 'ips' => $ips,
            'resolve' => $isIp ? [] : [$host . ':' . $port . ':' . implode(',', $addresses)]];
    }

    public static function request($url, string $method = 'GET', $data = null, $headers = [], $cookie = '', $timeout = 10, int $maxBytes = self::MAX_RESPONSE_BYTES): string|false
    {
        if (!function_exists('curl_init') || !in_array($method, ['GET', 'POST'], true)
            || !is_array($headers) || !is_string($cookie) || preg_match('/[\r\n\x00]/', $cookie)) {
            return false;
        }
        if ($method === 'POST') {
            if (!is_string($data) && !is_array($data) && $data !== null) { return false; }
            foreach (is_array($data) ? $data : [] as $value) {
                if (!is_scalar($value) && $value !== null && !$value instanceof \CURLFile && !$value instanceof \CURLStringFile) {
                    return false;
                }
            }
        }
        foreach ($headers as $header) {
            if (!is_string($header) || preg_match('/[\r\n\x00]/', $header)
                || !preg_match('/^([A-Za-z0-9!#$%&\'*+.^_`|~-]+):/', $header, $match)
                || in_array(strtolower($match[1]), ['host', 'content-length', 'transfer-encoding', 'connection', 'proxy-authorization'], true)) {
                return false;
            }
        }
        $deadline = microtime(true) + max(1, min(300, (int)$timeout));
        $maxBytes = max(1, min(52428800, $maxBytes));
        for ($redirects = 0; $redirects <= 5; $redirects++) {
            $target = self::resolve($url);
            $remaining = (int)ceil(($deadline - microtime(true)) * 1000);
            if ($target === null || $remaining <= 0) {
                return false;
            }
            $body = '';
            $location = null;
            $headerBytes = 0;
            $ch = curl_init($target['url']);
            if ($ch === false) { return false; }
            try {
                $options = [
                    CURLOPT_FOLLOWLOCATION => false,
                    CURLOPT_PROXY => '',
                    CURLOPT_NOPROXY => '*',
                    CURLOPT_RESOLVE => $target['resolve'],
                    CURLOPT_CONNECTTIMEOUT_MS => min(5000, $remaining),
                    CURLOPT_TIMEOUT_MS => $remaining,
                    CURLOPT_SSL_VERIFYPEER => true,
                    CURLOPT_SSL_VERIFYHOST => 2,
                    CURLOPT_USERAGENT => 'MacCMS/1.0',
                    CURLOPT_HTTPHEADER => $headers,
                    CURLOPT_COOKIE => $cookie,
                    CURLOPT_ENCODING => '',
                    CURLOPT_HEADERFUNCTION => static function ($handle, $line) use (&$location, &$headerBytes) {
                        $length = strlen($line);
                        $headerBytes += $length;
                        if ($headerBytes > 65536) { return 0; }
                        if (str_starts_with($line, 'HTTP/')) { $location = null; }
                        if (stripos($line, 'Location:') === 0) { $location = trim(substr($line, 9)); }
                        return $length;
                    },
                    CURLOPT_WRITEFUNCTION => static function ($handle, $chunk) use (&$body, $maxBytes) {
                        $length = strlen($chunk);
                        if (strlen($body) + $length > $maxBytes) { return 0; }
                        $body .= $chunk;
                        return $length;
                    },
                ];
                if (defined('CURLOPT_PROTOCOLS_STR')) {
                    $options[CURLOPT_PROTOCOLS_STR] = 'http,https';
                } else {
                    $options[CURLOPT_PROTOCOLS] = CURLPROTO_HTTP | CURLPROTO_HTTPS;
                }
                if ($method === 'POST') {
                    $options[CURLOPT_POST] = true;
                    $options[CURLOPT_POSTFIELDS] = $data;
                } else {
                    $options[CURLOPT_HTTPGET] = true;
                }
                if (!curl_setopt_array($ch, $options) || curl_exec($ch) === false) {
                    return false;
                }
                $status = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
                $peer = curl_getinfo($ch, CURLINFO_PRIMARY_IP);
                if (!self::isPublicIp($peer) || !in_array(inet_pton($peer), array_map('inet_pton', $target['ips']), true)) {
                    return false;
                }
            } catch (\Throwable $e) {
                return false;
            } finally {
                curl_close($ch);
            }
            if (!in_array($status, [301, 302, 303, 307, 308], true) || $location === null || $location === '') {
                return $body;
            }
            if ($redirects === 5) { return false; }
            $nextUrl = self::redirectUrl($target['url'], $location);
            // Validate before carrying any headers or POST data to another destination.
            $next = self::resolve($nextUrl);
            if ($next === null || ($target['scheme'] === 'https' && $next['scheme'] !== 'https')) {
                return false;
            }
            $crossOrigin = [$target['scheme'], $target['host'], $target['port']] !== [$next['scheme'], $next['host'], $next['port']];
            if ($crossOrigin) {
                if ($method === 'POST' && in_array($status, [307, 308], true)) {
                    return false;
                }
                $headers = array_values(array_filter($headers, static fn($header) => preg_match('/^(Accept|Accept-Language|User-Agent|Range):/i', $header)));
                $cookie = '';
            }
            if ($status === 303 || ($method === 'POST' && in_array($status, [301, 302], true))) {
                $method = 'GET';
                $data = null;
                $headers = array_values(array_filter($headers, static fn($header) => stripos($header, 'Content-') !== 0));
            }
            $url = $next['url'];
        }
        return false;
    }

    private static function redirectUrl(string $base, string $location): ?string
    {
        if ($location === '' || preg_match('/[\x00-\x20\x7f\\\\]/', $location)) { return null; }
        if (preg_match('/^[A-Za-z][A-Za-z0-9+.-]*:/', $location)) { return $location; }
        $parts = parse_url($base);
        if (str_starts_with($location, '//')) { return $parts['scheme'] . ':' . $location; }
        $relative = parse_url($location);
        if ($relative === false) { return null; }
        $authority = $parts['scheme'] . '://' . $parts['host'] . (isset($parts['port']) ? ':' . $parts['port'] : '');
        $path = $relative['path'] ?? '';
        if ($path === '') {
            $path = $parts['path'] ?? '/';
            $query = $relative['query'] ?? ($parts['query'] ?? null);
        } else {
            $query = $relative['query'] ?? null;
            if (!str_starts_with($path, '/')) { $path = substr($parts['path'] ?? '/', 0, strrpos($parts['path'] ?? '/', '/') + 1) . $path; }
            $segments = [];
            foreach (explode('/', $path) as $segment) {
                if ($segment === '..') { array_pop($segments); }
                elseif ($segment !== '.' && $segment !== '') { $segments[] = $segment; }
            }
            $path = '/' . implode('/', $segments) . (str_ends_with($path, '/') || str_ends_with($path, '/.') || str_ends_with($path, '/..') ? '/' : '');
        }
        return $authority . $path . ($query !== null ? '?' . $query : '');
    }
}
