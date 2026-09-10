<?php
declare(strict_types=1);
namespace app\common\util;

/** One explicit proxy policy for framework consumers, rate limits and legacy helpers. */
final class ClientIp
{
    private const HEADERS = ['x-forwarded-for','x-real-ip','cf-connecting-ip','ali-cdn-real-ip'];

    public static function fromRequest(\think\Request $request): string
    {
        $options = \think\facade\Config::get('client_ip', []);
        if (!is_array($options)) { throw new \InvalidArgumentException('Invalid client IP configuration'); }
        $header = array_key_exists('forwarded_header', $options) ? $options['forwarded_header'] : 'x-forwarded-for';
        if (!is_string($header) || !in_array($header, self::HEADERS, true)) {
            throw new \InvalidArgumentException('Invalid client IP forwarded header');
        }
        $server = $request->server();
        $key = 'HTTP_' . strtoupper(str_replace('-', '_', $header));
        $value = array_key_exists($key, $server) ? $server[$key] : $request->header($header);
        return self::resolve($server['REMOTE_ADDR'] ?? null, $value,
            array_key_exists('trusted_proxies', $options) ? $options['trusted_proxies'] : [], $header);
    }

    public static function resolve(mixed $peer, mixed $forwarded, mixed $trusted = [], string $header = 'x-forwarded-for'): string
    {
        if (!in_array($header, self::HEADERS, true)) { throw new \InvalidArgumentException('Invalid client IP forwarded header'); }
        $ranges = self::ranges($trusted);
        $peer = self::address($peer);
        if ($peer === null) { return '0.0.0.0'; }
        if (!self::trusted($peer, $ranges) || !is_string($forwarded) || $forwarded === '' || strlen($forwarded) > 8192) {
            return $peer;
        }
        if ($header !== 'x-forwarded-for') {
            return self::address(trim($forwarded, " \t")) ?? $peer;
        }
        $chain = explode(',', $forwarded);
        $current = $peer;
        $hops = 0;
        // Each trusted proxy must append its direct peer. Anything left of the first
        // untrusted hop belongs to that client and cannot replace its actual address.
        while ($chain !== [] && self::trusted($current, $ranges)) {
            if (++$hops > 32) { return $peer; }
            $next = self::address(trim(array_pop($chain), " \t"));
            if ($next === null) { return $peer; }
            $current = $next;
        }
        return $current;
    }

    private static function address(mixed $value): ?string
    {
        if (!is_string($value) || strlen($value) > 45 || filter_var($value, FILTER_VALIDATE_IP) === false) {
            return null;
        }
        return inet_ntop(inet_pton($value));
    }

    private static function ranges(mixed $configured): array
    {
        if (is_string($configured)) { $configured = trim($configured) === '' ? [] : explode(',', $configured); }
        if (!is_array($configured) || !array_is_list($configured) || count($configured) > 128) {
            throw new \InvalidArgumentException('Invalid client IP trusted proxy list');
        }
        $ranges = [];
        foreach ($configured as $range) {
            if (!is_string($range) || strlen($range) > 64) { throw new \InvalidArgumentException('Invalid client IP trusted proxy range'); }
            $parts = explode('/', trim($range));
            $address = self::address($parts[0]);
            if ($address === null || count($parts) > 2) { throw new \InvalidArgumentException('Invalid client IP trusted proxy range'); }
            $packed = inet_pton($address);
            $maximum = strlen($packed) * 8;
            $bits = $parts[1] ?? (string)$maximum;
            if (!preg_match('/^(?:0|[1-9][0-9]{0,2})$/D', $bits) || (int)$bits > $maximum) {
                throw new \InvalidArgumentException('Invalid client IP trusted proxy prefix');
            }
            $ranges[] = [$packed, (int)$bits];
        }
        return $ranges;
    }

    private static function trusted(string $address, array $ranges): bool
    {
        $packed = inet_pton($address);
        foreach ($ranges as [$network, $bits]) {
            if (strlen($packed) !== strlen($network)) { continue; }
            $bytes = intdiv($bits, 8);
            $remainder = $bits % 8;
            if (substr($packed, 0, $bytes) === substr($network, 0, $bytes)
                && ($remainder === 0 || ((ord($packed[$bytes]) ^ ord($network[$bytes])) & (255 << (8 - $remainder))) === 0)) {
                return true;
            }
        }
        return false;
    }
}
