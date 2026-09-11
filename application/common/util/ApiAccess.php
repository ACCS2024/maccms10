<?php
declare(strict_types=1);
namespace app\common\util;

/** Shared public/collector API gates that unwind through the framework response pipeline. */
final class ApiAccess
{
    public static function enforce($settings): void
    {
        if (!is_array($settings) || !in_array($settings['status'] ?? null, [1,'1'], true)) { self::stop('closed', 503); }
        if (!in_array($settings['charge'] ?? null, [0,1,'0','1'], true)) { self::stop('closed', 503); }
        if ((string)$settings['charge'] === '0') { return; }
        $auth = array_key_exists('auth', $settings) ? $settings['auth'] : '';
        if (!is_string($auth) || strlen($auth) > 16384 || preg_match('/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/', $auth)) { self::stop('closed', 503); }
        $entries = preg_split('/[#\r\n]+/', $auth);
        if (count($entries) > 128) { self::stop('closed', 503); }
        $addresses = ['127.0.0.1'=>true, '::1'=>true];
        $domains = [];
        foreach ($entries as $entry) {
            $entry = trim($entry);
            if ($entry === '') { continue; }
            if (filter_var($entry, FILTER_VALIDATE_IP) !== false) {
                $addresses[inet_ntop(inet_pton($entry))] = true;
                continue;
            }
            $entry = strtolower(rtrim($entry, '.'));
            if (strlen($entry) > 253 || preg_match('/^[0-9.]+$/D', $entry)
                || filter_var($entry, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) === false) { self::stop('closed', 503); }
            $domains[$entry] = true;
            if (count($domains) > 32) { self::stop('closed', 503); }
        }
        $peer = request()->server('REMOTE_ADDR');
        if (!is_string($peer) || filter_var($peer, FILTER_VALIDATE_IP) === false || in_array($peer, ['0.0.0.0','::'], true)) {
            self::stop(lang('api/auth_err'), 403);
        }
        try { $ip = ClientIp::fromRequest(request()); }
        catch (\Throwable $error) { self::stop('closed', 503); }
        if (in_array($ip, ['0.0.0.0','::'], true)) { self::stop(lang('api/auth_err'), 403); }
        if (isset($addresses[$ip])) { return; }
        foreach ($domains as $domain=>$_) {
            try { $resolved = @gethostbyname($domain.'.'); }
            catch (\Throwable $error) { continue; }
            if (filter_var($resolved, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false && $resolved === $ip) { return; }
        }
        self::stop(lang('api/auth_err'), 403);
    }

    private static function stop(string $message, int $status): never
    {
        throw new \think\exception\HttpResponseException(\think\Response::create($message, 'html', $status)->header([
            'Content-Type'=>'text/plain; charset=utf-8', 'Cache-Control'=>'private, no-store', 'X-Content-Type-Options'=>'nosniff',
        ]));
    }
}
