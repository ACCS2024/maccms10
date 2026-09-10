<?php
namespace app\common\util;

/** Cache settings shared by lazy production stores and the isolated administrator probe. */
final class CacheConnection
{
    private const DRIVERS = [
        'file'=>\think\cache\driver\File::class,
        'redis'=>\app\common\cache\Redis::class,
        'memcached'=>\app\common\cache\Memcached::class,
        'memcache'=>\app\common\cache\Memcache::class,
    ];

    public static function configuration(array $app): array
    {
        $type = self::type(array_key_exists('cache_type', $app) ? $app['cache_type'] : 'file');
        $expire = self::expire($app['cache_time'] ?? null);
        $input = [];
        foreach (['host','port','username','password','db','timeout'] as $field) {
            if (array_key_exists('cache_'.$field, $app)) { $input[$field] = $app['cache_'.$field]; }
        }
        $stores = ['file'=>['type'=>'file', 'path'=>'', 'prefix'=>'', 'expire'=>$expire]];
        foreach (['redis','memcache','memcached'] as $name) {
            $stores[$name] = ['type'=>self::DRIVERS[$name], 'connection'=>$input, 'expire'=>$expire];
        }
        // Unselected stores remain lazy: unrelated old form fields cannot break a file-cache site.
        if ($type !== 'file') { self::options($type, $stores[$type]); }
        return ['default'=>$type, 'stores'=>$stores];
    }

    public static function type($value): string
    {
        if (!is_string($value)) { throw new \InvalidArgumentException('Invalid cache type'); }
        $value = strtolower(trim($value));
        if ($value === '') { $value = 'file'; }
        if (!isset(self::DRIVERS[$value])) { throw new \InvalidArgumentException('Unsupported cache type'); }
        return $value;
    }

    public static function expire($value): int
    {
        if ($value === null || $value === '') { return 60; }
        if ((!is_int($value) && !is_string($value)) || !preg_match('/^-?[0-9]{1,10}$/D', (string)$value)
            || (int)$value > 2147483647) { throw new \InvalidArgumentException('Invalid cache lifetime'); }
        return (int)$value > 0 ? (int)$value : 60;
    }

    public static function timeout($value): float
    {
        if ($value === null || $value === '') { return 1.5; }
        if ((!is_int($value) && !is_float($value) && !is_string($value))
            || (is_string($value) && !preg_match('/^-?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)$/D', $value))) {
            throw new \InvalidArgumentException('Invalid cache timeout');
        }
        $value = (float)$value;
        if (!is_finite($value) || $value > 30) { throw new \InvalidArgumentException('Invalid cache timeout'); }
        return $value > 0 ? max(0.001, $value) : 1.5;
    }

    /** Memcache protocols interpret values above 30 days as absolute timestamps. */
    public static function memcacheExpiration(int $seconds): int
    {
        if ($seconds < 0) { return time() - 1; }
        if ($seconds <= 2592000) { return $seconds; }
        $now = time();
        // Keep long expirations within the common signed 32-bit client/server timestamp range.
        if ($seconds > 2147483647 - $now) { throw new \InvalidArgumentException('Cache lifetime exceeds supported timestamp'); }
        return $now + $seconds;
    }

    /** Validation also runs when an otherwise unused named store is first requested. */
    public static function options(string $type, array $options): array
    {
        if (!isset(self::DRIVERS[$type]) || $type === 'file' || !is_array($options['connection'] ?? null)) {
            throw new \InvalidArgumentException('Invalid cache connection settings');
        }
        $input = $options['connection'];
        $host = array_key_exists('host', $input) ? $input['host'] : '127.0.0.1';
        if (!is_string($host) || trim($host) === '' || strlen($host) > 1024 || preg_match('~[/\\\\?#@\x00-\x20\x7f]~', $host)) {
            throw new \InvalidArgumentException('Invalid cache host');
        }
        $port = array_key_exists('port', $input) ? $input['port'] : ($type === 'redis' ? 6379 : 11211);
        if ((!is_int($port) && !is_string($port)) || !preg_match('/^[0-9]{1,5}$/D', (string)$port)
            || (int)$port < 1 || (int)$port > 65535) { throw new \InvalidArgumentException('Invalid cache port'); }
        $credentials = [];
        foreach (['username','password'] as $field) {
            $value = array_key_exists($field, $input) ? $input[$field] : '';
            if (!is_string($value)) { throw new \InvalidArgumentException('Invalid cache credentials'); }
            $credentials[$field] = $value;
        }
        if ($type === 'memcache' && ($credentials['username'] !== '' || $credentials['password'] !== '')) {
            throw new \InvalidArgumentException('Memcache does not support configured credentials');
        }
        if ($type === 'memcached' && ($credentials['username'] === '') !== ($credentials['password'] === '')) {
            throw new \InvalidArgumentException('Incomplete Memcached credentials');
        }
        $select = 0;
        if ($type === 'redis') {
            $select = array_key_exists('db', $input) ? $input['db'] : 0;
            if ($select === '') { $select = 0; }
            if ((!is_int($select) && !is_string($select)) || !preg_match('/^[0-9]{1,10}$/D', (string)$select)
                || (int)$select > 2147483647) { throw new \InvalidArgumentException('Invalid Redis database'); }
        }
        $expire = self::expire($options['expire'] ?? null);
        if ($type === 'memcache' || $type === 'memcached') { self::memcacheExpiration($expire); }
        return $credentials + ['host'=>$host, 'port'=>(int)$port, 'select'=>(int)$select,
            'timeout'=>self::timeout($input['timeout'] ?? null), 'persistent'=>false, 'prefix'=>'',
            'expire'=>$expire];
    }

    public static function driver(array $input, $timeout = null): \think\cache\Driver
    {
        $type = self::type($input['type'] ?? null);
        if ($type === 'file') { return new \think\cache\driver\File(\think\Container::getInstance()->make('app'), ['expire'=>30]); }
        if (!array_key_exists('timeout', $input)) { $input['timeout'] = $timeout; }
        $class = self::DRIVERS[$type];
        return new $class(['connection'=>$input, 'expire'=>30]);
    }

    /** Writes only a short-lived, unpredictable probe key; never flushes a shared cache. */
    public static function probe(array $input, $timeout = null): array
    {
        $driver = null; $key = null; $stage = 0;
        // Native clients may emit warnings for ordinary network failures; keep the JSON response intact.
        set_error_handler(static function ($severity, $message, $file, $line) {
            if (!(error_reporting() & $severity)) { return false; }
            throw new \ErrorException($message, 0, $severity, $file, $line);
        });
        try {
            $driver = self::driver($input, $timeout);
            $key = 'mac_probe_'.bin2hex(random_bytes(16));
            $value = bin2hex(random_bytes(24));
            $stage = 1006;
            if (!$driver->set($key, $value, 30) || $driver->get($key) !== $value) {
                throw new \RuntimeException('Cache probe write/read failed', 1006);
            }
            $stage = 1007;
            if (!$driver->delete($key) || $driver->get($key) !== null) {
                throw new \RuntimeException('Cache probe cleanup failed', 1007);
            }
            $key = null;
            return ['code'=>1, 'msg'=>lang('test_ok')];
        } catch (\InvalidArgumentException $error) {
            return ['code'=>1001, 'msg'=>'Invalid cache configuration'];
        } catch (\Throwable $error) {
            $messages = [1002=>'Cache extension unavailable', 1003=>'Cache connection failed',
                1004=>'Cache authentication failed', 1005=>'Redis database selection failed',
                1006=>'Cache write/read verification failed', 1007=>'Cache probe cleanup failed'];
            return ['code'=>1002, 'msg'=>$messages[$error->getCode()] ?? $messages[$stage] ?? 'Cache connection or operation failed'];
        } finally {
            if ($driver !== null && $key !== null) { try { $driver->delete($key); } catch (\Throwable $ignored) {} }
            if ($driver !== null && method_exists($driver, 'disconnect')) { $driver->disconnect(); }
            restore_error_handler();
        }
    }
}
