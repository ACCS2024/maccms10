<?php
namespace app\common\cache;

use app\common\util\CacheConnection;

/** Native Redis cache with explicit ACL authentication and bounded, nonpersistent I/O. */
class Redis extends \think\cache\driver\Redis
{
    public function __construct(array $options = [])
    {
        parent::__construct(CacheConnection::options('redis', $options));
        if (!extension_loaded('redis')) { throw new \RuntimeException('Redis extension unavailable', 1002); }
    }

    public function handler()
    {
        if ($this->handler) { return $this->handler; }
        $client = new \Redis(); $stage = 1003;
        try {
            if (!$client->connect($this->options['host'], $this->options['port'], $this->options['timeout'], null, 0, $this->options['timeout'])) {
                throw new \RuntimeException('Cache connection failed');
            }
            $stage = 1004;
            if ($this->options['username'] !== '' || $this->options['password'] !== '') {
                $credentials = $this->options['username'] !== ''
                    ? [$this->options['username'], $this->options['password']] : $this->options['password'];
                if ($client->auth($credentials) !== true) { throw new \RuntimeException('Cache authentication failed'); }
            }
            $stage = 1005;
            if ($this->options['select'] !== 0 && $client->select($this->options['select']) !== true) {
                throw new \RuntimeException('Redis database selection failed');
            }
            $this->handler = $client;
            return $this->handler;
        } catch (\Throwable $error) {
            try { $client->close(); } catch (\Throwable $ignored) {}
            throw new \RuntimeException('Cache initialization failed', $stage, $error);
        }
    }

    public function set($name, $value, $expire = null): bool
    {
        $expire = $this->getExpireTime($expire ?? $this->options['expire']);
        $key = $this->getCacheKey($name); $value = $this->serialize($value);
        return ($expire ? $this->handler()->setex($key, $expire, $value) : $this->handler()->set($key, $value)) === true;
    }

    public function disconnect(): void
    {
        if ($this->handler) { try { $this->handler->close(); } catch (\Throwable $ignored) {} $this->handler = null; }
    }
}
