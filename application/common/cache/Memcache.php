<?php
namespace app\common\cache;

use app\common\util\CacheConnection;

/** Native Memcache accepts fractional socket timeouts; the framework adapter discards them. */
class Memcache extends \think\cache\driver\Memcache
{
    public function __construct(array $options = [])
    {
        $this->options = array_merge($this->options, CacheConnection::options('memcache', $options));
        if (!extension_loaded('memcache')) { throw new \RuntimeException('Memcache extension unavailable', 1002); }
        $this->handler = new \Memcache();
        if (!$this->handler->addServer($this->options['host'], $this->options['port'], false, 1, $this->options['timeout'])) {
            throw new \RuntimeException('Memcache connection setup failed', 1003);
        }
    }

    public function set($name, $value, $expire = null): bool
    {
        $seconds = $this->getExpireTime($expire ?? $this->options['expire']);
        return $this->handler->set($this->getCacheKey($name), $this->serialize($value), 0,
            CacheConnection::memcacheExpiration($seconds));
    }

    public function disconnect(): void
    {
        if ($this->handler) { try { $this->handler->close(); } catch (\Throwable $ignored) {} }
    }
}
