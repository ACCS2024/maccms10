<?php
namespace app\common\cache;

use app\common\util\CacheConnection;

/** Preserve native Memcached SASL and convert shared seconds into its per-option time units. */
class Memcached extends \think\cache\driver\Memcached
{
    public function __construct(array $options = [])
    {
        $options = CacheConnection::options('memcached', $options);
        if (!extension_loaded('memcached')) { throw new \RuntimeException('Memcached extension unavailable', 1002); }
        if ($options['username'] !== '' && !\Memcached::HAVE_SASL) {
            throw new \RuntimeException('Memcached authentication unavailable', 1004);
        }
        $milliseconds = (int)ceil($options['timeout'] * 1000);
        $microseconds = (int)ceil($options['timeout'] * 1000000);
        $options['timeout'] = $milliseconds;
        $options['option'] = [
            \Memcached::OPT_CONNECT_TIMEOUT=>$milliseconds, \Memcached::OPT_POLL_TIMEOUT=>$milliseconds,
            \Memcached::OPT_SEND_TIMEOUT=>$microseconds, \Memcached::OPT_RECV_TIMEOUT=>$microseconds,
            \Memcached::OPT_BINARY_PROTOCOL=>$options['username'] !== '',
            \Memcached::OPT_BUFFER_WRITES=>false, \Memcached::OPT_NOREPLY=>false,
        ];
        parent::__construct($options); // Native Memcached without a persistent id creates a private connection.
    }

    public function set($name, $value, $expire = null): bool
    {
        $seconds = $this->getExpireTime($expire ?? $this->options['expire']);
        $stored = parent::set($name, $value, CacheConnection::memcacheExpiration($seconds));
        if (!$stored && $this->handler->getResultCode() === \Memcached::RES_AUTH_FAILURE) {
            throw new \RuntimeException('Memcached authentication failed', 1004);
        }
        return $stored;
    }

    public function disconnect(): void
    {
        if ($this->handler) { try { $this->handler->quit(); } catch (\Throwable $ignored) {} }
    }
}
