<?php

namespace app\common\util;

use think\facade\Cache;
use think\facade\Db;
use think\facade\Log;

/**
 * 播放/阅读量 Redis 计数缓冲(可选,默认关闭)。
 *
 * 目的:高流量下把"每播一次写一次库"削减为"每累计 N 次写一次库"(N=THRESHOLD),
 * 进一步降低 mac_vod/mac_art 的写压与锁竞争(在 P1 原子自增 + InnoDB 行锁之上的增量优化)。
 *
 * 设计要点:
 * - 仅当后台开启 hits_buffer 且缓存后端为 Redis 时启用;否则 bump() 返回 false,调用方回退原子 UPDATE。
 * - 阈值触发落库;低频内容由 flush() 收尾。DB 故障时积压可以超过阈值。
 * - 落库用与单条自增同语义的原子条件 UPDATE(步长为累计 delta),日/周/月跨期归零一致。
 * - Lua 原子读取并删除待写增量;阈值请求和 flush() 共用领取逻辑,不会重复领取同一批。
 * - DB 抛错时用 HINCRBY 回补,保留领取后新到的计数。Redis 已确认接收后不再让调用方重复自增。
 * - 这是尽力而为的缓冲,不是跨 Redis/DB 事务:领取后进程崩溃可能丢计数;
 *   DB 提交但回执丢失后回补可能重复。Redis 回执不明或回补失败也无法保证计数完整。
 */
class HitsBuffer
{
    /** 单条累计达到该值即尝试落库一次 */
    const THRESHOLD = 10;

    /**
     * 是否启用:后台 hits_buffer=1 且缓存句柄为 Redis。
     * 关闭时(默认)第一行即返回,零额外开销、不触碰缓存。
     */
    public static function enabled()
    {
        $c = isset($GLOBALS['config']['app']) ? $GLOBALS['config']['app'] : [];
        if (empty($c['hits_buffer']) || (string)$c['hits_buffer'] !== '1') {
            return false;
        }
        try {
            $h = Cache::store()->handler();
            return class_exists('\Redis', false) && $h instanceof \Redis;
        } catch (\Throwable $e) {
            return false;
        }
    }

    /**
     * 缓冲一次自增;累计达阈值则落库。
     *
     * @return bool true=Redis 已确认接收(包括 DB 失败待重试);false=未启用/未确认接收
     */
    public static function bump($kind, $id)
    {
        if (!in_array($kind, ['vod', 'art'], true)) {
            return false;
        }
        $id = (int)$id;
        if ($id <= 0 || !self::enabled()) {
            return false;
        }
        $accepted = false;
        try {
            $h = Cache::store()->handler();
            $key = self::key($kind);
            $pending = $h->hIncrBy($key, (string)$id, 1);
            if ($pending === false) {
                throw new \RuntimeException('Redis did not acknowledge the increment');
            }
            $accepted = true;
            if ($pending >= self::THRESHOLD) {
                $delta = self::claim($h, $key, $id, self::THRESHOLD);
                if ($delta > 0) {
                    self::deliver($h, $key, $kind, $id, $delta);
                }
            }
            return true;
        } catch (\Throwable $e) {
            self::report('redis', $kind, $id, 0, $e);
            return $accepted;
        }
    }

    /**
     * 把缓冲中所有内容的零头落库(供定时任务低峰调用;阈值已自动落大头,此处兜低频)。
     *
     * @return int 落库的条目数
     */
    public static function flush($kind = null)
    {
        if (($kind !== null && !in_array($kind, ['vod', 'art'], true)) || !self::enabled()) {
            return 0;
        }
        $kinds = $kind === null ? ['vod', 'art'] : [$kind];
        $n = 0;
        foreach ($kinds as $k) {
            try {
                $h = Cache::store()->handler();
                $key = self::key($k);
                $cursor = null;
                do {
                    $batch = $h->hScan($key, $cursor, null, 100);
                    foreach ($batch ?: [] as $id => $unused) {
                        if (!ctype_digit((string)$id) || (int)$id <= 0) {
                            continue;
                        }
                        $delta = self::claim($h, $key, (int)$id, 1);
                        if ($delta > 0 && self::deliver($h, $key, $k, (int)$id, $delta)) {
                            $n++;
                        }
                    }
                } while ($cursor !== 0);
            } catch (\Throwable $e) {
                self::report('flush', $k, 0, 0, $e);
            }
        }
        return $n;
    }

    /** Reading and removing the same batch must be one Redis operation. */
    private static function claim(\Redis $h, string $key, int $id, int $minimum): int
    {
        $script = <<<'LUA'
local delta = redis.call('HGET', KEYS[1], ARGV[1])
if delta and tonumber(delta) >= tonumber(ARGV[2]) then
    redis.call('HDEL', KEYS[1], ARGV[1])
    return delta
end
return '0'
LUA;
        $delta = $h->eval($script, [$key, (string)$id, (string)$minimum], 1);
        if ($delta === false) {
            throw new \RuntimeException('Redis did not acknowledge the claim');
        }
        return (int)$delta;
    }

    private static function deliver(\Redis $h, string $key, string $kind, int $id, int $delta): bool
    {
        try {
            // Zero affected rows means the content no longer exists; do not retain an orphan counter.
            return self::apply($kind, $id, $delta) > 0;
        } catch (\Throwable $e) {
            try {
                if ($h->hIncrBy($key, (string)$id, $delta) === false) {
                    throw new \RuntimeException('Redis did not acknowledge the restore');
                }
            } catch (\Throwable $restoreError) {
                self::report('restore_failed', $kind, $id, $delta, $restoreError);
            }
            self::report('database', $kind, $id, $delta, $e);
            return false;
        }
    }

    /**
     * 以原子条件 UPDATE 把累计 delta 落库(与 P1 单条自增同语义,步长为 delta)。
     */
    private static function apply($kind, $id, $delta): int
    {
        $delta = (int)$delta;
        $id = (int)$id;
        if ($delta <= 0 || $id <= 0) {
            return 0;
        }
        $now        = time();
        $dayStart   = strtotime('today');
        $weekStart  = $dayStart - ((int)date('w', $now)) * 86400;
        $monthStart = mktime(0, 0, 0, (int)date('n', $now), 1, (int)date('Y', $now));
        $p = ($kind === 'vod') ? 'vod' : 'art';
        return Db::name($p)->where($p . '_id', $id)
            ->inc($p . '_hits', $delta)
            ->exp($p . '_hits_day',   "IF({$p}_time_hits >= {$dayStart}, {$p}_hits_day + {$delta}, {$delta})")
            ->exp($p . '_hits_week',  "IF({$p}_time_hits >= {$weekStart}, {$p}_hits_week + {$delta}, {$delta})")
            ->exp($p . '_hits_month', "IF({$p}_time_hits >= {$monthStart}, {$p}_hits_month + {$delta}, {$delta})")
            ->update([$p . '_time_hits' => $now]);
    }

    private static function key($kind)
    {
        return Cache::store()->getCacheKey('mac_hits_buf:' . $kind);
    }

    private static function report(string $stage, string $kind, int $id, int $delta, \Throwable $error): void
    {
        try {
            Log::warning('HitsBuffer ' . $stage, [
                'kind' => $kind, 'id' => $id, 'delta' => $delta, 'exception' => get_class($error),
            ]);
        } catch (\Throwable $ignored) {
            // Logging must not turn a counting failure into a playback error.
        }
    }
}
