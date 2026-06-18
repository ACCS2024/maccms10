<?php

namespace app\common\util;

use think\facade\Cache;
use think\facade\Db;

/**
 * 播放/阅读量 Redis 计数缓冲(可选,默认关闭)。
 *
 * 目的:高流量下把"每播一次写一次库"削减为"每累计 N 次写一次库"(N=THRESHOLD),
 * 进一步降低 mac_vod/mac_art 的写压与锁竞争(在 P1 原子自增 + InnoDB 行锁之上的增量优化)。
 *
 * 设计要点:
 * - 仅当后台开启 hits_buffer 且缓存后端为 Redis 时启用;否则 bump() 返回 false,调用方回退原子 UPDATE。
 * - 阈值触发落库:同一内容累计达 THRESHOLD 即落库一次 → 无需依赖 cron,DB 展示最多滞后 THRESHOLD-1。
 * - 落库用与单条自增同语义的原子条件 UPDATE(步长为累计 delta),日/周/月跨期归零一致。
 * - 落库时用 HINCRBY -delta 扣减(而非 HDEL),并发新增的增量保留在计数里,不丢。
 * - flush() 供定时任务低峰收尾(把低频内容的零头也落库);用 RENAME 快照排空,期间新增计入新 key。
 * - 任何 Redis 异常都吞掉并回退,绝不影响播放/阅读主流程。
 */
class HitsBuffer
{
    /** 单条累计达到该值即落库一次(写入削减约 N 倍;DB 展示最多滞后 N-1) */
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
            $h = Cache::init()->handler();
            return class_exists('\Redis', false) && $h instanceof \Redis;
        } catch (\Throwable $e) {
            return false;
        }
    }

    /**
     * 缓冲一次自增;累计达阈值则落库。
     *
     * @return bool true=已缓冲(调用方无需再写库);false=未启用/异常(调用方走原子 UPDATE)
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
        try {
            $h = Cache::init()->handler();
            $key = self::key($kind);
            $delta = (int)$h->hIncrBy($key, (string)$id, 1);
            if ($delta >= self::THRESHOLD) {
                // 原子扣减待落库量(并发新增留在计数里,不丢),再落库
                $h->hIncrBy($key, (string)$id, -$delta);
                self::apply($kind, $id, $delta);
            }
            return true;
        } catch (\Throwable $e) {
            return false;
        }
    }

    /**
     * 把缓冲中所有内容的零头落库(供定时任务低峰调用;阈值已自动落大头,此处兜低频)。
     *
     * @return int 落库的条目数
     */
    public static function flush($kind = null)
    {
        if (!self::enabled()) {
            return 0;
        }
        $kinds = $kind ? [$kind] : ['vod', 'art'];
        $n = 0;
        try {
            $h = Cache::init()->handler();
            foreach ($kinds as $k) {
                $key = self::key($k);
                if (!$h->exists($key)) {
                    continue;
                }
                // 重命名快照再排空:期间新增计入新 key,避免丢增量
                $snap = $key . ':flush:' . getmypid() . ':' . mt_rand(1000, 9999);
                if (!$h->rename($key, $snap)) {
                    continue;
                }
                $all = $h->hGetAll($snap);
                if (is_array($all)) {
                    foreach ($all as $id => $delta) {
                        if ((int)$delta > 0) {
                            self::apply($k, (int)$id, (int)$delta);
                            $n++;
                        }
                    }
                }
                $h->del($snap);
            }
        } catch (\Throwable $e) {
        }
        return $n;
    }

    /**
     * 以原子条件 UPDATE 把累计 delta 落库(与 P1 单条自增同语义,步长为 delta)。
     */
    private static function apply($kind, $id, $delta)
    {
        $delta = (int)$delta;
        $id = (int)$id;
        if ($delta <= 0 || $id <= 0) {
            return;
        }
        $now        = time();
        $dayStart   = strtotime('today');
        $weekStart  = $dayStart - ((int)date('w', $now)) * 86400;
        $monthStart = mktime(0, 0, 0, (int)date('n', $now), 1, (int)date('Y', $now));
        $p = ($kind === 'vod') ? 'vod' : 'art';
        try {
            Db::name($p)->where($p . '_id', $id)
                ->inc($p . '_hits', $delta)
                ->exp($p . '_hits_day',   "IF({$p}_time_hits >= {$dayStart}, {$p}_hits_day + {$delta}, {$delta})")
                ->exp($p . '_hits_week',  "IF({$p}_time_hits >= {$weekStart}, {$p}_hits_week + {$delta}, {$delta})")
                ->exp($p . '_hits_month', "IF({$p}_time_hits >= {$monthStart}, {$p}_hits_month + {$delta}, {$delta})")
                ->update([$p . '_time_hits' => $now]);
        } catch (\Throwable $e) {
        }
    }

    private static function key($kind)
    {
        return 'mac_hits_buf:' . $kind;
    }
}
