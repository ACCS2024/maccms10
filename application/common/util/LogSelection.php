<?php
declare(strict_types=1);
namespace app\common\util;

/** Bounded log selection: null rejects input; [] means an explicit all=1. */
final class LogSelection
{
    public static function ids(array $param): ?array
    {
        $all = $param['all'] ?? '0';
        $raw = $param['ids'] ?? '';
        if ((!is_int($all) && !is_string($all)) || !in_array((string)$all, ['0', '1'], true)
            || (!is_string($raw) && !is_int($raw))) { return null; }
        if ((string)$all === '1') { return []; }
        $raw = trim((string)$raw);
        if ($raw === '' || strlen($raw) > 12000) { return null; }
        $parts = explode(',', $raw);
        if (count($parts) > 1000) { return null; }
        $ids = [];
        foreach ($parts as $part) {
            $part = trim($part);
            if (!preg_match('/^[0-9]{1,10}$/D', $part) || (int)$part < 1 || (int)$part > 4294967295) { return null; }
            $ids[(int)$part] = (int)$part;
        }
        return array_values($ids);
    }
}
