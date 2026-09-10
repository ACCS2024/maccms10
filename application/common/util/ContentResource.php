<?php
namespace app\common\util;

/** Resolve server-side resource coordinates before asking the permission policy or building a response. */
final class ContentResource
{
    public static function scalarParameters(array $parameters): bool
    {
        foreach ($parameters as $value) {
            if (!is_string($value) && !is_int($value)) {
                return false;
            }
        }
        return true;
    }

    public static function positiveInt($value, ?int $default = null): ?int
    {
        if ($value === null) {
            return $default;
        }
        if ((!is_string($value) && !is_int($value)) || !preg_match('/^[0-9]{1,10}$/D', (string)$value)) {
            return null;
        }
        $number = (int)$value;
        return $number > 0 && $number <= 4294967295 ? $number : null;
    }

    public static function vodSelection(array $row, string $operation, array $parameters): array
    {
        if (!in_array($operation, ['play', 'down'], true)) {
            throw new \InvalidArgumentException('Unsupported video resource operation');
        }
        $id = self::positiveInt($row['vod_id'] ?? null);
        $sid = array_key_exists('sid', $parameters) ? self::positiveInt($parameters['sid']) : 1;
        $nid = array_key_exists('nid', $parameters) ? self::positiveInt($parameters['nid']) : 1;
        if ($id === null || $sid === null || $nid === null) {
            return ['code' => 1001, 'msg' => lang('param_err')];
        }
        if ((int)($row['vod_status'] ?? 0) !== 1 || (int)($row['vod_recycle_time'] ?? 0) !== 0) {
            return ['code' => 1002, 'msg' => lang('obtain_err')];
        }
        $sources = $row['vod_' . $operation . '_list'] ?? [];
        $source = is_array($sources) && is_array($sources[$sid] ?? null) ? $sources[$sid] : [];
        $current = is_array($source['urls'][$nid] ?? null) ? $source['urls'][$nid] : [];
        if (!is_string($current['url'] ?? null) || $current['url'] === '') {
            return ['code' => 1002, 'msg' => lang('obtain_err')];
        }
        $coordinates = [];
        foreach ($source['urls'] as $key => $episode) {
            if (is_array($episode) && is_string($episode['url'] ?? null) && $episode['url'] !== '') {
                $coordinates[] = (int)$key;
            }
        }
        $position = array_search($nid, $coordinates, true);
        return ['code' => 1, 'msg' => 'ok', 'id' => $id, 'sid' => $sid, 'nid' => $nid,
            'previous_nid' => $position > 0 ? $coordinates[$position - 1] : null,
            'next_nid' => $coordinates[$position + 1] ?? null,
            'source' => $source, 'current' => $current];
    }

    /** The same resolved coordinates and server price are used for reading and purchasing. */
    public static function vodContext(array $row, string $operation, array $parameters): array
    {
        $selected = self::vodSelection($row, $operation, $parameters);
        if ($selected['code'] !== 1) {
            return $selected;
        }
        $whole = (string)($GLOBALS['config']['user']['vod_points_type'] ?? '0') === '1';
        $field = $whole ? 'vod_points' : 'vod_points_' . $operation;
        $points = PointsBalance::amount($row[$field] ?? 0, true);
        if ($points === null) {
            return ['code' => 1002, 'msg' => lang('obtain_err')];
        }
        return $selected + ['points' => $points, 'whole' => $whole,
            'ulog_mid' => 1, 'ulog_type' => $operation === 'play' ? 4 : 5, 'ulog_rid' => $selected['id'],
            'ulog_sid' => $whole ? 0 : $selected['sid'], 'ulog_nid' => $whole ? 0 : $selected['nid']];
    }

    /** Keep source/episode keys; callers of resource APIs already use one-based catalogs. */
    public static function vodCatalog(array $row, string $operation): array
    {
        $result = [];
        foreach (is_array($row['vod_' . $operation . '_list'] ?? null) ? $row['vod_' . $operation . '_list'] : [] as $sid => $source) {
            if (!is_array($source)) {
                continue;
            }
            $from = is_string($source['from'] ?? null) ? $source['from'] : '';
            $show = is_string($source['player_info']['show'] ?? null) ? $source['player_info']['show'] : $from;
            $catalog = ['sid' => (int)$sid, 'from' => $from, 'player_info' => ['show' => $show, 'from' => $from],
                'url_count' => 0, 'urls' => []];
            foreach (is_array($source['urls'] ?? null) ? $source['urls'] : [] as $nid => $episode) {
                if (!is_array($episode)) {
                    continue;
                }
                $link = $operation === 'play' ? mac_url_vod_play($row, ['sid' => (int)$sid, 'nid' => (int)$nid])
                    : mac_url_vod_down($row, ['sid' => (int)$sid, 'nid' => (int)$nid]);
                $catalog['urls'][$nid] = ['name' => is_string($episode['name'] ?? null) ? $episode['name'] : '',
                    'nid' => (int)$nid, $operation . '_link' => $link];
            }
            $catalog['url_count'] = count($catalog['urls']);
            $result[$sid] = $catalog;
        }
        return $result;
    }

    public static function vodTemplate(array $row): array
    {
        $row['vod_play_list'] = self::vodCatalog($row, 'play');
        $row['vod_down_list'] = self::vodCatalog($row, 'down');
        foreach (['vod_play_url', 'vod_down_url', 'vod_play_server', 'vod_down_server', 'vod_play_note', 'vod_down_note'] as $field) {
            $row[$field] = '';
        }
        foreach (['detail', 'play', 'down'] as $operation) {
            $field = 'vod_pwd' . ($operation === 'detail' ? '' : '_' . $operation);
            $row[$field . '_url'] = ContentPassword::vodState($row, $operation)['help_url'];
            $row[$field] = is_string($row[$field] ?? null) && $row[$field] !== '' ? 1 : 0;
        }
        unset($row['player_info']);
        return $row;
    }
}
