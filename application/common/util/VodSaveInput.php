<?php
declare(strict_types=1);
namespace app\common\util;

/** Normalize complete source groups without treating an omitted group as a deletion. */
final class VodSaveInput
{
    public static function normalize($data): ?array
    {
        if (!is_array($data) || count($data) > 256) { return null; }
        $id = $data['vod_id'] ?? '';
        $id = $id === '' ? 0 : PointsBalance::amount($id, true);
        $type = PointsBalance::amount($data['type_id'] ?? null);
        // The installed Vod type_id is signed SMALLINT.
        if ($id === null || $type === null || $type > 32767) { return null; }
        if ($id === 0) { unset($data['vod_id']); }
        else { $data['vod_id'] = $id; }
        $data['type_id'] = $type;
        foreach (['uptime', 'uptag'] as $field) {
            $value = $data[$field] ?? 0;
            if (!in_array($value, [0, 1, '0', '1'], true)) { return null; }
            $data[$field] = (int)$value;
        }
        if (array_key_exists('vod_content', $data)) {
            $value = $data['vod_content'];
            if (!is_string($value) && !is_int($value) && $value !== null) { return null; }
            $data['vod_content'] = (string)$value;
            if (strlen($data['vod_content']) > 1048576 || !mb_check_encoding($data['vod_content'], 'UTF-8')) { return null; }
        } elseif ($id === 0) {
            $data['vod_content'] = '';
        }
        foreach (['play', 'down'] as $operation) {
            $prefix = 'vod_' . $operation . '_';
            $marker = $data[$prefix . 'present'] ?? 0;
            if (!in_array($marker, [0, 1, '0', '1'], true)) { return null; }
            unset($data[$prefix . 'present']);
            $fields = [$prefix.'from', $prefix.'server', $prefix.'note', $prefix.'url'];
            $provided = false;
            foreach ($fields as $field) { $provided = $provided || array_key_exists($field, $data); }
            if (!$provided && (int)$marker === 0 && $id > 0) { continue; }
            // A patch must carry its source identifiers; a full form marker can clear all groups.
            if ($provided && !array_key_exists($prefix.'from', $data)) { return null; }
            foreach ($fields as $field) {
                $limit = $field === $prefix.'url' ? 8388608 : 4096;
                $joined = self::join($data[$field] ?? '', $limit);
                if ($joined === null || !mb_check_encoding($joined, 'UTF-8') || substr_count($joined, '$$$') >= 256) { return null; }
                if ($field === $prefix.'url') {
                    $joined = str_replace(["\r\n", "\r", "\n"], '#', $joined);
                } elseif (mb_strlen(mac_filter_xss($joined), 'UTF-8') > 255) {
                    // formatDataBeforeDb otherwise silently truncates these paired source columns.
                    return null;
                }
                $data[$field] = $joined;
            }
            $from = mac_filter_xss($data[$prefix.'from']);
            $url = $data[$prefix.'url'];
            if ($from === '') {
                if ($url !== '') { return null; }
                foreach ($fields as $field) { $data[$field] = ''; }
                continue;
            }
            $sourceNames = explode('$$$', $from);
            foreach ($sourceNames as $sourceName) {
                if (trim($sourceName) === '' || $sourceName === '0') { return null; }
            }
            $sources = count($sourceNames);
            foreach (['server', 'note', 'url'] as $suffix) {
                $value = $suffix === 'url' ? $data[$prefix.$suffix] : mac_filter_xss($data[$prefix.$suffix]);
                if ($value !== '' && substr_count($value, '$$$') + 1 > $sources) { return null; }
            }
            if ($url !== '' && substr_count($url, '#') + substr_count($url, '$$$') + 1 > 20000) {
                return null;
            }
        }
        foreach ($data as $key => $value) {
            if (!is_string($key) || (!is_scalar($value) && $value !== null)) { return null; }
        }
        return $data;
    }

    private static function join($value, int $limit): ?string
    {
        $parts = is_array($value) ? $value : [$value];
        if (count($parts) > 256) { return null; }
        $bytes = max(0, count($parts) - 1) * 3;
        foreach ($parts as $part) {
            if (!is_string($part) && !is_int($part) && $part !== null) { return null; }
            $bytes += strlen((string)$part);
            if ($bytes > $limit) { return null; }
        }
        return implode('$$$', array_map(static fn($part) => (string)$part, $parts));
    }
}
