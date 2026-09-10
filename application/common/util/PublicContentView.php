<?php
namespace app\common\util;

/** Public catalog data. Resource authorization belongs to the separate read/play/download endpoints. */
final class PublicContentView
{
    private const COMMON_FIELDS = [
        'id','name','en','sub','alias','status','letter','color','pic','pic_thumb','pic_slide','blurb','remarks',
        'author','actor','director','writer','area','lang','year','class','tag','serial','isend','total','level',
        'time','time_add','hits','hits_day','hits_week','hits_month','score','score_all','score_num','up','down',
        'points','points_detail','lock','copyright','link',
    ];
    private const TYPE_FIELDS = ['type_id','type_pid','type_mid','type_name','type_en','type_sub','type_sort','type_status'];

    public static function detail(string $kind, array $row, array $players = []): array
    {
        if (!in_array($kind, ['vod','art','manga'], true)) {
            throw new \InvalidArgumentException('Unsupported public content kind');
        }
        $fields = ['type_id','type_id_1','group_id','type_is_vip_exclusive','is_fav','fav_ulog_id','user_has_up'];
        foreach (self::COMMON_FIELDS as $field) {
            $fields[] = $kind . '_' . $field;
        }
        if ($kind === 'vod') {
            $fields = array_merge($fields, ['vod_content','vod_duration','vod_pubdate','vod_state','vod_version',
                'vod_douban_id','vod_douban_score','vod_points_play','vod_points_down','vod_trysee']);
        } elseif ($kind === 'art') {
            $fields[] = 'art_read_points';
            $fields[] = 'art_page_total';
        } else {
            $fields = array_merge($fields, ['manga_content','manga_page_total','manga_read_points']);
        }
        $out = self::scalars($row, $fields);
        $out['has_password'] = self::hasPassword($row[$kind . '_pwd'] ?? null);
        foreach (['type','type_1'] as $field) {
            if (isset($row[$field]) && is_array($row[$field])) {
                $out[$field] = self::scalars($row[$field], self::TYPE_FIELDS);
            }
        }
        if (isset($row['group']) && is_array($row['group'])) {
            $out['group'] = self::scalars($row['group'], ['group_id','group_name']);
        }
        if ($kind === 'vod') {
            $out['has_play_password'] = self::hasPassword($row['vod_pwd_play'] ?? null);
            $out['has_down_password'] = self::hasPassword($row['vod_pwd_down'] ?? null);
            $out['vod_play_list'] = self::videoDirectory($row, 'play', $players);
            $out['vod_down_list'] = self::videoDirectory($row, 'down', []);
            if (isset($row['vod_plot_list']) && is_array($row['vod_plot_list'])) {
                $out['vod_plot_list'] = [];
                foreach ($row['vod_plot_list'] as $plot) {
                    if (is_array($plot)) {
                        $out['vod_plot_list'][] = self::scalars($plot, ['name','detail','page']);
                    }
                }
            }
        } elseif ($kind === 'art') {
            $out['art_page_list'] = [];
            foreach (is_array($row['art_page_list'] ?? null) ? $row['art_page_list'] : [] as $page => $chapter) {
                if (is_array($chapter)) {
                    $out['art_page_list'][$page] = self::scalars($chapter, ['page','title','note']);
                }
            }
            foreach (['art_prev','art_next'] as $field) {
                $out[$field] = is_array($row[$field] ?? null)
                    ? self::scalars($row[$field], ['art_id','art_name','art_en','art_link']) : null;
            }
        } else {
            $out['manga_page_list'] = [];
            foreach (is_array($row['manga_page_list'] ?? null) ? $row['manga_page_list'] : [] as $sid => $group) {
                if (!is_array($group)) {
                    continue;
                }
                $catalog = self::scalars($group, ['sid','from','note','url_count']);
                $catalog['urls'] = [];
                foreach (is_array($group['urls'] ?? null) ? $group['urls'] : [] as $nid => $chapter) {
                    if (!is_array($chapter)) {
                        continue;
                    }
                    $catalog['urls'][$nid] = self::scalars($chapter, ['name','nid']);
                    $catalog['urls'][$nid]['play_link'] = mac_url_manga_play($row, ['sid'=>(int)$sid,'nid'=>(int)$nid]);
                }
                $out['manga_page_list'][$sid] = $catalog;
            }
        }
        return $out;
    }

    private static function scalars(array $row, array $fields): array
    {
        $out = [];
        foreach ($fields as $field) {
            if (array_key_exists($field, $row) && (is_scalar($row[$field]) || $row[$field] === null)) {
                $out[$field] = $row[$field];
            }
        }
        return $out;
    }

    private static function hasPassword($value): bool
    {
        return is_string($value) && $value !== '';
    }

    private static function videoDirectory(array $row, string $action, array $players): array
    {
        $fromText = $row['vod_' . $action . '_from'] ?? '';
        $urlText = $row['vod_' . $action . '_url'] ?? '';
        if (!is_string($fromText) || !is_string($urlText) || $fromText === '' || $urlText === '') {
            return [];
        }
        $urls = explode('$$$', $urlText);
        $groups = [];
        foreach (explode('$$$', $fromText) as $sourceIndex => $source) {
            $source = trim($source);
            if ($source === '') {
                continue;
            }
            $sid = $sourceIndex + 1;
            $episodes = [];
            foreach (explode('#', $urls[$sourceIndex] ?? '') as $episodeIndex => $episode) {
                $episode = trim($episode);
                if ($episode === '') {
                    continue;
                }
                $nid = $episodeIndex + 1;
                $parts = explode('$', $episode, 3);
                // A bare resource address is not a chapter title. Keep it entirely server-side.
                $name = count($parts) > 1 && $parts[0] !== '' && $parts[1] !== '' ? $parts[0]
                    : ($action === 'play' ? '第' . $nid . '集' : '下载' . $nid);
                $link = $action === 'play' ? mac_url_vod_play($row, ['sid'=>$sid,'nid'=>$nid])
                    : mac_url_vod_down($row, ['sid'=>$sid,'nid'=>$nid]);
                $episodes[] = ['name'=>$name,'nid'=>$nid,$action . '_link'=>$link];
            }
            $group = ['from'=>$source,'sid'=>$sid,'urls'=>$episodes];
            if ($action === 'play') {
                $show = $players[$source]['show'] ?? $source;
                $group['player_info'] = ['show'=>is_string($show) ? $show : $source,'from'=>$source];
            }
            $groups[] = $group;
        }
        return $groups;
    }
}
