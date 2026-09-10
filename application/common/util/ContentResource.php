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

    /** Article chapters retain their original one-based page coordinates, including empty chapters. */
    public static function artPages(array $row): array
    {
        if (is_array($row['art_page_list'] ?? null)) {
            return $row['art_page_list'];
        }
        $content = $row['art_content'] ?? '';
        if (!is_string($content) || $content === '') {
            return [];
        }
        $titles = explode('$$$', is_string($row['art_title'] ?? null) ? $row['art_title'] : '');
        $notes = explode('$$$', is_string($row['art_note'] ?? null) ? $row['art_note'] : '');
        $pages = [];
        foreach (explode('$$$', $content) as $index => $body) {
            $pages[$index + 1] = ['page' => $index + 1, 'title' => $titles[$index] ?? '',
                'note' => $notes[$index] ?? '', 'content' => $body];
        }
        return $pages;
    }

    /** Pure parsing contract for both reading and purchasing: the Ulog sid is the resolved page. */
    public static function artContext(array $row, array $parameters): array
    {
        $id = self::positiveInt($row['art_id'] ?? null);
        $page = array_key_exists('page', $parameters) ? self::positiveInt($parameters['page']) : 1;
        if ($id === null || $page === null) {
            return ['code' => 1001, 'msg' => lang('param_err')];
        }
        if ((int)($row['art_status'] ?? 0) !== 1 || (int)($row['art_recycle_time'] ?? 0) !== 0) {
            return ['code' => 1002, 'msg' => lang('obtain_err')];
        }
        $pages = self::artPages($row);
        $coordinates = array_keys(array_filter($pages, static fn($item, $key) => self::positiveInt($key) !== null
            && is_array($item) && is_string($item['content'] ?? null), ARRAY_FILTER_USE_BOTH));
        if ($coordinates === []) {
            return ['code' => 1002, 'msg' => '暂无正文'];
        }
        sort($coordinates, SORT_NUMERIC);
        // Preserve the old last-page fallback, but resolve it before checking a purchase record.
        $page = min($page, (int)end($coordinates));
        $position = array_search($page, $coordinates, true);
        if ($position === false) {
            return ['code' => 1002, 'msg' => '该页不存在'];
        }
        $whole = (string)($GLOBALS['config']['user']['art_points_type'] ?? '0') === '1';
        $points = PointsBalance::amount($row[$whole ? 'art_points' : 'art_points_detail'] ?? 0, true);
        if (!$whole && $points === 0) {
            $points = PointsBalance::amount($row['art_points'] ?? 0, true);
        }
        if ($points === null) {
            return ['code' => 1002, 'msg' => lang('obtain_err')];
        }
        $purchasePage = $page;
        if ($whole) {
            $purchasePage = 0;
            foreach ($coordinates as $key) {
                if ($pages[$key]['content'] !== '') {
                    $purchasePage = (int)$key;
                    break;
                }
            }
        }
        return ['code' => 1, 'msg' => 'ok', 'id' => $id, 'page' => $page, 'page_total' => count($coordinates),
            'previous_page' => $position > 0 ? (int)$coordinates[$position - 1] : null,
            'next_page' => isset($coordinates[$position + 1]) ? (int)$coordinates[$position + 1] : null,
            'current' => $pages[$page], 'points' => $points, 'whole' => $whole,
            'purchase_supported' => $purchasePage > 0 && $purchasePage <= 255 && $points <= 65535
                && ($pages[$purchasePage]['content'] ?? '') !== '', 'purchase_page' => $purchasePage,
            'ulog_mid' => 2, 'ulog_type' => 1, 'ulog_rid' => $id, 'ulog_sid' => $whole ? 0 : $page, 'ulog_nid' => 0];
    }

    public static function artReadLink(array $row, int $page = 1): string
    {
        return MAC_PATH . 'index.php/art/read?' . http_build_query(['id'=>(int)($row['art_id'] ?? 0), 'page'=>$page]);
    }

    /** Only the authorized current chapter may be present in a template, never adjacent chapter bodies. */
    public static function artTemplate(array $row, ?int $authorizedPage = null): array
    {
        $pages = self::artPages($row);
        $state = ContentPassword::artState($row);
        $row['art_pwd'] = $state['required'] ? 1 : 0;
        $row['art_pwd_url'] = $state['help_url'];
        $row['has_password'] = $state['required'];
        $row['art_content'] = '';
        unset($row['art_content_text']);
        $row['art_page_list'] = [];
        foreach ($pages as $key => $item) {
            if (self::positiveInt($key) === null || !is_array($item)) {
                continue;
            }
            $content = (int)$key === $authorizedPage && is_string($item['content'] ?? null) ? $item['content'] : '';
            $row['art_page_list'][$key] = ['page' => (int)$key,
                'title' => is_string($item['title'] ?? null) ? $item['title'] : '',
                'note' => is_string($item['note'] ?? null) ? $item['note'] : '', 'content' => $content,
                'read_link' => self::artReadLink($row, (int)$key)];
            if ((int)$key === $authorizedPage) {
                $row['art_content'] = $content;
            }
        }
        $row['art_page_total'] = count($row['art_page_list']);
        return $row;
    }

    public const MANGA_MAX_CHAPTER_BYTES = 8388608;
    public const MANGA_MAX_DESCRIPTION_BYTES = 1048576;
    public const MANGA_MAX_SOURCE_BYTES = 4096;
    public const MANGA_MAX_SOURCES = 256;
    public const MANGA_MAX_CHAPTERS = 20000;
    public const MANGA_MAX_IMAGES = 1024;
    public const MANGA_MAX_IMAGE_BYTES = 8192;

    /** Reject over-budget catalogs as a whole; never turn a truncated catalog into a different paid chapter. */
    public static function mangaWithinBudget(array $row): bool
    {
        if (is_string($row['manga_content'] ?? null) && strlen($row['manga_content']) > self::MANGA_MAX_DESCRIPTION_BYTES) {
            return false;
        }
        foreach (['manga_chapter_from','manga_play_server','manga_play_note'] as $field) {
            if (is_string($row[$field] ?? null) && strlen($row[$field]) > self::MANGA_MAX_SOURCE_BYTES) {
                return false;
            }
        }
        $from = is_string($row['manga_chapter_from'] ?? null) ? $row['manga_chapter_from'] : '';
        if (substr_count($from, '$$$') + 1 > self::MANGA_MAX_SOURCES) {
            return false;
        }
        if (array_key_exists('manga_chapter_url', $row)) {
            $text = is_string($row['manga_chapter_url']) ? $row['manga_chapter_url'] : '';
            if (strlen($text) > self::MANGA_MAX_CHAPTER_BYTES || substr_count($text, '$$$') + 1 > self::MANGA_MAX_SOURCES
                || substr_count($text, '#') + substr_count($text, '$$$') + 1 > self::MANGA_MAX_CHAPTERS) {
                return false;
            }
            foreach (explode('$$$', $text) as $source) {
                foreach (explode('#', $source) as $chapter) {
                    $parts = explode('$', $chapter, 3);
                    if (!self::mangaImageBudget($parts[1] ?? $parts[0])) {
                        return false;
                    }
                }
            }
            return true;
        }
        $sources = is_array($row['manga_page_list'] ?? null) ? $row['manga_page_list'] : [];
        if (count($sources) > self::MANGA_MAX_SOURCES) {
            return false;
        }
        $total = $bytes = 0;
        foreach ($sources as $source) {
            if (!is_array($source)) {
                return false;
            }
            foreach (is_array($source['urls'] ?? null) ? $source['urls'] : [] as $chapter) {
                if (++$total > self::MANGA_MAX_CHAPTERS) {
                    return false;
                }
                $address = is_string($chapter['url'] ?? null) ? $chapter['url'] : '';
                $bytes += strlen($address);
                if ($bytes > self::MANGA_MAX_CHAPTER_BYTES || !self::mangaImageBudget($address)) {
                    return false;
                }
            }
        }
        return true;
    }

    private static function mangaImageBudget(string $text): bool
    {
        if (strlen($text) > self::MANGA_MAX_CHAPTER_BYTES || substr_count($text, ',') + 1 > self::MANGA_MAX_IMAGES) {
            return false;
        }
        foreach (explode(',', $text) as $address) {
            if (strlen(trim($address)) > self::MANGA_MAX_IMAGE_BYTES) {
                return false;
            }
        }
        return true;
    }

    /** Resolve chapter catalogs without compressing their actual one-based source/episode keys. */
    public static function mangaPages(array $row): array
    {
        if (!self::mangaWithinBudget($row)) {
            return [];
        }
        if (!array_key_exists('manga_chapter_url', $row)) {
            return is_array($row['manga_page_list'] ?? null) ? $row['manga_page_list'] : [];
        }
        $sources = mac_manga_list($row['manga_chapter_from'] ?? '', $row['manga_chapter_url'] ?? '',
            $row['manga_play_server'] ?? '', $row['manga_play_note'] ?? '');
        foreach ($sources as &$source) {
            foreach (explode('#', $source['url']) as $index=>$text) {
                $parts = explode('$', $text, 3);
                if (count($parts) > 1 && $parts[1] === '' && isset($source['urls'][$index + 1])) {
                    // An explicitly empty image address is not a title-only relative image path.
                    $source['urls'][$index + 1]['name'] = $parts[0];
                    $source['urls'][$index + 1]['url'] = '';
                }
            }
        }
        unset($source);
        return $sources;
    }

    /** Images may use HTTP(S), protocol-relative URLs or local paths, including the existing image mapping. */
    public static function mangaImages($addresses): array
    {
        if (!is_string($addresses) || !self::mangaImageBudget($addresses)) {
            return [];
        }
        $result = [];
        foreach (explode(',', $addresses) as $address) {
            $address = trim($address);
            if ($address === '') {
                continue;
            }
            if (strlen($address) > 8192 || preg_match('/[\x00-\x20\x7f\\\\]/', $address)) {
                return [];
            }
            if (preg_match('/^mac:/i', $address)) {
                $scheme = strtolower((string)($GLOBALS['config']['upload']['protocol'] ?? 'http'));
                $address = (in_array($scheme, ['http','https'], true) ? $scheme : 'http') . substr($address, 3);
            }
            if (preg_match('/^[a-z][a-z0-9+.-]*:/i', $address) && !preg_match('~^https?://~i', $address)) {
                return [];
            }
            $address = preg_replace_callback('~^https?://~i', static fn($match) => strtolower($match[0]), $address);
            $address = mac_url_img($address);
            if (!is_string($address) || $address === '' || strlen($address) > 8192
                || preg_match('/[\x00-\x20\x7f\\\\]/', $address)) {
                return [];
            }
            if (str_starts_with($address, '//')) {
                $scheme = strtolower((string)($GLOBALS['config']['upload']['protocol'] ?? 'http'));
                $address = (in_array($scheme, ['http','https'], true) ? $scheme : 'http') . ':' . $address;
            }
            $parsed = parse_url($address);
            if ($parsed === false || isset($parsed['user']) || isset($parsed['pass'])) {
                return [];
            }
            if (isset($parsed['scheme'])) {
                if (!in_array(strtolower($parsed['scheme']), ['http','https'], true) || empty($parsed['host'])) {
                    return [];
                }
            } elseif (!str_starts_with($address, '/') || str_starts_with($address, '//')) {
                return [];
            }
            $result[] = $address;
        }
        return $result;
    }

    /** Pure fresh-row quote shared by the reader and the transaction-owned purchase resolver. */
    public static function mangaContext(array $row, array $parameters): array
    {
        if (!self::mangaWithinBudget($row)) {
            return ['code'=>1002, 'msg'=>'漫画资源超过读取上限', 'purchase_supported'=>false];
        }
        $id = self::positiveInt($row['manga_id'] ?? null);
        $sid = array_key_exists('sid', $parameters) ? self::positiveInt($parameters['sid']) : 1;
        $nid = array_key_exists('nid', $parameters) ? self::positiveInt($parameters['nid']) : 1;
        if ($id === null || $sid === null || $nid === null) {
            return ['code'=>1001, 'msg'=>lang('param_err')];
        }
        if ((int)($row['manga_status'] ?? 0) !== 1 || (int)($row['manga_recycle_time'] ?? 0) !== 0) {
            return ['code'=>1002, 'msg'=>lang('obtain_err')];
        }
        $sources = self::mangaPages($row);
        $source = is_array($sources[$sid] ?? null) ? $sources[$sid] : [];
        $current = is_array($source['urls'][$nid] ?? null) ? $source['urls'][$nid] : [];
        if (!is_string($current['url'] ?? null)) {
            return ['code'=>1002, 'msg'=>'该话不存在'];
        }
        $coordinates = [];
        foreach ($source['urls'] as $key=>$chapter) {
            if (self::positiveInt($key) !== null && is_array($chapter) && is_string($chapter['url'] ?? null)) {
                $coordinates[] = (int)$key;
            }
        }
        sort($coordinates, SORT_NUMERIC);
        $position = array_search($nid, $coordinates, true);
        $mode = PointsBalance::amount($GLOBALS['config']['user']['manga_points_type'] ?? 0, true);
        if (!in_array($mode, [0,1], true)) {
            return ['code'=>1002, 'msg'=>lang('obtain_err')];
        }
        $whole = $mode === 1;
        $points = PointsBalance::amount($row[$whole ? 'manga_points' : 'manga_points_detail'] ?? 0, true);
        if (!$whole && $points === 0) {
            $points = PointsBalance::amount($row['manga_points'] ?? 0, true);
        }
        if ($points === null || $points > 65535) {
            return ['code'=>1002, 'msg'=>lang('obtain_err')];
        }
        $images = self::mangaImages($current['url']);
        $purchaseSid = $sid;
        $purchaseNid = $nid;
        $purchaseSupported = $sid <= 255 && $nid <= 65535 && $images !== [];
        if ($whole) {
            $purchaseSid = $purchaseNid = 0;
            $purchaseSupported = false;
            foreach ($sources as $sourceKey=>$group) {
                if (self::positiveInt($sourceKey) === null || (int)$sourceKey > 255 || !is_array($group)) {
                    continue;
                }
                foreach (is_array($group['urls'] ?? null) ? $group['urls'] : [] as $chapterKey=>$chapter) {
                    if (self::positiveInt($chapterKey) !== null && (int)$chapterKey <= 65535
                        && is_array($chapter) && self::mangaImages($chapter['url'] ?? null) !== []) {
                        $purchaseSid = (int)$sourceKey;
                        $purchaseNid = (int)$chapterKey;
                        $purchaseSupported = true;
                        break 2;
                    }
                }
            }
        }
        return ['code'=>1, 'msg'=>'ok', 'id'=>$id, 'sid'=>$sid, 'nid'=>$nid,
            'source'=>$source, 'current'=>$current, 'images'=>$images, 'episode_total'=>count($coordinates),
            'previous_nid'=>$position > 0 ? $coordinates[$position - 1] : null,
            'next_nid'=>$coordinates[$position + 1] ?? null,
            'points'=>$points, 'whole'=>$whole, 'purchase_supported'=>$purchaseSupported,
            'purchase_sid'=>$purchaseSid, 'purchase_nid'=>$purchaseNid,
            'ulog_mid'=>12, 'ulog_type'=>1, 'ulog_rid'=>$id,
            'ulog_sid'=>$whole ? 0 : $sid, 'ulog_nid'=>$whole ? 0 : $nid];
    }

    /** Fixed numeric dynamic entry: independent of detail rewrite and unsupported static-reader paths. */
    public static function mangaReadLink(array $row, int $sid = 1, int $nid = 1): string
    {
        return MAC_PATH . 'index.php/manga/play?' . http_build_query(['id'=>(int)($row['manga_id'] ?? 0), 'sid'=>$sid, 'nid'=>$nid]);
    }

    /** Public templates never receive raw chapter addresses; current authorized images are assigned separately. */
    public static function mangaTemplate(array $row): array
    {
        $row['manga_page_list'] = self::mangaPages($row);
        $template = PublicContentView::detail('manga', $row);
        $state = ContentPassword::mangaState($row);
        $template['manga_pwd'] = $state['required'] ? 1 : 0;
        $template['manga_pwd_url'] = $state['help_url'];
        $template['manga_page_total'] = count($template['manga_page_list']);
        foreach (['manga_chapter_url','manga_chapter_from','manga_play_server','manga_play_note'] as $field) {
            $template[$field] = '';
        }
        return $template;
    }
}
