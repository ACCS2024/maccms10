<?php
namespace app\common\util;

use GuzzleHttp\Psr7\Uri;
use GuzzleHttp\Psr7\UriResolver;

class Collection
{
    private const MAX_URLS = 10000;
    private const MAX_CONTENT_PAGES = 100;

    /** Return collected fields, or false when fetching/parsing any required page fails. */
    public static function get_content($url, $config, $page = 0)
    {
        $config = self::normalizeConfig($config);
        if ($config === false || !is_scalar($page)) {
            return false;
        }
        $visited = [];
        return self::collectContent($url, $config, (int)$page, $visited);
    }

    private static function collectContent($url, array $config, int $page, array &$visited)
    {
        $url = self::url_check($url, $url, $config);
        if ($url === '' || isset($visited[$url]) || count($visited) >= self::MAX_CONTENT_PAGES) {
            return false;
        }
        $visited[$url] = true;
        $html = self::get_html($url, $config);
        if ($html === false) {
            return false;
        }
        $data = ['content' => ''];
        if ($page === 0) {
            $data['time'] = time();
            foreach (['title', 'type'] as $field) {
                if ($config[$field . '_rule'] !== '') {
                    $data[$field] = self::extract($html, $config[$field . '_rule'], $config[$field . '_html_rule']);
                    if ($data[$field] === false) { return false; }
                }
            }
            foreach ($config['customize_config'] as $item) {
                if ($item['rule'] === '' || $item['en_name'] === '') { continue; }
                $value = self::extract($html, $item['rule'], $item['html_rule']);
                if ($value === false) { return false; }
                $data[$item['en_name']] = $value;
            }
        }
        if ($config['content_rule'] !== '') {
            $data['content'] = self::extract($html, $config['content_rule'], $config['content_html_rule']);
            if ($data['content'] === false) { return false; }
        }
        // Resolve each page's images against that page before joining the content.
        $data['content'] = preg_replace_callback(
            '~(<img\b[^>]*?\ssrc\s*=\s*)(?:"([^"]*)"|\'([^\']*)\'|([^\s>]+))~i',
            static function ($match) use ($url, $config) {
                $source = html_entity_decode($match[2] !== '' ? $match[2] : (($match[3] ?? '') !== '' ? $match[3] : ($match[4] ?? '')), ENT_QUOTES | ENT_HTML5, 'UTF-8');
                $absolute = self::url_check($source, $url, $config, false);
                return $absolute === '' ? $match[0] : $match[1] . '"' . htmlspecialchars($absolute, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '"';
            }, $data['content']);

        if (in_array($page, [0, 2], true) && $config['content_page_start'] !== '' && $config['content_page_end'] !== '') {
            $pageHtml = self::cut_html($html, $config['content_page_start'], $config['content_page_end']);
            $parts = [$data['content']];
            $nextMode = (int)$config['content_page_rule'] === 2;
            if ($pageHtml !== false && ($nextMode || ((int)$config['content_page_rule'] === 1 && $page === 0))) {
                foreach (self::links($pageHtml) as $link) {
                    if ($nextMode && ($config['content_nextpage'] === '' || !str_contains($link['title'], $config['content_nextpage']))) { continue; }
                    if ($link['url'] === '' || str_starts_with($link['url'], '#')) { continue; }
                    $next = self::url_check($link['url'], $url, $config);
                    if ($next === '' || isset($visited[$next])) { continue; }
                    $result = self::collectContent($next, $config, $nextMode ? 2 : 1, $visited);
                    if ($result === false) { return false; }
                    if ($result['content'] !== '' && !in_array($result['content'], $parts, true)) { $parts[] = $result['content']; }
                }
            }
            $data['content'] = implode((int)$config['content_page'] === 1 ? '[page]' : '', $parts);
        }
        return $data;
    }

    /** Invalid/empty list configuration returns an empty list for the existing controller error path. */
    public static function url_list(&$config, $num = '')
    {
        $settings = self::normalizeConfig($config);
        if ($settings === false || !is_scalar($num)) { return []; }
        $urls = [];
        switch ((int)$settings['sourcetype']) {
            case 1:
                $start = filter_var($settings['pagesize_start'], FILTER_VALIDATE_INT);
                $end = filter_var($num === '' ? $settings['pagesize_end'] : $num, FILTER_VALIDATE_INT);
                $step = filter_var($settings['par_num'], FILTER_VALIDATE_INT);
                if ($start === false || $end === false || $step === false || $step <= 0 || $start < 0 || $end < $start
                    || (($end - $start) / $step) >= self::MAX_URLS) { return []; }
                for ($i = $start; $i <= $end;) {
                    $urls[] = str_replace('(*)', (string)$i, $settings['urlpage']);
                    if ($end - $i < $step) { break; }
                    $i += $step;
                }
                break;
            case 2:
                $urls = preg_split('/\r\n|\r|\n/', $settings['urlpage']);
                break;
            case 3:
            case 4:
                $urls = [$settings['urlpage']];
                break;
        }
        $urls = array_values(array_filter(array_map('trim', $urls), static fn($url) => $url !== ''));
        return count($urls) <= self::MAX_URLS ? $urls : [];
    }

    /** Return URL/title records, [] for a valid empty list, or false for a failed fetch/parse. */
    public static function get_url_lists($url, &$config)
    {
        $settings = self::normalizeConfig($config);
        if ($settings === false) { return false; }
        $html = self::get_html($url, $settings);
        if ($html === false) { return false; }
        if ((int)$settings['sourcetype'] === 4) {
            // The application helper rejects DTD/entities and disables XML network access.
            $rss = mac_xml2array($html);
            if (!is_array($rss) || !isset($rss['channel']) || !is_array($rss['channel'])) { return false; }
            $items = $rss['channel']['item'] ?? [];
            if (!is_array($items)) { return false; }
            if (isset($items['link'])) { $items = [$items]; }
            $links = [];
            foreach ($items as $item) {
                if (is_array($item) && is_string($item['link'] ?? null) && is_string($item['title'] ?? null)) {
                    $links[] = ['url' => $item['link'], 'title' => $item['title']];
                }
            }
        } else {
            $html = self::cut_html($html, $settings['url_start'], $settings['url_end']);
            if ($html === false) { return false; }
            $links = self::links($html);
        }
        $data = [];
        foreach ($links as $link) {
            if ($settings['url_contain'] !== '' && !str_contains($link['url'], $settings['url_contain'])) { continue; }
            if ($settings['url_except'] !== '' && str_contains($link['url'], $settings['url_except'])) { continue; }
            $absolute = self::url_check($link['url'], $url, $settings);
            if ($absolute !== '') { $data[] = ['url' => $absolute, 'title' => $link['title']]; }
        }
        return $data;
    }

    private static function links(string $html): array
    {
        preg_match_all('~<a\b([^>]*)>(.*?)</a\s*>~is', $html, $anchors, PREG_SET_ORDER);
        $links = [];
        foreach ($anchors as $anchor) {
            if (preg_match('~(?:^|\s)href\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s>]+))~i', $anchor[1], $match)) {
                $links[] = [
                    'url' => html_entity_decode($match[1] !== '' ? $match[1] : (($match[2] ?? '') !== '' ? $match[2] : ($match[3] ?? '')), ENT_QUOTES | ENT_HTML5, 'UTF-8'),
                    'title' => html_entity_decode(strip_tags($anchor[2]), ENT_QUOTES | ENT_HTML5, 'UTF-8'),
                ];
            }
        }
        return $links;
    }

    private static function normalizeConfig($config)
    {
        if (!is_array($config)) { return false; }
        $defaults = array_fill_keys([
            'title_rule', 'title_html_rule', 'type_rule', 'type_html_rule', 'content_rule', 'content_html_rule',
            'content_page_start', 'content_page_end', 'content_nextpage', 'content_page_rule', 'content_page',
            'sourcetype', 'pagesize_start', 'pagesize_end', 'par_num', 'urlpage', 'url_start', 'url_end',
            'url_contain', 'url_except', 'page_base',
        ], '');
        $defaults['sourcecharset'] = 'UTF-8';
        foreach ($defaults as $key => $default) {
            $value = $config[$key] ?? $default;
            if (!is_scalar($value)) { return false; }
            $config[$key] = (string)$value;
        }
        $custom = $config['customize_config'] ?? [];
        if (is_string($custom)) { $custom = $custom === '' ? [] : json_decode($custom, true); }
        if (!is_array($custom)) { return false; }
        foreach ($custom as &$item) {
            if (!is_array($item)) { return false; }
            foreach (['en_name', 'rule', 'html_rule'] as $field) {
                if (isset($item[$field]) && !is_scalar($item[$field])) { return false; }
                $item[$field] = (string)($item[$field] ?? '');
            }
        }
        unset($item);
        $config['customize_config'] = $custom;
        return $config;
    }

    protected static function get_html($url, &$config)
    {
        if (!is_string($url) || $url === '') { return false; }
        $html = mac_curl_get($url);
        if (!is_string($html) || $html === '') { return false; }
        if (strtoupper($config['sourcecharset']) !== 'UTF-8' && (int)$config['sourcetype'] !== 4) {
            $html = @iconv($config['sourcecharset'], 'UTF-8//TRANSLIT//IGNORE', $html);
        }
        return $html;
    }

    protected static function cut_html($html, $start, $end)
    {
        $html = str_replace(["\r", "\n"], '', $html);
        $start = trim(str_replace(["\r", "\n"], '', $start));
        $end = trim(str_replace(["\r", "\n"], '', $end));
        if ($start !== '') {
            $position = strpos($html, $start);
            if ($position === false) { return false; }
            $html = substr($html, $position + strlen($start));
        }
        if ($end !== '') {
            $position = strpos($html, $end);
            if ($position === false) { return false; }
            $html = substr($html, 0, $position);
        }
        return trim($html);
    }

    private static function extract(string $html, string $rule, string $filter)
    {
        if (!str_contains($rule, '[内容]')) { return $rule; }
        $parts = explode('[内容]', $rule);
        if (count($parts) !== 2) { return false; }
        $value = self::cut_html($html, $parts[0], $parts[1]);
        return $value === false ? false : self::replace_item($value, $filter);
    }

    protected static function replace_item($html, $config)
    {
        if ($config === '') { return $html; }
        foreach (preg_split('/\r\n|\r|\n/', $config) as $line) {
            if (trim($line) === '') { continue; }
            $parts = explode('[|]', $line, 2);
            if (count($parts) !== 2) { return false; }
            $html = @preg_replace('/' . str_replace('/', '\\/', $parts[0]) . '/i', $parts[1], $html);
            if ($html === null) { return false; }
        }
        return $html;
    }

    protected static function url_check($url, $baseurl, $config, bool $stripFragment = true)
    {
        if (!is_string($url) || !is_string($baseurl) || $url === '' || preg_match('/[\x00-\x20\x7f]/', $url)) { return ''; }
        try {
            $reference = new Uri($url);
            $base = new Uri($baseurl);
            if ($reference->getScheme() === '' && $reference->getHost() === '' && !str_starts_with($url, '/') && $config['page_base'] !== '') {
                $base = UriResolver::resolve($base, new Uri($config['page_base']));
                $base = $base->withPath(rtrim($base->getPath(), '/') . '/')->withQuery('')->withFragment('');
            }
            $result = UriResolver::resolve($base, $reference);
            if ($stripFragment) { $result = $result->withFragment(''); }
            return in_array($result->getScheme(), ['http', 'https'], true) && $result->getHost() !== '' && $result->getUserInfo() === ''
                ? (string)$result : '';
        } catch (\InvalidArgumentException $error) {
            return '';
        }
    }
}
