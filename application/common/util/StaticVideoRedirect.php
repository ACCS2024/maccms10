<?php
namespace app\common\util;

/** Static video pages only transport public coordinates to the dynamic authorization boundary. */
final class StaticVideoRedirect
{
    public static function pages(array $row, string $operation, int $mode): array
    {
        if (!in_array($operation, ['play', 'down'], true) || !in_array($mode, [2, 3, 4], true)) {
            throw new \InvalidArgumentException('Unsupported static video mode');
        }
        $id = ContentResource::positiveInt($row['vod_id'] ?? null);
        if ($id === null) {
            throw new \InvalidArgumentException('Invalid video ID');
        }
        $pages = [];
        foreach (is_array($row['vod_' . $operation . '_list'] ?? null) ? $row['vod_' . $operation . '_list'] : [] as $sid => $source) {
            if (!is_array($source)) {
                continue;
            }
            foreach (is_array($source['urls'] ?? null) ? $source['urls'] : [] as $nid => $episode) {
                if (!is_string($episode['url'] ?? null) || $episode['url'] === '') {
                    continue;
                }
                $coordinates = ['sid' => (int)$sid, 'nid' => (int)$nid];
                if (ContentResource::positiveInt($sid) === null || ContentResource::positiveInt($nid) === null) {
                    continue;
                }
                $url = $operation === 'play' ? mac_url_vod_play($row, $coordinates) : mac_url_vod_down($row, $coordinates);
                $pages[] = ['url' => $url, 'id' => $id, 'operation' => $operation,
                    'sid' => (int)$sid, 'nid' => (int)$nid, 'legacy_query' => $mode !== 3];
                if ($mode === 2) {
                    return $pages;
                }
                if ($mode === 4) {
                    break;
                }
            }
        }
        return $pages;
    }

    public static function render(array $page): string
    {
        $entry = MAC_PATH . 'index.php/vod/resource';
        if (!str_starts_with($entry, '/') || str_starts_with($entry, '//') || preg_match('/[\\\\\x00-\x20\x7f]/', $entry)) {
            throw new \InvalidArgumentException('Invalid application path');
        }
        $parameters = ['id' => $page['id'], 'operation' => $page['operation'], 'sid' => $page['sid'], 'nid' => $page['nid']];
        if (!in_array($parameters['operation'], ['play', 'down'], true)
            || ContentResource::positiveInt($parameters['id']) === null
            || ContentResource::positiveInt($parameters['sid']) === null
            || ContentResource::positiveInt($parameters['nid']) === null
            || !is_bool($page['legacy_query'] ?? null)) {
            throw new \InvalidArgumentException('Invalid static video coordinates');
        }
        $escape = static fn(string $value): string => htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        $fallback = $escape($entry . '?' . http_build_query($parameters));
        $attributes = ' data-entry="' . $escape($entry) . '"';
        foreach ($parameters as $name => $value) {
            $attributes .= ' data-' . $name . '="' . $escape((string)$value) . '"';
        }
        $attributes .= ' data-legacy-query="' . ($page['legacy_query'] ? '1' : '0') . '"';
        // External, local JavaScript preserves view-2/view-4 selectors under script-src 'self'.
        // The visible link remains usable when JavaScript is disabled or unavailable.
        return '<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">'
            . '<meta name="referrer" content="same-origin">'
            . '<title>打开播放或下载页面</title></head><body><p><a id="resource-link" href="' . $fallback
            . '"' . $attributes . '>前往播放或下载页面</a></p><script defer src="'
            . $escape(MAC_PATH . 'static/js/vod-resource-redirect.js') . '"></script></body></html>';
    }

    /** Publish only an HTML redirect below the deployment root, replacing that requested file atomically. */
    public static function write(string $url, string $content, string $root): string
    {
        $parts = parse_url($url);
        if (!is_array($parts) || isset($parts['scheme']) || isset($parts['host']) || !is_string($parts['path'] ?? null)) {
            throw new \RuntimeException('Invalid static page path');
        }
        $path = $parts['path'];
        if (MAC_PATH !== '/') {
            if (!str_starts_with($path, MAC_PATH)) {
                throw new \RuntimeException('Static page is outside the application URL prefix');
            }
            $path = substr($path, strlen(MAC_PATH));
        }
        $segments = explode('/', ltrim($path, '/'));
        foreach ($segments as &$segment) {
            $segment = rawurldecode($segment);
            if ($segment === '' || $segment[0] === '.' || !preg_match('/^[\p{L}\p{N} _.-]+$/uD', $segment)) {
                throw new \RuntimeException('Invalid static page path');
            }
        }
        unset($segment);
        if (in_array(strtolower($segments[0]), ['application', 'config', 'vendor', 'extend', 'runtime'], true)
            || !preg_match('/\.(?:html?|shtml?|xhtml)$/iD', end($segments))) {
            throw new \RuntimeException('Static redirects require a public HTML path');
        }
        $root = realpath($root);
        if ($root === false || !is_dir($root)) {
            throw new \RuntimeException('Static deployment root is missing');
        }
        $filename = array_pop($segments);
        $directory = $root;
        $temporary = null;
        try {
            foreach ($segments as $segment) {
                $directory .= DIRECTORY_SEPARATOR . $segment;
                if (is_link($directory) || (!is_dir($directory) && !mkdir($directory, 0755))) {
                    throw new \RuntimeException('Static output directory is unavailable');
                }
                $resolved = realpath($directory);
                if ($resolved === false || !str_starts_with($resolved . DIRECTORY_SEPARATOR, $root . DIRECTORY_SEPARATOR)) {
                    throw new \RuntimeException('Static output directory escaped its root');
                }
            }
            $target = $directory . DIRECTORY_SEPARATOR . $filename;
            if (is_link($target) || is_dir($target)) {
                throw new \RuntimeException('Static output target is not a regular file');
            }
            $temporary = $directory . DIRECTORY_SEPARATOR . '.vod-redirect-' . bin2hex(random_bytes(12));
            $stream = fopen($temporary, 'xb');
            if ($stream === false) {
                throw new \RuntimeException('Cannot create a static redirect');
            }
            try {
                $written = fwrite($stream, $content);
                if ($written !== strlen($content) || !fflush($stream)) {
                    throw new \RuntimeException('Cannot finish a static redirect');
                }
            } finally {
                fclose($stream);
            }
            if (!rename($temporary, $target)) {
                throw new \RuntimeException('Cannot publish a static redirect');
            }
            $temporary = null;
            return $target;
        } catch (\Throwable $error) {
            throw new \RuntimeException('Static redirect generation failed', 0, $error);
        } finally {
            if ($temporary !== null && is_file($temporary)) {
                unlink($temporary);
            }
        }
    }
}
