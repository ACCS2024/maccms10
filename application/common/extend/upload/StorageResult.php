<?php
namespace app\common\extend\upload;

/** Finish only after the provider has confirmed a usable remote object. */
final class StorageResult
{
    public static function complete(string $localPath, $url, array $config): string
    {
        if (!is_string($url) || $url === '') { return $localPath; }
        $parts = parse_url($url);
        if ($parts === false || empty($parts['host'])
            || !in_array(strtolower($parts['scheme'] ?? ''), ['http', 'https'], true)) {
            return $localPath;
        }
        if (empty($config['keep_local'])) { @unlink(ROOT_PATH . $localPath); }
        return $url;
    }
}
