<?php
declare(strict_types=1);
namespace app\common\util;

use think\facade\Db;

/** Resolve only attested, committed objects that still have their exact Annex reference. Never trusts free-form user URLs. */
final class StorageObjectUrl
{
    public static function resolve(array $paths, array $avatarOwners = []): array
    {
        $paths = array_values(array_unique(array_filter($paths, [StoragePublicUrl::class, 'localPath'])));
        if ($paths === []) { return []; }
        $urls = []; $policies = [];
        try {
            foreach (array_chunk($paths, 500) as $chunk) {
                $rows = Db::name('StorageIntent')->master()->alias('s')
                    ->join(Db::name('Annex')->getTable() . ' a', 'a.annex_id=s.annex_id')
                    ->field('s.*,a.annex_file,a.annex_size,a.annex_type')
                    ->whereIn('s.local_path', $chunk)->where('s.transfer_state', 'remote_confirmed')
                    ->where('s.reference_state', 'committed')->where('s.result_code', 'remote_confirmed')->select()->toArray();
                foreach ($rows as $row) {
                    $path = $row['local_path'];
                    $bytes = PointsBalance::amount($row['source_bytes'], true);
                    if ($row['annex_file'] !== $path
                        || !in_array($row['annex_type'], ['image','file','media'], true)
                        || $bytes === null || PointsBalance::amount($row['annex_size'], true) !== $bytes) { continue; }
                    if (isset($avatarOwners[$path]) && ($row['scope'] !== 'avatar' || $row['annex_type'] !== 'image'
                        || PointsBalance::amount($row['owner_id']) !== $avatarOwners[$path]
                        || !UserPortrait::isManagedPath($avatarOwners[$path], $path))) { continue; }
                    $provider = $row['provider'];
                    if (!array_key_exists($provider, $policies)) {
                        try { $policies[$provider] = StoragePublicUrl::current($provider); }
                        catch (\Throwable $error) { $policies[$provider] = null; }
                    }
                    $policy = $policies[$provider];
                    if ($policy !== null && hash_equals($policy->fingerprint, $row['destination_hash'])
                        && $policy->accepts($row['remote_url'], $path)) { $urls[$path] = $row['remote_url']; }
                }
            }
        } catch (\Throwable $error) {
            // Old schemas/unavailable metadata preserve the existing local/legacy read behavior.
        }
        return $urls;
    }

    public static function annexList(array $rows): array
    {
        $urls = self::resolve(array_column($rows, 'annex_file'));
        foreach ($rows as &$row) {
            $path = $row['annex_file'] ?? null;
            $row['annex_url'] = is_string($path) ? ($urls[$path] ?? (StoragePublicUrl::localPath($path) ? (defined('MAC_PATH') ? MAC_PATH : '/') . $path : '')) : '';
        }
        unset($row);
        return $rows;
    }

    /** Absence of a local file proves nothing about an attempted remote object. Unknown metadata must fail closed. */
    public static function protectedPaths(array $paths): array
    {
        $paths = array_values(array_unique(array_filter($paths, [StoragePublicUrl::class, 'localPath'])));
        if ($paths === []) { return []; }
        $protected = [];
        try {
            foreach (array_chunk($paths, 500) as $chunk) {
                $rows = Db::name('StorageIntent')->master()->field('local_path')->whereIn('local_path', $chunk)->select()->toArray();
                foreach ($rows as $row) { $protected[$row['local_path']] = true; }
            }
        } catch (\Throwable $error) { return array_fill_keys($paths, true); }
        return $protected;
    }
}
