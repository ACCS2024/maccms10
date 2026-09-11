<?php
declare(strict_types=1);
namespace app\common\util;

use think\facade\Db;

/** Server-created snapshot; joins LocalAttachment's owned transaction after external transfers. */
final class VodCoverBinding
{
    public const FIELDS = ['vod_id','vod_recycle_time','vod_pic','vod_pic_thumb','vod_pic_original',
        'vod_pic_thumb_original','vod_en','vod_name','vod_sub','vod_class','vod_area','vod_year',
        'vod_blurb','vod_content'];

    public function __construct(private array $snapshot)
    {
        if (PointsBalance::amount($snapshot['vod_id'] ?? null) === null) {
            throw new \InvalidArgumentException('Invalid cover owner');
        }
        foreach (self::FIELDS as $field) {
            if (!array_key_exists($field, $snapshot)
                || (!is_string($snapshot[$field]) && !is_int($snapshot[$field])
                    && !($field === 'vod_pic_thumb_original' && $snapshot[$field] === null))) {
                throw new \RuntimeException('Incomplete cover snapshot; check the cover backup migration');
            }
        }
        if ((string)$snapshot['vod_recycle_time'] !== '0') { throw new \RuntimeException('Cover owner is recycled'); }
    }

    public function owner(): int { return (int)$this->snapshot['vod_id']; }
    public function snapshot(): array { return $this->snapshot; }

    public static function capture(int $id): self
    {
        LocalAttachment::assertRequestReady();
        FinancialTransaction::requireTables([Db::name('Vod')->getTable()]);
        $connection = Db::connect();
        $connection->query('SELECT 1', [], true);
        if ($connection->getConfig('break_reconnect') || $connection->getPdo()->inTransaction()) {
            throw new \RuntimeException('Cover changes require an independent writer transaction');
        }
        return new self(Db::name('Vod')->master()->field(self::FIELDS)->where('vod_id', $id)->find() ?? []);
    }

    /** Caller must hold an acknowledged transaction on its original writer. */
    public function lock(): array
    {
        $row = Db::name('Vod')->master()->field(self::FIELDS)->where('vod_id', $this->owner())->lock(true)->find();
        if (!$row) { throw new \RuntimeException('Cover owner no longer exists'); }
        foreach (self::FIELDS as $field) {
            $before = $this->snapshot[$field]; $now = $row[$field];
            if (($before === null) !== ($now === null) || (string)$before !== (string)$now) {
                throw new \RuntimeException('Video changed while preparing its cover; refresh before retrying');
            }
        }
        return $row;
    }

    public function bind(array $files): array
    {
        $row = $this->lock();
        $update = ['vod_pic'=>$files[0]['file'], 'vod_pic_thumb'=>$files[1]['file'] ?? ''];
        // NULL distinguishes missing historical thumbnail evidence from an intentionally empty thumbnail.
        if ($row['vod_pic_thumb_original'] === null && $row['vod_pic_original'] === '') {
            $update['vod_pic_original'] = $row['vod_pic'];
            $update['vod_pic_thumb_original'] = $row['vod_pic_thumb'];
        }
        return $this->persist($update);
    }

    public function restore(): array
    {
        $row = $this->lock();
        if ($row['vod_pic_thumb_original'] === null) {
            throw new \RuntimeException('No complete original cover pair is available');
        }
        return $this->persist(['vod_pic'=>$row['vod_pic_original'], 'vod_pic_thumb'=>$row['vod_pic_thumb_original'],
            'vod_pic_original'=>'', 'vod_pic_thumb_original'=>null]);
    }

    private function persist(array $update): array
    {
        foreach ($update as $value) {
            if ($value !== null && (!is_string($value) || strlen($value) > 1024)) {
                throw new \RuntimeException('Cover URL exceeds its storage budget');
            }
        }
        if (Db::name('Vod')->where('vod_id', $this->owner())->update($update) !== 1) {
            throw new \RuntimeException('Cover owner was not updated exactly once');
        }
        $row = Db::name('Vod')->master()->field(array_keys($update))->where('vod_id', $this->owner())->find();
        foreach ($update as $field => $value) {
            if (!$row || $row[$field] !== $value) { throw new \RuntimeException('Cover did not persist exactly'); }
        }
        return array_replace(array_intersect_key($this->snapshot, array_flip([
            'vod_pic','vod_pic_thumb','vod_pic_original','vod_pic_thumb_original'])), $update);
    }
}
