<?php
declare(strict_types=1);
namespace app\common\util;

/** One prepared attachment set: no database locks are held while invoking its storage provider. */
final class RemoteAttachment
{
    private array $intents = [];
    private array $results = [];
    private bool $attempted = false;
    private bool $ready = false;

    public function __construct(private string $provider, private ?int $owner, private bool $download = false, private ?int $coverOwner = null)
    {
        if ($download && $owner !== null) { throw new \InvalidArgumentException('Downloaded assets cannot be avatars'); }
        if ($coverOwner !== null && (!$download || $owner !== null || PointsBalance::amount($coverOwner) === null)) {
            throw new \InvalidArgumentException('Invalid cover transfer owner');
        }
    }

    public static function provider(array $config): ?string
    {
        $mode = $config['mode'] ?? '';
        if (!is_string($mode) && !is_int($mode)) { return null; }
        $mode = strtolower((string)$mode);
        $mode = ['2'=>'upyun','3'=>'qiniu','4'=>'ftp','5'=>'weibo'][$mode] ?? $mode;
        return in_array($mode, StoragePublicUrl::PROVIDERS, true) ? $mode : null;
    }

    public function transfer(array $records, callable $journal): void
    {
        // Prepare the entire set before any SDK call. Missing/old schema and invalid destinations retain local behavior.
        try {
            $policy = StoragePublicUrl::current($this->provider);
            if ($this->download) {
                foreach ($records as $record) {
                    if (strlen($policy->expected($record['annex_file'])) > 1024) {
                        throw new \RuntimeException('Download destination exceeds the resource URL column');
                    }
                }
            }
            foreach ($records as $record) {
                $path = $record['annex_file'];
                $scope = $this->coverOwner !== null ? 'ai_cover' : ($this->download ? 'download' : ($this->owner === null ? 'attachment' : 'avatar'));
                $this->intents[$path] = StorageIntent::prepare($path, $policy, $scope, $this->coverOwner ?? $this->owner ?? 0);
            }
        } catch (\Throwable $error) {
            $journal($this->evidence());
            return;
        }
        $this->ready = true;
        $journal($this->evidence());
        foreach ($this->intents as $path => $intent) {
            $this->attempted = true;
            $journal($this->evidence());
            $result = StorageTransfer::attempt($intent['intent_id']);
            $this->results[$path] = $result;
            $journal($this->evidence());
            if (!in_array($result['outcome'] ?? null, ['remote','local_fallback'], true)
                || !is_string($result['file'] ?? null)) {
                // Do not commit business references when their transfer receipt is unavailable or ambiguous.
                throw new \RuntimeException('Attachment transfer could not be durably reconciled');
            }
        }
    }

    public function evidence(): array
    {
        $evidence = ['ready'=>$this->ready,'attempted'=>$this->attempted,
            'intents'=>array_map(static fn($row)=>$row['intent_id'], $this->intents), 'results'=>$this->results];
        if ($this->download) {
            $evidence['scope'] = $this->coverOwner !== null ? 'ai_cover' : 'download';
            if ($this->coverOwner !== null) { $evidence['owner_id'] = $this->coverOwner; }
            $evidence['selected_urls'] = [];
            foreach ($this->results as $path => $result) { $evidence['selected_urls'][$path] = $this->url($path); }
        }
        return $evidence;
    }

    public function hasAttempt(): bool { return $this->attempted; }

    public function url(string $path): string
    {
        $url = $this->results[$path]['file'] ?? $path;
        // Image services can return an unpredictable but attested URL. Keep the local resource if it will not fit.
        return $this->download && strlen($url) > 1024 ? $path : $url;
    }

    /** Join exactly the final Annex/User transaction; a no-SDK fallback has no completed transfer to reference. */
    public function recordReferences(array $annexIds): void
    {
        if (!$this->ready) { return; }
        $references = [];
        foreach ($this->intents as $path => $intent) {
            if (!isset($this->results[$path], $annexIds[$path])) { throw new \RuntimeException('Incomplete attachment transfer set'); }
            $references[$intent['intent_id']] = $annexIds[$path];
        }
        StorageIntent::recordReferences($references);
    }

    /** Only acknowledged business commits may remove this upload's confirmed remote replicas. */
    public function cleanup(array $config): void
    {
        if (!empty($config['keep_local'])) { return; }
        try {
            $urls = StorageObjectUrl::resolve(array_keys($this->results));
            foreach ($this->results as $path => $result) {
                if (($result['remote_confirmed'] ?? false) !== true || ($urls[$path] ?? null) !== $result['file']) { continue; }
                if ($this->url($path) !== $result['file']) { continue; }
                StorageIntent::sameSource($this->intents[$path]);
                @unlink(ROOT_PATH . $path);
            }
        } catch (\Throwable $error) {
            // Retaining an extra local copy is safe. Cleanup must not turn a committed upload into failure.
        }
    }
}
