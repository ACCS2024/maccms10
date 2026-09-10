<?php
declare(strict_types=1);
namespace app\common\util;

use app\common\model\Annex;
use app\common\model\Image;
use think\facade\Db;

/** One new local attachment and all its derivatives. Never replaces or deletes pre-existing files. */
final class LocalAttachment
{
    private const IMAGES = ['jpg','jpeg','png','gif','webp'];
    private const FILES = ['doc','docx','xls','xlsx','ppt','pptx','pdf','wps','txt','rar','zip','torrent'];
    private const MEDIA = ['rm','rmvb','avi','mkv','mp4','mp3'];

    public static function store(array $parameters, array $config): array
    {
        return self::process($parameters, $config, null, false);
    }

    /** The upload controller/model supplies the verified owner and server-selected admin context. */
    public static function storeAvatar(array $parameters, array $config, int $owner, bool $requireActiveOwner): array
    {
        if (PointsBalance::amount($owner) === null || ($parameters['flag'] ?? null) !== 'user') {
            throw new \InvalidArgumentException('Invalid avatar owner');
        }
        return self::process($parameters, $config, $owner, $requireActiveOwner);
    }

    private static function process(array $parameters, array $config, ?int $owner, bool $requireActiveOwner): array
    {
        if (!isset($parameters['flag']) || !is_string($parameters['flag'])
            || ($owner === null && $parameters['flag'] === 'user')
            || !preg_match('/^[a-z0-9_]{1,64}$/D', $parameters['flag'])) {
            throw new \InvalidArgumentException('Invalid local attachment flag');
        }
        $stage = null; $published = []; $directories = []; $remote = null;
        $connection = null; $transaction = false; $committed = false; $commitStarted = false;
        try {
            $stage = rtrim(sys_get_temp_dir(), DIRECTORY_SEPARATOR) . '/maccms-attachment-' . bin2hex(random_bytes(16));
            if (!@mkdir($stage, 0700)) { throw new \RuntimeException('Cannot create upload staging directory'); }
            [$source, $type] = self::receive($stage, $parameters);
            self::scan($source);
            $prepared = [$source];
            if ($owner !== null) {
                if ($type !== 'image') { throw new \RuntimeException('Avatar must be an image'); }
                // Validate the declared image type before producing the explicitly flattened JPEG avatar.
                (new Image())->prepareLocalUpload($source, ['watermark'=>0], false);
                $size = $GLOBALS['config']['user']['portrait_size'] ?? null;
                if ((!is_string($size) && !is_int($size)) || !preg_match('/^([0-9]{1,5})(?:x([0-9]{1,5}))?$/Di', (string)$size, $dimensions)) {
                    throw new \RuntimeException('Invalid avatar dimensions');
                }
                $avatar = $stage . '/source-avatar.jpg';
                ImageProcessor::open($source)->thumb($dimensions[1], $dimensions[2] ?? $dimensions[1], 6)->save($avatar, 'jpeg');
                $prepared = [$avatar];
            } elseif ($type === 'image') {
                $prepared = array_merge($prepared, (new Image())->prepareLocalUpload($source, $config, $parameters['thumb'] === '1'));
            }
            $name = ($owner === null ? '' : $owner . '-') . bin2hex(random_bytes(16));
            $directory = $owner === null ? self::targetDirectory($parameters['flag']) : 'upload/user/' . ($owner % 10);
            $descriptors = []; $records = [];
            foreach ($prepared as $index => $file) {
                clearstatcache(true, $file);
                $bytes = @filesize($file);
                if (!is_int($bytes) || $bytes < 0 || $bytes > 4294967295) { throw new \RuntimeException('Attachment size exceeds schema'); }
                $relative = $directory . '/' . $name . ($owner === null ? substr(basename($file), strlen('source')) : '.jpg');
                $descriptors[] = ['file'=>$relative, 'type'=>$type, 'size'=>round($bytes / 1024, 2),
                    'flag'=>$parameters['flag'], 'ctime'=>request()->time()];
                $records[] = ['annex_file'=>$relative, 'annex_type'=>$type, 'annex_size'=>$bytes];
            }
            // A crash/ambiguous COMMIT must leave enough identity to inspect only this upload's files.
            $manifest = ['state'=>'prepared', 'created'=>time(), 'root'=>realpath(ROOT_PATH),
                'metadata_table'=>Db::name('Annex')->getTable(), 'files'=>$records];
            if ($owner !== null) { $manifest['avatar_owner'] = $owner; $manifest['owner_table'] = Db::name('User')->getTable(); }
            self::manifest($stage, $manifest);
            $connection = Db::connect();
            Db::name('Annex')->getTableFields();
            if ($owner !== null) { Db::name('User')->getTableFields(); }
            if ($connection->getPdo() && $connection->getPdo()->inTransaction()) {
                throw new \RuntimeException('Upload must own its transaction');
            }
            $connection->query('SELECT 1', [], true);
            if ($connection->getPdo()->inTransaction()) { throw new \RuntimeException('Upload must own its master transaction'); }
            if ($connection->getPdo()->getAttribute(\PDO::ATTR_DRIVER_NAME) === 'mysql') {
                foreach ($owner === null ? ['Annex'] : ['Annex', 'User'] as $model) {
                    $engines = $connection->query('SELECT ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?', [Db::name($model)->getTable()], true);
                    if (count($engines) !== 1 || strtolower((string)$engines[0]['ENGINE']) !== 'innodb') {
                        throw new \RuntimeException('Attachment metadata requires transactional storage');
                    }
                }
            }
            $provider = RemoteAttachment::provider($config);
            if ($provider !== null) {
                self::makeDirectories($directory, $directories);
                foreach ($prepared as $index => $file) {
                    self::publish($file, ROOT_PATH . $records[$index]['annex_file'], $records[$index]['annex_size'], $published);
                }
                $remote = new RemoteAttachment($provider, $owner);
                $remote->transfer($records, static function (array $evidence) use ($stage, &$manifest): void {
                    $manifest['remote'] = $evidence;
                    self::manifest($stage, $manifest);
                });
            }
            $connection->startTrans(); $transaction = true;
            if ($owner !== null) {
                $user = Db::name('User')->master()->field('user_id,user_status,user_portrait')->where('user_id', $owner)->lock(true)->find();
                if (!$user || ($requireActiveOwner && (string)$user['user_status'] !== '1')) {
                    throw new \RuntimeException('Avatar owner is no longer available');
                }
            }
            $annexIds = [];
            foreach ($records as $record) {
                if (Db::name('Annex')->where('annex_file', $record['annex_file'])->count() !== 0) {
                    throw new \RuntimeException('Attachment identity already exists');
                }
                $started = time();
                $saved = (new Annex())->saveData($record);
                if (($saved['code'] ?? null) !== 1) { throw new \RuntimeException('Attachment metadata rejected'); }
                $rows = Db::name('Annex')->master()->where('annex_file', $record['annex_file'])->limit(2)->select()->toArray();
                if (count($rows) !== 1 || ($rows[0]['annex_file'] ?? null) !== $record['annex_file']
                    || ($rows[0]['annex_type'] ?? null) !== $record['annex_type']
                    || PointsBalance::amount($rows[0]['annex_size'] ?? null, true) !== $record['annex_size']
                    || PointsBalance::amount($rows[0]['annex_id'] ?? null) === null
                    || ($storedTime = PointsBalance::amount($rows[0]['annex_time'] ?? null)) === null
                    || $storedTime < $started || $storedTime > time()) {
                    throw new \RuntimeException('Attachment metadata did not persist exactly');
                }
                $annexIds[$record['annex_file']] = (int)$rows[0]['annex_id'];
            }
            if ($remote === null) {
                self::makeDirectories($directory, $directories);
                foreach ($prepared as $index => $file) {
                    self::publish($file, ROOT_PATH . $records[$index]['annex_file'], $records[$index]['annex_size'], $published);
                }
            }
            if ($owner !== null) {
                $path = $records[0]['annex_file'];
                $changed = Db::name('User')->where('user_id', $owner)->where('user_portrait', $user['user_portrait'])->update(['user_portrait'=>$path]);
                if ($changed !== 1 || Db::name('User')->master()->where('user_id', $owner)->value('user_portrait') !== $path) {
                    throw new \RuntimeException('Avatar pointer did not persist exactly');
                }
            }
            if ($remote !== null) { $remote->recordReferences($annexIds); }
            $commitStarted = true;
            $connection->commit(); $transaction = false; $committed = true;
            if ($owner !== null) { UserPortrait::forget($owner); }
            if ($remote !== null) {
                $remote->cleanup($config);
                foreach ($descriptors as &$descriptor) { $descriptor['file'] = $remote->url($descriptor['file']); }
                unset($descriptor);
            }
            $data = $descriptors[0];
            if ($owner !== null) { $data['_portrait_path'] = $records[0]['annex_file']; }
            $data['thumb_class'] = $parameters['thumb_class'];
            $data['thumb'] = array_slice($descriptors, 1);
            return $data;
        } catch (\Throwable $error) {
            if ($transaction && $connection !== null) {
                try { $connection->rollback(); } catch (\Throwable $rollbackError) { /* The transaction may have lost its connection. */ }
            }
            if ($commitStarted && !$committed && $stage !== null) {
                // Do not delete files referenced by a COMMIT whose acknowledgement may have been lost.
                try { self::manifest($stage, array_merge($manifest, ['state'=>'commit_outcome_unknown'])); } catch (\Throwable $manifestError) {}
                error_log('Upload commit outcome unknown; inspect private manifest: ' . $stage . '/manifest.json');
            } elseif ($remote !== null && $remote->hasAttempt() && $stage !== null) {
                try { self::manifest($stage, array_merge($manifest, ['state'=>'remote_reference_failed'])); } catch (\Throwable $manifestError) {}
                error_log('Remote upload reference failed; inspect private manifest: ' . $stage . '/manifest.json');
            }
            throw $error;
        } finally {
            $retainRemoteEvidence = !$committed && $remote !== null && $remote->hasAttempt();
            if (!$committed && !$commitStarted && !$retainRemoteEvidence) {
                foreach (array_reverse($published) as $file) { if (is_file($file) && !is_link($file)) { @unlink($file); } }
                foreach (array_reverse($directories) as $directory) { @rmdir($directory); }
            }
            if ($stage !== null && (!$commitStarted || $committed) && !$retainRemoteEvidence) { self::removeStage($stage); }
        }
    }

    private static function receive(string $stage, array $parameters): array
    {
        $base64 = $parameters['imgdata'] ?? '';
        if ($base64 !== '') {
            if (!is_string($base64) || !preg_match('/^data:\s*image\/(\w+);base64,/', $base64, $match)) {
                throw new \RuntimeException('Invalid base64 upload');
            }
            $extension = strtolower($match[1]);
            if (!in_array($extension, self::IMAGES, true)) { throw new \RuntimeException('Forbidden image extension'); }
            $bytes = base64_decode(substr($base64, strlen($match[0])), true);
            if ($bytes === false || $bytes === '' || strlen($bytes) > ImageProcessor::MAX_BYTES) { throw new \RuntimeException('Invalid image data'); }
            $path = $stage . '/source.' . $extension;
            if (@file_put_contents($path, $bytes) !== strlen($bytes)) { throw new \RuntimeException('Incomplete staged image'); }
            return [$path, 'image'];
        }
        $file = request()->file($parameters['input']);
        if (!$file instanceof \think\file\UploadedFile || !$file->isValid() || $file->getMime() === 'text/x-php') {
            throw new \RuntimeException('Invalid uploaded file');
        }
        $extension = strtolower($file->getOriginalExtension());
        $type = in_array($extension, self::IMAGES, true) ? 'image'
            : (in_array($extension, self::FILES, true) ? 'file' : (in_array($extension, self::MEDIA, true) ? 'media' : null));
        if ($type === null || $file->getSize() > 4294967295) { throw new \RuntimeException('Forbidden attachment'); }
        $file->move($stage, 'source.' . $extension);
        return [$stage . '/source.' . $extension, $type];
    }

    /** Retain the existing edge-signature check, but only on a private staged file. Image decoding is separate. */
    private static function scan(string $file): void
    {
        $handle = @fopen($file, 'rb');
        if ($handle === false) { throw new \RuntimeException('Cannot inspect staged file'); }
        try {
            $bytes = @filesize($file);
            if (!is_int($bytes)) { throw new \RuntimeException('Cannot size staged file'); }
            $sample = $bytes > 0 ? @fread($handle, min(512, $bytes)) : '';
            if ($sample === false) { throw new \RuntimeException('Cannot scan staged file'); }
            if ($bytes > 512) {
                if (@fseek($handle, $bytes - 512) !== 0 || ($tail = @fread($handle, 512)) === false) {
                    throw new \RuntimeException('Cannot scan staged file');
                }
                $sample .= $tail;
            }
            if (preg_match('/(<%.*?\(.*?\).*?%>)|(<\?.*?\(.*?\).*?\?>)|(<script)|(\/script>)/is', $sample)) {
                throw new \RuntimeException('Attachment contains a rejected signature');
            }
        } finally { fclose($handle); }
    }

    private static function targetDirectory(string $flag): string
    {
        $day = date('Ymd');
        for ($index = 1; $index <= 100; $index++) {
            $relative = 'upload/' . $flag . '/' . $day . '-' . $index;
            $files = glob(ROOT_PATH . $relative . '/*.*');
            if (!is_dir(ROOT_PATH . $relative) || !$files || count($files) <= 999) { return $relative; }
        }
        // Preserve the legacy rollover policy once all 100 date buckets are populated.
        return 'upload/' . $flag . '/' . $day . '-100';
    }

    private static function makeDirectories(string $relative, array &$created): void
    {
        $path = rtrim(ROOT_PATH, '/\\');
        foreach (explode('/', $relative) as $component) {
            $path .= '/' . $component;
            if (is_link($path)) { throw new \RuntimeException('Upload directory cannot be a symbolic link'); }
            if (!is_dir($path)) {
                $made = @mkdir($path, 0755);
                if (!$made && !is_dir($path)) { throw new \RuntimeException('Cannot create upload directory'); }
                if ($made) { $created[] = $path; }
            }
        }
    }

    private static function publish(string $source, string $destination, int $expectedBytes, array &$published): void
    {
        $output = @fopen($destination, 'x+b');
        if ($output === false) { throw new \RuntimeException('Cannot create new attachment'); }
        $published[] = $destination;
        $input = null;
        try {
            $input = @fopen($source, 'rb');
            if ($input === false || @stream_copy_to_stream($input, $output) !== $expectedBytes || !@fflush($output)
                || !@fsync($output) || ($stat = @fstat($output)) === false || $stat['size'] !== $expectedBytes) {
                throw new \RuntimeException('Incomplete attachment publication');
            }
        } finally { if (is_resource($input)) { fclose($input); } fclose($output); }
        $sourceHash = @hash_file('sha256', $source); $destinationHash = @hash_file('sha256', $destination);
        if (!is_string($sourceHash) || !is_string($destinationHash) || !hash_equals($sourceHash, $destinationHash)) {
            throw new \RuntimeException('Published attachment does not match prepared content');
        }
    }

    private static function manifest(string $stage, array $value): void
    {
        $json = json_encode($value, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        if (@file_put_contents($stage . '/manifest.json', $json, LOCK_EX) !== strlen($json)) { throw new \RuntimeException('Cannot write upload manifest'); }
    }

    private static function removeStage(string $directory): void
    {
        if (!is_dir($directory) || is_link($directory)) { return; }
        try {
            foreach (new \DirectoryIterator($directory) as $entry) {
                if (!$entry->isDot() && !$entry->isDir()) { @unlink($entry->getPathname()); }
            }
            @rmdir($directory);
        } catch (\Throwable $error) { /* Never turn a committed upload into a failed response during cleanup. */ }
    }
}
