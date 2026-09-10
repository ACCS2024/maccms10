<?php
/** Real Upyun/Guzzle sequential upload protocol over disposable loopback HTTP. */
declare(strict_types=1);
$root = dirname(__DIR__);
require $root . '/vendor/autoload.php';
require $root . '/extend/upyun/vendor/autoload.php';
error_reporting(E_ALL);
set_error_handler(static function ($level, $message, $file, $line) {
    if (error_reporting() & $level) { throw new ErrorException($message, 0, $level, $file, $line); }
    return false;
});
$checks = 0;
function verify($ok, string $message): void {
    global $checks;
    if (!$ok) { throw new RuntimeException($message); }
    ++$checks;
}
class UploadFixtureStream implements \Psr\Http\Message\StreamInterface {
    use \GuzzleHttp\Psr7\StreamDecoratorTrait;
    private \Psr\Http\Message\StreamInterface $stream;
    public function __construct($stream, private ?int $reportedSize, private ?int $readLimit = null) { $this->stream = $stream; }
    public function getSize(): ?int { return $this->reportedSize; }
    public function read($length): string { return $this->stream->read($this->readLimit === null ? $length : min($length, $this->readLimit)); }
}
$tmp = sys_get_temp_dir() . '/upyun-blocks-' . bin2hex(random_bytes(5));
mkdir($tmp, 0700);
$router = <<<'PHP'
<?php
$mode = basename(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH));
$stage = $_SERVER['HTTP_X_UPYUN_MULTI_STAGE'] ?? '';
$id = $_SERVER['HTTP_X_UPYUN_PART_ID'] ?? '';
$body = file_get_contents('php://input');
$log = __DIR__ . '/requests.jsonl';
$previous = is_file($log) ? count(file($log)) : 0;
file_put_contents($log, json_encode(['mode' => $mode, 'stage' => $stage, 'id' => $id, 'length' => strlen($body),
    'sha256' => hash('sha256', $body), 'uuid' => $_SERVER['HTTP_X_UPYUN_MULTI_UUID'] ?? '',
    'total' => $_SERVER['HTTP_X_UPYUN_MULTI_LENGTH'] ?? '']) . "\n", FILE_APPEND);
$uuid = '11111111-2222-3333-4444-555555555555';
if ($previous >= 35 || ($mode === 'repeat' && $previous >= 6)) { http_response_code(409); exit; }
if ($stage === 'initiate') {
    http_response_code(204);
    if ($mode !== 'missing-uuid') { header('X-Upyun-Multi-Uuid: ' . ($mode === 'empty-uuid' ? '' : $uuid)); }
    header('X-Upyun-Next-Part-Id: ' . ($mode === 'bad-init' ? '2' : '0'));
} elseif ($stage === 'upload') {
    http_response_code(204);
    header('X-Upyun-Multi-Uuid: ' . ($mode === 'changed-uuid' ? 'changed-task' : $uuid));
    if ($mode === 'missing-next') { exit; }
    $total = json_decode(file($log)[0], true)['total'];
    $next = ((int)$id + 1) * 1048576 >= (int)$total ? '-1' : (string)((int)$id + 1);
    $next = match ($mode) { 'repeat' => $id, 'early-end' => '-1', 'skip' => '7', 'nonnumeric' => 'oops', 'past-eof' => (string)((int)$id + 1), default => $next };
    header('X-Upyun-Next-Part-Id: ' . $next);
} elseif ($stage === 'complete') { http_response_code(201); header('X-Upyun-Width: 10'); }
else { header('X-Upyun-Width: 10'); }
PHP;
file_put_contents($tmp . '/router.php', $router);
$socket = stream_socket_server('tcp://127.0.0.1:0', $errno, $error);
$address = stream_socket_get_name($socket, false);
fclose($socket);
$pipes = [];
$server = proc_open([PHP_BINARY, '-S', $address, $tmp . '/router.php'], [0 => ['pipe', 'r'], 1 => ['file', $tmp . '/server.log', 'a'], 2 => ['file', $tmp . '/server.log', 'a']], $pipes, $tmp);
fclose($pipes[0]);
function requests(): array {
    global $tmp;
    $file = $tmp . '/requests.jsonl';
    return is_file($file) ? array_map(static fn($line) => json_decode($line, true, 512, JSON_THROW_ON_ERROR), file($file)) : [];
}
function clearRequests(): void { global $tmp; if (is_file($tmp . '/requests.jsonl')) { unlink($tmp . '/requests.jsonl'); } }
try {
    for ($i = 0; $i < 50; ++$i) {
        $ready = @stream_socket_client('tcp://' . $address, $errno, $error, .05);
        if ($ready !== false) { fclose($ready); break; }
        usleep(20000);
    }
    verify($ready !== false, 'Loopback fixture starts');
    $config = new \Upyun\Config('fixture-bucket', 'fixture-operator', 'fixture-password');
    $config->useSsl = false; // Isolated local HTTP only; production HTTPS defaults stay unchanged.
    $config->uploadType = 'BLOCK';
    $config->timeout = 3;
    \Upyun\Config::$restApiEndPoint = $address;
    $client = new \Upyun\Upyun($config);
    if (($argv[1] ?? '') === 'baseline') {
        foreach (['missing-uuid', 'missing-next'] as $mode) {
            clearRequests(); $thrown = false;
            try { $client->write('/' . $mode, 'fixture'); } catch (ErrorException $e) { $thrown = true; }
            verify($thrown, 'Original missing protocol header triggers a strict PHP error');
        }
        clearRequests();
        $client->write('/early-end', str_repeat('x', 1048576) . 'tail');
        verify(count(requests()) === 3 && requests()[1]['length'] === 1048576, 'Original early completion drops the last fragment');
        clearRequests();
        try { $client->write('/repeat', 'fixture'); } catch (\GuzzleHttp\Exception\ClientException $e) {}
        verify(count(requests()) === 7 && requests()[2]['length'] === 0, 'Original repeated part ID loops after EOF until fixture guard stops it');
        clearRequests();
        $client->write('/normal', 'fixture');
        verify(requests()[2]['length'] === 7, 'Original completion retransmits stale final block body');
        echo "OK {$checks} original Upyun block reproductions on PHP " . PHP_VERSION . "\n";
        exit;
    }
    foreach (['missing-uuid', 'empty-uuid', 'bad-init', 'missing-next', 'changed-uuid', 'repeat', 'early-end', 'skip', 'nonnumeric', 'past-eof'] as $mode) {
        clearRequests(); $thrown = false;
        try { $client->write('/' . $mode, str_repeat('x', 1048576) . 'tail'); }
        catch (RuntimeException $e) { $thrown = true; }
        verify($thrown, 'Invalid upload protocol terminates with a controlled exception: ' . $mode);
        verify(count(requests()) <= 3 && !in_array('complete', array_column(requests(), 'stage'), true), 'Invalid sequence cannot loop or report completion: ' . $mode);
        verify(!in_array(0, array_column(array_filter(requests(), static fn($r) => $r['stage'] === 'upload'), 'length'), true), 'No empty data block is sent after EOF: ' . $mode);
    }
    foreach ([1, 1048576, 1048576 + 4] as $size) {
        clearRequests(); $body = str_repeat('x', $size);
        verify($client->write('/normal', $body) === ['x-upyun-width' => '10'], 'Normal block upload retains result headers');
        $rows = requests();
        verify(count($rows) === 2 + (int)ceil($size / 1048576) && $rows[0]['length'] === 0 && end($rows)['length'] === 0, 'Only data stages contain bytes, completion body is empty');
        foreach (array_values(array_filter($rows, static fn($r) => $r['stage'] === 'upload')) as $id => $row) {
            $expected = substr($body, $id * 1048576, 1048576);
            verify($row['id'] === (string)$id && $row['length'] === strlen($expected) && $row['sha256'] === hash('sha256', $expected), 'Sequential part ID and bytes agree');
        }
    }
    clearRequests();
    $config->uploadType = 'AUTO';
    $source = fopen($tmp . '/source.bin', 'w+b'); ftruncate($source, $config->sizeBoundary); rewind($source);
    verify($client->write('/normal', $source) === ['x-upyun-width' => '10'] && count(requests()) === 32, 'Actual 30 MiB AUTO boundary uses exactly thirty data blocks');
    verify(is_file($tmp . '/source.bin'), 'Successful upload preserves the local source file');
    if (is_resource($source)) { fclose($source); }
    $config->uploadType = 'BLOCK';
    foreach ([null, 0, 10] as $reportedSize) {
        clearRequests();
        $stream = new UploadFixtureStream(\GuzzleHttp\Psr7\Utils::streamFor('short'), $reportedSize);
        $thrown = false;
        try { $client->write('/normal', $stream); } catch (RuntimeException|InvalidArgumentException $e) { $thrown = true; }
        verify($thrown && count(requests()) <= 1 && !in_array('upload', array_column(requests(), 'stage'), true), 'Unknown/empty size and short source cannot send incomplete data');
        $stream->close();
    }
    clearRequests();
    $stream = new UploadFixtureStream(\GuzzleHttp\Psr7\Utils::streamFor('complete'), 8, 2);
    verify($client->write('/normal', $stream) === ['x-upyun-width' => '10'] && requests()[1]['sha256'] === hash('sha256', 'complete'), 'Progressing short reads accumulate the expected block');
    $stream->close();
    echo "OK {$checks} Upyun block checks on PHP " . PHP_VERSION . "\n";
} finally {
    proc_terminate($server); proc_close($server);
    foreach (glob($tmp . '/*') as $file) { unlink($file); }
    rmdir($tmp);
}
