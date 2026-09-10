<?php
declare(strict_types=1);
require __DIR__ . '/security_audit_test_helpers.php';
require getenv('IMAGE_AUDIT_AUTOLOAD') ?: dirname(__DIR__, 2) . '/vendor/autoload.php';

class ImageAuditRequest extends think\Request {
    public array $testFiles = [];
    public function file(string $name = '') { return $name === '' ? $this->testFiles : ($this->testFiles[$name] ?? null); }
}
function imageAuditRequest(array $params = [], array $files = []): void {
    // UploadedFile(test=true) bypasses PHP's HTTP-only upload provenance, retaining its real move/error methods.
    $request = (new ImageAuditRequest())->withServer(['REQUEST_METHOD'=>'POST', 'REQUEST_TIME'=>123456])->withPost($params);
    $request->testFiles = $files;
    think\Container::getInstance()->instance('request', $request);
    $GLOBALS['image_request'] = $request;
}
function request() { return $GLOBALS['image_request']; }
function lang($key) { return $key; }
function config($key, $default = null) { return $GLOBALS['image_config'][$key] ?? $default; }
function mac_mkdirss($path) { return mkdir($path, 0777, true); }
function mac_is_safe_remote_url($url) { return true; }
function mac_curl_get($url) { return $GLOBALS['image_download_fixture']; }
function mac_write_file($path,$data) {
    if (!is_dir(dirname($path))) { mkdir(dirname($path),0777,true); }
    return file_put_contents($path,$data);
}

/** Minimal independent GIF block reader; frame raster decoding uses GD, not Intervention's GIF decoder. */
function imageAuditGif(string $path): array {
    $data = file_get_contents($path);
    $screen = unpack('vwidth/vheight', substr($data, 6, 4));
    $tableLength = (ord($data[10]) & 128) ? 3 * (2 << (ord($data[10]) & 7)) : 0;
    $header = substr($data, 0, 13 + $tableLength);
    $position = strlen($header);
    $frames = [];
    $loops = null;
    $delay = 0;
    $gce = '';
    while ($position < strlen($data)) {
        $start = $position;
        $marker = ord($data[$position++]);
        if ($marker === 0x3b) { return $screen + ['frames'=>$frames, 'loops'=>$loops]; }
        if ($marker === 0x21) {
            $label = ord($data[$position++]);
            $payload = '';
            do {
                $size = ord($data[$position++]);
                $payload .= substr($data, $position, $size);
                $position += $size;
            } while ($size !== 0);
            if ($label === 0xf9) {
                $delay = unpack('vdelay', substr($payload, 1, 2))['delay'];
                $gce = substr($data, $start, $position - $start);
            }
            if ($label === 0xff && str_starts_with($payload, 'NETSCAPE2.0')) {
                $loops = unpack('vloops', substr($payload, 12, 2))['loops'];
            }
            continue;
        }
        if ($marker !== 0x2c) { throw new RuntimeException('Unexpected fixture GIF block'); }
        $descriptor = unpack('vx/vy/vwidth/vheight/Cpacked', substr($data, $position, 9));
        $position += 9 + (($descriptor['packed'] & 128) ? 3 * (2 << ($descriptor['packed'] & 7)) : 0) + 1;
        do {
            $size = ord($data[$position++]);
            $position += $size;
        } while ($size !== 0);
        $raw = $header . $gce . substr($data, $start, $position - $start) . "\x3b";
        $frames[] = $descriptor + ['delay'=>$delay, 'raw'=>$raw];
        $delay = 0;
        $gce = '';
    }
    throw new RuntimeException('Incomplete fixture GIF');
}
function imageAuditPixel(GdImage $image, int $x, int $y): array {
    $color = imagecolorsforindex($image, imagecolorat($image, $x, $y));
    return [$color['red'], $color['green'], $color['blue'], $color['alpha']];
}
function imageAuditCloseColor(array $actual, array $expected): bool {
    foreach ([0,1,2] as $channel) { if (abs($actual[$channel] - $expected[$channel]) > 5) { return false; } }
    return !isset($expected[3]) || $actual[3] === $expected[3];
}
function imageAuditRejected(callable $operation, string $message): void {
    $failed = false;
    try { $operation(); } catch (Throwable $e) { $failed = true; }
    check($failed, $message);
}

// These fixtures only isolate metadata persistence; image decoding, rendering, requests and upload moves are real.
class ImageAuditUserMetadata {
    public function where($where) { return $this; }
    public function update($data) { $GLOBALS['image_user_updates'][] = $data; return 1; }
}
class ImageAuditAnnexMetadata {
    public function infoData($where) { return ['code'=>1]; }
    public function saveData($data) { return ['code'=>1]; }
}
class_alias(ImageAuditUserMetadata::class, 'app\\common\\model\\User');
class_alias(ImageAuditAnnexMetadata::class, 'app\\common\\model\\Annex');
