<?php
declare(strict_types=1);
require __DIR__ . '/fixtures/security_audit_image_helpers.php';
require __DIR__ . '/fixtures/security_audit_image_io.php';
use app\common\util\ImageProcessor;
use app\common\model\Image;

$fixture = __DIR__ . '/fixtures/image-processing';
$root = dirname(__DIR__);
$temp = audit_temp_dir('image-processing');
$cwd = getcwd();
imageAuditRequest();
try {
    chdir($temp);
    $font = $root . '/static/font/test.ttf';
    $raster = imagecreatetruecolor(120, 60);
    foreach ([[0,39,255,0,0], [40,79,0,128,0], [80,119,0,0,255]] as [$x1,$x2,$r,$g,$b]) {
        imagefilledrectangle($raster, $x1, 0, $x2, 59, imagecolorallocate($raster, $r, $g, $b));
    }
    imagepng($raster, 'original.png');
    imagejpeg($raster, 'original.jpg', 95);
    imagegif($raster, 'static.gif');
    foreach (['png'=>IMAGETYPE_PNG, 'jpg'=>IMAGETYPE_JPEG, 'gif'=>IMAGETYPE_GIF] as $extension=>$type) {
        $source = $extension === 'gif' ? 'static.gif' : 'original.' . $extension;
        ImageProcessor::open($source)->thumb('60', '30')->save('saved.' . $extension);
        $info = getimagesize('saved.' . $extension);
        check([$info[0],$info[1],$info[2]] === [60,30,$type], 'Static source format/dimensions changed unexpectedly');
    }
    foreach ([1,2,3,4,5,6] as $mode) {
        ImageProcessor::open('original.png')->thumb(60,60,(string)$mode)->save('mode-' . $mode . '.png');
        $info = getimagesize('mode-' . $mode . '.png');
        check([$info[0],$info[1]] === [60,$mode === 1 ? 30 : 60], 'Legacy thumbnail dimensions changed: ' . $mode);
        if (in_array($mode, [3,4,5], true)) {
            $pixel = imageAuditPixel(imagecreatefrompng('mode-' . $mode . '.png'), 30,30);
            check($pixel === match ($mode) { 3=>[0,128,0,0], 4=>[255,0,0,0], 5=>[0,0,255,0] },
                'Crop alignment changed: ' . $mode);
        }
    }
    check(imageAuditPixel(imagecreatefrompng('mode-2.png'), 30,1) === [255,255,255,0], 'Filled thumbnails lost their white padding');
    ImageProcessor::open('original.png')->thumb(240,120,1)->save('no-upscale.png');
    check(getimagesize('no-upscale.png')[0] === 120, 'Proportional thumbnails unexpectedly enlarged small originals');

    foreach ([1,2,3,4,5,6] as $mode) {
        $path = 'animated-' . $mode . '.gif';
        ImageProcessor::open($fixture . '/animation.gif')->thumb(40,40,$mode)->save($path);
        $gif = imageAuditGif($path);
        check(count($gif['frames']) === 3 && array_column($gif['frames'],'delay') === [7,13,25]
            && $gif['loops'] === 4, 'GIF frame delays/loops were changed: ' . $mode);
        check([$gif['width'],$gif['height']] === [40,$mode === 1 ? 20 : 40], 'Animated thumbnail dimensions are incorrect');
        foreach ($gif['frames'] as $index=>$frame) {
            $pixel = imageAuditPixel(imagecreatefromstring($frame['raw']), 20,10);
            check(imageAuditCloseColor($pixel,[[255,0,0],[0,128,0],[0,0,255]][$index]), 'An animation frame was duplicated or lost');
        }
    }
    ImageProcessor::open($fixture . '/disposal.gif')->save('disposal.gif');
    $gif = imageAuditGif('disposal.gif');
    check(count($gif['frames']) === 4 && array_column($gif['frames'],'delay') === [8,15,22,31]
        && $gif['loops'] === 0, 'Partial/disposal GIF lost timing or indefinite looping');
    foreach ([[[255,0,0,0],null,null,null], [[255,0,0,0],[0,128,0,0],null,null],
        [null,null,[0,0,255,0],null], [null,null,null,[255,255,0,0]]] as $index=>$expected) {
        $frame = imagecreatefromstring($gif['frames'][$index]['raw']);
        foreach ([[1,1],[5,1],[10,6],[1,6]] as $position=>$xy) {
            $pixel = imageAuditPixel($frame, $xy[0],$xy[1]);
            check($expected[$position] === null ? $pixel[3] === 127 : imageAuditCloseColor($pixel,$expected[$position]),
                'GIF frame disposal/transparency differs from the independently generated fixture');
        }
    }
    ImageProcessor::open($fixture . '/no-loop.gif')->thumb(10,5)->save('no-loop.gif');
    $noLoop = imageAuditGif('no-loop.gif');
    check(count($noLoop['frames']) === 3 && array_column($noLoop['frames'],'delay') === [29,57,0]
        && $noLoop['loops'] === null, 'A single-play animation gained infinite looping or its centisecond delays were rounded');
    ImageProcessor::open($fixture . '/static.webp')->thumb(20,10)->save('static.webp');
    $info = getimagesize('static.webp');
    check([$info[0],$info[1],$info[2]] === [20,10,IMAGETYPE_WEBP], 'Supported WebP images no longer decode/encode correctly');
    ImageProcessor::open($fixture . '/animation.gif')->thumb(30,30,6)->save('avatar.jpg','jpeg');
    check(getimagesize('avatar.jpg')[2] === IMAGETYPE_JPEG
        && imageAuditPixel(imagecreatefromjpeg('avatar.jpg'),15,15)[0] > 240, 'Explicit JPEG conversion did not retain the first frame');
    ImageProcessor::open($fixture . '/disposal.gif')->save('transparent-avatar.jpg','jpeg');
    $pixel = imageAuditPixel(imagecreatefromjpeg('transparent-avatar.jpg'),10,6);
    check(min(array_slice($pixel,0,3)) > 230, 'Transparent GIF avatar did not flatten onto the expected white JPEG background');

    $transparent = imagecreatetruecolor(80,40);
    imagealphablending($transparent,false);
    imagesavealpha($transparent,true);
    imagefill($transparent,0,0,imagecolorallocatealpha($transparent,0,0,0,127));
    imagefilledrectangle($transparent,20,10,60,30,imagecolorallocatealpha($transparent,255,0,0,0));
    imagepng($transparent,'transparent.png');
    ImageProcessor::open('transparent.png')->thumb(40,20)->save('transparent-thumb.png');
    check(imageAuditPixel(imagecreatefrompng('transparent-thumb.png'),0,0)[3] === 127, 'PNG resize discarded alpha transparency');

    $white = imagecreatetruecolor(120,60);
    imagefill($white,0,0,imagecolorallocate($white,255,255,255));
    imagepng($white,'white.png');
    foreach (range(1,9) as $location) {
        ImageProcessor::open('white.png')->text('X',$font,'12','#00000000',(string)$location)->save('text-' . $location . '.png');
        $image = imagecreatefrompng('text-' . $location . '.png');
        $xs = $ys = [];
        for ($x=0;$x<120;$x++) { for ($y=0;$y<60;$y++) {
            if (imageAuditPixel($image,$x,$y)[0] < 100) { $xs[]=$x; $ys[]=$y; }
        } }
        check($xs !== [] && (int)floor((min($xs)+max($xs))/2/40) === ($location-1)%3
            && (int)floor((min($ys)+max($ys))/2/20) === intdiv($location-1,3), 'Watermark position or legacy opaque alpha changed');
    }
    ImageProcessor::open($fixture . '/animation.gif')->text('X',$font,12,'#ffffff00',5)->save('watermark.gif');
    $watermarked = imageAuditGif('watermark.gif');
    check(array_column($watermarked['frames'],'delay') === [7,13,25] && $watermarked['loops'] === 4,
        'Watermark changed animation metadata');
    foreach ($watermarked['frames'] as $index=>$frame) {
        $image = imagecreatefromstring($frame['raw']);
        $whitePixels = 0;
        for ($x=20;$x<60;$x++) { for ($y=0;$y<40;$y++) {
            $pixel = imageAuditPixel($image,$x,$y);
            if ($pixel[0]>200 && $pixel[1]>200 && $pixel[2]>200) { $whitePixels++; }
        } }
        check($whitePixels > 0, 'Watermark was missing from an animation frame');
    }
    ImageProcessor::open('white.png')->text('', $font,12,'auto')->save('empty-text.png');
    ImageProcessor::open('white.png')->text(str_repeat('Long',50), $font,12,'auto',9)->save('clipped-auto.png');
    check(is_file('clipped-auto.png'), 'Clipped automatic watermark color caused out-of-range pixels or division by zero');

    $config = ['thumb_size'=>'30x30,90x90','thumb_type'=>1,'watermark'=>0];
    $thumbs = (new Image())->makethumb('original.png',$config);
    check(count($thumbs['thumb']) === 2 && getimagesize($thumbs['thumb'][0]['file'])[0] === 30
        && getimagesize($thumbs['thumb'][1]['file'])[0] === 90, 'Later thumbnail was derived from an earlier smaller thumbnail');
    copy('original.png','replace.png');
    (new Image())->makethumb('replace.png',$config,'vod',0);
    check(getimagesize('replace.png')[0] === 90, 'In-place thumbnail reused an already downscaled intermediate');
    $config += ['watermark_content'=>'X','watermark_font'=>$font,'watermark_size'=>12,'watermark_color'=>'#00000000','watermark_location'=>5];
    $config['watermark'] = 1;
    $config['thumb_size'] = '120x60';
    copy('white.png','watermark-once.png');
    check((new Image())->watermark('watermark-once.png',$config), 'Application watermark failed');
    $result = (new Image())->makethumb('watermark-once.png',$config,'vod',1,true);
    ImageProcessor::open('watermark-once.png')->thumb(120,60,1)->save('expected-once.png');
    check(hash_file('sha256',$result['thumb'][0]['file']) === hash_file('sha256','expected-once.png'), 'Application added a second watermark');
    $direct = (new Image())->makethumb('white.png',$config);
    check(hash_file('sha256',$direct['thumb'][0]['file']) !== hash_file('sha256','white.png'), 'Standalone thumbnail watermark was silently disabled');

    foreach ([[0,20],[-1,20],['1e2',20],[[],20],[8193,20],[20,'1.5']] as [$w,$h]) {
        imageAuditRejected(static fn()=>ImageProcessor::open('white.png')->thumb($w,$h)->save('white.png'), 'Invalid dimensions were accepted');
    }
    $original = file_get_contents('white.png');
    foreach ([static fn()=>ImageProcessor::open('white.png')->text('X','missing.ttf',12)->save('white.png'),
        static fn()=>ImageProcessor::open('white.png')->save('white.png','svg'),
        static fn()=>ImageProcessor::open('white.png')->save('missing/out.png'),
        static fn()=>ImageProcessor::open('https://127.0.0.1/image.png')] as $operation) {
        imageAuditRejected($operation,'Invalid image operation did not fail');
        check(file_get_contents('white.png') === $original, 'Failure replaced the original image');
    }
    symlink('white.png','symlink.png');
    imageAuditRejected(static fn()=>ImageProcessor::open('original.png')->save('symlink.png'), 'Output followed a symlink');
    check(file_get_contents('white.png') === $original && glob('.image-*') === [], 'Failed save damaged a target or leaked temporary output');
    foreach (['partial','rename'] as $fault) {
        $GLOBALS['image_io_fault'] = $fault;
        imageAuditRejected(static fn()=>ImageProcessor::open('original.png')->save('white.png'), 'Filesystem failure was acknowledged: ' . $fault);
        check(file_get_contents('white.png') === $original && glob('.image-*') === [],
            'Filesystem failure corrupted the original or retained temporary output: ' . $fault);
    }
    $GLOBALS['image_io_fault'] = '';
    file_put_contents('bad.gif',substr(file_get_contents($fixture . '/animation.gif'),0,-10));
    imageAuditRejected(static fn()=>ImageProcessor::open('bad.gif'), 'Truncated GIF was accepted');
    $large = substr_replace(file_get_contents($fixture . '/animation.gif'),pack('vv',65535,65535),6,4);
    file_put_contents('oversized.gif',$large);
    imageAuditRejected(static fn()=>ImageProcessor::open('oversized.gif'), 'Oversized GIF reached GD allocation');
    $sample = imageAuditGif($fixture . '/animation.gif')['frames'][0]['raw'];
    $headerSize = 13 + ((ord($sample[10]) & 128) ? 3 * (2 << (ord($sample[10]) & 7)) : 0);
    $excessive = substr($sample,0,$headerSize) . str_repeat(substr($sample,$headerSize,-1),ImageProcessor::MAX_FRAMES+1) . "\x3b";
    file_put_contents('excessive-frames.gif',$excessive);
    imageAuditRejected(static fn()=>ImageProcessor::open('excessive-frames.gif'), 'Unbounded GIF frame count reached native decoding');
    file_put_contents('excessive-bytes.png', str_pad(file_get_contents('white.png'),ImageProcessor::MAX_BYTES+1,"\0"));
    imageAuditRejected(static fn()=>ImageProcessor::open('excessive-bytes.png'), 'Oversized encoded image bypassed input limits');
    $badConfig = $config;
    $badConfig['watermark_font'] = 'missing.ttf';
    check(!(new Image())->watermark('white.png',$badConfig) && file_get_contents('white.png') === $original,
        'Application watermark failure did not preserve the original');
    $badConfig['thumb_size'] = '10x10,../../bad';
    check((new Image())->makethumb('white.png',$badConfig)['thumb'] === [], 'Malformed thumbnail list created partial outputs');
    echo "image processing audit: $checks checks passed on PHP " . PHP_VERSION . "\n";
} finally {
    chdir($cwd);
    audit_remove_temp($temp);
}
