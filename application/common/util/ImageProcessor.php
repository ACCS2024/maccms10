<?php
declare(strict_types=1);
namespace app\common\util;

use Intervention\Image\Drivers\Gd\Driver;
use Intervention\Image\Drivers\Imagick\Driver as AnimationDriver;
use Intervention\Image\Format;
use Intervention\Image\ImageManager;
use Intervention\Image\Interfaces\ImageInterface;

/** Legacy upload configuration adapted to maintained image drivers; GIF composition uses ImageMagick. */
final class ImageProcessor
{
    public const MAX_BYTES = 20971520;
    public const MAX_DIMENSION = 8192;
    public const MAX_FRAMES = 300;
    public const MAX_WORK_PIXELS = 16000000;

    private function __construct(private ImageInterface $image, private Format $format) {}

    public static function open(string $path): self
    {
        self::localPath($path);
        if (!is_file($path) || !is_readable($path)) { throw new \RuntimeException('Image is not readable'); }
        $data = @file_get_contents($path, false, null, 0, self::MAX_BYTES + 1);
        if ($data === false || strlen($data) > self::MAX_BYTES) { throw new \RuntimeException('Image exceeds input limit'); }
        $info = @getimagesizefromstring($data);
        if ($info === false) { throw new \RuntimeException('Invalid image'); }
        $format = match ($info[2]) {
            IMAGETYPE_JPEG => Format::JPEG, IMAGETYPE_PNG => Format::PNG,
            IMAGETYPE_GIF => Format::GIF, IMAGETYPE_WEBP => Format::WEBP,
            default => throw new \RuntimeException('Unsupported image format'),
        };
        self::dimension($info[0]);
        self::dimension($info[1]);
        $frames = $format === Format::GIF ? self::gifFrames($data, $info[0], $info[1]) : 1;
        self::capacity($info[0] * $info[1] * $frames);
        if (in_array($format, [Format::GIF, Format::WEBP], true)) {
            if (!extension_loaded('imagick')) { throw new \RuntimeException('Imagick is required for this image format'); }
            // Keep native decoder buffers bounded as well as PHP/GD allocations; no spill to unbounded disk caches.
            foreach ([\Imagick::RESOURCETYPE_MEMORY=>134217728, \Imagick::RESOURCETYPE_MAP=>134217728,
                \Imagick::RESOURCETYPE_DISK=>0, \Imagick::RESOURCETYPE_THREAD=>1] as $resource=>$limit) {
                $current = \Imagick::getResourceLimit($resource);
                if (!\Imagick::setResourceLimit($resource, min($current, $limit))) {
                    throw new \RuntimeException('Unable to limit the native image decoder');
                }
            }
        }
        $manager = new ImageManager(in_array($format, [Format::GIF, Format::WEBP], true) ? AnimationDriver::class : Driver::class,
            autoOrientation: false, decodeAnimation: true);
        $image = $manager->decodeBinary($data);
        if (count($image) !== $frames) { throw new \RuntimeException('Image frame count changed during decoding'); }
        return new self($image, $format);
    }

    /** Clone decoded frames so each requested thumbnail derives from the same original pixels. */
    public function copy(): self
    {
        self::capacity($this->image->width() * $this->image->height() * count($this->image));
        return new self(clone $this->image, $this->format);
    }

    public function thumb($width, $height, $type = 1): self
    {
        $width = self::dimension($width);
        $height = self::dimension($height);
        if ((!is_int($type) && !is_string($type)) || !preg_match('/^[1-6]$/D', (string)$type)) {
            throw new \RuntimeException('Invalid thumbnail mode');
        }
        $w = $this->image->width();
        $h = $this->image->height();
        self::capacity(($w * $h + $width * $height) * count($this->image));
        switch ((int)$type) {
            case 1:
            case 2:
                $scale = min(1, $width / $w, $height / $h);
                $this->image->resize(max(1, (int)($w * $scale)), max(1, (int)($h * $scale)));
                if ((int)$type === 2) { $this->image->resizeCanvas($width, $height, 'ffffff'); }
                break;
            case 3:
            case 4:
            case 5:
                // Keep the legacy crop-before-resize geometry and its integer rounding.
                $scale = max($width / $w, $height / $h);
                $cropW = max(1, (int)($width / $scale));
                $cropH = max(1, (int)($height / $scale));
                $x = (int)$type === 4 ? 0 : ((int)$type === 5 ? $w - $cropW : (int)(($w - $cropW) / 2));
                $y = (int)$type === 4 ? 0 : ((int)$type === 5 ? $h - $cropH : (int)(($h - $cropH) / 2));
                $this->image->crop($cropW, $cropH, $x, $y)->resize($width, $height);
                break;
            case 6:
                $this->image->resize($width, $height);
                break;
        }
        return $this;
    }

    /** Retain legacy point sizes and GD alpha (0 opaque, 127 transparent), including #RRGGBBAA. */
    public function text($text, $font, $size, $color = '#00000000', $location = 9): self
    {
        if (!is_string($text) || strlen($text) > 4096 || !is_string($font)
            || !is_numeric($size) || !is_finite((float)$size) || (float)$size <= 0 || (float)$size > 512
            || (!is_int($location) && !is_string($location)) || !preg_match('/^[1-9]$/D', (string)$location)) {
            throw new \RuntimeException('Invalid watermark configuration');
        }
        if ($text === '') { return $this; }
        self::localPath($font);
        if (!is_file($font) || !is_readable($font)) { throw new \RuntimeException('Watermark font is not readable'); }
        $box = @imagettfbbox((float)$size, 0, $font, $text);
        if ($box === false) { throw new \RuntimeException('Invalid watermark font'); }
        $left = min($box[0], $box[2], $box[4], $box[6]);
        $right = max($box[0], $box[2], $box[4], $box[6]);
        $top = min($box[1], $box[3], $box[5], $box[7]);
        $bottom = max($box[1], $box[3], $box[5], $box[7]);
        $column = ((int)$location - 1) % 3;
        $row = intdiv((int)$location - 1, 3);
        $x = (int)(($this->image->width() - ($right - $left)) * $column / 2) - $left;
        $y = (int)(($this->image->height() - ($bottom - $top)) * $row / 2) - $top;
        $rgba = $color === 'auto' ? null : self::color($color);
        foreach ($this->image as $frame) {
            $native = $frame->native();
            $value = $rgba ?? self::contrastColor($native, $x + $left, $y + $top, $right - $left, $bottom - $top);
            $gd = $native;
            if ($native instanceof \Imagick) {
                $gd = imagecreatetruecolor($this->image->width(), $this->image->height());
                imagealphablending($gd, false);
                imagefill($gd, 0, 0, imagecolorallocatealpha($gd, 0, 0, 0, 127));
                imagesavealpha($gd, true);
            }
            imagealphablending($gd, true);
            $ink = imagecolorallocatealpha($gd, $value[0], $value[1], $value[2], $value[3]);
            if (@imagettftext($gd, (float)$size, 0, $x, $y, $ink, $font, $text) === false) {
                throw new \RuntimeException('Unable to render watermark');
            }
            if ($native instanceof \Imagick) {
                // A lossless GD text overlay retains old point-size/alpha semantics on every composed GIF frame.
                ob_start();
                try { imagepng($gd); $png = ob_get_contents(); }
                finally { ob_end_clean(); }
                $overlay = new \Imagick();
                try {
                    $overlay->readImageBlob($png);
                    $native->compositeImage($overlay, \Imagick::COMPOSITE_OVER, 0, 0);
                } finally { $overlay->clear(); }
            }
        }
        return $this;
    }

    /** Encode completely before replacing the destination; GIF is preserved unless conversion is explicit. */
    public function save(string $path, ?string $type = null): self
    {
        self::localPath($path);
        $format = $type === null ? $this->format : match (strtolower($type)) {
            'jpg', 'jpeg' => Format::JPEG, 'png' => Format::PNG, 'gif' => Format::GIF, 'webp' => Format::WEBP,
            default => throw new \RuntimeException('Unsupported output format'),
        };
        if (is_link($path) || (file_exists($path) && !is_file($path))) {
            throw new \RuntimeException('Invalid image destination');
        }
        $directory = realpath(dirname($path));
        if ($directory === false || !is_dir($directory) || !is_writable($directory)) {
            throw new \RuntimeException('Image directory is not writable');
        }
        // JPEG avatars intentionally use the first composed animation frame; ordinary GIF saves keep every frame.
        $image = $this->image;
        if ($format !== Format::GIF && $image->isAnimated()) {
            if ($type === null) { throw new \RuntimeException('Implicit animation loss is not allowed'); }
            $image = clone $image;
            $image->removeAnimation(0);
        }
        $encoded = $format === Format::JPEG
            ? $image->encodeUsingFormat($format, quality: 80, progressive: true)
            : $image->encodeUsingFormat($format);
        $bytes = (string)$encoded;
        if ($bytes === '') { throw new \RuntimeException('Image encoder returned no data'); }
        $temporary = @tempnam($directory, '.image-');
        if ($temporary === false) { throw new \RuntimeException('Unable to create image output'); }
        try {
            if (dirname($temporary) !== $directory || @file_put_contents($temporary, $bytes) !== strlen($bytes)
                || !@chmod($temporary, is_file($path) ? fileperms($path) & 0777 : 0666 & ~umask())
                || !@rename($temporary, $path)) {
                throw new \RuntimeException('Unable to save complete image');
            }
        } finally {
            if (is_file($temporary)) { @unlink($temporary); }
        }
        return $this;
    }

    private static function localPath(string $path): void
    {
        if ($path === '' || str_contains($path, "\0") || str_contains($path, '://')) {
            throw new \RuntimeException('Only local image paths are supported');
        }
    }

    private static function dimension($value): int
    {
        if ((!is_int($value) && !is_string($value)) || !preg_match('/^[0-9]{1,5}$/D', (string)$value)
            || (int)$value < 1 || (int)$value > self::MAX_DIMENSION) { throw new \RuntimeException('Invalid image dimensions'); }
        return (int)$value;
    }

    private static function capacity(int $pixels): void
    {
        if ($pixels < 1 || $pixels > self::MAX_WORK_PIXELS) { throw new \RuntimeException('Image exceeds decoded pixel limit'); }
        $limit = ini_parse_quantity((string)ini_get('memory_limit'));
        // Conservative working estimate; GD and GIF compositing need multiple image buffers.
        if ($limit > 0 && $pixels * 16 + 16777216 > $limit - memory_get_usage(true)) {
            throw new \RuntimeException('Image exceeds available decoding memory');
        }
    }

    /** Validate and count GIF blocks before the GD driver allocates composed animation frames. */
    private static function gifFrames(string $data, int $width, int $height): int
    {
        $length = strlen($data);
        if ($length < 14 || !in_array(substr($data, 0, 6), ['GIF87a', 'GIF89a'], true)) {
            throw new \RuntimeException('Invalid GIF header');
        }
        $packed = ord($data[10]);
        $position = 13 + (($packed & 128) ? 3 * (2 << ($packed & 7)) : 0);
        $frames = 0;
        while ($position < $length) {
            $marker = ord($data[$position++]);
            if ($marker === 0x3b && $frames > 0) { return $frames; }
            if ($marker === 0x21) {
                if ($position >= $length) { break; }
                $position++; // extension label; each following payload is a length-prefixed block
            } elseif ($marker === 0x2c) {
                if ($position + 9 >= $length) { break; }
                $frame = unpack('vx/vy/vwidth/vheight/Cpacked', substr($data, $position, 9));
                if ($frame['width'] < 1 || $frame['height'] < 1 || $frame['x'] + $frame['width'] > $width
                    || $frame['y'] + $frame['height'] > $height || ++$frames > self::MAX_FRAMES) {
                    throw new \RuntimeException('Invalid or oversized GIF frame');
                }
                self::capacity($width * $height * $frames);
                $position += 9 + (($frame['packed'] & 128) ? 3 * (2 << ($frame['packed'] & 7)) : 0) + 1;
            } else { break; }
            do {
                if ($position >= $length) { throw new \RuntimeException('Truncated GIF block'); }
                $size = ord($data[$position++]);
                $position += $size;
                if ($position > $length) { throw new \RuntimeException('Truncated GIF data'); }
            } while ($size !== 0);
        }
        throw new \RuntimeException('Incomplete GIF image');
    }

    private static function color($value): array
    {
        if (is_string($value) && preg_match('/^#[0-9a-f]{6}([0-9a-f]{2})?$/Di', $value)) {
            $value = array_map('hexdec', str_split(substr($value, 1), 2));
            $value[3] = ($value[3] ?? 0) > 127 ? 0 : ($value[3] ?? 0);
        }
        if (!is_array($value) || !array_is_list($value) || count($value) !== 4) { throw new \RuntimeException('Invalid watermark color'); }
        foreach ($value as $index => $channel) {
            if (!is_int($channel) || $channel < 0 || $channel > ($index === 3 ? 127 : 255)) {
                throw new \RuntimeException('Invalid watermark color channel');
            }
        }
        return $value;
    }

    private static function contrastColor(\GdImage|\Imagick $image, int $x, int $y, int $width, int $height): array
    {
        $right = min($image instanceof \GdImage ? imagesx($image) : $image->getImageWidth(), $x + $width);
        $bottom = min($image instanceof \GdImage ? imagesy($image) : $image->getImageHeight(), $y + $height);
        $x = max(0, $x);
        $y = max(0, $y);
        $step = max(1, (int)ceil(sqrt(max(0, ($right - $x) * ($bottom - $y)) / 4096)));
        $sum = $count = 0;
        for ($i = $x; $i < $right; $i += $step) {
            for ($j = $y; $j < $bottom; $j += $step) {
                if ($image instanceof \GdImage) {
                    $rgb = imagecolorsforindex($image, imagecolorat($image, $i, $j));
                    $sum += $rgb['red'] * .299 + $rgb['green'] * .587 + $rgb['blue'] * .114;
                } else {
                    $rgb = $image->getImagePixelColor($i, $j)->getColor();
                    $sum += $rgb['r'] * .299 + $rgb['g'] * .587 + $rgb['b'] * .114;
                }
                $count++;
            }
        }
        return $count > 0 && $sum / $count > 127 ? [0, 0, 0, 0] : [255, 255, 255, 0];
    }
}
