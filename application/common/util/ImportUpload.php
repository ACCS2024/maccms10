<?php
namespace app\common\util;

use think\file\UploadedFile;

/** Inspect one PHP temporary upload without moving it into the site or trusting its MIME label. */
final class ImportUpload
{
    public static function inspect($file, array $extensions, int $maximumBytes): array
    {
        if (!$file instanceof UploadedFile || !$file->isValid() || $maximumBytes < 1) {
            throw new \InvalidArgumentException('A valid single upload is required');
        }
        $name = $file->getOriginalName();
        if ($name === '' || strlen($name) > 1024 || str_contains($name, "\0")) {
            throw new \InvalidArgumentException('Invalid upload name');
        }
        $extension = strtolower($file->getOriginalExtension());
        $path = $file->getPathname();
        if (!in_array($extension, $extensions, true) || is_link($path) || !$file->isFile()) {
            throw new \InvalidArgumentException('Unsupported import file');
        }
        $size = $file->getSize();
        if ($size === false || $size > $maximumBytes) {
            throw new \InvalidArgumentException('Import file exceeds the byte limit');
        }
        return ['path' => $path, 'extension' => $extension];
    }
}
