<?php
namespace app\common\model;
use app\common\util\ImageProcessor;

/**
 * 图片处理辅助类：下载/水印/缩略图；下载通过独立附件服务登记文件，不映射 image 表。
 *
 * 【不要让它继承 Base/Model】
 * 本类没有对应的数据表（mac_image 在官方原版与老库中同样不存在）。
 * TP8 的 think\Model::__construct() 会调用 initializeData() -> getFields()，
 * 即「实例化」本身就会去查自己那张表的字段结构；TP5 是懒加载从不触发，
 * 迁到 TP8 后 new Image() 直接抛
 * SQLSTATE[42S02] Table '...mac_image' doesn't exist。
 * 与 Extend / Cj 是同一类问题，处置一致：退回普通类。
 */
class Image {

    public function down_load($url, $config, $flag = 'vod')
    {
        if (!is_string($url)) { return '#err'; }
        return preg_match('~^https?://~i', $url) === 1 ? $this->down_exec($url, $config, $flag) : $url;
    }

    public function down_exec($url, $config, $flag = 'vod')
    {
        $original = is_string($url) ? $url : '';
        try {
            if (!is_string($url) || !is_array($config) || !is_string($flag) || $flag === 'user'
                || !preg_match('/^[a-z0-9_]{1,64}$/D', $flag) || !mac_is_safe_remote_url($url)) {
                return $original . '#err';
            }
            $bytes = mac_curl_get($url);
            if (!is_string($bytes) || $bytes === '') { return $original . '#err'; }
            $asset = \app\common\util\LocalAttachment::storeDownloadedImage($bytes, $config, $flag);
            return $asset['file'];
        } catch (\Throwable $error) {
            // The attachment owner retains evidence after an external effect or ambiguous commit.
            // Collect/Images still own their later resource-row update; this method only commits the asset catalog.
            return $original . '#err';
        }
    }

    /** Strict preparation for new local attachments; failures must not publish a partial image set. */
    public function prepareLocalUpload(string $file, array $config, bool $thumbnails): array
    {
        $source = ImageProcessor::open($file);
        $types = [IMAGETYPE_JPEG=>['jpg','jpeg'], IMAGETYPE_PNG=>['png'], IMAGETYPE_GIF=>['gif'], IMAGETYPE_WEBP=>['webp']];
        $info = getimagesize($file);
        if (!in_array(strtolower(pathinfo($file, PATHINFO_EXTENSION)), $types[$info[2]] ?? [], true)) {
            throw new \RuntimeException('Image extension does not match its content');
        }
        if (($config['watermark'] ?? 0) == 1) {
            $this->applyWatermark($source, $config);
            $source->save($file);
        }
        $files = [];
        if (!$thumbnails || ($config['thumb'] ?? 0) != 1) { return $files; }
        $sizes = $config['thumb_size'] ?? '';
        if (!is_string($sizes) || $sizes === '') { throw new \RuntimeException('Missing thumbnail dimensions'); }
        $sizes = explode(',', $sizes);
        if (count($sizes) > 16) { throw new \RuntimeException('Too many thumbnail dimensions'); }
        foreach ($sizes as $size) {
            if (!preg_match('/^([0-9]{1,4})(?:x([0-9]{1,4}))?$/Di', trim($size), $match)) {
                throw new \RuntimeException('Invalid thumbnail dimensions');
            }
            $width = $match[1]; $height = $match[2] ?? $width;
            $path = $file . '_' . $width . 'x' . $height . '.' . strtolower(pathinfo($file, PATHINFO_EXTENSION));
            if (in_array($path, $files, true)) { throw new \RuntimeException('Duplicate thumbnail dimensions'); }
            $source->copy()->thumb($width, $height, $config['thumb_type'] ?? 1)->save($path);
            $files[] = $path;
        }
        return $files;
    }

    public function watermark($file_path,$config,$flag='vod')
    {
        try {
            $image = ImageProcessor::open('./' . $file_path);
            $this->applyWatermark($image, $config);
            $image->save('./' . $file_path);
            return true;
        }
        catch(\Throwable $e){
            return false;
        }
    }

    private function applyWatermark(ImageProcessor $image, array $config): void
    {
        $image->text($config['watermark_content'] ?? '', !empty($config['watermark_font']) ? $config['watermark_font'] : './static/font/test.ttf',
            $config['watermark_size'] ?? 20, $config['watermark_color'] ?? '#00000000', $config['watermark_location'] ?? 9);
    }

    public function makethumb($file_path,$config,$flag='vod',$new=1,$watermarked=false)
    {
        $thumb_type = $config['thumb_type'] ?? 1;
        $data['thumb'] = [];
        if (!empty($config['thumb_size'])) {
            try {
                // 支持多种尺寸的缩略图
                $thumbs = explode(',', $config['thumb_size']);
                if (count($thumbs) > 16) { return $data; }
                foreach ($thumbs as $value) {
                    if (!preg_match('/^[0-9]{1,4}(x[0-9]{1,4})?$/Di', trim($value))) { return $data; }
                }
                $source = ImageProcessor::open('./' . $file_path);
                foreach ($thumbs as $k => $v) {
                    $image = $source->copy();
                    $t_size = explode('x', strtolower(trim($v)));
                    if (!isset($t_size[1])) {
                        $t_size[1] = $t_size[0];
                    }
                    $new_thumb = $file_path . '_' . $t_size[0] . 'x' . $t_size[1] . '.' . strtolower(pathinfo($file_path, PATHINFO_EXTENSION));
                    if($new==0){
                        $new_thumb = $file_path;
                    }
                    $image->thumb($t_size[0], $t_size[1], $thumb_type);
                    if (($config['watermark'] ?? 0) == 1 && !$watermarked) {
                        $this->applyWatermark($image, $config);
                    }
                    $image->save('./' . $new_thumb);
                    clearstatcache(true, './' . $new_thumb);
                    $thumb_size = round(filesize('./' . $new_thumb) / 1024, 2);
                    $data['thumb'][$k]['type'] = 'image';
                    $data['thumb'][$k]['flag'] = $flag;
                    $data['thumb'][$k]['file'] = $new_thumb;
                    $data['thumb'][$k]['size'] = $thumb_size;
                    $data['thumb'][$k]['ctime'] = request()->time();
                }
            }
            catch(\Throwable $e){

            }
        }
        return $data;
    }




}
