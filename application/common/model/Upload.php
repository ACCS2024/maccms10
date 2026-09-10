<?php
namespace app\common\model;

use app\common\util\Ftp as ftpOper;

/**
 * 上传处理辅助类：接收文件、本地保存或转投 FTP/云存储，不落库。
 *
 * 【不要让它继承 Base/Model】
 * 本类没有对应的数据表（mac_upload 在官方原版与老库中同样不存在）。
 * TP8 的 think\Model::__construct() 会调用 initializeData() -> getFields()，
 * 即「实例化」本身就会去查自己那张表的字段结构；TP5 是懒加载从不触发，
 * 迁到 TP8 后 new Upload() 直接抛
 * SQLSTATE[42S02] Table '...mac_upload' doesn't exist。
 * 与 Extend / Cj 是同一类问题，处置一致：退回普通类。
 */
class Upload {

    public function api($file_path,$config)
    {
        if(empty($config)){
            return $file_path;
        }

        if ($config['mode'] == '2') {
            $config['mode'] = 'upyun';
        }
        elseif ($config['mode'] == '3'){
            $config['mode'] = 'qiniu';
        }
        elseif ($config['mode'] == '4') {
            $config['mode'] = 'ftp';
        }
        elseif ($config['mode'] == '5') {
            $config['mode'] = 'weibo';
        }

        if(!in_array($config['mode'],['local','remote'])){
            $cp = 'app\\common\\extend\\upload\\' . ucfirst($config['mode']);
            if (class_exists($cp)) {
                $c = new $cp($config);
                $file_path = $c->submit($file_path);
            }
        }

        return str_replace(['http:','https:'],'mac:',$file_path);
    }

    /** $adminContext is supplied only by the authenticated admin controller, never by request data. */
    public function upload($p=[], bool $adminContext = false)
    {
        $param = \think\facade\Request::param();
        if (!is_array($p)) {
            return self::upload_return(lang('param_err'));
        }
        $param = array_merge($param, $p);
        foreach (['from', 'input', 'flag', 'thumb', 'thumb_class', 'user_id', 'action', 'ueditor_theme'] as $key) {
            if (isset($param[$key]) && !is_string($param[$key]) && !is_int($param[$key])) {
                return self::upload_return(lang('param_err'));
            }
        }
        $param['from'] = strtolower((string)($param['from'] ?? ''));
        $param['input'] = (string)($param['input'] ?? 'file');
        $param['flag'] = strtolower((string)($param['flag'] ?? ($adminContext ? 'vod' : 'user')));
        $param['thumb'] = (string)($param['thumb'] ?? '0');
        $param['thumb_class'] = (string)($param['thumb_class'] ?? '');
        if ($param['input'] === '') { $param['input'] = 'file'; }
        if ($param['flag'] === '') { $param['flag'] = $adminContext ? 'vod' : 'user'; }
        if ($param['thumb'] === '') { $param['thumb'] = '0'; }
        if (!preg_match('/^[a-z0-9_]{1,64}$/D', $param['flag'])
            || !preg_match('/^[A-Za-z][A-Za-z0-9_]{0,63}$/D', $param['input'])
            || !in_array($param['thumb'], ['0', '1'], true)
            || strlen($param['thumb_class']) > 128
            || !in_array($param['from'], ['', 'ueditor', 'umeditor', 'kindeditor', 'ckeditor', 'tinymce'], true)) {
            return self::upload_return(lang('param_err'));
        }

        try {
            if ($adminContext) {
                $login = (new Admin())->checkLogin();
                if (($login['code'] ?? null) !== 1 || !self::adminMayUpload($login['info'], 'upload/upload')) {
                    return self::upload_return(lang('permission_denied'));
                }
                if ($param['flag'] === 'user') {
                    $targetId = \app\common\util\PointsBalance::amount($param['user_id'] ?? null);
                    if ($targetId === null || !self::adminMayUpload($login['info'], 'user/info')
                        || !\think\facade\Db::name('User')->where('user_id', $targetId)->value('user_id')) {
                        return self::upload_return(lang('permission_denied'));
                    }
                    $param['user_id'] = $targetId;
                }
            } else {
                $login = (new User())->checkLogin();
                $ownerId = ($login['code'] ?? null) === 1
                    ? \app\common\util\PointsBalance::amount($login['info']['user_id'] ?? null) : null;
                if ($ownerId === null) {
                    return self::upload_return(lang('model/user/not_login'));
                }
                if (($GLOBALS['config']['user']['portrait_status'] ?? '0') != '1') {
                    return self::upload_return(lang('index/portrait_tip1'));
                }
                $requestedId = $param['user_id'] ?? null;
                if ($param['flag'] !== 'user' || $param['from'] !== ''
                    || (!in_array($requestedId, [null, '', 0, '0'], true)
                        && \app\common\util\PointsBalance::amount($requestedId) !== $ownerId)) {
                    return self::upload_return(lang('permission_denied'));
                }
                $param['user_id'] = $ownerId;
            }
        } catch (\Throwable $error) {
            return self::upload_return(lang('permission_denied'));
        }

        $editorConfig = $adminContext && request()->isGet()
            && in_array($param['from'], ['ueditor', 'umeditor'], true) && ($param['action'] ?? '') === 'config';
        if (!request()->isPost() && !$editorConfig) {
            return self::upload_return(lang('illegal_request'));
        }

        $base64_img = $param['imgdata'] ?? '';
        if (!is_string($base64_img) || strlen($base64_img) > 4 * (int)ceil(\app\common\util\ImageProcessor::MAX_BYTES / 3) + 128) {
            return self::upload_return(lang('admin/upload/upload_faild'), $param['from']);
        }
        $data = [];
        $config = (array)config('maccms.site');
        $pre= $config['install_dir'];
        $upload_image_ext = 'jpg,jpeg,png,gif,webp';
        $upload_file_ext = 'doc,docx,xls,xlsx,ppt,pptx,pdf,wps,txt,rar,zip,torrent';
        $upload_media_ext = 'rm,rmvb,avi,mkv,mp4,mp3';
        $add_rnd = false;
        $config = (array)config('maccms.upload');

        if(!empty($param['from'])){
            $cp = 'app\\common\\extend\\editor\\' . ucfirst($param['from']);
            if (class_exists($cp)) {
                $c = new $cp;
                $c->front($param);
            }
            else{
                return self::upload_return(lang('admin/upload/not_find_extend'), '');
            }
        }
        else{
            $pre='';
        }

        // 上传附件路径
        $_upload_path = ROOT_PATH . 'upload' . '/' . $param['flag'] . '/' ;
        // 附件访问路径
        $_save_path = 'upload'. '/' . $param['flag'] . '/';
        if($param['flag']=='user'){
            $uniq = $param['user_id'] % 10;
            $_upload_path .= $uniq .'/';
            $_save_path .= $uniq .'/';
            // Decode new avatar data before replacing the user's existing JPEG.
            $_save_name = '.portrait-' . bin2hex(random_bytes(16)) . '.tmp';

            if(!file_exists($_save_path)){
                mac_mkdirss($_save_path);
            }
        }
        else{
            $ymd = date('Ymd');
            $n_dir = $ymd;
            for($i=1;$i<=100;$i++){
                $n_dir = $ymd .'-'.$i;
                $path1 = $_upload_path . $n_dir. '/';
                if(file_exists($path1)){
                    $farr = glob($path1.'*.*');
                    if($farr){
                        $fcount = count($farr);
                        if($fcount>999){
                            continue;
                        }
                        else{
                            break;
                        }
                    }
                    else{
                        break;
                    }
                }
                else{
                    break;
                }
            }
            $_save_name = $n_dir . '/' . md5(microtime(true));
        }
        $portraitInput = $param['flag'] === 'user' ? $_save_path . $_save_name : null;
        try {
        if(!empty($base64_img)){
            if(preg_match('/^(data:\s*image\/(\w+);base64,)/', $base64_img, $result)){
                $extension = strtolower($result[2]);
                if(in_array($extension, explode(',', $upload_image_ext), true)){
                    $type = 'image';
                    if ($param['flag'] !== 'user') { $_save_name .= '.' . $extension; }
                    $directory = dirname($_save_path . $_save_name);
                    if (!is_dir($directory) && !@mkdir($directory, 0777, true) && !is_dir($directory)) {
                        return self::upload_return(lang('admin/upload/upload_faild'), $param['from']);
                    }
                    $decoded = base64_decode(substr($base64_img, strlen($result[1])), true);
                    if($decoded === false || !file_put_contents($_save_path.$_save_name, $decoded)){
                        return self::upload_return(lang('admin/upload/upload_faild'), $param['from']);
                    }
                    $file_size = round(filesize('./'.$_save_path.$_save_name)/1024, 2);
                }
                else {
                    return self::upload_return(lang('admin/upload/forbidden_ext'), $param['from']);
                }
            }
            else{
                return self::upload_return(lang('admin/upload/no_input_file'), $param['from']);
            }
        }
        else {
            try {
                $file = request()->file($param['input']);
            } catch (\Throwable $e) {
                return self::upload_return(lang('admin/upload/upload_faild'), $param['from']);
            }
            if (!$file instanceof \think\file\UploadedFile || !$file->isValid()) {
                return self::upload_return(lang('admin/upload/no_input_file'), $param['from']);
            }
            if ($file->getMime() == 'text/x-php') {
                return self::upload_return(lang('admin/upload/forbidden_ext'), $param['from']);
            }

            $extension = strtolower($file->getOriginalExtension());
            if (in_array($extension, explode(',', $upload_image_ext), true)) {
                $type = 'image';
            } elseif (in_array($extension, explode(',', $upload_file_ext), true)) {
                $type = 'file';
            } elseif (in_array($extension, explode(',', $upload_media_ext), true)) {
                $type = 'media';
            } else {
                return self::upload_return(lang('admin/upload/forbidden_ext'), $param['from']);
            }
            if ($param['flag'] !== 'user') { $_save_name .= '.' . $extension; }
            $relativeDirectory = dirname($_save_name);
            $targetDirectory = $_upload_path . ($relativeDirectory === '.' ? '' : $relativeDirectory);
            try {
                $upfile = $file->move($targetDirectory, basename($_save_name));
            } catch (\Throwable $e) {
                return self::upload_return(lang('admin/upload/upload_faild'), $param['from']);
            }
            $file_size = round($upfile->getSize()/1024, 2);
        }


        $resource = fopen($_save_path.$_save_name, 'rb');
        $fileSize = filesize($_save_path.$_save_name);
        fseek($resource, 0);
        if ($fileSize>512){
            $hexCode = bin2hex(fread($resource, 512));
            fseek($resource, $fileSize - 512);
            $hexCode .= bin2hex(fread($resource, 512));
        } else {
            $hexCode = bin2hex(fread($resource, $fileSize));
        }
        fclose($resource);
        if(preg_match("/(3c25.*?28.*?29.*?253e)|(3c3f.*?28.*?29.*?3f3e)|(3C534352495054)|(2F5343524950543E)|(3C736372697074)|(2F7363726970743E)/is", $hexCode)){
            return self::upload_return(lang('admin/upload/upload_safe'), $param['from']);
        }

        $file_count = 1;
        $data = [
            'file'  => $_save_path.$_save_name,
            'type'  => $type,
            'size'  => $file_size,
            'flag' => $param['flag'],
            'ctime' => request()->time(),
            'thumb_class'=>$param['thumb_class'],
        ];

        $data['thumb'] = [];
        if($param['flag']=='user'){
            $add_rnd=true;
            $file = $_save_path.str_replace('\\', '/', $_save_name);
            $new_thumb = $param['user_id'] .'.jpg';
            $new_file = $_save_path . $new_thumb;
            try {
                $image = \app\common\util\ImageProcessor::open('./' . $file);
                $t_size = explode('x', strtolower($GLOBALS['config']['user']['portrait_size']));
                if (!isset($t_size[1])) {
                    $t_size[1] = $t_size[0];
                }
                $image->thumb($t_size[0], $t_size[1], 6)->save('./' . $new_file, 'jpeg');
                clearstatcache(true, './' . $new_file);
                $file_size = round(filesize('./' .$new_file)/1024, 2);
            }
            catch(\Throwable $e){
                return self::upload_return(lang('admin/upload/make_thumb_faild'), $param['from']);
            }
            $data['file'] = $new_file;
            $data['size'] = $file_size;
            $data['type'] = 'image';
            $update = [];
            $update['user_portrait'] = $new_file;
            $where = [];
            $where['user_id'] = $param['user_id'];
            (new \app\common\model\User())->where($where)->update($update);
        }
        else {
            if ($type == 'image') {
                $watermarked = false;
                if ($config['watermark'] == 1) {
                    $watermarked = (new \app\common\model\Image())->watermark($data['file'], $config, $param['flag']);
                }
                if ($param['thumb'] == 1 && $config['thumb'] == 1) {
                    $dd = (new \app\common\model\Image())->makethumb($data['file'], $config, $param['flag'], 1, $watermarked);
                    if (is_array($dd)) {
                        $data = array_merge($data, $dd);
                    }
                }
            }
        }
        unset($upfile);

        if ($config['mode'] == 2) {
            $config['mode'] = 'upyun';
        }
        elseif ($config['mode'] == 3){
            $config['mode'] = 'qiniu';
        }
        elseif ($config['mode'] == 4) {
            $config['mode'] = 'ftp';
        }
        elseif ($config['mode'] == 5) {
            $config['mode'] = 'weibo';
        }

        $config['mode'] = strtolower($config['mode']);

        if(!in_array($config['mode'],['local','remote'])){
            $data['file'] = (new \app\common\model\Upload())->api($data['file'],$config);
            if(!empty($data['thumb'])){
                $data['thumb'][0]['file'] = (new \app\common\model\Upload())->api($data['thumb'][0]['file'],$config);
            }
        }
        if(!empty($param['from'])){
            if(substr($data['file'],0,4)!='http' && substr($data['file'],0,4)!='mac:'){
                $data['file']  =  $pre. $data['file'];
            }
            else{
                $data['file']  = mac_url_content_img($data['file']);
            }
        }

        $tmp = $data['file'];
        if((substr($tmp,0,7) == "/upload")){
            $tmp = substr($tmp,1);
        }
        if((substr($tmp,0,6) == "upload")){
            $annex = [];
            $annex['annex_file'] = $tmp;
            $r = (new \app\common\model\Annex())->infoData($annex);
            if($r['code']!==1){
                $annex['annex_type'] = $type;
                $annex['annex_size'] = $file_size;
                (new \app\common\model\Annex())->saveData($annex);
                $tmp = $data['thumb'][0]['file'] ?? '';
                if(!empty($tmp)){
                    $file_size = filesize($tmp);
                    $annex = [];
                    $annex['annex_file'] = $tmp;
                    $r = (new \app\common\model\Annex())->infoData($annex);
                    if($r['code']!==1){
                        $annex['annex_type'] = $type;
                        $annex['annex_size'] = $file_size;
                        (new \app\common\model\Annex())->saveData($annex);
                    }
                }
            }
        }
        return self::upload_return(lang('admin/upload/upload_success'), $param['from'], 1, $data);
        } finally {
            if ($portraitInput !== null && is_file($portraitInput)) { @unlink($portraitInput); }
        }
    }

    private static function adminMayUpload(array $admin, string $permission): bool
    {
        if ((string)($admin['admin_id'] ?? '') === '1') { return true; }
        foreach (explode(',', (string)($admin['admin_auth'] ?? '')) as $grant) {
            if (!str_contains($grant, '/')) { continue; }
            [$controller, $action] = explode('/', trim($grant), 2);
            $key = strtolower(str_replace('_', '', $controller)).'/'.strtolower(explode('?', $action, 2)[0]);
            if ($key === $permission) { return true; }
        }
        return false;
    }

    private function upload_return($info='',$from='',$status=0,$data=[])
    {
        $arr = [];
        if(!empty($from)){
            $cp = 'app\\common\\extend\\editor\\' . ucfirst($from);
            if (class_exists($cp)) {
                $c = new $cp;
                $arr = $c->back($info,$status,$data);
            }
        }
        elseif(ENTRANCE=='index'){
            $arr['msg'] = $info;
            $arr['code'] = $status;
            $arr['file'] = isset($data['file']) ? MAC_PATH . $data['file'] . '?'. mt_rand(1000, 9999) : '';
        }
        else{
            $arr['msg'] = $info;
            $arr['code'] = $status;
            $arr['data'] = $data;
        }
        return $arr;
    }

}
