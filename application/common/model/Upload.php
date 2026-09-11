<?php
namespace app\common\model;

use app\common\util\Ftp as ftpOper;

/**
 * 上传处理辅助类：接收文件、本地保存或转投 FTP/云存储，并协调附件元数据。
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

        $verifiedBearer = false;
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
                // checkLogin above verifies this same enabled Bearer and never falls back on failure.
                $verifiedBearer = \app\common\util\JwtService::isEnabled()
                    && \app\common\util\JwtService::bearerFromRequest(request()) !== '';
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
        if (!$editorConfig && !$verifiedBearer && !\app\common\util\UploadCsrf::validate(request())) {
            return self::upload_return(lang('token_err'));
        }

        $result = $this->processUpload($param, $adminContext);
        // Editors deliberately echo + exit: only invoke them after processing cleanup/transactions finish.
        return self::upload_return($result['info'], $param['from'], $result['status'], $result['data']);
    }

    private static function uploadResult(string $info, int $status = 0, array $data = []): array
    {
        return ['info'=>$info, 'status'=>$status, 'data'=>$data];
    }

    private function processUpload(array $param, bool $adminContext): array
    {
        $base64_img = $param['imgdata'] ?? '';
        if (!is_string($base64_img) || strlen($base64_img) > 4 * (int)ceil(\app\common\util\ImageProcessor::MAX_BYTES / 3) + 128) {
            return self::uploadResult(lang('admin/upload/upload_faild'));
        }
        $data = [];
        $config = (array)config('maccms.site');
        $pre = $config['install_dir'] ?? '';
        if (!is_string($pre) || strlen($pre) > 7937 || preg_match('//u', $pre) !== 1
            || preg_match('/[\x00-\x1f\x7f]/', $pre)) { return self::uploadResult(lang('param_err')); }
        $config = (array)config('maccms.upload');

        if(!empty($param['from'])){
            $cp = 'app\\common\\extend\\editor\\' . ucfirst($param['from']);
            if (class_exists($cp)) {
                $c = new $cp;
                $c->front($param);
            }
            else{
                return self::uploadResult(lang('admin/upload/not_find_extend'));
            }
        }
        else{
            $pre='';
        }

        $mode = $config['mode'] ?? '';
        if (!is_string($mode) && !is_int($mode)) { return self::uploadResult(lang('admin/upload/upload_faild')); }
        try {
            $data = $param['flag'] === 'user'
                ? \app\common\util\LocalAttachment::storeAvatar($param, $config, $param['user_id'], !$adminContext)
                : \app\common\util\LocalAttachment::store($param, $config);
            if (!$adminContext && $param['flag'] === 'user'
                && \app\common\util\UserPortrait::isManagedPath($param['user_id'], $data['_portrait_path'] ?? null)) {
                $portrait = preg_match('~^https?://~D', $data['file']) ? $data['file'] : MAC_PATH . $data['file'];
                cookie('user_portrait', $portrait, ['expire'=>2592000]);
            }
            unset($data['_portrait_path']);
            if ($param['from'] !== '' && !preg_match('~^https?://~D', $data['file'])) { $data['file'] = $pre . $data['file']; }
            return self::uploadResult(lang('admin/upload/upload_success'), 1, $data);
        } catch (\app\common\util\StorageOutcomeUnknown $error) {
            return self::uploadResult(lang('model/financial/outcome_unknown', [$error->details['reference']]), 2005, $error->details);
        } catch (\Throwable $error) {
            return self::uploadResult(lang('admin/upload/upload_faild'));
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
            $arr['file'] = isset($data['file'])
                ? (preg_match('~^https?://~D', $data['file']) ? $data['file'] : MAC_PATH . $data['file']) . '?'. mt_rand(1000, 9999) : '';
            if (($data['retryable'] ?? null) === false) { $arr['data'] = $data; }
        }
        else{
            $arr['msg'] = $info;
            $arr['code'] = $status;
            $arr['data'] = $data;
        }
        return $arr;
    }

}
