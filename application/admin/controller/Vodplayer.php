<?php
namespace app\admin\controller;
use think\facade\Db;

class Vodplayer extends Base
{
    var $_pre;
    public function __construct()
    {
        parent::__construct();
        $this->_pre = 'vodplayer';
    }

    public function index()
    {
        $list = config($this->_pre);
        $this->assign('list',$list);
        $this->assign('title',lang('admin/vodplayer/title'));
        return $this->fetch('admin@vodplayer/index');
    }

    public function info()
    {
        $param = \think\facade\Request::param();
        $list = config($this->_pre);
        if (Request()->isPost()) {
            $validate = mac_validate('Token');
            if(!$validate->check($param)){
                return $this->error($validate->getError());
            }
            unset($param['__token__']);
            unset($param['flag']);
            // 【安全治理】播放器一律配置化，不再向 static/player/ 写任何 JS 文件。
            // 历史实现把一个 code 文本框的原始 JS 落盘成 <from>.js，而 player.js 会在
            // 每个播放页加载并 innerHTML 它 —— 等于「后台加播放器 = 给全站每页注入任意
            // HTML/跳转」，是架构级注入面。详见 docs/security/player-injection-hardening.md。
            // 这里把 code 直接丢弃，不落盘。
            unset($param['code']);
            if(is_numeric($param['from'])){
                $param['from'] .='_';
            }
            if (strpos($param['from'], '.') !== false || strpos($param['from'], '/') !== false || strpos($param['from'], '\\') !== false) {
                $this->error(lang('param_err'));
                return;
            }
            // 新增/编辑的播放器必须能被【内置渲染器】处理：要么是内置类型，要么走解析
            // (ps=1 且填了解析地址)。否则前端 player.js 的白名单会拒绝加载它 ——
            // 从此不存在「未注册的自定义 JS 播放器」这条路。
            $builtin = ['dplayer','videojs','iva','iframe','link','swf','flv'];
            $isParse = (($param['ps'] ?? '0') === '1') && trim((string)($param['parse'] ?? '')) !== '';
            if (!in_array($param['from'], $builtin, true) && !$isParse) {
                return $this->error('播放器「'.$param['from'].'」无法渲染：请选择内置播放器类型，或开启解析(ps=1)并填写解析接口地址');
            }
            $list[$param['from']] = $param;
            $sort=[];
            foreach ($list as $k=>&$v){
                $sort[] = $v['sort'];
            }
            array_multisort($sort, SORT_DESC, SORT_FLAG_CASE , $list);

            $res = mac_arr2file( APP_PATH .'extra/'.$this->_pre.'.php', $list);
            if($res===false){
                return $this->error(lang('write_err_config'));
            }
            cache('cache_data','1');
            return $this->success(lang('save_ok'));
        }

        // 不再读取 static/player/<id>.js —— 播放器已无自定义 JS，只剩配置。
        $info = $list[$param['id']];
        $this->assign('info',$info);
        $this->assign('title',lang('admin/vodplayer/title'));
        return $this->fetch('admin@vodplayer/info');
    }

    public function del()
    {
        $param = \think\facade\Request::param();
        $list = config($this->_pre);
        unset($list[$param['ids']]);
        $res = mac_arr2file(APP_PATH. 'extra/'.$this->_pre.'.php', $list);
        if($res===false){
            return $this->error(lang('del_err'));
        }
        cache('cache_data','1');
        return $this->success(lang('del_ok'));
    }

    public function field()
    {
        $param = \think\facade\Request::param();
        $ids = $param['ids'];
        $col = $param['col'];
        $val = $param['val'];

        if(!empty($ids) && in_array($col,['ps','status'])){
            $list = config($this->_pre);
            $ids = explode(',',$ids);
            foreach($list as $k=>&$v){
                if(in_array($k,$ids)){
                    $v[$col] = $val;
                }
            }
            $res = mac_arr2file(APP_PATH. 'extra/'.$this->_pre.'.php', $list);
            if($res===false){
                return $this->error(lang('save_err'));
            }
            return $this->success(lang('save_ok'));
        }
        return $this->error(lang('param_err'));
    }

    public function export()
    {
        $param = \think\facade\Request::param();
        $list = config($this->_pre);
        // 导出只带配置，不再附带任何 JS 代码。
        $info = $list[$param['id']];

        header("Content-type: application/octet-stream");
        if(strpos($_SERVER['HTTP_USER_AGENT'] ?? '', "MSIE")) {
            header("Content-Disposition: attachment; filename=mac_" . urlencode($info['from']) . '.txt');
        }
        else{
            header("Content-Disposition: attachment; filename=mac_" . $info['from'] . '.txt');
        }
        echo base64_encode(json_encode($info));
    }

    public function import()
    {
        if (request()->isPost()) {
            $param = \think\facade\Request::param();
            $validate = mac_validate('Token');
            if(!$validate->check($param)){
                return $this->error($validate->getError());
            }
            unset($param['__token__']);
            $file = $this->request->file('file');
            $info = $file->rule('uniqid')->validate(['size' => 10240000, 'ext' => 'txt']);
            if ($info) {
                $data = json_decode(base64_decode(file_get_contents($info->getpathName())), true);
                @unlink($info->getpathName());
                if ($data) {
                    if (empty($data['status']) || empty($data['from']) || empty($data['sort'])) {
                        return $this->error(lang('format_err'));
                    }
                    if (strpos($data['from'], '.') !== false || strpos($data['from'], '/') !== false || strpos($data['from'], '\\') !== false) {
                        $this->error(lang('param_err'));
                        return;
                    }
                    // 【安全治理】导入只接受配置，丢弃任何随包携带的 JS（老的分享包仍可导入，
                    // 只是不再落盘执行）。同样要求可被内置渲染器处理。
                    unset($data['code']);
                    $builtin = ['dplayer','videojs','iva','iframe','link','swf','flv'];
                    $isParse = (($data['ps'] ?? '0') === '1') && trim((string)($data['parse'] ?? '')) !== '';
                    if (!in_array($data['from'], $builtin, true) && !$isParse) {
                        return $this->error('导入的播放器「'.$data['from'].'」无法渲染：需为内置类型或解析型(ps=1+解析地址)');
                    }

                    $list = config($this->_pre);
                    $list[$data['from']] = $data;
                    $res = mac_arr2file(APP_PATH . 'extra/' . $this->_pre . '.php', $list);
                    if ($res === false) {
                        return $this->error(lang('write_err_config'));
                    }
                }
                return $this->success(lang('import_ok'));
            } else {
                return $this->error($file->getError());
            }
        }
        else{
            return $this->fetch('admin@vodplayer/import');
        }
    }

}
