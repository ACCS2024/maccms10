<?php
namespace app\admin\controller;
use think\facade\Db;

class Timming extends Base
{
    var $_pre;
    public function __construct()
    {
        parent::__construct();
    }

    public function index()
    {
        $list = config('timming');
        // 只传状态和掩码,明文要点"显示"才通过 token(act=reveal) 单独取
        $this->assign('token_state', $this->tokenState((array)config('maccms')));
        $this->assign('is_super', (string)($this->_admin['admin_id'] ?? '') === '1' ? 1 : 0);
        $this->assign('list',$list);
        $this->assign('title',lang('admin/timming/title'));
        return $this->fetch('admin@timming/index');
    }

    public function info()
    {
        $param = \think\facade\Request::param();
        $list = config('timming');
        if (Request()->isPost()) {
            $validate = mac_validate('Token');
            if(!$validate->check($param)){
                return $this->error($validate->getError());
            }

            $param['weeks'] = join(',',$param['weeks']);
            $param['hours'] = join(',',$param['hours']);
            $list[$param['name']] = $param;
            $res = mac_arr2file( APP_PATH .'extra/timming.php', $list);
            if($res===false){
                return $this->error(lang('write_err_config'));
            }

            return $this->success(lang('save_ok'));
        }
        $info = $list[$param['id']];

        $this->assign('info',$info);
        $this->assign('title',lang('admin/timming/title'));
        return $this->fetch('admin@timming/info');
    }

    /**
     * 远程触发 Token 管理(生成 / 显示 / 重置 / 停用)。
     *
     * 为什么非要有这东西:api\Timming::index() 的闸门是 fail-closed —— `timming_token`
     * 没配置时【HTTP 一律拒绝】,这是为了防止默认空 token 的站点被任何人触发采集、
     * 清缓存、生成静态。代价是列表页那个"测试"链接从此点不动,而本机 PHP-FPM 又禁用了
     * exec/proc_open(后台没法 shell 出去跑 CLI),于是后台内触发也只能自调 HTTP。
     *
     * 明文只在【显式点"显示"】时下发(act=reveal),页面初次渲染只给掩码 ——
     * 免得 token 躺在 HTML 源码里,被截图、浏览器缓存、误分享一并带走。
     */
    public function token()
    {
        // 只有超管能碰:拿到 token 就等于拿到采集/清缓存/静态生成的触发权
        if ((string)($this->_admin['admin_id'] ?? '') !== '1') {
            return json(['code' => 0, 'msg' => lang('permission_denied')]);
        }

        $param = \think\facade\Request::param();
        $act   = (string)($param['act'] ?? 'status');
        $cfg   = config('maccms');
        $token = (string)($cfg['app']['timming_token'] ?? '');

        if (!\think\facade\Request::isPost()) {
            return json(['code' => 1, 'msg' => 'ok', 'data' => $this->tokenState($cfg)]);
        }

        if ($act === 'reveal') {
            if ($token === '') {
                return json(['code' => 0, 'msg' => '尚未启用,请先生成 Token']);
            }
            \think\facade\Log::notice('[timming] token revealed by admin_id='
                . ($this->_admin['admin_id'] ?? '?') . ' ip=' . \think\facade\Request::ip());
            return json(['code' => 1, 'msg' => 'ok', 'data' => ['token' => $token]]);
        }

        if ($act === 'generate') {
            // 24 字节 = 48 位十六进制。够长到爆破无意义,又能整行复制不折行。
            $token = bin2hex(random_bytes(24));
        } elseif ($act === 'clear') {
            $token = '';
        } else {
            return json(['code' => 0, 'msg' => lang('param_err')]);
        }

        $cfg['app']['timming_token']      = $token;
        $cfg['app']['timming_token_time'] = $token === '' ? 0 : time();
        if (mac_arr2file(APP_PATH . 'extra/maccms.php', $cfg) === false) {
            return json(['code' => 0, 'msg' => lang('write_err_config')]);
        }

        \think\facade\Log::notice('[timming] token ' . ($token === '' ? 'disabled' : 'regenerated')
            . ' by admin_id=' . ($this->_admin['admin_id'] ?? '?') . ' ip=' . \think\facade\Request::ip());

        $cfg['app']['timming_token'] = $token;
        return json([
            'code' => 1,
            'msg'  => $token === '' ? '已停用远程触发' : '已生成新 Token,旧 Token 立即失效',
            'data' => $this->tokenState($cfg) + ($token === '' ? [] : ['token' => $token]),
        ]);
    }

    /** site_url 补全协议;为空时退回当前请求的域名,保证复制出来的命令能直接用 */
    private function normalizeSiteUrl(string $url): string
    {
        $url = trim($url);
        if ($url === '') {
            return rtrim(\think\facade\Request::domain(), '/');
        }
        if (!preg_match('~^https?://~i', $url)) {
            // 不能用 Request::isSsl() 判 —— 那反映的是【后台此刻怎么被访问的】
            // (站长常直接用 http://<IP>/<入口>.php 进后台),而这里要拼的是【公网站点地址】。
            // 现代站点一律 https;确实只有 http 的站,把协议写进 site_url 即可覆盖。
            $url = 'https://' . $url;
        }
        return rtrim($url, '/');
    }

    /** 页面/接口通用的 token 状态(不含明文) */
    private function tokenState(array $cfg): array
    {
        $token = (string)($cfg['app']['timming_token'] ?? '');
        $time  = (int)($cfg['app']['timming_token_time'] ?? 0);
        return [
            'enabled' => $token === '' ? 0 : 1,
            // 掩码保留首尾各 4 位:够运维核对"是不是同一个",又拼不出完整值
            'masked'  => $token === '' ? '' : substr($token, 0, 4) . str_repeat('•', 24) . substr($token, -4),
            'updated' => $time > 0 ? date('Y-m-d H:i:s', $time) : '',
            // site_url 配置里通常不带协议(本站是 "sex8zy.com"),直接拼会得到
            // "sex8zy.com/api.php/..." 这种点了打不开的地址,补上协议
            'site'    => $this->normalizeSiteUrl((string)($cfg['site']['site_url'] ?? '')),
            'dir'     => (string)($cfg['site']['install_dir'] ?? '/'),
        ];
    }

    public function del()
    {
        $param = \think\facade\Request::param();
        $list = config('timming');
        unset($list[$param['ids']]);
        $res = mac_arr2file(APP_PATH. 'extra/timming.php', $list);
        if($res===false){
            return $this->error(lang('del_err'));
        }

        return $this->success(lang('del_ok'));
    }

    public function field()
    {
        $param = \think\facade\Request::param();
        $ids = $param['ids'];
        $col = $param['col'];
        $val = $param['val'];

        if(!empty($ids) && in_array($col,['status'])){
            $list = config('timming');
            $ids = explode(',',$ids);
            foreach($list as $k=>&$v){
                if(in_array($k,$ids)){
                    $v[$col] = $val;
                }
            }
            $res = mac_arr2file(APP_PATH. 'extra/timming.php', $list);
            if($res===false){
                return $this->error(lang('save_err'));
            }
            return $this->success(lang('save_ok'));
        }
        return $this->error(lang('param_err'));
    }
}
