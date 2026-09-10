<?php
namespace app\admin\controller;
use think\addons\AddonException;
use think\addons\Service;
use think\facade\Cache;

class Addon extends Base
{
    public function __construct()
    {
        parent::__construct();
    }

    public function index()
    {
        $param = \think\facade\Request::param();
        $param['wd'] = is_string($param['wd'] ?? null) ? $param['wd'] : '';

        $this->assign('param',$param);
        $this->assign('title',lang('admin/addon/title'));
        return $this->fetch('admin@addon/index');
    }

    public function config()
    {
        $param = \think\facade\Request::param();
        $name = $this->pluginName($param['name'] ?? '');
        if(empty($name)){
            return $this->error(lang('param_err'));
        }

        if (!is_dir(ADDON_PATH . $name)) {
            return $this->error(lang('get_dir_err'));
        }

        $info = get_addon_info($name);
        $config = get_addon_fullconfig($name);
        if (!$info){
            return $this->error(lang('get_addon_info_err'));
        }
        if ($this->request->isPost()) {
            $params = $this->request->post("row/a");
            if(empty($params)){
                return $this->error(lang('param_err'));
            }
            foreach ($config as $k => &$v) {
                if (isset($params[$v['name']])) {
                    if ($v['type'] == 'array') {
                        $params[$v['name']] = is_array($params[$v['name']]) ? $params[$v['name']] : (array)json_decode($params[$v['name']], true);
                        $value = $params[$v['name']];
                    } else {
                        $value = is_array($params[$v['name']]) ? implode(',', $params[$v['name']]) : $params[$v['name']];
                    }
                    $v['value'] = $value;
                }
            }

            try {
                //更新配置文件
                set_addon_fullconfig($name, $config);
                Service::refresh();
                return $this->success(lang('save_ok'));
            } catch (\Throwable $e) {
                return $this->operationFailure($e);
            }
        }

        $this->assign('info',$info);
        $this->assign('config',$config);

        return $this->fetch('admin@addon/config');
    }

    public function info()
    {

    }

    public function downloaded()
    {
        $offset = (int)$this->request->get("offset");
        $limit = (int)$this->request->get("limit");
        $filter = $this->request->get("filter");
        $search = $this->request->get("search");
        $search = htmlspecialchars(strip_tags(is_string($search) ? $search : ''));
        $onlineaddons = []; // Retired remote catalog is never queried.
        $filter = is_string($filter) ? (array)json_decode($filter, true) : [];
        $addons = get_addon_list();
        $list = [];
        foreach ($addons as $k => $v) {
            if ($search && stripos($v['name'], $search) === FALSE && stripos($v['intro'], $search) === FALSE)
                continue;

            if (isset($onlineaddons[$v['name']])) {
                $v = array_merge($onlineaddons[$v['name']], $v);
            } else {
                if(!isset($v['category_id'])) {
                    $v['category_id'] = 0;
                }
                if(!isset($v['flag'])) {
                    $v['flag'] = '';
                }
                if(!isset($v['banner'])) {
                    $v['banner'] = '';
                }
                if(!isset($v['image'])) {
                    $v['image'] = '';
                }
                if(!isset($v['donateimage'])) {
                    $v['donateimage'] = '';
                }
                if(!isset($v['demourl'])) {
                    $v['demourl'] = '';
                }
                if(!isset($v['price'])) {
                    $v['price'] = '0.00';
                }
            }
            $v['url'] = addon_url($v['name']);
            $v['createtime'] = filemtime(ADDON_PATH . $v['name']);
            $v['install'] = (string)($v['installed'] ?? '1');
            if ($filter && isset($filter['category_id']) && is_numeric($filter['category_id']) && $filter['category_id'] != $v['category_id']) {
                continue;
            }
            $list[] = $v;
        }
        $total = count($list);
        if ($limit) {
            $list = array_slice($list, $offset, $limit);
        }
        $result = array("total" => $total, "rows" => $list);

        return json($result);
    }

    /**
     * 安装
     */
    public function install()
    {
        $this->requirePost();
        $param = \think\facade\Request::param();
        $name = $this->pluginName($param['name'] ?? '');
        $force = (int)($param['force'] ?? 0);
        if (!$name) {
            return $this->error(lang('param_err'));
        }
        // 安全加固(V7):插件名严格白名单,防止 ../ 操纵下载/解压/复制路径
        if (!preg_match('/^[a-zA-Z0-9_]+$/', $name)) {
            return $this->error(lang('admin/addon/path_err'));
        }
        try {
            $uid = $this->request->post("uid");
            $token = $this->request->post("token");
            $version = $this->request->post("version");
            $faversion = $this->request->post("faversion");
            $extend = [
                'uid'       => $uid,
                'token'     => $token,
                'version'   => $version,
                'faversion' => $faversion
            ];
            Service::install($name, $force, $extend);
            $info = get_addon_info($name);
            $info['config'] = get_addon_config($name) ? 1 : 0;
            $info['state'] = 1;
            return $this->success(lang('install_ok'));
        } catch (AddonException $e) {
            return $this->error($e->getMessage());
        } catch (\Throwable $e) {
            return $this->operationFailure($e);
        }
    }

    /**
     * 卸载
     */
    public function uninstall()
    {
        $this->requirePost();
        $param = \think\facade\Request::param();
        $name = $this->pluginName($param['name'] ?? '');
        $force = (int)($param['force'] ?? 0);
        if (!$name) {
            return $this->error(lang('param_err'));
        }
        try {
            if( strpos($name,".")!==false ||  strpos($name,"/")!==false ||  strpos($name,"\\")!==false  ) {
                $this->error(lang('admin/addon/path_err'));
                return;
            }


            Service::uninstall($name, $force);
            return $this->success(lang('uninstall_ok'));
        } catch (AddonException $e) {
            return $this->error($e->getMessage());
        } catch (\Throwable $e) {
            return $this->operationFailure($e);
        }
    }

    /**
     * 禁用启用
     */
    public function state()
    {
        $this->requirePost();
        $param = \think\facade\Request::param();
        $name = $this->pluginName($param['name'] ?? '');
        $action = $param['action'] ?? '';
        if (!in_array($action, ['enable', 'disable'], true)) {
            return $this->error(lang('param_err'));
        }
        $force = (int)($param['force'] ?? 0);
        if (!$name) {
            return $this->error(lang('param_err'));
        }
        // 安全加固(V7):插件名严格白名单
        if (!preg_match('/^[a-zA-Z0-9_]+$/', $name)) {
            return $this->error(lang('admin/addon/path_err'));
        }
        try {
            $action = $action == 'enable' ? $action : 'disable';
            //调用启用、禁用的方法
            Service::$action($name, $force);
            Cache::delete('__menu__');
            return $this->success(lang('opt_ok'));
        } catch (AddonException $e) {
            return $this->error($e->getMessage());
        } catch (\Throwable $e) {
            return $this->operationFailure($e);
        }
    }

    /**
     * 本地上传
     */
    public function local()
    {
        $this->requirePost();
        return json(['code' => 1001, 'msg' => '插件压缩包上传已停用，请部署审核后的本地插件'], 403);
    }

    public function add()
    {
        return $this->fetch('admin@addon/add');
    }
    /**
     * 更新插件
     */
    public function upgrade()
    {
        $this->requirePost();
        $name = $this->pluginName($this->request->post('name', ''));
        if (!$name) {
            return $this->error(lang('param_err'));
        }
        // 安全加固(V7):插件名严格白名单
        if (!preg_match('/^[a-zA-Z0-9_]+$/', $name)) {
            return $this->error(lang('admin/addon/path_err'));
        }
        try {
            $uid = $this->request->post("uid");
            $token = $this->request->post("token");
            $version = $this->request->post("version");
            $faversion = $this->request->post("faversion");
            $extend = [
                'uid'       => $uid,
                'token'     => $token,
                'version'   => $version,
                'faversion' => $faversion
            ];
            //调用更新的方法
            Service::upgrade($name, $extend);
            Cache::delete('__menu__');
            return $this->success(lang('update_ok'));
        } catch (AddonException $e) {
            return $this->error($e->getMessage());
        } catch (\Throwable $e) {
            return $this->operationFailure($e);
        }
    }

    private function requirePost(): void
    {
        if (!$this->request->isPost()) {
            throw new \think\exception\HttpResponseException(json(['code' => 1001, 'msg' => '请使用 POST 提交插件操作'], 405));
        }
    }

    private function pluginName($name): string
    {
        try {
            return Service::validateName($name);
        } catch (AddonException $e) {
            throw new \think\exception\HttpResponseException(json(['code' => 1001, 'msg' => $e->getMessage()], 400));
        }
    }

    private function operationFailure(\Throwable $e)
    {
        if ($e instanceof \think\exception\HttpResponseException) { throw $e; }
        \think\facade\Log::error('Addon operation failed: ' . $e->getMessage());
        return $this->error('插件操作失败，请检查后台日志');
    }

}
