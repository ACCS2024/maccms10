<?php
namespace think\addons;

use think\facade\Config;
use think\facade\Event;
use think\exception\HttpException;

/**
 * 插件路由执行器（内化自 fastadmin-addons，TP8 适配）
 */
class Route
{
    public function execute($addon = null, $controller = null, $action = null)
    {
        $request   = request();
        $convert   = Config::get('route.url_convert') ?? true;
        $filter    = $convert ? 'strtolower' : 'trim';

        $addon      = $addon      ? trim(call_user_func($filter, $addon))      : '';
        $controller = $controller ? trim(call_user_func($filter, $controller)) : 'index';
        $action     = $action     ? trim(call_user_func($filter, $action))     : 'index';

        Event::trigger('addon_begin', $request);

        if (empty($addon) || empty($controller) || empty($action)) {
            abort(500, lang('addon can not be empty'));
        }

        $info = get_addon_info($addon);
        if (!$info) {
            throw new HttpException(404, 'addon ' . $addon . ' not found');
        }
        if (!$info['state']) {
            throw new HttpException(500, 'addon ' . $addon . ' is disabled');
        }

        $class = get_addon_class($addon, 'controller', $controller);
        if (!$class) {
            throw new HttpException(404, 'addon controller ' . $controller . ' not found');
        }

        $instance = new $class($request);

        Event::trigger('addon_module_init', $request);
        Event::trigger('addons_init', $request);

        $vars = [];
        if (is_callable([$instance, $action])) {
            $call = [$instance, $action];
        } elseif (is_callable([$instance, '_empty'])) {
            $call = [$instance, '_empty'];
            $vars = [$action];
        } else {
            throw new HttpException(404, 'addon action ' . get_class($instance) . '->' . $action . '() not found');
        }

        Event::trigger('addon_action_begin', $call);

        return call_user_func_array($call, $vars);
    }
}
