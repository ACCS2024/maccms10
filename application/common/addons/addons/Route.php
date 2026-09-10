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
        foreach ([$addon, $controller, $action] as $value) {
            if ($value !== null && !is_string($value)) { throw new HttpException(404, 'Invalid addon route'); }
        }
        $request   = request();
        $convert   = Config::get('route.url_convert') ?? true;
        $filter    = $convert ? 'strtolower' : 'trim';

        $addon      = $addon      ? trim(call_user_func($filter, $addon))      : '';
        $controller = $controller ? trim(call_user_func($filter, $controller)) : 'index';
        $action     = $action     ? trim(call_user_func($filter, $action))     : 'index';
        if (!preg_match('/^[a-zA-Z0-9_]+$/D', $addon)
            || !preg_match('/^[a-zA-Z0-9_]+(?:\.[a-zA-Z0-9_]+)*$/D', $controller)
            || !preg_match('/^[a-zA-Z][a-zA-Z0-9_]*$/D', $action)) {
            throw new HttpException(404, 'Invalid addon route');
        }

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
            $method = new \ReflectionMethod($instance, $action);
            if ($method->isStatic() || $method->isConstructor() || $method->getDeclaringClass()->getName() === Controller::class) {
                throw new HttpException(404, 'Invalid addon action');
            }
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
