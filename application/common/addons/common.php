<?php
/**
 * 内化自 fastadmin-addons，适配 TP8。
 * 此文件通过 composer autoload.files 在 vendor/autoload.php 时加载（在 App 初始化之前），
 * 因此只做函数定义，不调用任何 Facade。
 * 真正的路由注册 / 事件绑定在 addons_boot() 中执行，由 AppInit 中间件调用。
 */

if (!defined('ADDON_PATH')) {
    define('ADDON_PATH', defined('ROOT_PATH') ? ROOT_PATH . 'addons/' : __DIR__ . '/../../../../addons/');
}
if (!defined('DS')) {
    define('DS', DIRECTORY_SEPARATOR);
}

/**
 * 启动插件系统：注册路由 + 事件钩子，由 AppInit 中间件在 App 初始化后调用。
 */
function addons_boot(): void
{
    static $booted = false;
    if ($booted) {
        return;
    }
    $booted = true;

    \think\facade\Event::trigger('addon_init');

    $autoload = (bool)config('addons.autoload', false);
    if ($autoload) {
        $config = app()->isDebug() ? [] : \think\facade\Cache::get('addons', []);
        if (empty($config)) {
            $config = get_addon_autoload_config();
            \think\facade\Cache::set('addons', $config);
        }

        $hooks = app()->isDebug() ? [] : \think\facade\Cache::get('hooks', []);
        if (empty($hooks)) {
            $hooks = (array)config('addons.hooks');
            foreach ($hooks as $key => $values) {
                if (is_string($values)) {
                    $values = explode(',', $values);
                }
                $hooks[$key] = array_filter(array_map('get_addon_class', (array)$values));
            }
            \think\facade\Cache::set('hooks', $hooks);
        }

        // 注册 addon 路由（TP8: 用 append() 传参，不用 ?k=v 查询串）
        $routeArr = (array)config('addons.route');
        foreach ($routeArr as $k => $v) {
            if (is_array($v)) {
                $addon   = $v['addon'];
                $domain  = $v['domain'];
                $drules  = [];
                foreach ($v['rule'] as $m => $n) {
                    [$addonN, $ctrlN, $actN] = explode('/', $n);
                    $drules[$m] = function () use ($addonN, $ctrlN, $actN) {
                        return (new \think\addons\Route())->execute($addonN, $ctrlN, $actN, true);
                    };
                }
                \think\facade\Route::domain($domain, function () use ($drules, $addon) {
                    foreach ($drules as $pattern => $closure) {
                        \think\facade\Route::any($pattern, $closure);
                    }
                    \think\facade\Route::any('<controller?>/<action?>', '\\think\\addons\\Route@execute')
                        ->append(['addon' => $addon, 'indomain' => 1]);
                });
            } else {
                if (!$v) {
                    continue;
                }
                [$addonN, $ctrlN, $actN] = explode('/', $v);
                \think\facade\Route::any($k, '\\think\\addons\\Route@execute')
                    ->append(['addon' => $addonN, 'controller' => $ctrlN, 'action' => $actN]);
            }
        }

        // 先注册监听器，再触发 app_init（顺序颠倒会导致 app_init 无人接收）
        foreach ($hooks as $hookName => $listeners) {
            foreach ((array)$listeners as $listener) {
                if ($listener) {
                    \think\facade\Event::listen($hookName, $listener);
                }
            }
        }
        if (isset($hooks['app_init'])) {
            foreach ($hooks['app_init'] as $listener) {
                \think\facade\Event::trigger('app_init', $listener);
            }
        }
    }

    // 注册 addons 默认路由（TP8 可选参数用 <param?> 语法）
    \think\facade\Route::any('addons/<addon>/<controller?>/<action?>', "\\think\\addons\\Route@execute");
}

/**
 * 触发插件钩子（兼容原 hook() 调用）
 */
function hook(string $hook, $params = []): void
{
    \think\facade\Event::trigger($hook, $params);
}

function remove_empty_folder(string $dir): void
{
    try {
        $isDirEmpty = !(new \FilesystemIterator($dir))->valid();
        if ($isDirEmpty) {
            @rmdir($dir);
            remove_empty_folder(dirname($dir));
        }
    } catch (\Exception $e) {
    }
}

function get_addon_list(): array
{
    $results = scandir(ADDON_PATH);
    $list    = [];
    foreach ($results as $name) {
        if ($name === '.' || $name === '..') {
            continue;
        }
        if (is_file(ADDON_PATH . $name)) {
            continue;
        }
        $addonDir = ADDON_PATH . $name . DS;
        if (!is_dir($addonDir)) {
            continue;
        }
        if (!is_file($addonDir . ucfirst($name) . '.php')) {
            continue;
        }
        $info_file = $addonDir . 'info.ini';
        if (!is_file($info_file)) {
            continue;
        }
        $info = parse_ini_file($info_file, true) ?: [];
        if (!isset($info['name'])) {
            continue;
        }
        $info['url'] = addon_url($name);
        $list[$name] = $info;
    }
    return $list;
}

function get_addon_autoload_config(bool $truncate = false): array
{
    $config = (array)config('addons');
    if ($truncate) {
        $config['hooks'] = [];
    }

    $priority = isset($config['priority']) && $config['priority']
        ? (is_array($config['priority']) ? $config['priority'] : explode(',', $config['priority']))
        : [];

    $route   = [];
    $base    = get_class_methods('\\think\\Addons');
    $base    = array_merge($base, ['install', 'uninstall', 'enable', 'disable']);
    $addons  = get_addon_list();
    $domain  = [];

    $priority = array_merge($priority, array_keys($addons));
    $orderedAddons = [];
    foreach ($priority as $key) {
        if (!isset($addons[$key])) {
            continue;
        }
        $orderedAddons[$key] = $addons[$key];
    }

    foreach ($orderedAddons as $name => $addon) {
        if (!$addon['state']) {
            continue;
        }
        $methods = (array)get_class_methods('\\addons\\' . $name . '\\' . ucfirst($name));
        $hooks   = array_diff($methods, $base);
        foreach ($hooks as $hook) {
            // 保持原始方法名（snake_case），与 Event::trigger() 保持一致
            if (!isset($config['hooks'][$hook])) {
                $config['hooks'][$hook] = [];
            }
            if (is_string($config['hooks'][$hook])) {
                $config['hooks'][$hook] = explode(',', $config['hooks'][$hook]);
            }
            if (!in_array($name, $config['hooks'][$hook])) {
                $config['hooks'][$hook][] = $name;
            }
        }
        $conf = get_addon_config($addon['name']);
        if ($conf) {
            $conf['rewrite'] = isset($conf['rewrite']) && is_array($conf['rewrite']) ? $conf['rewrite'] : [];
            $rule = array_map(fn($value) => "{$addon['name']}/{$value}", array_flip($conf['rewrite']));
            if (isset($conf['domain']) && $conf['domain']) {
                $domain[] = [
                    'addon'  => $addon['name'],
                    'domain' => $conf['domain'],
                    'rule'   => $rule,
                ];
            } else {
                $route = array_merge($route, $rule);
            }
        }
    }
    $config['route'] = array_merge($route, $domain);
    return $config;
}

function get_addon_class(string $name, string $type = 'hook', ?string $class = null): string
{
    $name  = strtolower($name);
    $class = is_null($class) ? ucfirst($name) : ucfirst($class);
    if (strpos((string)$class, '.') !== false) {
        $classParts = explode('.', $class);
        $classParts[count($classParts) - 1] = ucfirst(end($classParts));
        $class = implode('\\', $classParts);
    }
    $namespace = match($type) {
        'controller' => "\\addons\\{$name}\\controller\\{$class}",
        default      => "\\addons\\{$name}\\{$class}",
    };
    return class_exists($namespace) ? $namespace : '';
}

function get_addon_info(string $name): array
{
    $addon = get_addon_instance($name);
    return $addon ? $addon->getInfo($name) : [];
}

function get_addon_fullconfig(string $name): array
{
    $addon = get_addon_instance($name);
    return $addon ? $addon->getFullConfig($name) : [];
}

function get_addon_config(string $name): array
{
    $addon = get_addon_instance($name);
    return $addon ? $addon->getConfig($name) : [];
}

function get_addon_instance(string $name): ?\think\Addons
{
    static $_addons = [];
    if (isset($_addons[$name])) {
        return $_addons[$name];
    }
    $class = get_addon_class($name);
    if ($class && class_exists($class)) {
        $_addons[$name] = new $class();
        return $_addons[$name];
    }
    return null;
}

function addon_url(string $url, array $vars = [], bool $suffix = true, bool $domain = false): string
{
    $url  = ltrim($url, '/');
    $val  = '@addons/' . $url;
    $addon = substr($url, 0, stripos($url, '/') ?: strlen($url));
    $config = get_addon_config($addon);
    $rewrite = $config && isset($config['rewrite']) && $config['rewrite'] ? $config['rewrite'] : [];
    if ($rewrite) {
        $path = substr($url, stripos($url, '/') + 1);
        if (isset($rewrite[$path]) && $rewrite[$path]) {
            $val = $rewrite[$path];
            array_walk($vars, function ($value, $key) use (&$val) {
                $val = str_replace("[{$key}]", $value, $val);
            });
            $val    = str_replace(['^', '$'], '', $val);
            $suffix = substr($val, -1) !== '/';
        }
    }
    $built = url($val, [], $suffix, $domain);
    return preg_replace("/\/((?!index)[\w]+)\.php\//i", "/", (string)$built)
        . ($vars ? '?' . http_build_query($vars) : '');
}

function set_addon_info(string $name, array $array): bool
{
    $file  = ADDON_PATH . $name . DS . 'info.ini';
    $addon = get_addon_instance($name);
    if (!$addon) {
        throw new \Exception('addon not found: ' . $name);
    }
    $array = $addon->setInfo($name, $array);
    if (!isset($array['name']) || !isset($array['title']) || !isset($array['version'])) {
        throw new \Exception('插件配置写入失败');
    }
    $res = [];
    foreach ($array as $key => $val) {
        if (is_array($val)) {
            $res[] = "[$key]";
            foreach ($val as $skey => $sval) {
                $res[] = "$skey = " . (is_numeric($sval) ? $sval : $sval);
            }
        } else {
            $res[] = "$key = " . (is_numeric($val) ? $val : $val);
        }
    }
    if ($handle = fopen($file, 'w')) {
        fwrite($handle, implode("\n", $res) . "\n");
        fclose($handle);
        \think\facade\Config::set($name . '.addoninfo', null);
        return true;
    }
    throw new \Exception('文件没有写入权限');
}

function set_addon_config(string $name, array $config, bool $writefile = true): bool
{
    $addon = get_addon_instance($name);
    if (!$addon) {
        throw new \Exception('addon not found: ' . $name);
    }
    $addon->setConfig($name, $config);
    if ($writefile) {
        $fullconfig = get_addon_fullconfig($name);
        foreach ($fullconfig as $k => &$v) {
            if (isset($config[$v['name']])) {
                $v['value'] = $v['type'] !== 'array' && is_array($config[$v['name']])
                    ? implode(',', $config[$v['name']]) : $config[$v['name']];
            }
        }
        unset($v);
        set_addon_fullconfig($name, $fullconfig);
    }
    return true;
}

function set_addon_fullconfig(string $name, array $array): bool
{
    $file = ADDON_PATH . $name . DS . 'config.php';
    if (!is_writable($file)) {
        throw new \Exception('文件没有写入权限');
    }
    if ($handle = fopen($file, 'w')) {
        fwrite($handle, "<?php\n\nreturn " . var_export($array, true) . ";\n");
        fclose($handle);
        return true;
    }
    throw new \Exception('文件没有写入权限');
}
