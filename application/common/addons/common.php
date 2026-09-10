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

        $hooks = (array)($config['hooks'] ?? []);

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
        $viewFilters = [];
        foreach ($hooks as $hookName => $listeners) {
            foreach (is_string($listeners) ? explode(',', $listeners) : (array)$listeners as $name) {
                $instance = is_string($name) ? get_addon_instance($name) : null;
                $method = \think\helper\Str::camel($hookName);
                if (!$instance || !is_callable([$instance, $method]) || empty($instance->getInfo()['state'])) {
                    continue;
                }
                $reflection = new \ReflectionMethod($instance, $method);
                if ($reflection->isStatic()) { continue; }
                $callback = static function ($params = null) use ($instance, $method, $reflection) {
                    $result = $reflection->getNumberOfParameters() === 0 ? $instance->$method() : $instance->$method($params);
                    return $result ?? $params;
                };
                \think\facade\Event::listen($hookName, $callback);
                if ($hookName === 'view_filter') { $viewFilters[] = $callback; }
            }
        }
        if ($viewFilters) {
            \think\facade\View::filter(static function (string $content) use ($viewFilters): string {
                foreach ($viewFilters as $filter) { $content = $filter($content); }
                return $content;
            });
        }
        \think\facade\Event::trigger('app_init', request());
    }

    // 注册 addons 默认路由（TP8 可选参数语法：param? 表示可选）
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
        if (!preg_match('/^[a-zA-Z0-9_]+$/D', $name) || is_link(ADDON_PATH . $name)) {
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
        if (!isset($info['name']) || $info['name'] !== $name) {
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
        if (empty($addon['state']) || (int)($addon['installed'] ?? 1) !== 1) {
            continue;
        }
        $class = get_addon_class($name);
        if ($class === '') { continue; }
        $methods = (array)get_class_methods($class);
        $hooks   = array_diff($methods, $base);
        foreach ($hooks as $hook) {
            $method = new \ReflectionMethod($class, $hook);
            if ($method->isStatic() || str_starts_with($hook, '_')) { continue; }
            $hook = \think\helper\Str::snake($hook);
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
    if (!preg_match('/^[a-zA-Z0-9_]+$/D', $name)
        || ($class !== null && !preg_match('/^[a-zA-Z0-9_]+(?:\.[a-zA-Z0-9_]+)*$/D', $class))) {
        return '';
    }
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
    $name = \think\addons\Service::validateName($name);
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
                $res[] = "$skey = " . addons_ini_value($sval);
            }
        } else {
            $res[] = "$key = " . addons_ini_value($val);
        }
    }
    addons_atomic_write($file, implode("\n", $res) . "\n");
    \think\facade\Config::set(['addoninfo' => null], $name);
    return true;
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
    $name = \think\addons\Service::validateName($name);
    $file = ADDON_PATH . $name . DS . 'config.php';
    if (!is_writable($file)) {
        throw new \Exception('文件没有写入权限');
    }
    addons_atomic_write($file, "<?php\n\nreturn " . var_export($array, true) . ";\n");
    return true;
}

function addons_ini_value($value): string
{
    if (!is_scalar($value) && $value !== null) { throw new \RuntimeException('Invalid plugin metadata value'); }
    $value = (string)$value;
    if (strpbrk($value, "\r\n\0") !== false) { throw new \RuntimeException('Plugin metadata cannot contain newlines'); }
    return '"' . addcslashes($value, '\\"') . '"';
}

function addons_atomic_write(string $file, string $content): void
{
    if (is_link($file)) { throw new \RuntimeException('Refusing to replace a linked plugin configuration'); }
    $temporary = tempnam(dirname($file), '.addon-');
    if ($temporary === false) { throw new \RuntimeException('Cannot create plugin configuration'); }
    try {
        if (file_put_contents($temporary, $content, LOCK_EX) !== strlen($content)
            || !chmod($temporary, is_file($file) ? fileperms($file) & 0777 : 0640)
            || !rename($temporary, $file)) {
            throw new \RuntimeException('Cannot save plugin configuration');
        }
        if (function_exists('opcache_invalidate')) { opcache_invalidate($file, true); }
    } finally {
        if (is_file($temporary)) { unlink($temporary); }
    }
}
