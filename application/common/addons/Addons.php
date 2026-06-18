<?php
namespace think;

use think\facade\Cache;
use think\facade\Config;

/**
 * 插件基类（内化自 fastadmin-addons，保持 think\Addons 命名空间以兼容现有插件）
 */
abstract class Addons
{
    protected $error         = '';
    public    $addons_path   = '';
    protected $configRange   = 'addonconfig';
    protected $infoRange     = 'addoninfo';

    public function __construct()
    {
        $name              = $this->getName();
        // 路径使用小写目录名（Linux 文件系统大小写敏感）
        $this->addons_path = ADDON_PATH . strtolower($name) . DS;

        // 不在构造函数中调用 View::config()：
        // 其会改写单例驱动的全局 view_path，污染主应用后续所有模板渲染。
        // 需要自定义视图路径的插件控制器请在 render 时单独配置。

        if (method_exists($this, '_initialize')) {
            $this->_initialize();
        }
    }

    final public function getInfo(string $name = ''): array
    {
        if (empty($name)) {
            $name = $this->getName();
        }
        $info = Config::get($name . '.' . $this->infoRange) ?: [];
        if (empty($info)) {
            $file = ADDON_PATH . $name . DS . 'info.ini';
            if (is_file($file)) {
                $info = parse_ini_file($file, true) ?: [];
            }
        }
        return $info;
    }

    final public function getConfig(string $name = ''): array
    {
        if (empty($name)) {
            $name = $this->getName();
        }
        $config = [];
        $file   = ADDON_PATH . $name . DS . 'config.php';
        if (is_file($file)) {
            $cfg = include $file;
            if (is_array($cfg)) {
                foreach ($cfg as $item) {
                    if (isset($item['name'], $item['value'])) {
                        $config[$item['name']] = $item['value'];
                    }
                }
            }
        }
        return $config;
    }

    final public function getFullConfig(string $name = ''): array
    {
        if (empty($name)) {
            $name = $this->getName();
        }
        $file = ADDON_PATH . $name . DS . 'config.php';
        return is_file($file) ? (include $file ?: []) : [];
    }

    final public function setConfig(string $name = '', array $config = []): bool
    {
        if (empty($name)) {
            $name = $this->getName();
        }
        Config::set($name . '.' . $this->configRange, $config);
        return true;
    }

    final public function setInfo(string $name = '', array $array = []): array
    {
        if (empty($name)) {
            $name = $this->getName();
        }
        Config::set($name . '.' . $this->infoRange, $array);
        return $array;
    }

    final public function getName(): string
    {
        $class = get_class($this);
        $parts = explode('\\', $class);
        return $parts[count($parts) - 1] ?? '';
    }

    public function getError(): string
    {
        return $this->error;
    }

    abstract public function install(): bool;
    abstract public function uninstall(): bool;
    abstract public function enable(): bool;
    abstract public function disable(): bool;
}
