<?php
namespace think;

use think\facade\Cache;
use think\facade\Config;
use think\facade\View;

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
        $name             = $this->getName();
        $this->addons_path = ADDON_PATH . $name . DS;

        $config = ['view_path' => $this->addons_path];
        $config = array_merge(config('view') ?: [], $config);
        View::config($config);

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
