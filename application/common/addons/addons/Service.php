<?php
namespace think\addons;

use think\facade\Cache;
use think\facade\Config;

/** Lifecycle operations for reviewed plugins already present on local disk. */
class Service
{
    public static function validateName($name): string
    {
        if (!is_string($name) || !preg_match('/^[a-zA-Z0-9_]+$/D', $name)) {
            throw new AddonException('插件名称无效');
        }
        return strtolower($name);
    }

    private static function localAddon(string $name): \think\Addons
    {
        $base = realpath(ADDON_PATH);
        $directory = ADDON_PATH . $name;
        $actual = realpath($directory);
        if ($base === false || $actual === false || is_link($directory)
            || !str_starts_with($actual . DIRECTORY_SEPARATOR, $base . DIRECTORY_SEPARATOR)) {
            throw new AddonException('仅支持安装已部署到本地 addons 目录的插件；在线下载已停用');
        }
        foreach ([ucfirst($name) . '.php', 'info.ini', 'config.php'] as $file) {
            if (is_link($directory . '/' . $file)) {
                throw new AddonException('插件入口或配置不能是符号链接');
            }
        }
        $addon = get_addon_instance($name);
        if (!$addon || !$addon->getInfo($name)) {
            throw new AddonException('本地插件缺少有效入口或 info.ini');
        }
        return $addon;
    }

    public static function install($name, $force = false, array $extend = []): void
    {
        $name = self::validateName($name);
        $addon = self::localAddon($name);
        if (!$addon->install() || !$addon->enable()) {
            throw new AddonException($addon->getError() ?: '插件安装失败');
        }
        self::saveState($name, 1, 1);
    }

    public static function uninstall($name, $force = false): void
    {
        $name = self::validateName($name);
        $addon = self::localAddon($name);
        if (!$addon->disable() || !$addon->uninstall()) {
            throw new AddonException($addon->getError() ?: '插件卸载失败');
        }
        // Keep reviewed source files so reinstall does not require a remote download.
        self::saveState($name, 0, 0);
    }

    public static function enable($name, $force = false): void
    {
        self::changeState($name, true);
    }

    public static function disable($name, $force = false): void
    {
        self::changeState($name, false);
    }

    private static function changeState($name, bool $enabled): void
    {
        $name = self::validateName($name);
        $addon = self::localAddon($name);
        if ($enabled && (int)($addon->getInfo($name)['installed'] ?? 1) !== 1) {
            throw new AddonException('请先安装此本地插件');
        }
        $method = $enabled ? 'enable' : 'disable';
        if (!$addon->$method()) {
            throw new AddonException($addon->getError() ?: '插件状态更新失败');
        }
        self::saveState($name, (int)$enabled);
    }

    private static function saveState(string $name, int $state, ?int $installed = null): void
    {
        $info = get_addon_info($name);
        $info['state'] = $state;
        if ($installed !== null) { $info['installed'] = $installed; }
        set_addon_info($name, $info);
        self::refresh();
    }

    public static function refresh(): void
    {
        $config = get_addon_autoload_config(true);
        $config['autoload'] = !empty($config['hooks']);
        $file = APP_PATH . 'extra/addons.php';
        addons_atomic_write($file, "<?php\nreturn " . var_export($config, true) . ";\n");
        Config::set($config, 'addons');
        Cache::delete('addons');
        Cache::delete('hooks');
        Cache::delete('__menu__');
    }

    public static function upgrade($name, array $extend = []): void
    {
        self::validateName($name);
        throw new AddonException('在线插件更新已停用，请部署审核后的插件文件后重新安装');
    }
}
