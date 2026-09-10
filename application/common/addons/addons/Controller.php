<?php
namespace think\addons;

use think\Request;
use think\exception\HttpResponseException;
use think\view\driver\Think;

/** Minimal controller contract used by the bundled addon controllers. */
class Controller
{
    protected Request $request;
    private array $viewData = [];

    public function __construct(?Request $request = null)
    {
        $this->request = $request ?? request();
        $this->_initialize();
    }

    protected function _initialize(): void
    {
    }

    protected function assign(string|array $name, $value = null): void
    {
        $this->viewData = array_merge($this->viewData, is_array($name) ? $name : [$name => $value]);
    }

    protected function fetch(string $template, array $vars = []): string
    {
        $parts = explode('\\', static::class);
        $addon = $parts[1] ?? '';
        if (!preg_match('/^[a-zA-Z0-9_]+$/D', $addon)) {
            throw new \RuntimeException('Invalid addon controller namespace.');
        }

        $config = (array) config('view');
        $config['view_path'] = ADDON_PATH . $addon . '/view/';
        // A separate driver prevents addon templates from replacing the main view path.
        $driver = new Think(app(), $config);
        $vars = array_merge($this->viewData, $vars);
        $vars['addonRoot'] = rtrim((string) config('maccms.site.install_dir', ''), '/');
        ob_start();
        try {
            $driver->fetch($template, $vars);
            return (string) ob_get_clean();
        } catch (\Throwable $e) {
            ob_end_clean();
            throw $e;
        }
    }

    protected function error(string $message): never
    {
        throw new HttpResponseException(json(['code' => 0, 'message' => $message], 400));
    }
}
