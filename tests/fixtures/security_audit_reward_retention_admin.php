<?php
/** Isolate only the admin shell; execute real list/delete actions, ORM and table templates. */
namespace app\admin\controller {
    class Base {
        protected $_pagesize = 20;
        private array $assigned = [];
        public function assign($key, $value) { $this->assigned[$key] = $value; }
        public function fetch($template) { return ['template'=>$template, 'data'=>$this->assigned]; }
        public function error($message) { return ['code'=>0, 'msg'=>$message]; }
    }
}
namespace {
    function url($path, $parameters = []) { return '/'.$path.($parameters ? '?'.http_build_query($parameters) : ''); }
    function mac_filter_xss($value) { return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
    function mac_get_mid_text($mid) { return $mid == 11 ? 'website' : 'user'; }
    function mac_day($time, $style = '') { return date('Y-m-d H:i:s', (int)$time); }

    function retentionAdmin(string $controller, string $action, array $parameters = [], string $method = 'GET'): array {
        $request = (new \think\Request())->withServer(['REQUEST_METHOD'=>$method]);
        $request = $method === 'POST' ? $request->withPost($parameters) : $request->withGet($parameters);
        \think\Container::getInstance()->instance('request', $request);
        $instance = (new \ReflectionClass('app\\admin\\controller\\'.$controller))->newInstanceWithoutConstructor();
        return $instance->$action();
    }

    function retentionRender(array $page): string {
        $path = match ($page['template']) {
            'admin@task/log' => 'task/log.html',
            'admin@visit/index' => 'visit/index.html',
        };
        $content = file_get_contents(dirname(__DIR__, 2).'/application/admin/view/'.$path);
        // Shared layout needs an authenticated full app. The actual table, filters and pagination remain intact.
        $content = str_replace([
            '{include file="../../../application/admin/view/public/head" /}',
            '{include file="../../../application/admin/view/public/foot" /}',
        ], '', $content);
        $temporary = audit_temp_dir('reward-retention-template');
        $level = ob_get_level();
        try {
            $template = new \think\Template(['cache_path'=>$temporary.'/', 'tpl_cache'=>false, 'default_filter'=>'']);
            ob_start();
            $template->display($content, $page['data']);
            return ob_get_clean();
        } finally {
            while (ob_get_level() > $level) { ob_end_clean(); }
            audit_remove_temp($temporary);
        }
    }

    function retentionReadOnlyPage(string $html, string $scope): void {
        check(str_contains($html, '仅供查阅') && str_contains($html, '保留'), $scope.' retention policy is absent');
        check(!str_contains($html, 'type="checkbox"') && !str_contains($html, 'name="ids[]"'), $scope.' still exposes record selection');
        check(!str_contains($html, 'data-href=') && !str_contains($html, 'all=1') && !str_contains($html, 'j-tr-del'), $scope.' still exposes destructive actions');
        check(str_contains($html, 'j-search') && str_contains($html, 'laypage.render'), $scope.' lost search or pagination');
    }
}
