<?php
/**
 * 权限节点归一回归测试。
 *
 * 背景:权限节点的权威形态存在 application/admin/common/auth.php
 * (controller = URL 段 snake,action = 方法原名),后台勾选框原样提交、原样入库。
 * 但 check_auth 有两处调用方,形态不同:
 *   (a) 菜单渲染 —— 传 auth.php 原值(resource_hub / multiCollect);
 *   (b) 真实请求 —— 传 request()->controller()(Str::studly 后的 ResourceHub)与 URL 原样动作名。
 * 两侧必须都能命中同一条存库记录,否则子管理员会被静默拒绝(超管 admin_id=='1'
 * 直接放行,所以后台里看不出来)。
 *
 * 用法:  php tests/auth_nodes.php
 * 退出码:0 全绿;1 存在误拒 / 越权泄漏 / 超管被拒。
 * 无需数据库。
 */

$root = dirname(__DIR__) . '/';
define('ROOT_PATH',      $root);
define('APP_PATH',       $root . 'application/');
define('RUNTIME_PATH',   $root . 'runtime/');
define('ADDON_PATH',     $root . 'addons/');
define('MAC_COMM',       $root . 'application/common/common/');
define('MAC_HOME_COMM',  $root . 'application/index/common/');
define('MAC_ADMIN_COMM', $root . 'application/admin/common/');
define('MAC_START_TIME', microtime(true));
define('ENTRANCE',       'admin');
define('DS',             DIRECTORY_SEPARATOR);
define('EXT',            '.php');
define('IN_FILE',        '/admin.php');

require $root . 'vendor/autoload.php';

$app = new \app\MacApp(ROOT_PATH);
$app->setAppPath(APP_PATH);
$app->initialize();

$nodes = [];
$tree  = include APP_PATH . 'admin/common/auth.php';
$walk  = function (array $arr) use (&$walk, &$nodes) {
    foreach ($arr as $v) {
        if (!is_array($v)) {
            continue;
        }
        if (isset($v['controller'], $v['action'])) {
            $nodes[] = $v['controller'] . '/' . $v['action'];
        }
        if (isset($v['sub']) && is_array($v['sub'])) {
            $walk($v['sub']);
        }
    }
};
$walk($tree);
$nodes = array_values(array_unique($nodes));

$ref = new ReflectionClass(\app\admin\controller\Base::class);
$prop = $ref->getProperty('_admin');
$prop->setAccessible(true);

/** 造一个只被授予 $granted 一个节点的子管理员(admin_id != 1) */
$subAdmin = function (string $granted) use ($ref, $prop) {
    $o = $ref->newInstanceWithoutConstructor();
    $prop->setValue($o, ['admin_id' => '7', 'admin_auth' => ',' . $granted . ',']);
    return $o;
};

$failMenu = [];
$failReq  = [];
foreach ($nodes as $node) {
    [$c, $a] = explode('/', $node, 2);
    $o = $subAdmin($node);
    if (!$o->check_auth($c, $a)) {                              // (a) 菜单形态
        $failMenu[] = $node;
    }
    if (!$o->check_auth(\think\helper\Str::studly($c), $a)) {    // (b) 请求形态
        $failReq[] = $node;
    }
}

// 越权负例:只授予一个节点,访问其它节点必须被拒
$leak = [];
$o = $subAdmin('resource_hub/multiCollect');
foreach (['vod/del', 'admin/del', 'system/info', 'resource_hub/poster', 'database/import'] as $other) {
    [$c, $a] = explode('/', $other, 2);
    if ($o->check_auth(\think\helper\Str::studly($c), $a)) {
        $leak[] = $other;
    }
}

// 超管必须仍然全通
$sup = $ref->newInstanceWithoutConstructor();
$prop->setValue($sup, ['admin_id' => '1', 'admin_auth' => '']);
$supOk = $sup->check_auth('ResourceHub', 'multiCollect');

$bad = count($failMenu) + count($failReq) + count($leak) + ($supOk ? 0 : 1);
printf("权限节点 %d 个\n", count($nodes));
printf("  菜单形态被误拒 : %d%s\n", count($failMenu), $failMenu ? ' -> ' . implode(', ', $failMenu) : '');
printf("  请求形态被误拒 : %d%s\n", count($failReq), $failReq ? ' -> ' . implode(', ', $failReq) : '');
printf("  越权泄漏       : %d%s\n", count($leak), $leak ? ' -> ' . implode(', ', $leak) : '');
printf("  超管全通       : %s\n", $supOk ? 'YES' : 'NO');
echo $bad ? "auth nodes FAILED\n" : "auth nodes OK\n";
exit($bad ? 1 : 0);
