<?php
namespace app\command;

use think\console\Command;
use think\console\Input;
use think\console\input\Option;
use think\console\Output;
use think\facade\Config;

/**
 * 结构自检:专抓「不报错、只是安静地不对」的那一类缺陷。
 *
 *   php think mac:selfcheck [--json] [--strict]
 *
 * 为什么需要它
 * ------------
 * TP5 → TP8 迁移期连续踩到三个同型缺陷,共同特征是**全程零报错**,
 * 只能靠人肉发现,平均潜伏数周:
 *
 *   1. session.path 留空 → File 驱动回落到 $app->getRuntimePath(),
 *      而多应用模式下该路径按应用分 → 前台写的验证码后台读不到,
 *      表现为「验证码怎么输都是错的」。
 *   2. view.default_filter 未声明 → 继承 think-template 的包内默认值
 *      'htmlentities' → 全站模板变量被转义,装 HTML 的地方源码外泄。
 *      (TP5 时代该键设在 application/config.php,TP8 根本不加载那个文件)
 *   3. admin/common/auth.php 里一个菜单项漏写数组键 → 自动取
 *      max(int key)+1,被紧随其后的显式同号键覆盖 → 整项在 include
 *      瞬间消失,菜单里找不到,但直接访问 URL 又是通的。
 *
 * 逐个去抓是抓不完的。本命令把这一类变「响」:全部检查都是静态的,
 * 不需要 HTTP、不需要会话、不需要凭据,可以进 CI 和发布前门禁。
 * 有 FAIL 时退出码非 0。
 */
class SelfCheck extends Command
{
    /** @var array<int,array{level:string,scope:string,msg:string,fix:string}> */
    private array $issues = [];

    protected function configure()
    {
        $this->setName('mac:selfcheck')
            ->setDescription('结构自检:配置基线 / 菜单完整性 / 语言键覆盖 / extra 加载桩 / 模板转义回归')
            ->addOption('json', null, Option::VALUE_NONE, '以 JSON 输出,供 CI 消费')
            ->addOption('strict', null, Option::VALUE_NONE, '把 WARN 也算作失败(退出码非 0)');
    }

    protected function execute(Input $input, Output $output)
    {
        $this->checkUpdateHash();
        $this->checkConfigBaseline();
        $this->checkMenuIntegrity();
        $this->checkLangParity();
        $this->checkExtraStubs();
        $this->checkTemplateEscapeRegression();
        $this->checkPlayerFiles();

        $fails = array_filter($this->issues, fn($i) => $i['level'] === 'FAIL');
        $warns = array_filter($this->issues, fn($i) => $i['level'] === 'WARN');

        if ($input->hasOption('json') && $input->getOption('json')) {
            $output->writeln(json_encode([
                'ok'     => count($fails) === 0,
                'fail'   => count($fails),
                'warn'   => count($warns),
                'issues' => array_values($this->issues),
            ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT));
        } else {
            if (empty($this->issues)) {
                $output->writeln('<info>全部通过。</info>');
            } else {
                foreach ($this->issues as $i) {
                    $tag = $i['level'] === 'FAIL' ? '<error>FAIL</error>' : '<comment>WARN</comment>';
                    $output->writeln($tag . '  [' . $i['scope'] . '] ' . $i['msg']);
                    if ($i['fix'] !== '') {
                        $output->writeln('        修复: ' . $i['fix']);
                    }
                }
                $output->writeln('');
            }
            $output->writeln(sprintf('FAIL %d,WARN %d', count($fails), count($warns)));
        }

        $strict = $input->hasOption('strict') && $input->getOption('strict');
        return (count($fails) > 0 || ($strict && count($warns) > 0)) ? 1 : 0;
    }

    private function add(string $level, string $scope, string $msg, string $fix = ''): void
    {
        $this->issues[] = ['level' => $level, 'scope' => $scope, 'msg' => $msg, 'fix' => $fix];
    }

    // ------------------------------------------------------------------
    // 0. update_hash 完整性
    //
    // application/admin/controller/Base.php 在构造函数里比对
    // config('version.update_hash') 与 md5_file(admin/controller/Update.php)，
    // 不一致就 exit(lang('admin/update/core_file_error')) —— 【整个后台连同登录页全部打不开】。
    // 这个坑已经发生过两次，两次都是改完 Update.php 忘了同步 version.php，
    // 而且两次都是等站长打不开后台才发现：PHP 语法检查过、部署脚本全绿、
    // 冒烟只测前台也全绿，没有任何一件仪器覆盖它。放在所有检查的最前面。
    // ------------------------------------------------------------------
    private function checkUpdateHash(): void
    {
        $file = $this->appPath() . 'admin/controller/Update.php';
        if (!is_file($file)) {
            return;
        }
        $expected = (string)(\think\facade\Config::get('version.update_hash') ?? '');
        if ($expected === '') {
            return;   // 未启用该校验
        }
        $actual = md5_file($file);
        if ($expected !== $actual) {
            $this->add('FAIL', 'update_hash', sprintf(
                'version.update_hash (%s) 与 Update.php 的实际 md5 (%s) 不一致 —— '
                . '部署上去后 Base::__construct 会 exit，整个后台连同登录页全部打不开。',
                $expected, $actual
            ), "把 application/extra/version.php 的 update_hash 改成 {$actual}");
        }
    }

    // ------------------------------------------------------------------
    // 1. 配置基线
    //
    // 只收录「maccms 依赖的值 ≠ 框架/扩展包的默认值」的键。这类键一旦在
    // config/ 下漏声明,就会静默继承包内默认值,而不是报错。
    // ------------------------------------------------------------------
    private function checkConfigBaseline(): void
    {
        // view.default_filter:包内默认 'htmlentities',maccms 整套模板按不转义编写
        $df = Config::get('view.default_filter');
        if ($df !== '') {
            $this->add('FAIL', 'config', sprintf(
                "view.default_filter 当前为 %s,必须是空串。think-template 的包内默认值是 'htmlentities',"
                . '一旦继承,全站 {$var} 都会被转义:装 HTML 的变量会把源码打到页面上,'
                . '装文本的会冒出 &quot; &amp; &#039;,<script> 里的字符串还会直接坏掉。',
                var_export($df, true)
            ), "在 config/view.php 里显式写 'default_filter' => ''");
        }

        // session.path:留空则 File 驱动回落到 $app->getRuntimePath(),多应用下按应用分裂
        $sp = (string)Config::get('session.path');
        if ($sp === '') {
            $this->add('FAIL', 'config',
                'session.path 为空。TP8 的 File 会话驱动会回落到 $app->getRuntimePath(),'
                . '而 think-multi-app 下该路径按应用分 —— 同一个 PHPSESSID 会写成两份互不可见的文件,'
                . '跨应用的会话数据(验证码答案、登录态)全部失效。',
                "在 config/session.php 里指定一个跨应用共享的绝对目录(不要填 '/',那会写进文件系统根目录)");
        } elseif ($sp === '/' || $sp === DIRECTORY_SEPARATOR) {
            $this->add('FAIL', 'config',
                "session.path 被设成了 '/'。这是 file 驱动的**存储目录**,不是 cookie 路径 —— "
                . '会话会写进文件系统根目录,且 GC 从 / 递归扫盘,引发间歇 500。',
                '改成站点内的绝对目录,例如 runtime/session/');
        } else {
            // 落盘验证:运行期是否真的只有一个会话目录
            $rt = defined('RUNTIME_PATH') ? RUNTIME_PATH : (defined('ROOT_PATH') ? ROOT_PATH . 'runtime/' : '');
            if ($rt !== '' && is_dir($rt)) {
                $dirs = glob($rt . '*/session', GLOB_ONLYDIR) ?: [];
                if ($dirs) {
                    $this->add('WARN', 'config',
                        '发现按应用分裂的会话目录: ' . implode(', ', array_map(fn($d) => str_replace($rt, '', $d), $dirs))
                        . '。session.path 已配置,这些多半是改配置之前的残留。',
                        '清空 runtime/ 后复查;若改完仍在生成,说明有代码在运行期覆盖了 session.path');
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // 2. 菜单完整性
    //
    // 核心是「源码里写了 N 项,include 之后只剩 M 项」的键覆盖检测 ——
    // PPVOD 菜单项就是这么整项消失的,零报错。
    // ------------------------------------------------------------------
    private function checkMenuIntegrity(): void
    {
        $file = $this->appPath() . 'admin/common/auth.php';
        if (!is_file($file)) {
            $this->add('WARN', 'menu', "找不到 {$file}");
            return;
        }

        $src = (string)file_get_contents($file);
        // 源码里声明了多少个菜单项(以 'action' => 为准,注释行不算)
        $declared = 0;
        foreach (explode("\n", $src) as $line) {
            $t = ltrim($line);
            if ($t !== '' && $t[0] !== '/' && $t[0] !== '*' && preg_match("/'action'\s*=>/", $t)) {
                $declared++;
            }
        }

        $menus = @include $file;
        if (!is_array($menus)) {
            $this->add('FAIL', 'menu', 'auth.php 未返回数组');
            return;
        }

        // show=1 是可见菜单项(点不开就是用户可见的故障);
        // show=0 只是权限树节点,指向已废弃动作时只是噪音,不算故障。
        // 计数与去重必须分开:同一个路由可以合法地在权限树里出现多次
        // (菜单一份、权限节点一份),按路由做键会把它们并成一条,
        // 拿去和源码声明数比就会误报「丢失」。
        $loaded    = [];
        $loadedCnt = 0;
        $walk = function ($arr) use (&$walk, &$loaded, &$loadedCnt) {
            foreach ($arr as $v) {
                if (!is_array($v)) {
                    continue;
                }
                if (isset($v['action'], $v['controller'])) {
                    $loadedCnt++;
                    $route = $v['controller'] . '/' . $v['action'];
                    // 同一路由多处出现时,取「可见」的那次:可见菜单点不开才是用户可见故障
                    $loaded[$route] = max($loaded[$route] ?? 0, (int)($v['show'] ?? 0));
                }
                $walk($v);
            }
        };
        $walk($menus);

        if ($declared > $loadedCnt) {
            $this->add('FAIL', 'menu', sprintf(
                '菜单项在 include 时丢失:源码声明 %d 项,实际只加载到 %d 项。'
                . '本数组混用了显式整数键,任何一个漏写键的元素都会自动取「当前最大整数键 + 1」,'
                . '若紧随其后有同号的显式键,该项会被静默覆盖 —— 菜单里找不到,直接访问 URL 却是通的。',
                $declared, $loadedCnt
            ), 'grep 出 auth.php 里所有没有 "数字 =>" 前缀的 array(,给它们补上唯一显式键');
        }

        // 每个菜单项都要能落到真实的控制器动作上。
        //
        // 类名必须按 TP8 的规则推导:think\route\dispatch\Controller 用的是
        // Str::studly() —— 'sign_milestone' → 'SignMilestone'、'vodplayer' → 'Vodplayer'。
        // 两者规则不同,不能一律 ucfirst 或一律全小写。Linux 文件系统大小写敏感,
        // PSR-4 自动加载按类名找文件,差一个字母就是 404(而且是静默的:
        // 菜单渲染得出来,点进去才发现)。
        foreach ($loaded as $route => $show) {
            [$c, $a] = array_pad(explode('/', $route, 2), 2, '');
            $a = (string)strtok($a, '?');     // 菜单里存在 'index?ac2=wap' 这种带参写法
            if ($c === '' || $a === '') {
                continue;
            }
            $level = $show === 1 ? 'FAIL' : 'WARN';
            $tag   = $show === 1 ? '可见菜单项' : '权限节点';

            $cls  = 'app\\admin\\controller\\' . \think\helper\Str::studly($c);
            $file = $this->appPath() . 'admin/controller/' . \think\helper\Str::studly($c) . '.php';
            if (!is_file($file)) {
                // 找出仅大小写不同的邻居,直接把修法指出来
                $near = '';
                foreach (glob($this->appPath() . 'admin/controller/*.php') ?: [] as $p) {
                    if (strcasecmp(basename($p), basename($file)) === 0) {
                        $near = basename($p);
                        break;
                    }
                }
                $this->add($level, 'menu',
                    "{$tag} {$route} 解析不到控制器:TP8 按 Str::studly('{$c}') 找 "
                    . basename($file) . ($near !== '' ? "，而磁盘上是 {$near}(仅大小写不同)" : '，磁盘上没有对应文件'),
                    $near !== '' ? "把 {$near} 改名为 " . basename($file) . ' 并同步改类名' : '');
                continue;
            }
            if (class_exists($cls) && !method_exists($cls, $a)) {
                $this->add($level, 'menu', "{$tag} {$route} 指向的动作 {$cls}::{$a}() 不存在");
            }
        }
    }

    // ------------------------------------------------------------------
    // 3. 语言键覆盖:某个语言缺键时,界面会直接显示裸键名
    // ------------------------------------------------------------------
    private function checkLangParity(): void
    {
        $dir = $this->appPath() . 'lang/';
        $files = glob($dir . '*.php') ?: [];
        if (count($files) < 2) {
            return;
        }

        $sets = [];
        foreach ($files as $f) {
            $a = @include $f;
            if (is_array($a)) {
                $sets[basename($f)] = $a;
            }
        }
        if (!$sets) {
            return;
        }

        // 以键最全的那个语言为基准
        $baseName = array_keys($sets)[0];
        foreach ($sets as $n => $a) {
            if (count($a) > count($sets[$baseName])) {
                $baseName = $n;
            }
        }
        $base = array_keys($sets[$baseName]);

        foreach ($sets as $n => $a) {
            if ($n === $baseName) {
                continue;
            }
            $missing = array_diff($base, array_keys($a));
            // 只报菜单键:界面上直接可见,缺了就露出裸键名
            $menuMissing = array_values(array_filter($missing, fn($k) => strncmp($k, 'menu/', 5) === 0));
            if ($menuMissing) {
                $this->add('WARN', 'lang', sprintf(
                    '%s 相对 %s 缺 %d 个 menu/* 键(界面会显示裸键名): %s',
                    $n, $baseName, count($menuMissing),
                    implode(', ', array_slice($menuMissing, 0, 8)) . (count($menuMissing) > 8 ? ' …' : '')
                ));
            }
        }
    }

    // ------------------------------------------------------------------
    // 4. extra 加载桩
    //
    // 本 fork 靠 config/<name>.php 去 include application/extra/<name>.php。
    // 少一个桩,那份配置就永远不会被加载 —— 同样零报错。
    // 另外 middleware/Begin.php 有一份白名单,会删掉不在名单内的 extra 文件。
    // ------------------------------------------------------------------
    private function checkExtraStubs(): void
    {
        $extraDir = $this->appPath() . 'extra/';
        $confDir  = $this->rootPath() . 'config/';
        if (!is_dir($extraDir) || !is_dir($confDir)) {
            return;
        }

        $extras = array_map(fn($p) => basename($p, '.php'), glob($extraDir . '*.php') ?: []);
        $stubs  = array_map(fn($p) => basename($p, '.php'), glob($confDir . '*.php') ?: []);

        foreach ($extras as $name) {
            if (!in_array($name, $stubs, true)) {
                $this->add('WARN', 'extra', sprintf(
                    'application/extra/%s.php 没有 config/%s.php 加载桩,TP8 永远不会加载它。',
                    $name, $name
                ), "若确实需要,补一个 config/{$name}.php 桩;若已废弃,删掉以免误导");
            }
        }

        // Begin.php 的白名单:不在名单里的 extra 文件会被逐请求删除
        $begin = $this->appPath() . 'middleware/Begin.php';
        if (is_file($begin)) {
            $src = (string)file_get_contents($begin);
            if (preg_match('/allowedExtraFiles\s*=\s*\[(.*?)\]/s', $src, $m)) {
                preg_match_all("/'([^']+)'/", $m[1], $mm);
                $allowed = array_map(fn($s) => basename($s, '.php'), $mm[1] ?? []);
                foreach ($extras as $name) {
                    if ($allowed && !in_array($name, $allowed, true)) {
                        $this->add('FAIL', 'extra', sprintf(
                            'application/extra/%s.php 不在 Begin.php 的 allowedExtraFiles 白名单里,'
                            . '该中间件会在每次请求时把它删掉。',
                            $name
                        ), "把 {$name}.php 加进 Begin.php 的白名单");
                    }
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // 5. 模板转义回归
    //
    // default_filter 的静态断言在 (1) 里做了。这里补一条落盘证据:
    // 已编译的模板里不应出现 htmlentities( —— 出现即说明某次渲染时
    // 该配置没生效(例如 OPcache 还缓存着旧的 config/view.php)。
    // ------------------------------------------------------------------
    private function checkTemplateEscapeRegression(): void
    {
        $rt = defined('RUNTIME_PATH') ? RUNTIME_PATH : (defined('ROOT_PATH') ? ROOT_PATH . 'runtime/' : '');
        if ($rt === '' || !is_dir($rt)) {
            return;
        }

        $hits = 0;
        $sample = '';
        foreach (glob($rt . '*/temp/*.php') ?: [] as $f) {
            $s = (string)file_get_contents($f);
            if (strpos($s, 'echo htmlentities(') !== false) {
                $hits++;
                if ($sample === '') {
                    $sample = str_replace($rt, '', $f);
                }
            }
        }
        if ($hits > 0) {
            $this->add('FAIL', 'template', sprintf(
                '已编译模板里有 %d 个文件包含 "echo htmlentities(" (例: %s)。'
                . '说明渲染时 view.default_filter 并未生效 —— 常见原因是 OPcache 还缓存着旧的 config/view.php。',
                $hits, $sample
            ), '清空 runtime/ 并 reload php-fpm,然后复查');
        }
    }

    /**
     * static/player/ 下只允许存在【内置渲染器】文件。
     *
     * 背景：maccms 的播放器体系历史上支持「后台填一段 JS → 落盘成 <from>.js →
     * 在每个播放页 innerHTML 执行」，这是全站级注入面（被 FUNNULL 链滥用过）。
     * 治理后播放器一律配置化，static/player/ 只应有下面这几个随仓库版本化的内置文件。
     * 任何多出来的 .js 都是异常，两种可能都要拦：
     *   1) 有人（含被入侵后的后台）又往这里丢了自定义/恶意 JS —— 安全绊线；
     *   2) 换机迁移时带过来了本不该有的旧自定义播放器 —— 迁移完整性兜底
     *      （本次 155m3u8.js 漏迁那类问题的通用防线）。
     * 详见 docs/security/player-injection-hardening.md。
     */
    private function checkPlayerFiles(): void
    {
        $allow = [
            'dplayer.js', 'videojs.js', 'iva.js', 'iframe.js', 'link.js',
            'swf.js', 'flv.js', 'parse.js', 'mac-play-child-bridge.js',
        ];
        foreach (['static/player', 'static_new/player'] as $rel) {
            $dir = $this->rootPath() . $rel;
            if (!is_dir($dir)) {
                continue;
            }
            foreach (glob($dir . '/*.js') ?: [] as $p) {
                $name = basename($p);
                if (!in_array($name, $allow, true)) {
                    $this->add('FAIL', 'player', sprintf(
                        '%s/%s 不在内置播放器白名单内 —— 播放器已治理为纯配置，'
                        . '不允许在此目录放自定义 JS（既可能是注入，也可能是迁移漏带的旧文件）。',
                        $rel, $name
                    ), "确认来源后删除它；播放器请在后台用「解析接口地址(ps=1+parse)」或内置类型配置");
                }
            }
        }
    }

    private function appPath(): string
    {
        return defined('APP_PATH') ? APP_PATH : $this->rootPath() . 'application/';
    }

    private function rootPath(): string
    {
        return defined('ROOT_PATH') ? ROOT_PATH : dirname(__DIR__, 2) . DIRECTORY_SEPARATOR;
    }
}
