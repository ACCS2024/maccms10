<?php

namespace app;

/**
 * maccms 应用类 —— 将 TP8 的「应用基础目录」显式指向 application/。
 *
 * TP8 默认 getBasePath() = rootPath . 'app/'，但 maccms 的业务代码、全局
 * 中间件(application/middleware.php)、多应用目录(index/api/admin)以及
 * common.php / provider.php 等启动文件都位于 application/。
 *
 * 历史上靠 `app -> application` 符号链接桥接,但符号链接不可移植
 * (Windows、部分部署环境、全新 git 克隆会丢失),一旦缺失,TP8 会从
 * 不存在的 rootPath/app/middleware.php 读取全局中间件 → MultiApp 等 9 个
 * 中间件零加载 → 控制器命名空间退化为 app\ → 整站 404,且 CSRF/安全头/
 * 会话等中间件静默失效。
 *
 * 这里在框架层显式覆盖基础目录,彻底摆脱符号链接依赖,任何环境一致可用。
 */
class MacApp extends \think\App
{
    /**
     * think\App::__construct() 把 $this->appPath 硬编码成 rootPath.'app/',并【就地】
     * 从那里加载 provider.php(App.php:182/185-186)。入口文件后来调的 setAppPath()
     * 已经晚了,getBasePath() 的覆盖也管不着构造函数里那两行。
     *
     * 于是 application/provider.php(把 think\exception\Handle 换成 app\ExceptionHandle
     * 的那条绑定,也就是对外零信息泄露的安全边界)实际上挂在 `app -> application`
     * 这个 .gitignore 忽略、不入库的符号链接上:一次全新 clone、一次带 --delete 的
     * 同步、或换台机器,链接消失 → 绑定静默失效 → 脱敏 500 页换成框架默认错误页,
     * 而部署与合并全程绿灯。实测(无符号链接):make('think\exception\Handle')
     * 返回 think\exception\Handle 而非 app\ExceptionHandle。
     *
     * 这里在父构造之后按真正的基础目录再绑一次。父类那次 bind 要么没发生
     * (无符号链接),要么绑的是同一份文件(有符号链接),重复绑定是幂等的。
     */
    public function __construct(string $rootPath = '')
    {
        parent::__construct($rootPath);

        $provider = $this->getBasePath() . 'provider.php';
        if (is_file($provider)) {
            $this->bind(include $provider);
        }
    }

    public function getBasePath(): string
    {
        return $this->rootPath . 'application' . DIRECTORY_SEPARATOR;
    }

    /**
     * TP8 的 think\initializer\Error::init() 会强制 error_reporting(E_ALL),
     * 并把【任何】在报告级别内的 PHP 诊断(含 E_WARNING/E_NOTICE/E_DEPRECATED)
     * 一律 throw 成 ErrorException。
     *
     * 但 maccms 自己在 application/common.php:12 写的是
     *     error_reporting(E_ERROR | E_PARSE);
     * ——它的代码和模板体系是按「notice/warning 被抑制」设计的:
     *   · mac_url() 里对 $info/$param 有 130+ 处裸下标(URL 构造本就接收
     *     vod/art/type/topic 等异构数组,缺键是常态而非异常);
     *   · 第三方主题(如从 TP5 时代沿用的 155zy)大量引用当前模型不存在的字段。
     * 在 PHP 7.4 下这些只是 notice,静默跳过;迁到 PHP 8 + TP8 后,
     * "未定义数组键"升为 E_WARNING 并被转成异常,于是【一个缺字段就 500 整页】。
     * 实测:前台详情页、文章分类页全部 500。
     *
     * 这里在框架初始化【之后】接管错误处理,恢复 maccms 的既定语义:
     *   - 非致命诊断:记日志(每请求按 file:line 去重,避免刷屏),不中断渲染;
     *   - 致命错误:原样交回框架先前的处理器,行为不变。
     * 需要在开发期恢复 TP8 的严格行为时,把 config/app.php 的
     * strict_php_errors 设为 true 即可。
     */
    public function initialize()
    {
        parent::initialize();

        if ($this->config->get('app.strict_php_errors', false)) {
            return $this;
        }

        // 不要把 E_STRICT 写进掩码:PHP 8.0 起该级别永不触发(纯冗余),而 PHP 8.4
        // 把常量本身标为 deprecated —— 引用它会在【本方法装上自定义处理器之前】
        // 触发 E_DEPRECATED,被 parent::initialize() 刚装好的 think\initializer\Error
        // 转成 ErrorException,于是 8.4 上每个请求在 MacApp::initialize() 当场 500。
        $nonFatal = E_WARNING | E_NOTICE | E_DEPRECATED | E_USER_WARNING
                  | E_USER_NOTICE | E_USER_DEPRECATED;

        $seen = [];
        $prev = null;
        $prev = set_error_handler(
            function (int $errno, string $errstr, string $errfile = '', int $errline = 0) use (&$prev, $nonFatal, &$seen) {
                if (!($errno & $nonFatal)) {
                    // 致命级别:交回框架原处理器(仍会抛 ErrorException)
                    return $prev ? $prev($errno, $errstr, $errfile, $errline) : false;
                }
                $key = $errfile . ':' . $errline;
                if (!isset($seen[$key])) {
                    $seen[$key] = true;
                    try {
                        \think\facade\Log::notice('[php] ' . $errstr . ' in ' . $errfile . ':' . $errline);
                    } catch (\Throwable $e) {
                        // 日志系统尚未就绪时不能反过来影响请求
                    }
                }
                return true; // 已处理,不再冒泡为异常
            }
        );

        return $this;
    }
}
