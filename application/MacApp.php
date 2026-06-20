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
    public function getBasePath(): string
    {
        return $this->rootPath . 'application' . DIRECTORY_SEPARATOR;
    }
}
