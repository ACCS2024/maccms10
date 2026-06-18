# ThinkPHP 8 迁移方案

- **当前版本**：ThinkPHP 5.0.25，PHP 8.2.31
- **目标版本**：ThinkPHP 8.1.x，PHP 8.2+
- **分支**：`feat/tp8-migration`（不合并进 master，直到全量回归通过）
- **文档日期**：2026-06-18

---

## 一、必须改动的代码面（静态扫描结果）

| 改动点 | 处数 | 原因 |
|--------|------|------|
| `model()` 助手函数 | **822** | TP8 完全移除 |
| `$this->assign()` | **771** | 控制器模板赋值方式变了 |
| `$this->success/error()` | **543** | 完全移除，需自封跳转逻辑 |
| `input()` 助手函数 | **347** | 改为 `request()->param()` |
| `$this->fetch()` | **176** | 改为返回 `view()` |
| 模板 `{:url(` | **562**（107 个文件）| URL 生成方式变 |
| **合计** | **≈ 3,200+** | — |

---

## 二、五大关键决策

### 决策 1：目录结构——保留 `application/`，不重组

TP8 的 `app_path` 可配置，在 `config/app.php` 中指向 `application/`。
强行迁移 325 个 PHP 文件到 `app/` 是纯体力活，风险极高，收益为零。
TP8 多应用模式（`topthink/think-multi-app`）直接映射 `application/admin/`、`application/api/`、`application/index/`，与现有结构一致。

### 决策 2：兼容层策略——先建 Shim，再分模块渐进改写

1700+ 处不能一次性改写。在 `application/common.php` 追加 shim 函数（`model/input/session/url`），在 `application/common/controller/All.php` 追加 `success/error/assign/fetch` 兼容方法，让项目先跑起来，再按模块逐步移除 shim。

### 决策 3：fastadmin-addons——内化，脱离 karsonzhang 包

`karsonzhang/fastadmin-addons 1.1.11` 依赖 `think\Hook`、`think\Loader`（TP8 已移除），与 TP8 **完全不兼容**。
方案：将 src/ 核心 5 个文件复制到 `application/common/addons/`，把 `think\Hook` 替换为 TP8 事件系统 `Event::listen/trigger`，把 `Loader::addNamespace` 替换为 PSR-4 直接加载。保持命名空间 `think\Addons`，现有 addon 代码的 `use think\Addons` 无需修改。

### 决策 4：路由迁移——转译为 `route/` 多文件

现有 `application/route.php`（553 行数组格式）拆分为：
- `route/index.php`：前台路由（约 80%）
- `route/api.php`：API 路由（约 20%）
- `route/admin.php`：后台路由（目前基本靠 URL 模式）

### 决策 5：模板 url() ——注册全局函数，零改 HTML 文件

在 `application/common.php` 中注册全局 `url()` 函数委托给现有 `mac_url()` 逻辑，206 个 HTML 模板中 562 处 `{:url(` 调用一行不改。

---

## 三、依赖变化

| 包 | 当前 | 目标 | 备注 |
|----|------|------|------|
| `topthink/framework` | 5.0.25（`thinkphp/` 目录）| `^8.1` | 从 hardcode 目录迁到 vendor |
| `topthink/think-captcha` | `^1.0` | `^3.0` | 3.x 需 TP6/8 |
| `topthink/think-helper` | `^1.0` | `^3.0` | 3.x 需 TP6/8 |
| `topthink/think-image` | `^1.0` | `^2.0` | 2.x 需 TP6/8 |
| `karsonzhang/fastadmin-addons` | `1.1.11` | **移除，内化** | TP8 不兼容 |
| `phpmailer/phpmailer` | `^6.12` | 保留 | 无需升级 |
| 新增 `topthink/think-multi-app` | — | `^1.0` | 多应用模式必须 |

---

## 四、8 个 Behavior → Middleware 对应关系

| Behavior（TP5 钩子） | Middleware | 执行位置 |
|---------------------|-----------|---------|
| `SessionSameSite`（app_init） | `app\middleware\SessionSameSite` | 全局，最前 |
| `Init`（app_init）| `app\middleware\AppInit` | 全局，第二（最重，4335 行）|
| `RequestSecurity`（app_init） | `app\middleware\RequestSecurity` | 全局 |
| `Begin`（app_begin） | `app\middleware\Begin` | 全局 |
| `CsrfGuard`（app_begin） | `app\middleware\CsrfGuard` | 全局（admin 有效）|
| `AntiScrape`（app_begin） | `app\middleware\AntiScrape` | 全局 |
| `SecurityHeaders`（app_end） | `app\middleware\SecurityHeaders` | 全局，最后（处理 Response）|
| `AdminAudit`（app_end） | `app\middleware\AdminAudit` | 全局，最后 |

---

## 五、分阶段执行计划

### Phase 0：基础设施搭建（0.5 人天）

**目标**：TP8 框架包进 vendor，骨架目录建好，composer.lock 更新。

**步骤**：
1. 修改 `composer.json`：移除 `think\\` → `thinkphp/library/think/` 的 autoload 条目，添加 TP8 依赖（见第三节）
2. `COMPOSER_ALLOW_SUPERUSER=1 php composer.phar update --no-dev`
3. 创建 `config/`、`route/` 目录骨架
4. 创建 `config/app.php`，设置 `app_path => application/`，开启多应用模式

**验证**：
```bash
php -r "require 'vendor/autoload.php'; echo \think\App::VERSION;"
# 输出 8.x.x
```

---

### Phase 1：Shim 层 + 入口改造（4 人天）

**目标**：三个入口文件跑在 TP8 下，首页 / admin 登录页 HTTP 200，不报 Fatal Error。这是整个迁移的基石，必须一次做完。

**步骤**：

**1.1 改造入口文件**（`index.php` / `admin.php` / `api.php`）

从：
```php
require __DIR__ . '/thinkphp/start.php';
```
改为：
```php
require __DIR__ . '/vendor/autoload.php';
define('ROOT_PATH', __DIR__ . '/');
define('APP_PATH', __DIR__ . '/application/');
define('RUNTIME_PATH', __DIR__ . '/runtime/');
define('ADDON_PATH', __DIR__ . '/addons/');
define('DS', DIRECTORY_SEPARATOR);
define('EXT', '.php');
define('ENTRANCE', 'index'); // 各入口对应值不同

$app = new \think\App(APP_PATH);
$response = $app->http->name('index')->run(); // admin 入口用 'admin'，api 用 'api'
$response->send();
$app->http->end($response);
```

**1.2 Config 文件拆分**

将 `application/config.php` 按 TP8 规范拆分为 `config/` 目录下多个文件：
- `app.php`、`database.php`、`cache.php`、`session.php`、`view.php`、`log.php`

`application/extra/*.php` 中的运行时配置在 Init Middleware 中用 `Config::set()` 动态写入（替代 TP5 的 `config('key', $value)` 写模式）。

**1.3 Shim 函数**（追加到 `application/common.php` 头部）

```php
// TP8 兼容 shim — 待各模块改写完毕后逐步移除
if (!function_exists('model')) {
    function model(string $name, string $layer = 'model'): object {
        $class = '\\app\\common\\' . $layer . '\\' . ucfirst($name);
        return new $class();
    }
}
if (!function_exists('input')) {
    function input(string $key = '', $default = null, string $filter = '') {
        return \think\facade\Request::input($key, $default, $filter);
    }
}
if (!function_exists('url')) {
    function url(string $url = '', array $vars = [], bool $suffix = true): string {
        return mac_url($url, $vars); // 委托给现有 mac_url()，模板 {:url(} 零改动
    }
}
```

**1.4 Controller Shim**（追加到 `application/common/controller/All.php`）

```php
protected function success($msg = '', $url = null, $data = '', $wait = 3) {
    if (\think\facade\Request::isAjax()) {
        return json(['code' => 1, 'msg' => $msg, 'data' => $data]);
    }
    $this->assign(['msg' => $msg, 'url' => $url ?? 'javascript:history.back();', 'wait' => $wait]);
    throw new \think\exception\HttpResponseException(\think\facade\View::fetch('public/jump'));
}
protected function error($msg = '', $url = null, $data = '', $wait = 3) {
    if (\think\facade\Request::isAjax()) {
        return json(['code' => 0, 'msg' => $msg, 'data' => $data]);
    }
    $this->assign(['msg' => $msg, 'url' => $url ?? 'javascript:history.back();', 'wait' => $wait]);
    throw new \think\exception\HttpResponseException(\think\facade\View::fetch('public/jump'));
}
protected function assign($name, $value = ''): void {
    \think\facade\View::assign(is_array($name) ? $name : [$name => $value]);
}
protected function fetch(string $template = '', array $vars = []): string {
    if ($vars) \think\facade\View::assign($vars);
    return \think\facade\View::fetch($template);
}
```

**1.5 Behavior → Middleware 改写**（最重：Init.php 4335 行）

创建 `application/middleware.php` 全局注册 8 个 Middleware。
核心改写规则：
- `Hook::listen('app_init', ...)` 删除（Middleware 机制替代）
- `config('key', $value)` 写模式 → `Config::set('key', $value)`
- `App::$debug` → `app()->isDebug()`
- `\think\Db` → `\think\facade\Db`

**1.6 fastadmin-addons 内化**

```
application/common/addons/
├── Addons.php      (think\Hook → Event::listen/trigger)
├── AddonsLoader.php (Loader::addNamespace → PSR-4 加载)
├── Route.php
└── Controller.php
```
`composer.json` autoload 追加 `"think\\": "application/common/addons/"`，让现有 addon 的 `use think\Addons` 无需修改。

**验证**：
- `curl localhost/index.php` → HTTP 200
- `curl localhost/admin.php` → 登录页 HTTP 200
- `curl localhost/api.php/vod/index` → JSON 响应

---

### Phase 2：ORM 与数据库层（2 人天）

**目标**：Model、Db、Validate、Cache 在 TP8 下稳定运行。

**关键改写点**：
- `application/common/model/Base.php`：`initialize()` → `init()`，`getError()` 用 `protected string $error = ''` 属性自封兼容
- 所有文件：`use think\Db` → `use think\facade\Db`（148 处 use 声明）
- 所有文件：`use think\Cache` → `use think\facade\Cache`（89 处）
- Cache 返回值：TP5 未命中返回 `false`，TP8 返回 `null`，grep 确认所有 `=== false` 判断（约 6 处）并修改
- `database.php`：`resultset_type: 'array'` → `result_type: 0`，移除 `builder`/`query`/`fields_strict`

**验证**：后台登录成功，内容列表页有数据。

---

### Phase 3：API 模块（2 人天）

**目标**：51 个 API 控制器完整运行，接口响应与 master 分支一致。

**关键改写点**：
- `use think\Db/Cache/Request` → 对应 facade（批量 sed）
- `model()` 169 处 → `new \app\common\model\Xxx()`
- `input()` 约 5 处 → `$request->post()/get()/param()`
- 创建 `route/api.php`（从 route.php 提取 API 路由段）
- Lang 文件在 Init Middleware 中手动加载

**验证**：核心 API 接口（视频列表、搜索、用户）JSON 响应正确，字段与 master 分支对比无差异。

---

### Phase 4：Admin 模块（4 人天）

**目标**：55 个后台控制器完整可用，所有管理功能无 500。

**关键改写点**：
- `model()` 297 处 → `new \app\common\model\Xxx()`（批量脚本辅助）
- `input()` 280 处 → `$request->post()/get()/param()`（sed 正则辅助）
- `success/error/assign/fetch` 474+574+133 处由 Phase 1 Shim 兜住，本阶段验证无遗漏
- `Addon.php`：适配 Phase 1 内化的 AddonsLoader

**验证**：后台全部一级菜单可点击，增删改查/文件上传/CSRF 保护/用户登录注销全部正常。

---

### Phase 5：Index 前台模块（2.5 人天）

**目标**：25 个前台控制器正常运行，页面渲染、缓存、TagLib 全部正确。

**关键改写点**：
- `Maccms.php` / `Macdiy.php` TagLib：`use think\Db` → `use think\facade\Db`
- `config/view.php`：`taglib_pre_load => 'app\common\taglib\Maccms'`
- 页面缓存逻辑（`Cache::get/set` + `die` 直出）验证行为一致
- 创建 `route/index.php`（从 route.php 提取前台路由段，约 80%）

**验证**：首页/分类页/详情页/搜索页正常渲染，自定义标签数据正确，分页正常，移动端模板切换正常。

---

### Phase 6：Console Commands（0.5 人天）

**目标**：10 个命令在 TP8 下正常运行。

**关键改写点**：
- 创建 `config/console.php`，注册 10 个命令（替代 `application/command.php`）
- 各 Command 文件：`use think\Db` → `use think\facade\Db`

**验证**：`php think list` 显示所有命令，`php think info` 执行成功。

---

### Phase 7：移除 Shim + 全量回归（2 人天）

**目标**：代码全部采用 TP8 原生 API，系统级回归测试通过，可提 PR 合并 master。

**步骤**：
1. 移除 `common.php` 中的 `model()`、`input()` shim
2. 移除 `All.php` 中的 `success/error/assign/fetch` shim
3. 删除或归档 `thinkphp/` 目录
4. 全量回归测试（见下方清单）
5. `composer dump-autoload --optimize`，移除多余 autoload 条目

**回归测试清单**：
- [ ] 前台：首页、分类页、详情页、搜索页、分页
- [ ] 前台：用户注册/登录/个人中心
- [ ] 后台：登录、所有一级菜单、增删改查
- [ ] 后台：文件上传、系统设置保存
- [ ] API：视频列表、搜索、用户接口、采集接口
- [ ] Console：全部 10 个命令
- [ ] Addon：2 个插件安装/启用/禁用
- [ ] 安全：CSRF、防采集、会话安全、SecurityHeaders

---

## 六、里程碑总表

| 里程碑 | Phase | 完成标志 | 累计人天 |
|--------|-------|---------|---------|
| M0：框架进 vendor | Phase 0 | `think\App::VERSION` 输出 8.x | 0.5 |
| M1：系统可启动 | Phase 1 | 三个入口 HTTP 200 | **5** |
| M2：数据层稳定 | Phase 2 | 后台登录+列表正常 | **7** |
| M3：API 完整 | Phase 3 | 所有 API 接口响应正确 | **9** |
| M4：后台完整 | Phase 4 | 后台全功能无 500 | **13** |
| M5：前台完整 | Phase 5 | 前台所有页面正常 | **15.5** |
| M6：命令行可用 | Phase 6 | `php think list` 完整 | **16** |
| M7：生产就绪 | Phase 7 | Shim 全清，回归通过 | **18** |

**总计：约 18 个工作日（1 人全职约 3.5 个自然周）**

---

## 七、主要风险

| 风险 | 概率 | 影响 | 缓解 |
|------|------|------|------|
| `Init.php`（4335 行）的 `config()` 写模式在 TP8 配置失效 | 高 | 高 | Phase 1 优先改写，逐行验证配置读取 |
| fastadmin-addons 内化不完整，addon 加载失败 | 中 | 中 | 内化前先梳理 2 个 addon 的全部依赖 |
| TP8 `Cache::get` 返回 `null` 而非 `false` 导致判断逻辑出错 | 中 | 中 | Phase 2 专项 grep `=== false` 并全改 |
| TagLib 在 TP8 `think-template` 包中 API 变化 | 低 | 高 | Phase 5 前隔离测试两个 TagLib |
| `getLastInsID()` 在 TP8 ORM 行为变化 | 低 | 中 | Phase 4 中 14 处逐一验证 |

---

## 八、关键文件清单（实施时优先读这几个）

| 文件 | 重要性 | 说明 |
|------|--------|------|
| `application/common/behavior/Init.php` | ★★★★★ | 4335 行，改写为 Middleware 是最高优先级 |
| `application/common/controller/All.php` | ★★★★★ | Shim 层写在这里，所有控制器的根基类 |
| `vendor/karsonzhang/fastadmin-addons/src/common.php` | ★★★★☆ | 内化改写的主要参考源 |
| `application/common/model/Base.php` | ★★★★☆ | 41 个 Model 的基类，改一处影响全局 |
| `application/common.php` | ★★★★☆ | Shim 函数和 mac_url 都在这里 |
| `application/route.php` | ★★★☆☆ | 553 行，拆分为 route/ 目录 |
