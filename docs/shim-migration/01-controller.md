# think\Controller Shim 消除方案

## 现状

```php
// application/common/addons/Controller.php
namespace think;
class Controller
{
    public function __construct()
    {
        if (method_exists($this, 'initialize')) {
            $this->initialize();
        }
    }
}
```

```php
// application/common/controller/All.php
use think\Controller;
class All extends Controller { ... }
```

`All` 的 `__construct()` 调用 `parent::__construct()`，触发上面的 shim，
从而让各子控制器的 `initialize()` 钩子被调用。

## 继承链（现状）

```
think\Controller  (shim — application/common/addons/Controller.php)
└── app\common\controller\All
    ├── app\admin\controller\Base  → 52 个 Admin 控制器
    ├── app\index\controller\Base  → 19 个 Index 控制器
    └── app\api\controller\Base    → 28 个 API 控制器

直接继承 think\Controller（绕过 All）的 3 个文件：
  application/index/controller/Verify.php
  application/index/controller/Qrcode.php
  application/install/controller/Index.php
```

## 为什么好改

`All.php` 里已经用 TP8 原生 facade 实现了所有功能：
- `assign()` → `\think\facade\View::assign()`
- `fetch()` → `\think\facade\View::fetch()`
- `success()`/`error()` → 抛 `HttpResponseException`
- `__construct()` → 直接调 `parent::__construct()` 后再走自身逻辑

shim 唯一做的事只有"调 `initialize()` 钩子"——这一行内联进 `All::__construct()` 就行。

## 迁移步骤

### 步骤 1：All.php — 内联 initialize 并去掉 extends

```diff
-use think\Controller;
 use think\facade\Cache;
 use think\facade\Request;

-class All extends Controller
+class All
 {
     public function __construct()
     {
-        parent::__construct();
+        if (method_exists($this, 'initialize')) {
+            $this->initialize();
+        }
         $this->_ref = mac_get_refer();
         ...
     }
```

99 个通过 Base 继承 All 的子控制器**不需要改**。

### 步骤 2：Verify.php — 去掉多余 extends

```diff
-use think\Controller;
-class Verify extends Controller
+class Verify
 {
     public function __construct()
     {
-        parent::__construct();
     }
```

Verify 的两个方法（`index` 返回验证码图片、`check` 验证）都不依赖 Controller 任何功能，
constructor 也只是调 parent——去掉完全无影响。

### 步骤 3：Qrcode.php — 同上

```diff
-use think\Controller;
-class Qrcode extends Controller
+class Qrcode
 {
     public function __construct()
     {
-        parent::__construct();
     }
```

Qrcode 只调 `\think\facade\Request::param()` 和第三方库，同样不依赖 Controller。

### 步骤 4：install/controller/Index.php — 只改继承，TP5 import 另行处理

```diff
-use think\Controller;
 use think\Db;         // TODO: 改为 think\facade\Db（另一票债）
 use think\Lang;       // TODO: TP5 style
 use think\Request;    // TODO: TP5 style

-class Index extends Controller
+class Index
 {
     public function __construct(Request $request = null)
     {
         ...
-        parent::__construct($request);
     }
```

> 注意：`parent::__construct($request)` 中 shim 的构造函数根本不接受参数（PHP 不报错因为 shim 用的是 `...$args` 隐式忽略），所以这个 `$request` 现在就是死参数。
> install 模块的 `think\Db`/`think\Lang`/`think\Request` 是独立 TP5 残留，应另开 PR 处理。

### 步骤 5：删除 shim 文件

```bash
git rm application/common/addons/Controller.php
```

## 验证

```bash
# 语法检查
bash tests/lint.sh

# 确认没有其他地方 use/extends think\Controller
grep -r 'think\\Controller\|extends Controller\|use think\\Controller' application/ --include='*.php'
# 期望：只剩 application/common/addons/Addons.php（插件基类，那是另一个话题）
```

## 已知遗留

- `application/common/addons/Addons.php` 声明 `namespace think; class Addons extends Controller`，
  依赖 Controller shim 作为插件基类。这属于"插件子系统"技术债，与本 PR 范围分开处理。
- install/Index.php 的 `think\Db`/`think\Lang` 见 [install TP5 残留](../install-tp5-cleanup.md)（待建）。
