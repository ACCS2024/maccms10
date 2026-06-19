# think\Loader Shim 消除方案

## 现状

```php
// application/common/addons/Loader.php
namespace think;
class Loader
{
    public static function validate(string $name): \think\Validate
    {
        $class = '\\app\\common\\validate\\' . $name;
        if (class_exists($class)) {
            return new $class();
        }
        return new \think\Validate();  // ← 类不存在时静默返回空验证器
    }
}
```

调用方（全部 60 处）模式：
```php
$v = \think\Loader::validate('User');       // 字符串常量
$v = \think\Loader::validate($model_name);  // 或动态字符串
$v->check($data);
```

## 静默失败漏洞

`class_exists` 为 false 时返回 `new \think\Validate()`——一个**没有规则的空验证器**，
`$v->check($data)` 永远返回 `true`。

如果 Validate 类文件改名或 autoload 配置变化，验证会**悄无声息地通过**。
这在注册/登录/支付等路径上是安全隐患。

## 迁移方案：替换为项目级辅助函数

### 新增函数（放进 application/common.php）

```php
/**
 * 按名称实例化 Validator（替代 TP5 think\Loader::validate()）。
 * 与原 shim 的区别：找不到类时抛出异常而非静默返回空验证器。
 */
function mac_validate(string $name): \think\Validate
{
    $class = 'app\\common\\validate\\' . $name;
    if (!class_exists($class)) {
        throw new \RuntimeException("Validate class not found: {$class}");
    }
    return new $class();
}
```

### 60 处调用的机械替换

```bash
# 预览（不修改）
grep -rn 'think\\Loader::validate' application/ --include='*.php'

# 替换
find application -name '*.php' | xargs sed -i \
    's/\\think\\Loader::validate(/mac_validate(/g'

# 二次确认无遗留
grep -rn 'think\\Loader' application/ --include='*.php'
# 期望：零输出
```

替换完成后删除 shim：
```bash
git rm application/common/addons/Loader.php
```

### 验证

```bash
bash tests/lint.sh
# 若 System.php 等大文件有行内字符串拼接，也要目测核查一遍
grep -n 'mac_validate' application/admin/controller/System.php | head -25
```

## 调用方分布（执行前参考）

| 文件 | 行数 | 出现次数 |
|------|------|----------|
| `application/admin/controller/System.php` | 74,308,400,483,550,579,607,635,673,706,740,774,811,941,981,1007,1066,1141,1498 | **19** |
| `application/common/model/Vod.php` | 718, 848 | 2 |
| `application/common/model/User.php` | 115, 236 | 2 |
| `application/admin/controller/Database.php` | 372, 436 | 2 |
| `application/admin/controller/VodPlayer.php` | 27, 133 | 2 |
| `application/admin/controller/Template.php` | 181, 186 | 2 |
| 其余 30 个文件 | 各 1 处 | 30 |
| **合计** | | **60** |

## 可选强化：针对常量字符串直接 new

对 `$name` 始终是字面量字符串的少数调用点，可以进一步内联为直接 `new`，
消除字符串查找，获得 IDE 跳转支持：

```php
// Before
$v = \think\Loader::validate('User');

// After（可选优化）
$v = new \app\common\validate\User();
```

这不是必须做的，但对 System.php 里的高频路径有轻微性能收益，
更重要的是 IDE 能识别类型。

## 遗留注意

- `application/common.php:2242` 有一个 `mac_search_wd_like()` 函数，
  返回 TP5 格式的 `['like', ...]` 数组但**零调用者**——是独立死码，不影响本次迁移。
- 插件子系统 `application/common/addons/Addons.php` 不使用 `Loader::validate()`，
  不受本次迁移影响。
