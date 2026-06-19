# think\* Shim 架构债分析

ThinkPHP 8 移除了 TP5 的 `think\Controller`、`think\Loader` 等类。
迁移期间在 `application/common/addons/` 补了两个本地 shim，用 `namespace think;` 占位，
让旧代码调用链暂时不崩。这套 shim 现在可工作，但长期有几个风险：

| 风险 | 说明 |
|------|------|
| 命名空间劫持 | 本地文件声明 `namespace think;`，若 TP8 未来补回同名类，autoload 顺序决定谁赢，难以预测 |
| 第三方插件冲突 | 任何 composer 包若依赖真正的 `think\Loader` 或 `think\Controller` 会拿到 shim |
| Loader 静默吞错 | `validate()` 找不到类时返回空 `Validate()`，验证永远通过，是隐藏的安全漏洞 |
| 可读性 | 新人看到 `\think\Loader::validate('User')` 以为是框架 API，找不到出处 |

## 两个 Shim 概览

```
application/common/addons/
├── Controller.php   → namespace think; class Controller   (16 行)
└── Loader.php       → namespace think; class Loader        (18 行)
```

## 影响规模

| Shim | 文件 | 调用量 | 受影响控制器 |
|------|------|--------|-------------|
| `think\Controller` | `All.php` + 3 个直接继承 | — | 99+ 个控制器（传递性） |
| `think\Loader::validate()` | 36 个文件 | 60 处 | 23 个 Model + 13 个 Admin Controller |

## 迁移优先级与工作量

| 任务 | 优先级 | 估时 | 风险 |
|------|--------|------|------|
| 消除 `think\Controller` shim | 中 | 1h | 低——All.php 已用 TP8 facade，shim 几乎是空壳 |
| 消除 `think\Loader` shim | 中 | 2h | 低——60 处机械替换；顺手修 silent-fail 漏洞 |
| install/controller/Index.php TP5 残留 | 低 | 0.5h | 中——使用了 `think\Db`/`think\Lang`/`think\Request`（旧式） |

详细分析见：

- [01-controller.md](01-controller.md) — Controller shim 消除方案
- [02-loader.md](02-loader.md) — Loader shim 消除方案
