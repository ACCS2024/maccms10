# P1 · TP8 骨架 / 单入口多应用

## 目标

把"vendored 框架 + 多入口"换成"**composer 管理的 TP8 + `public/` 单入口 + 多应用**",让站点能在 PHP 8.4 **启动到框架就绪**(业务允许报错)。

## 前置依赖

P0 完成(有回归网与基线)。

## 改动清单

| 项 | 现状 | 目标 |
|---|---|---|
| 框架 | vendored `thinkphp/` 5.0.25 | composer `topthink/framework:^8.0` |
| 多应用 | `BIND_MODULE`/`bind.php` | `topthink/think-multi-app` |
| 视图 | 内置 think-template | `topthink/think-view` |
| 入口 | `index.php`/`admin.php`/`api.php`/`install.php` | `public/index.php`(+ `public/router.php` 供内置 server) |
| 业务根 | `application/` | `app/`(index/admin/api/install 为应用) |
| 自动加载 | 框架自带 | composer PSR-4(`app\` → `app/`,保留 `extend/`) |

## 设计要点

- **新建 `composer.json`**(项目首次有依赖账本,呼应 PHP85 审计 P0-1):
  - require:`topthink/framework:^8.0`、`topthink/think-multi-app`、`topthink/think-view`、`topthink/think-helper`(随框架)。
  - autoload:`"psr-4": { "app\\": "app/" }`、`"files": ["app/common.php"]`,`extend/` 走 classmap/`extend` 目录配置。
- **`app\BaseController`**:在此阶段就建好(承接老控制器的 `fetch/assign` 习惯),给 P5 铺路。
- **多应用映射**:index(默认)、admin、api、install;后台/接口的访问路径与现有保持兼容(必要时路由层做 alias,避免 SEO/外链断裂)。
- **保留安全分发校验**:原控制器名/方法正则校验(invokefunction RCE 防线)在多应用分发处保留等价实现(见 `security-invariants.md` 非行为类加固)。

## 切片建议(每轮先分析)

- ROUND:composer.json + 拉 TP8 + 删 vendored `thinkphp/`(框架能 autoload)
- ROUND:`public/index.php` 单入口 + 内置 server router + web 重写规则
- ROUND:`application/` → `app/` + 多应用目录骨架 + BaseController
- ROUND:启动到"框架就绪",记录首批业务报错清单(交给 P2–P6)

## 风险 & 安全不变量

🟠 中(结构大改但机械)。**触碰 INV-2/3/5/7**(入口/分发链路)——本阶段先确保中间件挂载点就位(具体逻辑 P3 填),并保留分发层安全校验。

## 验证

```bash
composer install
find app -name '*.php' -print0 | xargs -0 -n1 php -l >/dev/null && echo lint-ok
php -S 127.0.0.1:8800 -t public public/router.php
curl -sI http://127.0.0.1:8800/ | head -1     # 期望:框架已接管(可能业务 500,但非"白屏/类找不到")
```

冒烟行:#1(首页能进入框架)、#27(install 入口可达)。

## 退出标准(DoD)

- [ ] `composer install` 成功,vendored `thinkphp/` 已移除
- [ ] `app/` 全量 `php -l` 绿
- [ ] 站点启动到框架就绪;四个应用入口可路由(业务报错可接受)
- [ ] 分发层安全校验保留(INV 非行为类项)
- [ ] tag `tp8-p1-done`

## 回滚

整阶段 tag 回滚;骨架未触碰业务逻辑,回退干净。
