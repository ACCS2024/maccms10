# 02 · 约定:分支 / 提交 / 目录与 API 映射 / Rector

---

## 一、分支与提交

- **集成分支**:`feat/tp8-migration`(从当前迁移基线切出)。**不直接动 master**。
- **每阶段子分支**(可选):`feat/tp8-pN-<slice>`,合回集成分支。
- **每轮一个聚焦提交**,信息格式:

```
tp8(P<N>/<slice>): <一句话做了什么>

- 改动面:<文件数> 文件 / <调用点> 处
- 映射:<旧 API> → <新 API>
- 验证:php8.4 lint✓ 启动✓ 冒烟[行号]✓ 不变量[编号]✓
- 残留:<有/无,见 ROUND-XXX>
- round-log: progress/round-log/ROUND-XXX.md
```

- **每阶段结束打 tag**:`tp8-p<N>-done`,便于整阶段回滚/对照。

---

## 二、目录结构映射(TP5.0 多入口 → TP8 单入口多应用)

| TP5.0(现状) | TP8(目标) | 说明 |
|---|---|---|
| `index.php` `admin.php` `api.php` `install.php`(多入口) | `public/index.php`(单入口)+ `think-multi-app` | 入口收口到 `public/`,模块=应用 |
| `application/` | `app/` | 业务根目录改名 |
| `application/index` `admin` `api` `install` | `app/index` `app/admin` `app/api` `app/install` | 多应用映射;`BIND_MODULE`/`bind.php` → 多应用路由 |
| `application/config.php` + `application/extra/*.php` | `config/*.php` + `.env` | 见 P2;扁平 key → 分组多级 |
| `application/route.php` | `route/<app>.php` | 路由按应用拆 |
| `application/tags.php`(钩子) | `app/middleware.php` + `app/event.php` | **行为→中间件/事件,见 P3** |
| `application/common/behavior/*` | `app/middleware/*` + `app/listener/*` | 安全脊柱重落点 |
| `application/command.php` | `config/console.php` | 命令注册 |
| `application/common.php`(174 个 `mac_` helper) | `app/common.php`(保留)+ 内部 API 收口 | 函数体内的 TP API 逐个迁 |
| `thinkphp/`(vendored 框架) | composer `topthink/framework:^8.0` | 删 vendored 框架,转 composer |
| `extend/`(手工库) | `extend/`(保留,TP8 支持 `extend` 自动加载) | 三方收口见 P8 |
| `template/`(模板)、`static/` | `template/`、`public/static/` | taglib 注册方式变,见 P5 |

---

## 三、API 映射总表(核心机械替换依据)

> 计数为本仓库实测调用点(`application`+`addons`)。**逐项有对应阶段负责**。

| TP5.0 写法 | 调用点 | TP8 写法 | 阶段 | 备注 |
|---|---|---|---|---|
| `use think\Db; Db::name()/query()/...` | 459 | `use think\facade\Db;`(调用不变) | P4 | 仅 `use` 改门面;连接配置格式变 |
| `model('Xxx')` / `Loader::model` | 820 | 注入或 `new \app\common\model\Xxx` / `Xxx::` | P4 | `model()` 助手在 TP8 不默认存在,收口 |
| `$this->assign(...)` | 769 | `View::assign(...)` / `view(tpl, vars)` | P5 | 控制器不再自带 assign |
| `$this->fetch()` / `->display()` | 184 | `return View::fetch()` / `return view()` | P5 | 同上;返回 Response |
| `input('xxx')` | 371 | `input('xxx')`(think-helper,基本兼容) | P6 | 助手仍在,验签名差异 |
| `config('x')` | 341 | `config('group.x')`(多级) | P2 | **key 路径要改** |
| `url('...')` | 277 | `url('...')`(think-helper)/`Route::buildUrl` | P6 | 行为/签名差异需验 |
| `Cache::`/`cache()` | 265 | `use think\facade\Cache;` / `cache()` | P6 | 门面命名空间变 |
| `Cookie::`/`cookie()` | 118 | `use think\facade\Cookie;` / `cookie()` | P6 | 同上 |
| `Session::`/`session()` | 54 | `use think\facade\Session;` / `session()` | P6 | set/get API 微调,需验 |
| `Request::instance()` / `request()` | 43 | 注入 `Request $request` / `request()` | P6 | 优先依赖注入 |
| `class X extends Controller` | 151 | `extends app\BaseController`(自建) | P5 | TP8 无自带 fetch 的 Controller |
| `class X extends Validate` | 50 | `extends think\Validate`(基本兼容) | P5 | 命名空间不变,验规则差异 |
| `class X extends Model` | ~60 | `extends think\Model`(基本兼容) | P4 | 查询/事件细节验 |
| `Hook::listen()` / behavior | 49 | 中间件 `handle()` / 事件监听 | P3 | **架构级重写** |
| `taglib`(Maccms/Macdiy 727行) | — | `topthink/think-view` taglib 注册 | P5 | 标签编译 API 变 |

---

## 四、自动化:Rector + 自写规则

- **Rector** 跑机械替换(命名空间/门面/隐式可空参/返回类型),但**不盲信**:每轮 Rector 后必须 `php -l` + 冒烟 + 人工 diff review。
- 推荐规则集:`LevelSetList::UP_TO_PHP_84` + 自定义 ThinkPHP 门面替换规则(`use think\Db`→`use think\facade\Db` 等)。
- `config('x')` → `config('group.x')` 的 key 重写:**不能纯正则**(要知道每个 key 归哪个组),由 P2 生成"旧 key→新 key"映射表后,用映射驱动替换。
- **AI 角色**:负责 Rector 跑不动的语义改写(行为→中间件、taglib、config 归组、控制器视图收口)+ 每轮 diff 自审 + 验证。

---

## 五、命名/落点约定

- 中间件:`app\middleware\<Name>`,在 `app/middleware.php` 注册(全局)或应用级 `app/<app>/middleware.php`。
- 事件监听:`app\listener\<Name>`,在 `app/event.php` 注册。
- 自建基类控制器:`app\BaseController`(封装原 `fetch/assign` 习惯,降低 P5 改动面)。
- 安全相关中间件**集中放** `app\middleware\security\*`,便于安全复核与 `security-invariants.md` 对照。
