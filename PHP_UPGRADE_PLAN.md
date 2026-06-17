# 苹果CMS (maccms10) PHP 升级方案与技术债务分析

- **升级对象**:本仓库(magicblack/maccms10 fork,基于 ThinkPHP 5.0.25)
- **当前现状**:线上/容器实际跑 **PHP 7.4**,框架声明 `>=5.4`,入口声明 `>=5.5`(三处版本契约不一致,详见 §2)
- **升级目标**:统一并抬升到 **PHP 8.x**(推荐落地 8.3 → 8.4,详见 §3)
- **分析日期**:2026-06-17
- **分析方式**:全树版本测绘 + removed/deprecated 函数静态扫描(`application`/`extend`/`addons`/`thinkphp`/`vendor`)+ 框架 DI/反射热点定位 + 第三方依赖版本核对 + PHP 官方版本/EOL 联网核验
- **状态**:本文为**分析与方案交付,未改动任何业务代码**;落地步骤见 §6–§9

---

## 一、总体结论(必读 / TL;DR)

1. **真正的拦路虎不是业务代码,是框架 + 依赖管理方式。**
   - 框架 **ThinkPHP 5.0.25 已 EOL、非 PHP8-clean**(项目自己的 `tests/README.md` 已记录这一点)。
   - 仓库**没有根 `composer.json`**,`thinkphp/` 与 `vendor/` 是**整目录提交进仓库(vendored)**的。这意味着**不能 `composer update` 升上 PHP8**,任何框架/库升级都得**手工换文件**。

2. **业务代码本身相对干净,且事实上已经是 PHP 7 代码。**
   - `application/extend/addons` 共 **507 个 PHP 文件 / ~15.8 万行**,其中已使用 **814 处 `??`(null 合并,PHP7.0+)、11 处 `<=>`(太空船,PHP7.0+)**。所以"PHP 5.x"只是声明,**实际下限早已是 PHP 7**。
   - 静态扫描里那些"被移除函数"的命中**绝大多数是误报**(详见 §5,先看这节能省下白干的力气)。真实命中只有:`PclZip` 里的 `ereg()`、以及被 `function_exists()` 守卫的 `get_magic_quotes_*`(安全但属死代码)。

3. **TP5.0.25 跑在 PHP 8 上"能起来,但不干净"。**
   预期是**一大波 `E_DEPRECATED`**(DI 反射 `getClass()`、`ArrayAccess/Countable` 返回类型、null 传非空参、8.2 动态属性),外加少量边界真断。**几乎没有发现会直接 Fatal 的"被移除语法"**(无 `$x{...}` 花括号下标、无 `each()`/`create_function()`/`mysql_*`、无 `strftime`)。
   → 风险点是:**告警量大**,且一旦泄漏进响应体会破坏 JSON/跳转(这正是本仓库已做的 `show_error_msg` 关闭、500 不回显的加固所对应的面)。

4. **推荐路线:渐进打补丁,不重写框架。**
   - ✅ **路线 A(推荐)**:原地给 TP5.0.25 打 PHP8 兼容补丁 + 升级/替换少量第三方库 + 跑通 deprecation 基线 → 切 PHP 8.3/8.4。成本/风险最低。
   - ❌ **路线 B(不推荐现在做)**:TP5.0 → TP6/TP8 重写。maccms 深度耦合 TP5.0 的 API(`Db`/`Model`/`View`/钩子行为/`common.php` 174 个 `mac_` helper),重写≈重做一遍站,成本数量级更高。详见 §6。

---

## 二、版本现状测绘:三处版本契约不一致

| 位置 | 声明/实际 | 证据 |
|---|---|---|
| 框架版本 | ThinkPHP **5.0.25**(已 EOL) | `thinkphp/base.php:12` `define('THINK_VERSION', '5.0.25')` |
| 框架 PHP 下限 | 声明 `>=5.4.0`(过时) | `thinkphp/composer.json:19` `"php": ">=5.4.0"` |
| 入口 PHP 下限 | 硬断言 `>=5.5.0`(过时) | `index.php:11` `version_compare(PHP_VERSION,'5.5.0','<')` 直接 `die` |
| 运行时镜像 | **PHP 7.4**(实际目标) | `docker/Dockerfile:1` `FROM php:7.4-apache` |
| CI 校验 | **PHP 7.4** `php -l` | `.github/workflows/ci.yml` `php-version: '7.4'` |
| 团队认知 | "TP5.0.24 已 EOL、非 PHP8-clean,固定 7.4" | `tests/README.md` |
| 代码实际语法下限 | **PHP 7.0+**(`??`×814、`<=>`×11) | `application/**` 扫描 |

> 结论:**对外声称 5.4/5.5,实际跑 7.4,代码写法是 7.x**。升级第一步就是把"版本契约"统一收口到一个真实数字(见 §9-①)。

---

## 三、PHP 版本选型与时间线(2026-06 实况)

| 版本 | 状态(2026-06) | 主动支持(bug)截止 | 安全支持截止 | 建议 |
|---|---|---|---|---|
| 7.4 | **早已 EOL**(2022-11) | — | — | ⚠️ 当前线上版本,必须尽快离开 |
| 8.0 / 8.1 | EOL / 接近 EOL | — | 8.1 已结束 | 不作为目标 |
| 8.2 | 安全支持期 | 已结束 | **2026-12-31** | 跳板可,落地嫌短 |
| **8.3** | 安全支持期 | 2025-11 结束 | **2027-12-31** | ✅ **安全底线**(最成熟) |
| **8.4** | 主动支持期 | 2026-12-31 | **2028-12-31** | ✅ **推荐落地目标**(安全跑道最长且经过一年验证) |
| 8.5 | **最新稳定**(8.5.7,2026-06-04) | 2027 末 | 2029 末 | 跑道最长但偏新,作为"打通 8.5 即未来无忧"的验证项,不作首发落地 |

**选型建议:以 8.3 为兼容底线先打通(最成熟),落地首发选 8.4(安全支持到 2028、生态已充分跟进),并把 8.5 纳入 CI matrix 做前瞻验证。** 不建议legacy CMS 首发直接上 8.5。

---

## 四、技术债务清单(按"是否阻塞 PHP8"分级)

图例:🔴 阻塞/必须处理 · 🟠 需验证·有概率运行期告警或边界断 · ⚫ 结构性债务(不直接阻塞升级,但放大升级工作量/风险)

### 🔴 P0 — 升级硬阻塞

| # | 债务 | 影响 | 证据 / 定位 | 处理方向 |
|---|---|---|---|---|
| P0-1 | **依赖全量 vendored,无 composer 管理** | 无法 `composer update` 升级框架/库;每个升级=手工换文件、易漏 | 根目录**无** `composer.json`;`thinkphp/`、`vendor/topthink/*`、`vendor/karsonzhang/*` 均为提交进仓库的目录 | 引入根 `composer.json` 锁定版本(即使仍 vendor,也要有清单),把"哪些库、什么版本、为何 patch"写成可追溯账本 |
| P0-2 | **TP5.0 DI 反射用 `ReflectionParameter::getClass()`** | PHP 8.0 起 `E_DEPRECATED`(8.x 仍可用,但每次依赖注入都刷告警;9.0 将移除) | `thinkphp/library/think/App.php:403` `$class = $param->getClass();`(`bindParams`/`getParamValue` 路径,控制器/方法注入必经) | 改 `$param->getType()` + `ReflectionNamedType`/`ReflectionUnionType` 取类名(社区标准 TP5.0-PHP8 补丁) |

### 🟠 P1 — 第三方库与运行期告警面

| # | 债务 | 影响 | 证据 / 定位 | 处理方向 |
|---|---|---|---|---|
| P1-1 | **内置 Guzzle 6.x(非 PHP8-clean)** | Upyun 又拍云存储 SDK 依赖,Guzzle 6 在 PHP8 有兼容问题 | `extend/upyun/vendor/guzzlehttp/guzzle/composer.json` 声明 `php >=5.5`、`psr7 ^1.4`、`promises ^1.0`(=Guzzle 6 系) | 升 Guzzle 7;或若未启用又拍云,**抽象/移除**该 extend 以缩小升级面 |
| P1-2 | **5 个 vendored topthink 组件(TP5.0 era)** | `think-captcha / think-helper / think-image / think-queue / think-installer`,均需逐个验证 PHP8 兼容 | `vendor/topthink/*` | 逐个跑 PHP8 deprecation 扫描,必要时打补丁或换等价实现(尤其 captcha 用 GD、image 用 GD) |
| P1-3 | **`ArrayAccess`/`Countable` 实现无 `#[\ReturnTypeWillChange]`** | PHP 8.1 对内置接口方法返回类型缺失会 `E_DEPRECATED`;命中**热路径** | `thinkphp/library/think/Model.php`、`Collection.php`、`Paginator.php` 实现接口,全树 `ReturnTypeWillChange` 命中数 **0** | 给 `offsetGet/offsetSet/offsetExists/offsetUnset/count` 等补 `#[\ReturnTypeWillChange]` 或正确返回类型 |
| P1-4 | **`PclZip` 用已移除的 `ereg()`** | PHP 7.0 起 `ereg()` 已移除,命中即 Fatal(仅当走 `PCLZIP_OPT_BY_EREG` 选项分支) | `application/common/util/PclZip.php:3397`、`:4778` | 改 `preg_match`;或确认该选项分支不可达后加注释/移除 |
| P1-5 | **`get_magic_quotes_*`(已移除,但被守卫)** | PHP 8.0 起函数已移除;现有 `function_exists()` 守卫使其**安全但为死代码** | `application/common/extend/pay/Alipay.php:119`、`PclZip.php:5333/5344/5367` | 直接删除该分支(PHP8 下恒为 false) |
| P1-6 | **null 传非空内部参(8.1 deprecation)** | `htmlspecialchars/trim/strlen/...` 收到 null 在 8.1 起告警;本类问题量大、**只能运行期跑出来** | 业务遍布(`@` 错误抑制 **3250 处**会掩盖告警,排查更难) | 建立 8.x deprecation 基线日志,按出现频次收口;高频点加 `?? ''` 兜底 |

### ⚫ P2 — 结构性债务(不阻塞升级,但放大风险/成本)

| # | 债务 | 影响 | 证据 |
|---|---|---|---|
| P2-1 | **`common.php` god-file** | **4335 行 / 184 个函数(174 个 `mac_` helper)**,全局耦合,改一处易波及全站 | `application/common.php` |
| P2-2 | **几乎无类型签名** | 全 `application` 仅 **7 处**返回类型声明;升级时静态工具(PHPStan/Rector)发挥受限 | `application/**` 扫描 |
| P2-3 | **测试/CI 仅兜底级** | 现有 CI 只有 `php -l`(7.4)+ schema 装载断言,**无单元/集成测试**,升级缺少回归网 | `.github/workflows/ci.yml`、`tests/` |
| P2-4 | **`@` 错误抑制 3250 处** | 在 PHP8 下会掩盖大量 deprecation/类型告警,delay 暴露问题 | `application/extend/addons` 扫描 |

---

## 五、误报澄清(先看这节,避免白干)

静态扫"被移除函数"时有几类**高频误报**,如果照单全改会做无用功甚至改坏:

| 看似命中 | 实为 | 证据 | 结论 |
|---|---|---|---|
| `each(` ×4 | **GuzzleHttp\Promise 命名空间内的自定义函数**,非被移除的全局 `each()` | `extend/upyun/vendor/guzzlehttp/promises/src/functions.php:2` `namespace GuzzleHttp\Promise;` + `:346 function each(...)`,调用处 `return each(` 解析到本命名空间函数 | PHP8 安全,**不要动** |
| `split(` ×多处 | **变量闭包 `$split`**(包装 `preg_split`),非被移除的 `split()` | `application/common.php:151` `$split = function ($raw, $pattern){ ... preg_split(...) }`;`application/api/controller/Payment.php` 同名变量调用 | PHP8 安全,**不要动** |
| `$x{...}` 花括号下标 | 全树 **0 命中** | `application/extend/addons` + `thinkphp/vendor` 扫描 | 无此 8.0 Fatal 风险 |
| `create_function/mysql_*/mcrypt_*/money_format/strftime` | 全树 **0 命中** | 同上 | 无此类债务 |

> 真正要改的 removed-function 只有 **§4 P1-4 的 `ereg()`** 一处家族。

---

## 六、升级路线对比与建议

### ✅ 路线 A:渐进打补丁(推荐)

> 思路:**不动框架架构,只让它在 PHP8 下安静且正确地跑**,再把运行时抬到 8.3/8.4。

- 优点:工作量可控、可灰度、随时可回滚到 7.4;与本仓库"持续打补丁"的既有节奏(A/B 系列 debt commit)一致。
- 缺点:框架仍是 EOL,属于"延寿"而非"换心";需把所打补丁记成账本以便将来迁移。
- 适用:**现在就要上 PHP8、且不想停站重做**——即本项目的处境。

### ❌ 路线 B:升级到 TP6/TP8(暂不推荐)

- TP6/8 是**重架构**(`Container`/中间件/门面/严格类型/目录结构全变),与 TP5.0 不二进制兼容也不源码兼容。
- maccms 深度耦合 TP5.0:`Db::`/`Model` 用法、`View` 模板引擎与自定义标签、`behavior` 钩子(`Begin.php`/`Init.php`)、`common.php` 174 个全局 helper、`addons` 机制(fastadmin-addons)。迁移≈重写整站 + 重测全部插件/模板。
- 建议:**作为 12+ 个月的长期目标**单列,不与本次 PHP8 升级捆绑。先用路线 A 脱离 7.4 EOL,买出时间。

---

## 七、路线 A 分阶段落地

### 阶段 0 — 准备与基线(不改业务,先看清楚)
1. **统一版本契约**:`index.php` 的 `version_compare` 下限、`thinkphp/composer.json` 的 `php` 约束、`tests/README` 说明,统一改成本次确定的目标(见 §9-①)。
2. **建 PHP8 CI matrix**:在现有 `ci.yml` 的 `php-lint` 增加 `8.1 / 8.3 / 8.4`(可先 `continue-on-error`,只观测不卡门)。`php -l` 只抓解析错,**抓不到 deprecation**——所以还要↓。
3. **跑出 deprecation 基线**:用 PHP 8.3 容器跑全站冒烟(首页/列表/详情/搜索/播放/后台 CRUD/采集/支付回调/插件),`error_reporting=E_ALL`、`display_errors=Off`、`log_errors=On`,把 `E_DEPRECATED` 收集成清单。**这是后续所有工作的输入。**

### 阶段 1 — 框架补丁(P0-2 / P1-3)
4. 打 **`App.php:403` `getClass()` → `getType()`** 兼容补丁(社区有现成 TP5.0-PHP8 patch 可参照)。
5. 给 `Model`/`Collection`/`Paginator` 的 `ArrayAccess/Countable` 方法补 `#[\ReturnTypeWillChange]`。
6. 按基线清单处理框架内其余高频 deprecation。

### 阶段 2 — 第三方依赖(P0-1 / P1-1 / P1-2)
7. 引入根 `composer.json` 作为**依赖账本**(锁版本 + 记录 patch)。
8. **Guzzle 6 → 7**(或评估是否仍需 Upyun extend,不需则移除)。
9. 逐个验证 `vendor/topthink/*` 5 组件在 8.3 下的告警并处理。

### 阶段 3 — 业务代码收口(P1-4/5/6)
10. `PclZip` 的 `ereg()` → `preg_match`;删除 `get_magic_quotes_*` 死分支。
11. 按基线清单收口 null-传非空 高频点(`?? ''`/类型兜底);**注意 3250 处 `@` 抑制会掩盖问题**,排查时临时去抑制更易暴露。

### 阶段 4 — 切换与灰度
12. `docker/Dockerfile` `php:7.4-apache` → `php:8.3-apache`(或 8.4),`CI` 默认版本同步抬升,保留 7.4 job 一段时间做对照。
13. 灰度:先内网/预发跑 8.3 → 观察日志零新增 deprecation → 切 8.4。回滚即切回 7.4 镜像。

---

## 八、工作量与里程碑(粗估)

| 阶段 | 主要产出 | 粗估 | 风险 |
|---|---|---|---|
| 0 基线 | 版本契约统一 + PHP8 CI matrix + deprecation 清单 | 1–2 人日 | 低 |
| 1 框架补丁 | TP5.0.25 PHP8 兼容补丁集 | 2–4 人日 | 中(热路径,需回归) |
| 2 依赖 | composer 账本 + Guzzle7 + topthink 验证 | 2–5 人日 | 中(看是否动 Upyun) |
| 3 业务收口 | ereg/magic_quotes 清理 + null 收口 | 3–8 人日 | 量大但单点低危,依基线规模 |
| 4 切换 | 镜像/CI 切 8.3→8.4 + 灰度 | 1–2 人日 | 中(灰度可控) |

> 合计约 **9–21 人日**,主要变量是阶段 3 的 deprecation 规模(取决于基线清单大小)与是否升级 Upyun/Guzzle。**不含**路线 B(TP6/8 重写)。

---

## 九、本周可立即做的 5 件事(低风险、零业务改动)

1. **统一版本契约**:确定目标版本后,改 `index.php:11` 的下限断言 + `thinkphp/composer.json` 的 `php` 约束 + `tests/README.md` 说明,消除 5.4/5.5/7.4 三处打架。
2. **CI 加 PHP 8.3 lint job**(`continue-on-error: true` 先观测):立刻能看到哪些文件连 `php -l` 都过不了。
3. **跑一次 8.3 冒烟出 deprecation 基线**:用 `docker run php:8.3` 挂载代码跑首页/后台,`log_errors` 收集——这是后面所有排期的依据。
4. **清死代码**:删 `get_magic_quotes_*` 分支(PHP8 恒 false),改 `PclZip` 的 `ereg()` → `preg_match`(§4 P1-4/5)。
5. **打 `App.php` getClass 补丁**(§4 P0-2):一处改动消除 DI 路径全量 deprecation,收益最高、风险集中可测。

---

## 附:本次分析的关键数据来源

- 框架/依赖版本、扫描计数、文件行号:均来自本仓库 HEAD 静态扫描(命令见各 §证据列)。
- PHP 版本与 EOL 时间线(2026-06 实况)联网核验:
  - [PHP.Watch — Supported Versions](https://php.watch/versions)
  - [HeroDevs — PHP End-of-Life Dates (2026)](https://www.herodevs.com/blog-posts/php-end-of-life-dates-support-timeline-for-every-version-2026)
  - [endoflife.ai — PHP EOL (7.0–8.5)](https://endoflife.ai/article-php-eol)
  - [Cloudways — PHP Version History (2026 Update)](https://www.cloudways.com/blog/php-version-history/)
