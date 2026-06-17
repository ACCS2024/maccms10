# 苹果CMS (maccms10) 直升 PHP 8.5 —— 三方依赖兼容性审计

- **审计目标**:按"直接全量升到 **PHP 8.5**(最新稳定,8.5.7 / 2026-06)"的方案,逐个核验三方依赖**哪些支持、哪些不支持**,并标出**可低成本移除**项
- **审计对象**:本仓库 HEAD(maccms10,ThinkPHP 5.0.25,当前线上 PHP 7.4)
- **审计日期**:2026-06-17
- **审计方式**:全树依赖测绘(`thinkphp/`+`vendor/`+`extend/`+`application/common/util`+`pay`)+ 版本提取 + **逐库被引用情况(用没用)扫描** + 上游 PHP 8.5 支持联网核验 + 跳级弃用面量化
- **配套**:升级总策略见 `PHP_UPGRADE_PLAN.md`;本文是其中"第三方库"维度的落地审计
- **状态**:分析交付,**未改动业务代码**

---

## 〇、结论先行(必读)

1. 全树第三方依赖共 **17 类**,已逐个核验(矩阵见 §2)。
2. **可低成本移除 4 项**(`think-queue`、`think-installer`、`extend/aws`、以及按配置可去的 `extend/upyun`/`extend/qiniu`)。移除收益极高:**直接砍掉最棘手的 Guzzle 6 包袱**(Upyun 内置)、干掉一个**已经损坏的 S3 驱动**,缩小 ~1.2MB + 200+ 文件的升级面。
3. **必须保留 + 自行打补丁的核心 9 项**,以 **ThinkPHP 5.0.25** 为首。
4. **需原地升级的维护中库 2 项**:PHPMailer(易,升完即支持 8.5)、Qiniu SDK(如保留)。

> ⚠️ **直升 8.5 的现实提示(非反对,只是把账说清)**
> PHP 8.5 是 **2025-11 才发布的最新版**。本项目依赖链里**没有任何一个上游声明支持 8.5**——连现代的 TP6/TP8、Qiniu SDK 最新版,**官方也只验证到 ~PHP 8.1**(见 §5 来源)。
> 好消息:**8.5 相对 8.4 没有大批"移除"**,主要是**新增弃用**,所以"能跑起来"问题不大;实测本仓库**几乎没有会直接 Fatal 的已移除语法**(唯一的 `ereg()` 是死路径,见 §4-K)。
> 但"**8.5-clean**"基本等于"**我们自己验证 / 打补丁**",不是"上游背书"。
> **建议(同一条路线分两步,不是另起炉灶):先在 PHP 8.4 上验证**(这是依赖普遍支持的最高版本)**→ 弃用日志归零 → 再切 8.5**。这样出问题时能区分"是 8.x 通病"还是"8.5 独有"。

---

## 一、第三方依赖全景清单(17 类)

| # | 组件 | 位置 | 版本 | 体量 | 是否启用 | 类型 |
|---|---|---|---|---|---|---|
| 1 | **ThinkPHP** | `thinkphp/` | **5.0.25**(EOL) | — | 必用(核心) | 框架 |
| 2 | topthink/think-helper | `vendor/topthink/think-helper` | TP5.0-era 1.0.x | 小 | 框架内部用 | 组件 |
| 3 | topthink/think-captcha | `vendor/topthink/think-captcha` | TP5.0-era 1.0.x | 小 | ✅ 用(登录/注册验证码) | 组件(GD) |
| 4 | topthink/think-image | `vendor/topthink/think-image` | TP5.0-era 1.0.x | 小 | ✅ 用(缩略图/水印/二维码) | 组件(GD) |
| 5 | topthink/think-queue | `vendor/topthink/think-queue` | TP5.0-era | 156K | ❌ **0 引用** | 组件 |
| 6 | topthink/think-installer | `vendor/topthink/think-installer` | — | 32K | ❌ 仅 composer 构建期 | composer 插件 |
| 7 | karsonzhang/fastadmin-addons | `vendor/karsonzhang/...` | **1.1.11**(php>=7.0) | 小 | ✅ 用(插件系统) | 组件 |
| 8 | PHPMailer | `extend/phpmailer` | **6.0.3**(2018) | 416K | ✅ 用(邮件) | 库 |
| 9 | Qiniu SDK | `extend/qiniu` | **7.2.2**(2018) | 148K | ⚙️ 选配(七牛存储) | 库 |
| 10 | Upyun SDK + **内置 Guzzle 6** | `extend/upyun` | Guzzle `^6`(php>=5.5) | **1012K** | ⚙️ 选配(又拍云存储) | 库 |
| 11 | AWS SDK(S3) | `extend/aws` | **缺失**(仅 51 字节 autoload) | ~0 | ⚙️ 选配但**已损坏** | 库 |
| 12 | 社交登录 SDK | `extend/login` | 自带(ThinkOauth/QQ/微信) | 24K | ✅ 用(第三方登录) | 库 |
| 13 | IP 归属查询 | `extend/ip_limit` | 自带 + .dat | 1.5M | ✅ 用(IP 地域) | 库+数据 |
| 14 | **PclZip** | `application/common/util/PclZip.php` | 古老(~2.8) | **197K** | ⚙️ 仅 `Update.php` 用 | 库 |
| 15 | **PHPQRCode** | `application/common/util/Qrcode.php` | 古老(~2010) | **118K** | ✅ 用(支付/登录二维码) | 库 |
| 16 | Pinyin | `application/common/util/Pinyin.php` | 自带 | 小 | ✅ 用(拼音别名,大量) | 库 |
| 17 | 支付集成 | `application/common/extend/pay/*` | 自带(支付宝/微信/易支付等) | 小 | ✅ 用 | 集成代码 |

> 依赖管理现状:**无根 `composer.json`、无 `composer.lock`**,全部为**手工提交进仓库的目录**。所以下面每一项的"升级/移除"都得**手工换文件**,这也是为什么"能少一个是一个"。

---

## 二、PHP 8.5 兼容性矩阵(核心)

图例:✅ 可用 · ⚠️ 需打补丁/验证(能跑,会刷弃用或边界问题) · ❌ 不可用(必须升级或移除) · 🗑️ 建议移除

| 组件 | 用没用 | PHP 8.5 状态 | 判定 | 依据 / 关键风险点 |
|---|---|---|---|---|
| **ThinkPHP 5.0.25** | 必用 | ⚠️ 非 8.5-clean,但**无 Fatal 阻断** | **保留+打补丁** | `App.php:403` `getClass()`(8.0 弃用);`Model/Collection/Paginator` 实现 `ArrayAccess/Countable` 但 `ReturnTypeWillChange` 命中 **0**(8.1 弃用);隐式可空参 **27** 处(8.4 弃用) |
| think-helper | 框架内部 | ✅ 基本可用 | 保留+验证 | 纯函数 helper,风险低 |
| think-captcha | ✅ | ⚠️ TP5.0-era | 保留+打补丁 | GD 验证码;旧版有 8.x 弃用,需验证 |
| think-image | ✅ | ⚠️ TP5.0-era | 保留+验证 | GD;注意 8.0 起 `imagecreate*` 返回 `GdImage` 对象(未发现 `is_resource()` 误判,风险较预期低) |
| **think-queue** | ❌ 0 引用 | — | 🗑️ **移除** | 全 `application` 零引用,纯死重量(156K) |
| **think-installer** | ❌ 构建期 | — | 🗑️ **移除** | composer 安装插件,运行期无用;项目又不用 composer |
| fastadmin-addons 1.1.11 | ✅ | ⚠️ 声明 php>=7.0,**无 8.5 背书** | 保留+打补丁 | 插件加载器,TP5.0/5.1 era,需随框架一起验证 8.5 弃用 |
| **PHPMailer 6.0.3** | ✅ | ❌ 太旧 → ✅ **升级即支持 8.5** | **升级** | 最新 6.9.x:8.4 完整支持、**8.5 实验性支持**(官方 changelog) |
| Qiniu 7.2.2 | ⚙️ 选配 | ⚠️ 旧;最新 7.14 也仅验证到 ~8.1 | **升级 或 移除** | 不提供七牛存储则移除;提供则升 7.14(并自测 8.5) |
| **Upyun + Guzzle 6** | ⚙️ 选配 | ❌ **Guzzle 6 非 8.x-clean** | 🗑️ **移除(首选)/ 否则升 Guzzle 7** | 1012K 里裹着 Guzzle 6;移除又拍云驱动可**一举消除整个 Guzzle 6 包袱** |
| **AWS / S3** | ⚙️ 选配但**坏的** | ❌ `aws.phar` **缺失**,`require` 即 Fatal | 🗑️ **移除(首选)/ 需要则用 composer 正经引 AWS SDK v3** | `extend/aws/autoload.php` 指向不存在的 `src/Aws/aws.phar`;S3 驱动**当前就是坏的** |
| 社交登录 SDK | ✅ | ⚠️ 自带、curl 实现 | 保留+验证 | 量小,主要看隐式可空参/字符串下标 |
| IP 归属查询 | ✅ | ⚠️ pack/unpack/字符串下标 | 保留+验证 | 二进制 .dat 解析,注意 8.x 字符串偏移/null 处理 |
| **PclZip** | ⚙️ 仅 Update | ⚠️ 含已移除 `ereg()`,但**死路径** | **替换为 ZipArchive(推荐)/ 否则补 `ereg`** | `ereg()` 在 `PclZip.php:3397/4778`,但**全树无 `PCLZIP_OPT_BY_EREG` 调用方**→运行期不触发;项目已在别处用 `ZipArchive` 且 Docker 装了 `zip` 扩展 |
| **PHPQRCode** | ✅ | ⚠️ 古老(~2010) | 保留+打补丁 | 静态缓存/隐式可空参等老写法,需在 8.5 跑出弃用清单 |
| Pinyin | ✅ 大量 | ⚠️ 自带 | 保留+验证 | 拼音别名,使用面广,优先回归 |
| 支付集成 | ✅ | ⚠️ 含 `get_magic_quotes_gpc`(被守卫) | 保留+打补丁 | `Alipay.php:119` 死分支(8.0 起函数已移除,`function_exists` 守卫恒 false),直接删 |

---

## 三、可低成本移除清单(净收益,优先做)

> "代价低"= 未启用 / 已损坏 / 有内置替代,移除**不影响在用功能**,且**直接缩小 8.5 兼容面**。

| 移除项 | 为什么可移除 | 移除收益 | 风险 / 前置条件 |
|---|---|---|---|
| 🗑️ `vendor/topthink/think-queue` | 全 `application` **零引用** | -156K,少一个 TP5.0-era 组件要验 | 无;确认无计划任务/异步依赖即可 |
| 🗑️ `vendor/topthink/think-installer` | composer 安装期插件,**运行期不加载**;项目本就不用 composer | 去构建期噪音 | 无 |
| 🗑️ `extend/aws`(S3 驱动) | `aws.phar` **缺失**,S3 上传**当前就是坏的**(选了即 Fatal) | 去一个诈尸驱动 + 去 AWS SDK 升级负担 | 若确实要 S3:改用 composer 引 `aws/aws-sdk-php` v3(支持 8.x)并修 `upload/S3.php` |
| 🗑️ `extend/upyun`(含 Guzzle 6) | 又拍云为**选配存储**,默认本地上传不需要 | **-1012K,且一举消除整个 Guzzle 6(8.x 主要包袱)** | 前置:确认线上未启用又拍云存储;启用则改为升 Upyun SDK→Guzzle 7 |
| 🗑️ `extend/qiniu`(选配) | 七牛为**选配存储** | -148K,少一个旧 SDK | 前置:确认未启用七牛;启用则升 7.14 |
| ➜ `PclZip` 换 `ZipArchive` | 仅 `Update.php` 一处用;项目已用 `ZipArchive`、Docker 已装 `zip` | **-197K 古老库 + 去掉 `ereg()`/`get_magic_quotes` 两类历史债** | 代价"中":需改 `application/admin/controller/Update.php` 的解压逻辑并回归"在线更新" |

**一句话**:把上面前 5 项(尤其 upyun + aws)清掉,8.5 升级里"最脏的两块"(Guzzle 6、坏 S3)直接消失,剩下的就是"自家代码 + TP5.0 + 几个小库打补丁"。

---

## 四、必须保留 + 打补丁清单(逐项给修法)

**K. ThinkPHP 5.0.25(核心,先打这个)**
- `thinkphp/library/think/App.php:403` 的 DI 反射:
  ```php
  // 旧(8.0 起 E_DEPRECATED):
  $class = $param->getClass();
  // 新(8.x/8.5 安全):
  $type  = $param->getType();
  $class = ($type && !$type->isBuiltin()) ? new \ReflectionClass($type->getName()) : null;
  ```
- `Model.php` / `Collection.php` / `Paginator.php` 实现的 `offsetGet/offsetSet/offsetExists/offsetUnset/count` 等,补 `#[\ReturnTypeWillChange]`(消 8.1 弃用)。
- 框架内 **27 处隐式可空参**(`Type $x = null` 未写 `?Type`),按 8.4 弃用收口(可用 Rector `php84` 规则批量)。

**think-captcha / think-image**:在 8.5 容器跑验证码生成 + 缩略图/水印,按弃用日志补 `#[\ReturnTypeWillChange]` / GD 调用。

**fastadmin-addons 1.1.11**:随框架一起在 8.5 跑插件安装/卸载/渲染,补弃用(无上游 8.5 版本可换,只能自维护)。

**PHPQRCode(`util/Qrcode.php`)**:在 8.5 跑支付二维码/登录二维码,补隐式可空参 + 静态缓存写法;如愿引 composer 可换 `endroid/qr-code`(成本中)。

**社交登录 / IP 归属 / Pinyin**:量小,做冒烟 + 按弃用日志收口即可。

**支付集成**:删 `Alipay.php:119` 的 `get_magic_quotes_gpc` 死分支;其余按弃用日志收口。

**PclZip(若不换 ZipArchive)**:把 `PclZip.php:3397/4778` 的 `ereg()` 改 `preg_match`(虽是死路径,但留着碍眼且未来 9.0 风险)。

---

## 五、需升级的维护中库(有上游新版可用)

| 库 | 现状 | 升级目标 | 8.5 支持 | 备注 |
|---|---|---|---|---|
| PHPMailer | 6.0.3(2018) | **6.9.x 最新 6.x** | 8.4 完整 / **8.5 实验性** | 同 6.x 大版本,**接口兼容、近乎 drop-in**,性价比最高 |
| Qiniu SDK(如保留) | 7.2.2(2018) | **7.14.0** | 官方验证到 ~8.1,需自测 8.5 | 不提供七牛存储就直接移除,别升 |
| Upyun(如保留) | 内置 Guzzle 6 | Upyun 新版(拉 Guzzle 7) | Guzzle 7 支持 8.x | 不提供又拍云就直接移除,收益更大 |

---

## 六、跳级 8.0→8.5 一次承受的"弃用浪潮"量化

直升意味着把 8.0–8.5 的弃用**一次性**全吃下。实测本仓库的面是:

| 类别(引入版本) | 性质 | 本项目命中 | 处置 |
|---|---|---|---|
| 已移除语法/函数(8.0/7.x) | **Fatal** | **几乎为 0**:`ereg()` 唯一命中且为**死路径**;无 `$x{}`、`each()`、`create_function`、`mysql_*`、`strftime` | 低危,清理即可 |
| `ReflectionParameter::getClass()`(8.0) | 弃用 | TP `App.php:403`(DI 必经) | §4-K 补丁,一处解决 |
| `ArrayAccess/Countable` 返回类型(8.1) | 弃用 | TP `Model/Collection/Paginator`,`ReturnTypeWillChange`=0 | 补属性 |
| 动态属性(8.2) | 弃用 | TP 多数类有 `__set` 魔术方法兜底;散落赋值需运行期跑 | 跑基线 |
| 隐式可空参 `=null`(8.4) | 弃用 | 框架 **27** + 业务 **7** | Rector 批量 |
| 8.5 新增弃用 | 弃用 | 少量(8.5 以新增弃用为主、移除少) | 跑基线 |
| `@` 错误抑制 | **掩盖以上弃用** | **3250** 处 | 验证期临时去抑制,否则看不到问题 |

> 关键判断:**没有大面积 Fatal 阻断**,主要工作量在"**弃用清零**"——而弃用清零的前提是**能把它们打印出来**(`error_reporting=E_ALL`、`display_errors=Off`、`log_errors=On`,且绕开那 3250 处 `@`)。

---

## 七、执行顺序(先减后补,降低返工)

1. **先减面**:删 `think-queue`、`think-installer`、`extend/aws`;确认存储配置后删 `extend/upyun`、`extend/qiniu`。→ 最脏的 Guzzle 6 / 坏 S3 直接消失。
2. **升易升的**:PHPMailer 6.0.3 → 6.9.x(drop-in)。
3. **打核心补丁**:TP5.0.25(getClass + ReturnTypeWillChange + 隐式可空参);删支付/PclZip 的死分支。
4. **建基线**:`docker` 起一个 **PHP 8.4** 镜像跑全站冒烟(首页/列表/详情/搜索/播放/后台 CRUD/采集/支付回调/插件/二维码/拼音),收集弃用日志。
5. **逐项清零**:captcha/image/addons/Qrcode/Pinyin/login/ip_limit/pay 按日志收口;CI 增 `8.4` + `8.5` lint matrix。
6. **切换**:8.4 灰度、弃用归零 → **切 8.5**;`docker/Dockerfile` `php:7.4-apache` → `php:8.4-apache` →(稳定后)`php:8.5`。保留 7.4/8.4 job 一段时间对照,回滚即切镜像。

---

## 附:关键来源

- 依赖版本、引用计数、文件行号:本仓库 HEAD 静态扫描(命令见各证据列)。
- 上游 PHP 版本支持联网核验(2026-06):
  - PHPMailer 支持 8.4/实验性 8.5:[PHPMailer changelog](https://github.com/PHPMailer/PHPMailer/blob/master/changelog.md) · [Releases](https://github.com/phpmailer/phpmailer/releases)
  - Qiniu php-sdk v7.14、验证到 ~8.1:[qiniu/php-sdk Releases](https://github.com/qiniu/php-sdk/releases)
  - `ReflectionParameter::getClass()` 8.0 弃用与替代写法:[PHP.Watch](https://php.watch/versions/8.0/deprecated-reflectionparameter-methods)
  - 各版本 BC / 弃用速查(8.0–8.5):[php-changes-cheatsheet (incompatible)](https://eusonlito.github.io/php-changes-cheatsheet/incompatible.html) · [(deprecated)](https://eusonlito.github.io/php-changes-cheatsheet/deprecated.html)
  - PHP 版本/EOL 时间线:[PHP.Watch Versions](https://php.watch/versions)
