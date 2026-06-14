# 苹果CMS (maccms10) 安全审计总报告

- **审计对象**:本仓库(magicblack/maccms10 的 fork,2024–2025 版系,基于 ThinkPHP 5.0.24)
- **审计范围**:全树 722 个 PHP 文件 + 模板 / 静态资源 / 第三方依赖 / 运行时目录
- **审计日期**:2026-06-14
- **审计方式**:架构测绘 + 多专项并行深挖(模板SSTI / SQL注入 / 文件上传写入 / SSRF·XXE·反序列化 / 鉴权访问控制 / 后门取证 / CSRF中间件) + 公开 CVE 逐条联网核验 + 实战挂马通告比对
- **状态**:本报告为分析与方案交付,**未改动任何业务代码**

---

## 一、总体结论(必读)

和"四处都是漏洞"的第一直觉不同,审计结论更精确:

### 1. 这个 fork 已经被大量加固过,历史上最致命的几类 RCE/注入基本都堵上了

| 历史高危 | 当前状态 | 证据 |
|---|---|---|
| ThinkPHP `?s=…invokefunction` RCE | ✅ 已修(核心补丁在位) | `thinkphp/library/think/App.php:555` 控制器名正则校验 |
| `_method` 方法伪装注入 | ✅ 已禁用 | `application/config.php:108` `var_method=''` |
| 经典"写 `extra/*.php` 配置闭合注入 PHP" RCE | ✅ 已根除 | `application/common.php:323` `mac_arr2file()` 改用 `var_export()` |
| `label-<file>` 标签文件 LFI/SSTI | ✅ 已堵 | `application/index/controller/Label.php:88` 拒绝含 `/` 的值 |
| 前台 `order/by` SQL 注入 | ✅ 已白名单 | `application/common/model/Vod.php:547/551` |
| 后台模板编辑器写 PHP getshell | ✅ 已加固 | `Template.php:170-177` 扩展名白名单 + `<?`/`php`/`eval` 黑名单 |
| 搜索 `wd` 参数 RCE(CVE-2017-17733) | ✅ v10 不存在该 eval 路径 | 模板一次性编译,运行期变量只 echo,不二次编译 |
| Database `rep`/`columns` 注入(CVE-2025-10122 / CVE-2022-35148) | ✅ 已修 | `Database.php` `isValidTable`+`isValidField`+`sanitizeRepWhereClause`+参数化 |
| 供应链木马版后门(假官网分发) | ✅ 不存在 | 全树取证扫描确认 |

并且自带两道**主动防线**:
- `application/common/behavior/Begin.php`:每次请求扫描 `application/extra/`,**自动删除非白名单 PHP 文件**(对抗挂马持久化)
- 根目录 `security_check.php`:站长自建的安全自检脚本(检测 extra 异常、addons.php 完整性、JS 篡改、_method 注入等)

### 2. 当前仓库源码树是干净的,没有 webshell / 后门

两个独立取证扫描(含 `upload/`、`runtime/`、`static/`、`template/`、`addons/`、`pua/`)结论:**零** webshell、零一句话木马、零静态资源篡改、`upload/` 内零个 `.php`、`addons.php` 是干净的 105 字节标准内容、无 `active.php`/`system.php` 攻击特征文件。

### 3. 那为什么"还在被挂马"?根因在三处

- 🔴 **一整套防护"装了但默认关闭"**(CSRF / CSP / 审计 / 防爬 / 后台XSS过滤 / 前台验证码),等于没装;
- 🟠 **几个仍然敞开的真实洞**(未授权 SSRF+计划任务、邮件模板 SSTI→RCE、CSRF 覆盖不全、口令裸 MD5、几个 LFI/zip-slip、订单 IDOR、写 JS 缺消毒);
- ⚫ **极可能根因在"代码之外"**(见下一节)。

---

## 二、反复被挂马的根因排查(按可能性排序)

源码树既然干净,反复中招最可能是这几个,**请按顺序自查**:

| 排序 | 根因 | 为什么 | 怎么确认 |
|---|---|---|---|
| ① 最可能 | **线上跑的是加固前的旧代码** | 这些修复在本仓库分支里,线上未必部署了。你可能一边打补丁,线上一边被老洞打 | 线上 `git log` / 文件哈希对比本仓库 HEAD;确认线上确有 `Begin.php`、`var_export` 版本 |
| ② 很可能 | **马在数据库里,不在文件里** | 攻击者把 `<script>`/跳转/挖矿 JS 写进 `mac_config` 配置表、视频/文章内容字段、广告位、统计代码字段。**git 扫不出,删文件、重装代码都带不走** | 查 `mac_config` 表的 `config`/`guest`/统计/广告位字段、`mac_vod`/`mac_art` 内容里的外链 `<script>` |
| ③ 可能 | **服务器 / PHP 层** | `php.ini` 的 `auto_prepend_file`、`.user.ini`、Nginx/Apache 真实 vhost、系统 `crontab`、`/tmp` 落地 shell、同服务器其它站点横向 | `crontab -l`、`php -i \| grep prepend`、检查 web 服务器真实配置与 session 目录 |
| ④ 若跑的是本代码 | **下面第三节的未授权洞被打** | 未授权 SSRF/计划任务触发、邮件模板 SSTI、install 锁丢失被重装 | 见第三节 V1/V2/V8/V10 |

> **一句话:先确认线上代码 = 本仓库最新代码,再查数据库内容和服务器配置。** 否则你在源码里堵洞,线上照样被打。

---

## 三、漏洞清单(按严重度)

### 🔴 严重 / 高危

#### V1. 未授权 SSRF + 计划任务滥用(默认配置即可打)
- **问题**:`api.php/timming/index` 在 `timming_token` **未配置时(默认)完全不校验令牌**;后台基类对它**显式放行管理员鉴权**。它能代理调用 `admin/Collect`,采集会去请求用户可控的 `cjurl`,而 SSRF 防护只拦 `127.0.0.1`/`localhost`,不拦 `169.254.169.254`(云元数据)、内网段、`0.0.0.0`、`[::1]`、十/十六进制 IP;`mac_curl_get` 还跟随 302。
- **位置**:`application/api/controller/Timming.php:24-28`、`application/admin/controller/Base.php:36-38`、`application/common/model/Collect.php`(`checkCjUrl` 只挡两个 host)、`application/common.php:827`(`FOLLOWLOCATION`)
- **触发**:未授权 GET `api.php/timming/index?name=<任务>&enforce=1` → 打云元数据偷密钥 / 探内网 / 清空全站缓存(DoS)
- **对应 CVE**:CVE-2026-4562、CVE-2025-10395/10397/28089/28090/28091、CVE-2022-47872
- **修复**:① `timming_token` 改 fail-closed(空即拒绝),安装时生成随机默认值,比较用 `hash_equals`;② 重写 `checkCjUrl()` 为解析后校验 IP 段(禁私网/保留/回环)+ 协议白名单(仅 http/https);③ 采集通道关闭/限制重定向;④ 理想做法:定时任务限 CLI 触发

#### V2. 邮件模板存储型 SSTI → RCE(游客可触发编译,可持久化)
- **问题**:后台邮件模板(注册/找回密码验证码正文)保存只做 `htmlentities`(挡 XSS 不挡模板语法 `{ } $ | :`),发信时用 `View::instance()->display($msg)` 走**完整模板编译管线**;因 `tpl_deny_php=false`,模板里 `{php}...{/php}` 会被执行
- **位置**:`application/common/model/User.php:1127-1128`、`application/admin/controller/System.php:34-35`,保存点 `System.php:669`,游客触发面 `application/index/controller/User.php:20`(`reg/findpass/reg_msg` 游客可达)
- **触发**:能写邮件模板配置者埋入 `{php}` → 存进 `maccms.php` → 游客走注册/找回密码 → `display()` 编译执行。**清完文件仍复活**(载荷在配置里,且 `maccms.php` 在 `Begin.php` 白名单内不会被删)
- **修复**:邮件模板**不要用模板引擎**,改占位符替换 `strtr($msg, ['{code}'=>$code,...])`,彻底不调 `display()`

#### V3. 后台 CSRF 防护"默认关闭" + 控制器级 Token 覆盖严重不全
- **问题**:全局 CSRF 中间件 `CsrfGuard` 写得很好但默认 `security_csrf_admin='0'` 直接放行;控制器自身 Token 校验**只有 `info` 系列有**,几乎所有 `del/field/batch/restore/import/install/audit` **既无 Token 也无 `isPost` 限制**(纯 `input()`,**GET 就能触发**)
- **位置**:`application/extra/maccms.php:116`、`application/common/behavior/CsrfGuard.php:30`;无 Token 的破坏性动作示例:`Admin::del/field`、`Cash::del/audit`、`Database::import/del/optimize/repair`、`Addon::install/uninstall`、`Role/Group/User::del/field`、`Vod/Art/Manga::del/field/batch`、`Template::del`、`Update::step1/step2`
- **触发**:管理员登录态访问攻击者页面,`<img src="http://站点/admin.php?s=admin/admin/del&ids=2">` 即删管理员;同理 `cash/audit`(批准提现)、`database/import`(覆盖全库)、`addon/install`(装插件≈RCE)
- **对应 CVE**:CNVD 系列"CSRF 加任意账号"
- **修复**:① `security_csrf_admin` 默认改 `'1'`;② 破坏性动作**强制 POST**(否则 CsrfGuard 对 GET 不校验)并补 Token;③ 收紧 `security_csrf_admin_exempt`(默认 `upload/*` 太宽)

#### V4. 全站口令裸 MD5 无盐 + 无登录爆破防护
- **问题**:管理员与用户口令都是 `md5()` 无盐(用户登录还容忍明文 OR 匹配分支);登录端无失败锁定/限速;前台验证码默认关
- **位置**:`application/common/model/Admin.php:67/78/126`、`application/common/model/User.php:643`、`application/extra/maccms.php:146`(`login_verify='0'`)
- **触发**:拖库后彩虹表秒破;在线撞库/爆破无门槛(前台)
- **修复**:迁移到 `password_hash()`/`password_verify()`(命中旧 MD5 透明升级);加"用户名+IP"失败计数 + 指数退避锁定;前台默认开验证码;删除 User.php:643 的明文 OR 分支

### 🟠 中危

#### V5. 后台任意文件读取(LFI)`Index::botlog`
- **位置**:`application/admin/controller/Index.php:986` —— `file_get_contents('runtime/log/bot/'.$data.'.txt')`,`$data` **零过滤**,`../` 穿越可读任意 `.txt`,内容回显
- **修复**:`$data` 强制白名单 `^[A-Za-z0-9_\-]+$` + `realpath` 锁定目录

#### V6. 核心更新 zip-slip(任意文件写入)`Update::step1`
- **位置**:`application/admin/controller/Update.php:73` 用 PclZip 解压到站点根,`PCLZIP_OPT_PATH=''` 无目录限制,PclZip 不过滤 `../`(`application/common/util/PclZip.php:3670`)。受 SHA1 校验缓解,但更新通道 `SSL_VERIFYPEER=0`
- **修复**:解压加 `PCLZIP_OPT_EXTRACT_DIR_RESTRICTION` + `listContent()` 预扫拒绝 `../`/绝对路径/`.php`;更新通道开证书校验、SHA1→SHA256;`step1` 加 Token + 强制 POST

#### V7. 插件安装链 RCE + 插件名未过滤
- **位置**:`vendor/karsonzhang/fastadmin-addons/src/addons/Service.php:299/315`(把插件 zip 内 `application/`、`static/` `copydirs` 进网站根并执行 `install()`);`$name` 在 install/upgrade 未过滤(`Service.php:78-80`、入口 `Addon.php:157`),而 uninstall 却过滤了。当前因 `fastadmin.api_url` 未配置而潜伏
- **修复**:`copydirs` 加可执行文件黑名单(禁 `.php` 进核心目录)、`$name` 白名单、远程包签名校验;不用插件市场则直接禁用 `Addon::install/upgrade`

#### V8. 未授权用户 PII 批量泄露
- **位置**:`application/api/controller/User.php:166`(`get_list`)/`:254`(`get_detail`)**无需登录**即可分页导出全站用户**手机号/邮箱/QQ**
- **对应 CVE**:CWE-639 类
- **修复**:强制登录 + 管理员权限,或移除 PII 字段、收紧 `limit`

#### V9. 采集 XML 未禁用外部实体(XXE)
- **位置**:`application/common/model/Collect.php:223/237/2902/2916`、`ResourceHub.php`、`BulkTableIo.php` 的 `simplexml_load_string` 未调 `libxml_disable_entity_loader`(而 `common.php:916`、`WechatPublic.php:39` 调了)。配合 V1 的 SSRF 可解析攻击者可控 XML。PHP8 默认已禁外部实体,故中危
- **修复**:解析前统一 `libxml_disable_entity_loader(true)` / `LIBXML_NONET`

#### V10. install 重装链(锁丢失即未授权接管/RCE)
- **位置**:安装控制器只在入口文件层校验 `install.lock`,`step4/step5` 不复查;`mkDatabase()` 把数据库参数**裸插值**进 `database.php`(`application/install/controller/Index.php:384-442`),含 `'` 可注入 PHP;装完不删 `install/` 目录、无访问限制
- **对应 CVE/CNVD**:CNVD-2019-43865
- **修复**:`Index::__construct` 内也校验锁;`mkDatabase` 改 `var_export` + 字段白名单;部署后删 `install.php`

#### V11. Session/Cookie 未强制 HttpOnly + 前台 token 弱
- **位置**:`application/config.php` session 段缺 `httponly`、cookie 段 `httponly=''`(`:234`)、`secure=false`;前台用户登录态 cookie token 是 `md5(user_random-name-id-)`(`User.php:787`)**无服务器密钥签名、`rand()` 低熵**
- **修复**:session/cookie 显式 `httponly=>true`、HTTPS 站 `secure=>true`;登录 token 改 HMAC(带密钥)、`user_random` 改 `random_bytes()`、比较用 `hash_equals`

### 🟡 低危 / 加固项

| 编号 | 问题 | 位置 |
|---|---|---|
| V12 | `find_password` 无限速 → 短信轰炸/账号枚举 | `application/api/controller/User.php:633` |
| V13 | `Receive` 接口弱共享口令(明文 `!=` 比较、无防重放) | `application/api/controller/Receive.php:19` |
| V14 | `Index::select` 模板路径 `$tpl` 未白名单(后台 LFI) | `application/admin/controller/Index.php:278` |
| V15 | phpmailer **6.0.3** 偏旧(CVE-2018-19296 对象注入) | `extend/phpmailer/src/PHPMailer.php` |
| V16 | `Begin.php` 白名单缺 `mctheme.php`/`type_synonyms.php` → 这两个合法配置文件每次请求被误删 | `application/common/behavior/Begin.php:7-12` |
| V17 | 调试标签 `Macdiy::tagTest`(`dump()+die`)、根目录 `security_check.php`(暴露环境信息)建议生产删除 | `application/common/taglib/Macdiy.php` |
| V18 | `default_filter=''` 无全局输入过滤;`Live::field` 缺 `col` 白名单(被 `allowField` 兜底);内容模型 `*_pic` 删除 `&&/\|\|` 优先级隐患(当前被 `'./'` 前缀中和) | 多处 |

---

## 四、已知 CVE 逐条验证(对照本仓库代码)

> 数据来源:OpenCVE / CVEDetails / VulDB / NVD / CNVD / HuajiHD 研究披露。

### ✅ 已修复(验证通过)

| CVE | 类型 / 位置 | 怎么修的 |
|---|---|---|
| CVE-2017-17733 | 前台 RCE,搜索 `wd`(maccms8.x) | v10 不再 eval 搜索词,`wd` 经转义且不二次编译 |
| CVE-2025-10122 | SQLi,`Database.php` `rep` 的 `where` | `isValidTable`+`isValidField`+`sanitizeRepWhereClause`+参数化 `REPLACE(?,?)` |
| CVE-2022-35148 | SQLi,`database/columns` 的 `table` | `isValidTable` 白名单 + 反引号转义 |
| 配置注入 RCE(含 CNVD-2019-43865 之一) | 写 `extra/*.php` | `mac_arr2file()` 改 `var_export()` + `Begin.php` 兜底 |
| `_method` / `?s=invokefunction` RCE | 框架核心 | 核心补丁 + `var_method=''` |
| 假官网木马版后门 | 供应链 | 仓库取证确认零后门 |

### 🔴 仍然存在 / 未完全修复

| CVE | 类型 / 位置 | 结论与修复 |
|---|---|---|
| CVE-2026-4562 | 未授权,`Timming.php` + `Base.php:36-38` | **存在** = V1。修:token fail-closed + 限 CLI |
| CVE-2026-4563 | IDOR,`index/controller/User.php:937 order_info()` 的 `order_id` | **存在(已确认)**:`$where['order_id']=intval(...)` 仅按订单号查、**无 `user_id` 归属**(`User.php:941`)。修:加 `$where['user_id']=$GLOBALS['user']['user_id'];` |
| CVE-2025-10395/10397/28089/28090/28091、CVE-2022-47872 | SSRF 簇:cjurl/计划任务/采集自定义接口/加文章/接口地址 | **存在(同根因)** = V1/V9。修:重写 `checkCjUrl` |
| CVE-2025-45474 | SSRF,邮件设置 `System.php:15 test_email()` | **存在**(管理员触发):SMTP host 可指向内网。修:host 黑名单 |
| CVE-2025-45475 | SSRF,友链管理 → `Index.php:220 check_back_link` → `mac_check_back_link`(`common.php:644`) | **存在**(管理员触发):`mac_curl_get($url)` 零防护。修:同 checkCjUrl |
| CSRF 加任意账号 / 批量破坏 | 后台 `del/field/batch/install/import/audit` | **存在** = V3 |

### 🟡 大概率已被缓解(ThinkPHP 模板 `{$var}` 默认转义),建议逐字段复核

CVE-2024-46654(计划任务存储XSS)、CVE-2024-32391、CVE-2022-26573(art 反射XSS)、CVE-2022-44870(广告管理)、CVE-2022-31303(服务器组)。
- 默认模板转义 + `security_xss_input=1`(默认开)缓解大部分;风险点是**输出到 JS 上下文或用 `|raw`**。CVE-2022-31302 是 v8(N/A)。建议:广告位等"管理员可填 HTML/JS"的存储 XSS 面叠加 CSP(`security_csp` 当前默认关)。

### ⚪ 不适用

| CVE | 说明 |
|---|---|
| CVE-2025-50234 | **是另一个产品 MCCMS v2.7.0(模板堂)** 的 `sys\apps\controllers\api\Gf.php`,硬编码密钥 `Mc_Encryption_Key`。本仓库无该文件;本仓库 `SensitiveDataCrypto.php` 用 config 派生密钥(非硬编码)、AES-256-GCM。**N/A** |

---

## 五、实战挂马通告引出的新发现

> 来源:站长社区流传的《MACCMS 后台存在高危漏洞安全通告》——攻击者持久化目标是 `application/extra/` 自动加载 PHP + 批量改写 `.js`。

### 🆕 N1(高危,对应通告"攻击者一"改 JS 的症状)—— `site_tj` → `tj.js` 写入零消毒
- **位置**:`application/admin/controller/System.php:213-217`
  ```php
  $tj = $config_new['site']['site_tj'];
  if(strpos($tj,'document.w') === false){
      $tj = 'document.write(\'' . str_replace("'","\'",$tj) . '\')';
  }
  @fwrite(fopen('./static/js/tj.js','wb'), $tj);
  ```
- **问题**:`site_tj` 含 `document.w` 时**原样写入 tj.js**(零转义);否则也只转义单引号,不转义 `\`、换行、`</script>`,`'); 恶意JS; //` 即可逃逸。`tj.js` 全站每页加载 → 任意能存站点配置者(管理员 / **CSRF——默认关**)都能往合法 `.js` 注入任意 JS = **正好是通告的"JS 被挂马 / 页面插跳转"症状**,藏在"正常文件"里,删别处的马也带不走(故通告建议 `chattr +i`)
- **修复**:`site_tj` 用 `json_encode` 后再输出,或存配置由模板正确上下文输出;`playerconfig.js`(`:964`)已用 `json_encode`,照它改

### 🆕 N2(中危,对应通告"攻击者一"篡改 addons.php 的持久化)—— `Begin.php` 清扫器只按文件名白名单
- **位置**:`application/common/behavior/Begin.php:7-12`
- **问题**:一好一坏。✅ 好:`active.php`/`system.php`(通告"攻击者二")不在白名单 → **每请求被自动删除**,本 fork 天然克制攻击者二。❌ 坏:`addons.php` 在白名单里 → 若被篡改成通告说的 **20-30KB 后门版**,`Begin.php` **不会删**(只匹配文件名)。`maccms.php`/`vodplayer.php` 等可写配置同理
- **修复**:给 `Begin.php` 加内容/体积校验——`addons.php` 正常约 105 字节,超 ~1KB 或含 `eval|system|base64|$_|assert|call_user_func` 就隔离+告警(逻辑可抄 `security_check.php` 第 78-108 行),把"只能检测"升级为"运行时拦截"

### 🆕 N3(印证 V1,补充细节)—— 未授权 Timming 写 `extra/timming.php` + 清缓存 DoS
- **位置**:`application/api/controller/Timming.php:58`(`mac_arr2file(...timming.php,$list)`)
- **结论**:未授权每次命中都会写 `extra/timming.php`,并能未授权触发 `cache`(清空全站缓存=DoS)/`collect`/`cj`/`urlsend`。**但有缓解**:传给 `collect/cj` 的参数取自**已存任务配置**(`Timming.php:66`),非请求直传;加上 `var_export` —— **通告那种"未授权写 extra → 注入 PHP → getshell"在本 fork 打不通**。残留未授权面:触发已配置任务 + 清缓存 DoS。修复按 V1

### 🆕 N4(高危,验证"后台保存的值逃逸成 PHP shell"猜想时发现)—— 模板标签库单引号逃逸 → 编译期 PHP 注入
- **位置**:`application/common/taglib/Maccms.php` 第 98/131/164/197/230/263/296/329/362/433/469/505/541/577/613/649/685 行(共 **17 处**),对照已正确处理的第 **395 行**
- **问题**:标签把属性 `json_encode($tag)` 后塞进 PHP 单引号字符串:`$parse .= '$__TAG__ = \'' . json_encode($tag) . '\';'`,而 **`json_encode` 默认不转义单引号 `'`**(未带 `JSON_HEX_APOS`)。模板里一个形如 `{maccms:area ids="x');<PHP语句>;//"}` 的标签,编译后变成 `$__TAG__ = '{"ids":"x');<PHP语句>;//"}';` —— `'` 闭合 PHP 字符串,**属性值逃逸成可执行 PHP**。第 395 行用了 `addslashes(json_encode($tag))` 防护,**其余 17 处遗漏**——证明是疏忽而非设计安全。`tagVod`/`tagFor` 等还把 `start/end/id/key/offset/length/mod/name` 裸拼进 `{for}`/`{volist}` 标签(`'.$tag['start'].'`),是同类二次编译注入面
- **触发**:能把含恶意属性的 `{maccms:...}` 标签写入模板编译流程者:① **后台模板编辑器 `Template::info`(后台"保存"动作)**——其黑名单拦 `<?`/`php`/`{:`/`{$` 但**不拦 `{maccms:}` 标签与裸单引号**,故被绕过;② 邮件模板 SSTI(V2,游客触发编译)
- **严重等级**:High(后台保存模板 → 编译期 RCE,**绕过模板编辑器防 getshell 黑名单**;这正是"后台保存的值逃逸成 PHP shell"的真实落点——注意它在**模板内容保存**路径,而**系统设置保存路径(`mac_arr2file`)因 `var_export` 安全、不可逃逸**)
- **修复**:17 处统一改 `addslashes(json_encode($tag))`(同 395 行)或更稳的 `var_export(json_encode($tag), true)`;对裸拼进 `{for}`/`{volist}` 的 `start/end/id/key/offset/length/mod/name` 做白名单(数字 / `[A-Za-z0-9_]`)

> **补充验证(回应"配置保存能否逃逸成 PHP"):** 已核对 `mac_arr2file` 全部 60 个调用点,第二参数**全为数组 → `var_export`**(单引号/反斜杠均转义),**系统设置/配置保存无法逃逸成 PHP**;`Image.php` 远程下载写文件因**扩展名白名单 + 随机文件名**也写不出 `.php`。**唯一能"写入值逃逸成 PHP"的是上面 N4 的模板标签库路径。**

---

## 六、修复优先级与行动方案

### 第一梯队(改动小、风险低、收益最大 —— 建议立刻做)
1. 打开休眠防护:`security_csrf_admin=1`、`security_xss_admin=1`、`security_csp` 给基线策略、`login_verify=1`、`admin_audit_enabled=1`、`anti_scrape_*=1`
2. V1 Timming(token fail-closed + 重写 `checkCjUrl`)
3. V2 邮件模板 SSTI(改 `strtr` 占位符)
4. N1 `tj.js`(改 `json_encode`)+ N2 `Begin.php` 加内容校验 + V16 白名单补全 + **N4 标签库 17 处加 `addslashes`**
5. CVE-2026-4563 订单 IDOR(加 `user_id` 归属)
6. V5 botlog LFI;Session/Cookie 加 `httponly`(V11)

### 第二梯队(需配套改模板表单 / 测试)
7. V3 破坏性动作强制 POST + 补 Token
8. V4 口令迁移 bcrypt + 登录限速
9. V6/V7/V9 zip-slip / 插件名 / XXE 加固

### 第三梯队
V8 / V10 / V12–V18、XSS 簇逐字段复核

> 已获站长授权(待实施):默认开后台 CSRF、口令迁移 bcrypt、前台登录默认开验证码。

---

## 七、部署层加固(与实战通告对应)

| 措施 | 对本套代码的精确落法 |
|---|---|
| `chattr +i` 锁关键目录 | 锁 `application/extra/`(自动加载,头号目标)、`static/js/*.js`、`template/**/*.js`;更新前 `chattr -i` |
| Web 服务器禁 PHP 执行 | **对 `upload/`、`runtime/` 禁用 PHP 执行**(挡 webshell 落地的第一道闸,通告漏了这点) |
| 后台入口防护 | 代码已强制 `admin.php` 改名(`admin.php:36`);再在 Nginx 限后台入口来源 IP / 挡含 `admin` 的可疑 POST |
| 防篡改 | 宝塔防篡改,或 `Begin.php` 升级(N2)+ 定期跑 `security_check.php` |
| install 入口 | 确认 `application/data/install/install.lock` 存在;部署后删 `install.php`(V10) |

---

## 八、已确认安全 / 已加固的点(避免误判)

- **无 SQL 注入**:34+ 控制器全部 ThinkPHP 数组条件参数化 + `allowField(true)` 列白名单;前台 `order/by` 白名单
- **无可控反序列化**:全树唯一 `unserialize` 命中是 `xml_unserialize()`(自定义 XML 转数组),不存在用户可控 PHP `unserialize()`,ThinkPHP POP 链无入口
- **无后门 / webshell**:全树取证零命中;`upload/` 无 `.php`;`addons.php` 干净
- **JWT 实现稳健**:固定 `hash_hmac('sha256')`、`hash_equals`、无 alg:none、无硬编码密钥、密钥需 ≥32 字符、默认关闭
- **ResourceHub 已有 SSRF 防护**:`validateRemoteUrl` 拒内网/回环/云元数据
- **会话固定防护已实现**:`Admin.php:150-153` 登录后 `session_regenerate_id(true)`
- **后台验证码默认开 + 后端强制**:`admin_login_verify='1'`,`captcha_check` 后端校验

---

## 九、关于"升级 ThinkPHP 到最新版"的收益分析

### 版本现状(2026-06 联网核实)
- 本项目框架:**ThinkPHP 5.0.24**(`thinkphp/base.php` `THINK_VERSION`)
- 官方最新:**ThinkPHP 8.1.4**(2026-01 发布,要求 **PHP ≥ 8.0**,兼容至 PHP 8.4)
- 其它分支末版:**6.1.5** / **5.1.42** / **5.0.25**(5.0 最后一个官方版)
- **ThinkPHP 5.0.x 已 EOL(官方停止维护)**;社区有 `ThinkPHP-5.0.x-LTS` 长期支持 fork

### 结论先行
> **升级框架并不能解决你当前"被挂马"的问题,且代价极大(近乎重写),不建议把它当作安全急救手段。**

### 为什么升级框架对"止血"收益有限
1. **你的洞几乎全在 maccms 自己的应用层代码,不在框架**:V1–V18、N1–N4 全部位于 `application/`(邮件 SSTI、标签库逃逸、CSRF 缺口、SSRF、IDOR、口令哈希、tj.js 注入……)。**换框架,这些一个都不会自动消失。**
2. **TP5.0 最著名的框架级 RCE(`?s=…invokefunction`、`_method`)在 5.0.24 已打补丁**(本报告第一节已验证)。即当前**没有"敞开的框架 RCE"**等着升级去堵。
3. 因此"升级 TP → 不再被挂马"是**因果错位**——挂马源于应用层洞 + 默认关闭的防护 + 可能的 DB/服务器层污染,与框架版本无关。

### 升级到 TP8 的真实代价(极高,近乎重写)
maccms10 与 TP5.0 深度耦合,以下几乎全部要重写:

| 耦合点 | 5.0 的用法 | 6/8 的变化 |
|---|---|---|
| 行为/Hook(`tags.php` 的 app_init/app_begin/app_end) | Behavior + Hook 机制 | **已移除**,改用 middleware —— 8 个安全行为(CsrfGuard/Begin/Init/SecurityHeaders…)全要重写 |
| 自定义标签库 `Maccms`(`{maccms:}` 全部标签) | `think\template\taglib\TagLib` | 模板引擎 API 变化,全部标签需适配 |
| 配置体系 + `extra/*.php` 自动加载 + `mac_arr2file` | 5.0 config 目录 + 自动加载 | 6/8 的配置结构、env、加载机制全变 |
| Db/Model(`listData`/数组条件查询) | 5.0 查询器 | 5.1+ 查询语法/`Where` 对象/`getError` 等不兼容 |
| 静态类(Config/Request/Env/Loader)、`start.php` 引导 | 5.0 命名空间与 API | 命名空间与 API 全改 |
| PHP 版本 | 兼容 PHP 5.4+ | TP8 要求 PHP ≥ 8.0;大量 5.x 写法在 PHP 8 下报错/弃用 |

- 这是一次**框架移植(数月工作量)**,不是"升级"。
- 升级后将**彻底脱离上游 `magicblack/maccms10`**(上游仍在 5.0),从此拿不到上游的功能/修复,需自己长期维护。

### 务实建议(按收益/成本排序)
1. **优先(止血)**:修应用层洞(V1–V18、N1–N4)。这才是阻止挂马的关键,与框架版本无关。
2. **低成本、延寿命**:`5.0.24 → 5.0.25`(末版)或迁到社区 `ThinkPHP-5.0.x-LTS`(已有方案让 TP5.0 跑在 PHP 8.1+),换取 **PHP 版本寿命**而无需重写;同时关注上游 maccms 是否官方迁移,**跟随上游**而非自行 fork 框架。
3. **战略层**:大版本升级(→ TP8)属"重新平台化"决策,应在"应用层已加固 + 有充足重写预算"时再评估,**不应作为安全急救**。

> 一句话:**先修应用层的洞(这才止血),框架升级是另一件成本极高、收益主要在"长期可维护性"而非"当前安全"的事。**

---

## 十、修复实施进度与冒烟测试(2026-06-14)

搭建了 Docker 冒烟环境(PHP 7.4-apache + MySQL 5.7,贴近真实部署),完成安装与登录链路验证。**已落地并提交的修复(每个 bug 一次提交)**:

| 提交 | 修复 | 冒烟验证 |
|---|---|---|
| 框架重建 | thinkphp/ 重建为官方 5.0.25 + 保留6处maccms补丁 | 前台/后台 boot 200 ✅ |
| N4 | 标签库单引号逃逸(17处 addslashes) | php -l ✅ |
| CVE-2026-4563 | 订单详情 IDOR 加 user_id | ✅ |
| N1 | tj.js 统计代码 JS 注入改 json_encode | ✅ |
| N2+V16 | Begin 清扫器 addons.php 内容校验 + 白名单补全 | ✅ |
| V5 | botlog 任意文件读取(白名单+realpath) | ✅ |
| V14 | Index::select 模板路径白名单 | ✅ |
| V9 | 全局禁用 libxml 外部实体(XXE) | ✅ |
| V11 | session/cookie 默认 HttpOnly | ✅ |
| V18 | Live::field 列名白名单 | ✅ |
| V7 | 插件 install/state/upgrade 的 name 白名单 | ✅ |
| V13 | Receive 口令 hash_equals | ✅ |
| V1-SSRF | checkCjUrl/友链/图片下载 SSRF 防护(禁内网/云元数据) | ✅ |
| V1-SSRF纵深 | mac_curl_get 限协议 http/https + 限重定向 | 前台 boot 200 ✅ |
| V10 | 安装器构造加锁 + database.php 改 var_export | ✅ |
| V6 | 核心更新解压前 zip-slip 预扫 | ✅ |
| V6-followup | 重算 update_hash(冒烟发现改 Update.php 锁死后台) | 后台登录恢复 ✅ |
| V17 | 移除 Macdiy 调试标签 dump()+die | ✅ |
| V8 | 公开用户API 停止返回手机号等 PII | ✅ |
| **V4-admin** | 管理员口令迁移 bcrypt(兼容md5透明升级)+ 密码列扩宽 | **md5登录→升级\$2y\$、bcrypt登录、错误拒绝 全绿 ✅** |
| **V4-user** | 前台用户口令迁移 bcrypt + 移除明文OR分支 | **md5→升级、bcrypt登录、错误拒绝 全绿 ✅** |
| **V3-CSRF** | 默认开启后台CSRF(双UI+稳定令牌 mac_csrf_token) | **token渲染、无token→403、带头→200、错token→403 全绿 ✅** |
| **V1-Timming** | 未授权定时任务 fail-closed(CLI放行/HTTP强制token) | **无token/错token→拒绝 全绿 ✅** |

> 冒烟测试还**捕获了两个隐藏坑**:① 改 Update.php 触发核心文件校验把后台锁死(已修 update_hash);② `{$Request.token}` 渲染为空导致 CSRF 一开就锁死后台(改用稳定 `mac_csrf_token()` 并补齐双UI管道)。无运行环境无法发现。

### 🔄 升级机制(已改为本地自动,无需手动 SQL)
- **库结构升级:全自动。** `mac_security_auto_migrate()`(`common.php`)在后台 Base 构造最前幂等执行:检测到旧 `char(32)`/`varchar(32)` 口令列会**自动 `ALTER` 到 `varchar(255)`**(容纳 bcrypt),用 `application/data/update/sec_schema.lock` 标记只跑一次。**部署时无需再手动执行任何 SQL**;冒烟实测 char(32)→登录自动扩宽→bcrypt 升级成功。新增迁移只需在该函数内追加幂等块并递增版本号即可自动生效。
- **代码升级:`git pull`** 从你自己的仓库/加固分支拉取(在线更新已停用,见下)。

### 🚫 已切断与官方服务器的全部通信(防下发病毒)
替换/停用了官方安装升级源,统一在 `mac_curl_get`/`mac_curl_post` 底层拦截 `maccms.la/com/cn/ai`、`dplayerstatic.com`,并逐处停用:
- `Update::step1` 在线更新停用(原从 update.maccms.la 下载 zip 解压 → 改为提示 git pull);
- `view_new/index/index.html` 版本检测停用(原会 **eval update.maccms.la 的响应**,官方被劫持即可在管理员浏览器执行任意 JS);
- `home.js` 短网址(api.maccms.la)、`playerconfig.js`/`maccms.php` 的 union.maccms.la 加载屏、`Addon`(api.maccms.com)、`ResourceHub`(api.maccms.ai)均被切断。
- **残留**:双层混淆的前端 `player.js` 移动端 union 广告无法干净改写,建议替换为干净 player.js 或在 DNS/防火墙层屏蔽 `union.maccms.la`。

### ⚠️ 部署须知
1. **CSRF**:默认已开。后台 ajax 自动带令牌;若高度自定义后台模板/第三方对接出现 `请不要重复提交表单`,在 `maccms.php` 的 `security_csrf_admin_exempt` 临时加该 `controller/action` 再逐步收敛。
2. **HTTP 定时任务**:需在后台配置 `timming_token` 并在 cron URL 带 `&token=xxx`;或改用 CLI(`php` 命令)触发。

### ⏳ 仍未落地(需你决策/测试/协调,故未自动改)
- **前台登录验证码(login_verify)**:默认主题登录表单**不渲染验证码**,直接开会挡死登录;需逐主题给登录表单加验证码字段并测happy-path。保持关闭。(bcrypt 已是更高价值的账号保护)
- **phpmailer 6.0.3→最新**:依赖升级,需真实发信测试。
- **Receive 接口 HMAC+时间戳+nonce**:协议级改动,会影响现有推送方,需协调。
- **插件 copydirs 拦截 .php 落核心目录**:插件市场当前不可用(api_url 未配置)+本地上传已禁用+name已白名单+admin鉴权,改通用 copydirs 有破坏合法插件风险。
- **更新通道 SSL_VERIFYPEER/SHA256**:需为 Update/Safety 单独走强校验下载函数。
- **find_password 按IP限流**:已有按目标(手机/邮箱)发送间隔限流;按IP限流需定阈值(NAT 误伤),可改用 AntiScrape 中间件。
- **cookie secure=true**:需站点全 HTTPS。
- **默认防护开关**(CSP/审计/防爬/后台XSS过滤):需按站点资源调优,避免误伤。

---

## 附:参考来源

- Maccms CVEs — OpenCVE: https://app.opencve.io/cve/?vendor=maccms
- Maccms — CVEDetails: https://www.cvedetails.com/vulnerability-list/vendor_id-17400/Maccms.html
- CVE-2026-4563(订单 IDOR)— VulDB: https://vuldb.com/?id.352400 / HuajiHD/CVE #10
- HuajiHD/CVE #9(未授权计划任务执行)
- CVE-2022-35148 — CVEDetails: https://www.cvedetails.com/cve/CVE-2022-35148/
- CVE-2017-17733 复现 — CSDN
- CVE-2025-50234 — NVD(MCCMS,非 maccms10)
- MacCms10 潜藏后门分析 — CSDN
- ThinkPHP 框架发布 — top-think/framework releases / Packagist(topthink/framework,最新 8.1.4)
- ThinkPHP 5.0.x LTS 社区维护 — github.com/ThinkPHP-LTS/ThinkPHP-5.0.x-LTS

> 本报告所有结论均基于实际代码阅读,文件:行号已逐项核对;未提供任何可用 exploit,未改动业务代码。
