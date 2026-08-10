# TP5→TP8 债务偿还最终方案（可执行版）

**骨架**：方案 2 的绞杀环（契约先行 → 并存 → 生效值比对 → 切流 → 旧路径变硬错误）。
**已嫁接**：方案 4 的 MacConfig/appPath/负例铁律/仪器校准、方案 3 的三段装配切分/extra 数据化/锁版本/拒绝改目录名、方案 1 的「删除即空 diff」判据/基线白名单纪律/引导契约号。
**已修**：三位评审点名的全部 main_flaw，外加四条谁都没写但会让方案第一周失效的部署事实（我逐条实测过，见文末「已核实事实清单」）。

---

## 0. 三条贯穿全程的纪律（先写在最前面，因为它们决定后面每一条判据是否可信）

**纪律 A · 每条断言必须附一条负例。** 任何新增门禁在 PR 里必须带一次「故意打破它 → CI 确实 FAIL」的运行记录，否则不予合入。理由是活的：`security_check.php:174-186` 至今在 grep `APP_PATH . 'config.php'`（一个 TP8 从不加载的文件），然后打印 `SAFE: _method 覆盖已禁用`。对「零报错但不对」这个缺陷类，一台从未被证明会亮红灯的仪器比没有仪器更危险。

**纪律 B · 删除类变更绝不与行为变更同 commit、同部署。** 删除的正确性判据只有一条——删除前后五入口生效值 dump 逐字节相同。混进任何行为变更，这条判据立刻失去证明力。

**纪律 C · 每一个「并存层」出生时必须带死亡日期。** 绞杀模式的代价是兼容层，而兼容层不会自己消失。所有并存层登记在 `docs/strangler-ledger.md`，每条含：引入 commit、拆除前置条件（可机器判定）、硬到期日。CI 检查该文件——到期未拆即 FAIL；账本条目净增长超过 3 条即 FAIL。S9 的完成判据是账本清零。

---

## 1. 债务定性：8 个结构性根因 → 23 条叶子

### RC1 · 配置没有「事实源」，且 TP8 Config 对两类错误都静默

7 个平面（`config/*.php` / 13 个 extra 加载桩 / `application/extra/*.php` / `.env` / 5 个入口各自 define 的常量 / AppInit 运行期 6 次 `Config::set` / think-multi-app 的 per-app config），没有任何一处枚举它们。叠加两个静默行为：`set()` 接受任意字符串作域名并静默建组；`get()` 未命中返回 null，null 在下游变成 `''`/falsy/`LIKE '%'`。TP5 键整体下沉一到两层（`database.prefix`→`database.connections.mysql.prefix`，视图域 `template`→`view`，`default_lang`→独立 `lang` 组），调用点只改了一半。

**消灭的叶子（18 条，占清单 78%）**：
`cookie.httponly`（config/cookie.php 根本不存在）；`session.httponly` / `session.secure` / `session.samesite` / `session.domain`；`session.expire`；`log.channels.file.type` + `level`；`log.type`；`route.url_common_param`；`route.url_html_suffix`；`route_config_file`（配置侧）；`database.connections.mysql.fields_strict`（×2）；`database.connections.mysql.trigger_sql`；`database.database`（×2）；`database.prefix`（×2）；`database.hostname` / `database.hostport`（×2）；database 凭据源（×2）。

**清单外同根**：后台「系统设置→语言」写 `app` 域而 `Lang` 只读 `lang` 组；`SiteInstall.php:160` 的 `Config::set($cfg,'database.connections.mysql')` 是字面量扁平键（`set()` 不解析点号路径），进程内注入凭据是空操作，其上方 8 行注释还在论证它为什么正确。

### RC2 · 运行期装配器的时机窗口被 TP8 整体前移，而 CLI 根本不经过

TP5 的 `Init` 挂 `app_init` 钩子，早于 Session/Cache/View/Route 的任何一次使用，还有 `Cache::forgetDriver()` 兜底。迁移把它降级成第 4 个全局中间件 `AppInit`：它前面 MultiApp 已定死 runtimePath/routePath/namespace，SessionInit 已实例化 Store+handler，cache 的 file 驱动更早在 `App::initialize()` → BootService → ModelService 阶段就建好并 memoise，`loadLangPack()` 更早。于是 `Config::set` 永远成功、回读永远是新值、后台开关永远保存成功——唯独已实例化的组件不会重读。**排查者做的第一件事（打印 `config()`）必然得出「配置是对的」。**

**实测的正确接缝顺序**（`vendor/topthink/framework/src/think/App.php`）：
`initialize()`:458 → `load()`（含 config/ 加载、`event.php`、`service.php` 的 `register()`）→ `:480 loadLangPack()` → `:483 trigger(think\event\AppInit)` → `:488 initializers`（Error / RegisterService / BootService→ModelService→cache 驱动构造）。
HTTP 侧：`Http.php:155 initialize()` → `:162 runWithRequest()` → `:193 trigger(HttpRun)` → `:195 middleware pipeline`。
`Console::__construct` 同样触发 `AppInit` —— **所以 AppInit 事件里不能有任何依赖 Host 的逻辑**。

**消灭的叶子**：`view.tpl_replace_string` 的 `__STATIC__`/`__CSS__`/`__JS__`（`AppInit.php:29` 读 `$config`、`:53` 才赋值，同一根因在单函数尺度的投影）。
**清单外同根**：`session_type=redis` 是彻底空操作；`cache.stores.file.expire` 的覆盖到不了 boot 期已建好的驱动（实测 0）；CLI 下 `$GLOBALS['config']` 与 12 个 `MAC_*` 常量从不存在。

### RC3 · 身份三套真值 + 引导层手抄六份 + 内核基础目录有两个定义点

`ENTRANCE` 常量（5 个入口各自 define，全仓 **70 处**分支）、`$http->getName()`（驱动 runtimePath/routePath/namespace/视图根回退）、以及无身份的 CLI（`think:15` 谎称 `ENTRANCE='install'`、用裸 `\think\App`、不进任何中间件、连 `DS`/`EXT` 都没 define）。

**实测的隐藏地雷**：`App::__construct` **硬编码** `$this->appPath = $rootPath.'app/'`（App.php:182），并在 `:185-186` 从那里加载 `provider.php`。`MacApp` 只覆盖了 `getBasePath()`。我跑了探针：

```
ctor appPath      = /home/dev/maccms10/app/     ← 被 .gitignore 忽略的符号链接
getBasePath       = /home/dev/maccms10/application/
Handle bound?     = app\ExceptionHandle          ← 完全依赖那条符号链接
```

`common.php` / `event.php` / `service.php` 因为入口在 `run()` 之前调了 `setAppPath()` 所以是安全的；**只有 `provider.php` 走符号链接**。也就是说：整个 `ExceptionHandle` 绑定（对外零信息泄露的安全边界）挂在一个不入库、一次全新 clone 或一次带 `--delete` 的同步就会消失的链接上，而失败形态是「合并成功、部署成功、脱敏 500 页悄悄换成框架默认错误页」。MacApp 的类注释声称「彻底摆脱符号链接依赖」——这句话是错的。

**消灭的叶子**：`view.view_path`（AppInit 按 ENTRANCE 置空 + think-view 按 `getName()` 回退）；`view.cache_path`（`runtime/<app>/temp` 分裂 + 清理方只认全局路径 + `Dir::delDir` 返回 false 而 `_cache_clear` 恒 `return true` = 静默成功）；两条 log 的落盘位置；`session.path` 必须显式钉死的根因；`database.prefix`/`database.database` 的 CLI 侧后果（`db:search-replace` 无前缀过滤重写整库、`db:export` 导全库）。
**清单外新叶子**：`IS_CLI` 全仓零定义、唯一消费点 `application/api/controller/Timming.php:18` —— **整个定时任务子系统（采集/静态生成/清缓存）在 TP8 下是死的**（`Error` 不走 `set_error_handler`，被渲染成脱敏 500）。

### RC4 · 每个职责都有「活的」和「看起来更权威的死的」两份实现

`application/common/behavior/`（8 个类）+ `tags.php` 全仓零引用，与 `application/middleware/` 8 个同名类已分叉；`application/config.php` / `database.php` / `route.php` / `command.php` 零读取但仍被后台与安装器持续写入；路由表劈四份（仓库根 `route/index.php`、`route/api.php` 是死文件）；`config/console.php` 与 `application/command.php` 两份命令表；`security_check.php` 在给死平面发绿灯。

**消灭的叶子**：`route_config_file`（后台 URL/路由页与 `PublishPage::mergePublishRoutes()` 写 `application/route.php`，保存成功、dispatch 纹丝不动）；database 凭据源（web 安装器写死文件，全新安装永远装不完）；`session.httponly` 的缓解手段 `SessionSameSite` 是活着的死代码（TP8 从不 `session_start()`）；`view.view_path` 的条件回退丢失（`behavior/Init.php:89-93` 的 `file_exists` 判断在手抄时掉了）。

### RC5 · 视图/主题寻址三模式并存，且 TP8 反转了 view_path 与 `@app` 前缀的优先级

TP5：`@` 前缀压过 view_path，所以 view_path 可以全局设成主题目录（含 admin，仅当主题目录不存在时**有条件**回退）。TP8：view_path 非空则 `@` 前缀彻底失效。应用层用「按入口切换的全局开关」去模拟一条被反转的语义，而这个开关是 per-request 单例，恰好无法表达「后台里渲染前台模板」。

**当前 HEAD（6fb4a0c）的真实状态**（很重要，直接决定判据怎么写）：`Make.php:49` 已经从 `'template'` 域改成 `'view'` 域并显式指定主题目录，**所以「后台触发 vs api 触发产物 byte-identical」这条判据今天就已经通过**——四份候选方案都把它当验收标准，会拿到一个不做事也能得到的绿灯。真正剩下的是三件事：

1. `Make.php:49` 写的仍是**相对路径** `'template/<t>/<h>/'` —— FPM 与 CLI 的 CWD 不同，命令行/定时触发的生成会解析到别处；
2. `AppInit.php:128-132` 对 `ENTRANCE==='admin'` 仍是**无条件**置空；
3. `BatchPlayer.php:15` / `Help.php:17` / `Rep.php:14` / `ResourceHub.php:17` / `DataReplace.php:20` 五处仍写死域 `'template'`（纯空操作），今天只被 `view_path=''` 恰好兜住。

**消灭的叶子**：`view.view_path`（HIGH）、`view_path` 的 `'template'` 死域 6 处（MEDIUM）。

### RC6 · 名字没有权威形：一个控制器五种手工维护的拼写

磁盘类名 `ResourceHub` / URL 段 `resource_hub`（`Str::studly` 反解）/ 视图目录 `resourcehub`（think-view 走 `Str::snake`）/ 权限树键 `resource_hub/multiCollect`（`auth.php:1631,1638`）/ 语言键 `admin/resourcehub/*`。五者互不推导。TP5 的 `url_convert=true`（动作名一律小写）这个不变量在 TP8 不存在。

实测：`Base.php:96-98` 的 `check_auth()` 对 `$c`、`$a` 双侧 `strtolower()`，得到 `resourcehub/multicollect`，与 `auth.php` 的 `resource_hub/multiCollect` **永不相等** → 所有多词控制器对子管理员一律拒绝；`Base.php:118` 对 `admin_id=='1'` 直接 `return true`，所以超管永远看不见。`7d225bd` 全压小写 → 10 个控制器 404；`fcf6c91` 改回 studly → 5 组回归 404；净变化为零，权限错配至今未修好。

**清单未覆盖，但已确认是本次迁移代价最高的一族。**

### RC7 · 站点可写配置 extra/*.php 无 schema、无版本、无默认值合并、两条读路径返回不同值

链条：`application/extra/<name>.php` ← `config/<name>.php` 加载桩（**13 个**）← `Config::load`，外加 `middleware/Begin.php:6-12` 每请求 `scandir` 并 `@unlink` 不在白名单（**16 项**）者。两份人工名单已经不一致——`php think mac:selfcheck` 今天就在报：`queue.php` 有文件有白名单**无桩**（且无读者，纯孤儿）、`type_synonyms.php` 有文件有白名单**无桩**（被 `ResourceHub` 直接 include 绕过配置系统）、`resource_sites_custom.php` 在白名单里但文件不存在。
读路径两条且值不同：`config('maccms.*')` 是磁盘原始值，`$GLOBALS['config']`（**723 处** application/ + 40 处 template/）是经 `domain.php` 覆盖与 wap 主题切换后的值。写路径是 15 个后台控制器 + Installer + install 控制器各自 `mac_arr2file` **全量覆盖**。opcache 一致性只在同 SAPI 内成立（CLI 写完 FPM 看不到）。

**消灭的**：「缺加载桩」这个复发缺陷类本身（`config/captcha.php` 是在「验证码 500 无法登录后台」时才补的，`config/view.php` 的 `default_filter` 是 2a63bea 才补的，同型已复发 ≥4 次，每次都是线上炸了才发现）；`view.tpl_replace_string` 的数据源；多域名部署下两条读路径必然分叉（表现为「某个页面用了错误的主题目录」而非报错）。

### RC8 · 失败语义被两处独立降级为 fail-silent，而唯一的观测面被配成噪声海

`common.php:12` 的 `error_reporting(E_ERROR|E_PARSE)` + `MacApp::initialize()` 在 `parent::` 之后接管 `set_error_handler`，把 E_WARNING/E_NOTICE/E_DEPRECATED 按 file:line 去重记 `Log::notice` 后 `return true`。**这个降级是必要的**（ 第三方主题 <站点主题> 与 `mac_url()` 的 130+ 处裸下标在 PHP 8 下会让一个缺字段 = 整页 500，实测已打穿前台），不能靠恢复严格错误来解决。代价：配置漂移在 PHP 层的最终表现几乎总是「某个数组键不存在」，标准 TP8 是首次访问即 `ErrorException`，本仓库是 HTTP 200 渲染出一个错的结果。唯一逃生阀 `config('app.strict_php_errors')` 在 `config/app.php` 里**根本不存在**（`MacApp.php:52` 在读它），永远走降级分支。唯一观测面被配成「无 level 过滤 + 每条 SQL 一行 + `max_files=0` + 无人清理」。

**它不是某几条叶子的根因，是全部 23 条「平均潜伏数周」的放大器。** 方案层含义是决定性的：**检出必须整体从运行期异常挪到发布前的静态/启动期断言。**

---

## 2. 分阶段路线图

### 依赖图（一眼看清什么能并行）

```
第 0 周（全部并行，零结构改动，零回滚风险）
  S0-A 部署通道修复 ──┐
  S0-B 六道止血闸 ────┤
  S0-C 内核前置修复 ──┼──► 所有后续阶段的前置
  S0-D 上游拓扑 ──────┤
  S0-E 观测底座 ──────┘

S0 ──► S1 配置落点补齐 ──► S1b【URL 形状恢复·独占窗口·切 DNS 前必须完成】
                        └─► S3 装配器归位（需 S0-C + S2）
S0 ──► S2 引导层与身份归一 ──► S3 ──► S7 extra 数据化 ──► S8c schema 契约
S2 ──► S5A 视图消费者显式化 ──► S5B 视图寻址翻转
S0 ──► S4 死平面封板             （与 S5、S6 并行，文件面不重叠）
S0 ──► S6 名字权威化             （与 S4、S5 并行）
S8a 控制流语义 / S8b 命名空间去劫持   （与 S5/S6/S7 并行）
全部 ──► S9 上游闸门固化 + 并存层账本清零
```

**可并行**：S0 内部 5 项全并行；S4 / S5 / S6 三条线文件面不重叠可并行；S8a / S8b 可与 S5–S7 并行。
**强制串行**：S0-C → S3（`service.php`/`event.php` 的可靠性依赖 appPath 正确）；S2 → S3（装配器要用 Runtime 的身份）；S5A → S5B（同一死结的两半）；S1 → S1b。
**灰度顺序（所有阶段一律）**：<API站域名> 先发 → 观察 48h（drift 计数 + 日志增量 + smoke）→ <主站域名>。

---

### S0-A · 部署通道修复（**四份候选方案全都漏了，不做这一步后面每次部署都会亮红灯**）

**目标**：让「删除、composer、reload、远端自检」这四件后面每个阶段都要用的事，在生产上真的会发生。

**已实测的四条硬事实**（`bin/deploy-155.sh`）：

| 行 | 事实 | 后果 |
|---|---|---|
| :68 | `rsync -a --no-owner --no-group`，**没有 `--delete`** | S4 删掉的 `application/config.php`、`database.php`、`route.php`、`tags.php`、`common/behavior/*` 会**永久留在** `<主站根>/` 与 `<API站域名>/`。任何「断言这些路径不存在」的远端 selfcheck 恒 FAIL，门禁两周内被绕成摆设。一台刚做完 cs_jump 取证的机器上留一堆孤儿 PHP 是净负债 |
| :47 | `--exclude='vendor/'`，注释说「由 composer install 管理」，但**脚本里没有这一步** | S8b 改 `composer.json` 的 psr-4 → 两站整站 `Class not found`，且出现在部署「看起来成功」之后 |
| 全文 | `grep -c 'reload\|opcache'` = 0 | 所有「改 config → 立刻 curl 验证」的判据在 opcache 打开时既可能假绿也可能假红 |
| :27 / :82 | 远端一律 `ssh root@`；每次部署 `rm -rf runtime/*` | ① 远端跑 CLI 会在 www 属主目录里生成 root 属主文件，下一次 FPM 写同一文件失败——而这个运行时恰好 fail-silent；② 20 次部署 = 20 次清空所有管理员与会员会话 |

**动作**（只改 `bin/deploy-155.sh` 一个文件）：

1. 新增显式数组 `REMOVED_PATHS=()`（初始为空），同步后对两站逐条 `rm -f`；**规则：任何删除类 commit 必须同时往这个数组里加一行，CI 校验「git 里已删除的路径 ⊆ REMOVED_PATHS」**。这是 rsync 无 `--delete` 的唯一正确解药（不改成 `--delete`：那会连站点私有的 `template/<站点主题>/`、`.env`、随机名入口一起删掉）。
2. rsync 之后、chown 之前插入 `composer install --no-dev -o`（vendor 被排除，所以必须在远端执行）；post-flight 校验远端 `composer.json` 的 sha256 与本地一致，不一致则跑 `composer dump-autoload -o` 后再冒烟。
3. chown 之后、冒烟之前插入 `systemctl reload php-fpm-83`（或 aaPanel 的等价命令），并对 `application/extra/` 做 `opcache_invalidate`。
4. `rm -rf runtime/*` 改成 `rm -rf runtime/*/temp runtime/temp`（只清编译产物，**不清 session**），并把「清 session」变成显式的 `--flush-sessions` 开关。
5. 远端一切 PHP 调用改为 `sudo -u www php think ...`；每次远端 CLI 之后补 `chown -R www:www runtime`。
6. 新增 pre-flight（本地 `mac:selfcheck --strict` 绿才允许 rsync）与 post-flight（远端 `mac:selfcheck --strict --entry=index|api|admin` + `mac:effective --json` 回传本地 diff）的钩子位（S0-E 落地命令后接上）。
7. 增加 `MAC_SKIP_GATE=1` 旁路，但强制打印醒目告警并把绕过记录 append 到 `deploy/skip-gate.log`。

**判据**：① 往 `REMOVED_PATHS` 放一个测试文件，部署后两站 `test ! -e` 通过；② 故意改 `composer.json` 后部署，远端 autoload hash 校验触发 dump-autoload，冒烟绿；③ 改一个 config 值部署，不手动 reload 即可 curl 到新值；④ 部署后管理员会话仍在（不再被强制登出）；⑤ 远端跑一次 CLI 后 `find <站点根> -user root` 为空。
**回滚**：脚本单文件 `git revert`。
**停机**：无。

---

### S0-B · 六道止血闸（每条 ≤10 行、单独 commit、单独可 revert）

**目标**：在任何结构工作之前，先让不可逆的破坏 fail-closed。这是全部四份候选方案里最好的风险排序，不能推迟到 S5/S8。

| # | 位置 | 改动 | 今天的后果 |
|---|---|---|---|
| ① | `application/command/DbSearchReplace.php:42`、`DbExport.php:30`、`DbBackup::listTables` | 表前缀解析为空时 **abort**，不再退化为「全库」 | 18.2 万行的库上 `db:search-replace` 会 `TABLE_NAME LIKE '%'` 重写当前 schema 每张表的每个文本列（`DbSearchReplace.php:78`），不可逆 |
| ② | `application/admin/controller/Make.php::buildHtml` | 解析出的视图根落在 `application/*/view/` 内、或渲染产物含 layui/后台外壳标记时**拒绝写盘**并报错 | 把后台控制台外壳写进站点根 `index.html`（详见下方专段） |
| ③ | `application/admin/controller/Meilisearch.php:16` | 超管守卫从 `return $this->error(...)` 改成 `throw` | AJAX 下 `All.php` 的 `error()` 只 return 一个 Response、构造函数正常结束，非超管照样能改 Meilisearch 配置并触发 22 万文档重建 |
| ④ | `application/common/util/MeilisearchService.php:40-57` | 库名解析为空时**拒绝派生** UID；同时显式钉住 `extra/maccms.php:754` 现有的 `'maccms_contents'`，任何代码路径不得改写非空的 index_uid | 现在 `defaultIndexUid()` 对每个 `mac_` 前缀站点返回同一个常量 `maccms_site_<hash>`，`Meilisearch.php:30/68/106` 会在字段为空时自动回填它 → 两站串库 |
| ⑤ | `application/data/update/database.php` 入口 | `$col_list` 为空（schema 探测失效）时**拒绝执行整个升级脚本** | 60 个 `empty()` 守卫全开，合并式 ALTER 在部分升级过的库上整条失败、真正缺的列永远补不上；`mac_sign_milestone` 每跑一次追加 6 条重复行 |
| ⑥ | `application/api/controller/Timming.php:18` | `IS_CLI` 未定义时按「非 CLI」处理（`defined('IS_CLI') && IS_CLI`），而不是抛 `Error` | 整个定时任务子系统在 TP8 下是死的；`Error` 不走 `set_error_handler`，MacApp 的降级救不了它 |

**判据**（每条一个自动化负例，并入 `tests/`）：无前缀时 `db:search-replace` 退出码非 0 且 `information_schema` 审计证明零 UPDATE；非超管以 AJAX 调 `admin.php/meilisearch/save` 返回非 2xx 且 `application/extra/maccms.php` 的 mtime 不变；`curl /api.php/timming/index?token=<正确值>` 返回非 5xx 且不带 token 仍被拒。
**回滚**：6 个独立 commit，逐个 revert。改动方向全部是「变严」，回滚方向变松，不引入新风险。
**停机**：无。

---

#### 【专段】view_path → 公网首页变管理面板：处置优先级

**定性**：它既是叶子（清单里唯一同时具备「信息泄露 + 生成中断 + 分入口不一致」三重后果的一条），也是 RC3/RC5 最有说服力的证据——同一份 Make 代码经 `api.php` 跑正常、经后台点按钮跑坏掉，而两步（AppInit 按 ENTRANCE 置空、think-view 按 `getName()` 回退）**各自看都对**。

**它被拆成三段处置，优先级各不相同**：

- **P0（今天，代码之外）**：线上取证。`application/admin/view/index/index.html` 是 37KB 的后台 layui 控制台外壳，里面带着 `ADMIN_PATH="/<改名后的后台入口>"`。如果 TP8 期间有人点过「静态生成→首页」，那份外壳就写在了 `<站点根>/index.html`，而 webroot 的 `index.html` 优先于 `index.php` —— **公网首页 = 后台面板 + 改名后的后台入口路径**。这是正在发生的信息泄露，不是待办。
  ```
  for s in <主站域名> <API站域名>; do
    grep -l 'layui\|ADMIN_PATH\|layui-layout-admin' <站点根>/index.html \
      <站点根>/*.html 2>/dev/null
  done
  ```
  命中即：删除产物 → 重新生成 → **把后台入口再改一次随机名**（旧名视为已泄露）→ 检查 nginx access log 里对旧入口名的访问记录，判断是否已被扫到。
- **P0（S0-B ②）**：Make 写盘守卫。让这个事故在结构上不可能再发生一次，与后面所有重构无关，10 行。
- **P2（S5A/S5B）**：结构性收敛。因为守卫已经堵住了后果，S5 可以从容地拆成两次可上线、可独立回滚的变更，而不必像其它三份方案那样赌一次原子部署。

**注意判据不能照抄候选方案**：HEAD 6fb4a0c 已经把 `Make.php:49` 改成 `'view'` 域并显式指定主题目录，所以「后台触发 vs api 触发产物 byte-identical」这条判据**今天就已经通过**，用它验收 S5 会拿到一个不做事也能得到的绿灯。S5 的真判据见下文。

---

### S0-C · 内核前置修复：让 provider.php 不再挂在符号链接上（**必须先于 S3**）

**目标**：`application/event.php` 与 `application/service.php` 是 S3 的全部身家，而它们所在的目录解析规则今天有两个定义点。先把这个流沙填掉。

**动作**：给 `application/MacApp.php` 加构造函数——显式把 `$this->appPath` 指向 `rootPath.'application/'`，并在此处加载 `application/provider.php`（覆盖父类 `App.php:182/185-186` 的硬编码 `rootPath.'app/'`）。同步订正 MacApp 类注释里那句「彻底摆脱符号链接依赖」（它今天是错的）。随后从工作树和两站生产上删除 `app -> application` 符号链接。

**判据**：① 删除符号链接后 `tests/http_smoke.php` 全套仍全绿；② `$app->make('think\exception\Handle')` 仍返回 `app\ExceptionHandle`（负例：把构造函数改回去 + 删符号链接 → 必须返回框架默认 `think\exception\Handle`，用这次注入证明断言有效）；③ 一次全新 `git clone` + `composer install` 后 `php think mac:selfcheck` 直接可跑。
**回滚**：单 commit revert + 重建符号链接。
**停机**：无。

---

### S0-D · 上游拓扑（**今天连「上游改了什么」都不可计算**）

实测 `git remote -v` 只有 `origin = https://github.com/ACCS2024/maccms10.git`（fork 自身）。没有 upstream 远端，任何合并机制都是无源之水。

**动作**：`git remote add upstream https://github.com/magicblack/maccms10`；`git fetch upstream`；用 `git merge-base` 定位 fork 分叉点并打不可变 tag `upstream-base`；建立永不修改的 `vendor/upstream` 镜像分支；`docs/upstream/STATE.md` 记录最后合并的上游 commit。**放在 S0 而不是最后一个阶段**——你必须在开始删文件之前就有一份诚实的 diff base。
**判据**：`git diff upstream-base..upstream/master --name-status` 能产出完整清单。
**回滚**：`git remote remove upstream`。**停机**：无。

---

### S0-E · 观测底座：契约 + 生效值 + drift 通道 + 日志净化

**目标**：让「一个键的生效值」从「要在 7 个平面 × 2 套读法之间人工交叉解算」变成一条命令，并把当前状态（含全部已知错值）录成基线。此后每个阶段的验收都是同一句话：**基线 diff 恰好等于本阶段申报的键清单，一行都不多。**

**动作**：

1. **契约** `application/kernel/contract/config.php`：逐键声明 `{键路径, 期望生效值, 所属平面, TP5 基线值 + file:line 证据, 是否故意偏离 TP5 + 理由, 判据}`。首批覆盖清单 23 条的全部 config 类键 + 已知无落点的 cookie/route/lang 三组。**强制字段（来自方案 3）**：每个键必须二选一——「与 TP5 一致」或「故意偏离 + 理由」，不允许留空。TP5 侧的值从清单逐行转录（清单每条都带双侧 file:line 证据，这是本轮 43 个 agent 已经付过的钱）。
2. **`php think mac:effective [--entry=index|api|admin|install|cli] [--json] [--diff=<baseline>]`**（新增 `application/command/Effective.php`，注册进 `config/console.php`）：复用 `tests/http_smoke.php` 已验证的进程内引导法，按每个入口真实 `new MacApp` + `name()` + 完整走完中间件，导出**两类分列**的规范化 JSON：
   - **(a) 配置值**：全部已加载组的完整树；
   - **(b) 已实例化组件的实测参数** —— cache 驱动的 options 与 expire、session handler 的类名与 path、view 的 `view_path`/`cache_path` **绝对解析结果**、log 驱动的真实落盘目录、`Db::connect()->getConfig()`、Lang 的真实生效语言、route 组；
   - **(c) 派生事实**：`getRuntimePath()`、已 define 的全部常量、`ENTRANCE` vs `$http->getName()`、`$GLOBALS['config']` 与 `config('maccms')` 的逐键 diff、已注册中间件/命令表、已加载路由文件列表、`MAC_BOOT_CONTRACT`。
   **(a)/(b) 必须分列**——本仓库最典型的缺陷正是二者不一致，而排查者第一件事（打印 `config()`）只看得到 (a)。
3. **基线拆两半（关键，直接治好方案 1 那条永远收不了口的判据）**：
   - `tests/baseline/golden.json` —— **宿主无关**部分，入库、CI 校验；
   - `<站点根>/application/data/baseline/<site>.json` —— **宿主相关**部分（主题目录、domain 覆盖、站点 extra 值、`.env` 派生值），**不入库**，部署时在站上采集、回传本地比对。
   注意落点：`bin/deploy-155.sh:49-50` 已经 `--exclude` 了 `tests/` 和 `docs/`，所以任何放在这两处的基线**根本到不了生产**——远端比对必须走「站上生成 → 回传 → 本地 diff」，不能指望站上有一份基线文件。
   `tests/baseline/site-private-keys.txt` 白名单（`.env`、`site_url`、`template_dir`、`interface.pass`、`meilisearch.*`、`cache_flag`、`upload.mode`、api 开关等两站本就不同的键）**必须一次划准**，并写死规则：白名单只能因显式决策增长，CI 检查该目录的 commit message 必须带 `BASELINE:` 前缀与理由。**门禁疲劳是这套体系唯一的慢性死法**——划不准 → 天天误报 → 两周内 `MAC_SKIP_GATE` 变成常态 → 整套体系归零。
4. **drift channel**：`config/log.php` 新增独立 `drift` 通道（JSON、单文件、不与 SQL/notice 混），只收三类结构化事件：读旧配置路径、写死平面、身份不一致（`ENTRANCE ≠ appName`）。每条带调用栈与去重键。
5. **日志净化**（这是仪器不是补丁）：`config/log.php` 的 file 通道加 `'level' => ['error','warning','notice']` 白名单、`max_files` 设 30；`config/database.php` 的 mysql 连接加 `'trigger_sql' => false`。**先做一次取证保留的一次性清理**（这台部署环境刚经历 cs_jump 取证，现有 `runtime/*/log` 里含搜索词/用户名/邮箱/手机号/session token/密码哈希明文，清理前先打包归档到 `<迁移工作目录>/log-archive-<ts>.tar.gz` 并限权 600）。
6. **诚实清理**：`application/admin/controller/Base.php:175-180` 与 `application/command/CacheFlush.php:31` 改为遍历 `runtime/temp` + `runtime/*/temp` + `runtime/*/log` 并**返回真实删除计数**；`application/common/util/Dir.php:316-318` 区分「目录不存在」与「删除失败」，上层不得恒 `return true`。新增 `php think mac:runtime-gc`。
7. **CI**：新增 `selfcheck` job 与 `baseline-check` job。

**判据**：
① 同一台机器上连续 **3 次** `mac:effective --all` 输出字节一致（证明快照已规范化、无时间/随机噪声——没有这一条，基线会因噪声天天报 diff，两周内退化成被无视的红灯）；
② **仪器校准（在信任仪器之前先用已知缺陷集校准它）**：dump 必须独立复现清单里全部 23 条的 **TP8 生效值**，逐条对照 —— 特别是 `config('database.database') === null`、`route.url_common_param === true`、`route.url_html_suffix === 'html'`、cookie 组为 `[]`、lang 组不存在、cache 驱动实测 `expire = 0`、session handler 实测为 `think\session\driver\File`。**命中不到 23/23 就说明工具还有盲区，不允许进入 S1。**
③ 两站各产出一份 `<site>.json`，扣除白名单后与 golden 的 diff 为空集（若非空，说明线上与仓库已经不一致，必须先查清——这本身就是第一个产出）；
④ 24h 内 `runtime/*/log` 增量下降 ≥ 90%，`DD_sql.log` 不再产生，`drift` 通道文件存在且为空；
⑤ 后台点「清空缓存」返回删除文件数 > 0，紧接着再点一次返回 0（今天两次都报「成功」而实际删 0 个）。

**关于 TP5 侧 parity oracle 的诚实排期**：方案 4 把「tp5 vs tp8 自动 diff 必须命中 23/23」写成 S0 的**阻断**判据——我实测过，`thinkphp_legacy_20260618/` 在 PHP 8.2 下**跑不起来**（`think\Config::get()` 静态调用致命错误，源自 TP 5.0.25 与 PHP 8 的兼容性，这正是当初要迁移的原因）。所以：**TP5 侧 oracle 是一个非阻断的、timebox 1 人日的研究任务**，只覆盖 `url()` 生成这一件事（唯一转录不可靠、且必须逐字符比对的地方）。1 天跑不通就放弃 boot，改用清单里已经写死的 TP5 输出字符串做黄金夹具（例如 `url('vod/show',[id=>6,by=>time,order=>desc,page=>PAGELINK,+7个空过滤器])` 的 TP5 输出是 `/vodshow/6/by/time/order/desc/page/PAGELINK.html`，`url('vod/search',['wd'=>'a/b?c'])` 的 TP5 输出带 `%2F`/`%3F`）。阻断判据只有 TP8 侧的 23/23。

**回滚**：契约、命令、基线全是新增文件；日志/数据库两个 config 改动是单文件 revert + reload。
**停机**：无（config 改动需一次 graceful reload，不中断已建立连接）。

---

### S1 · 配置事实源收敛：补齐落点 + 唯一装载器 + set() 层守卫

**依赖**：S0-E（基线）、S0-A（部署通道）。

**动作**：

1. **补齐无落点的组**（值一律取自契约）：新增 `config/cookie.php`（`httponly=true`、`samesite=Lax`、`path=/`、`secure` 按 HTTPS）、`config/lang.php`；`config/database.php` 补 `fields_strict=false`（恢复 TP5 平价，S8c 再正向收紧）。**`config/route.php` 不在本阶段** —— 它改变全站 URL 文本形状，独立成 S1b。
2. **唯一装载器取代 13 个手抄桩**：新增 `app\kernel\ExtraConfigLoader`，对 `application/extra/*.php` 整目录 `Config::load(file, basename)`，恢复 TP5「新增 extra 文件即刻生效」的语义；`middleware/Begin.php` 的白名单改为与装载器共用同一份清单 `application/kernel/contract/extra.php`（**两份人工名单合而为一**）。三个孤儿一次性裁决并写进契约：`queue.php`（有文件有白名单无桩无读者 → 删）、`type_synonyms.php` / `resource_sites_custom.php`（`ResourceHub` 直接 include 绕过配置系统 → 纳入装载器）。删除 13 个桩。
3. **API 层守卫（不是 grep 规则，是语言层不可能）**：新增 `application/MacConfig.php extends \think\Config`，经 `application/provider.php` 绑定（实测 `App.php:149` 的 bind 映射表里有 `'config' => Config::class`，可覆盖）。`set()` **拒绝含点号的域名**并按域白名单校验 —— `SiteInstall.php:160` 那类字面量扁平键从「lint 规则违反」变成运行期异常。`get()` 在 strict / 采样模式下记录未命中键到 drift 通道，且**不改变返回值语义**。
   **绝不用框架自带的 `Config::hook()`** —— 实测 `Config.php:186-190`：
   ```php
   if (is_null($result)) { return $default; }
   ...
   return $result ?? ($value ?: $default);
   ```
   注册任何一个纯观察 hook（返回 null）都会让 `config('view.default_filter')` 从 `''` 变成 default，**当场复现刚修好的全站转义事故**。这条要写进 `docs/` 作为永久决策记录，否则迟早有人重新提议。
   **耦合风险与缓解**（arch 评审对方案 4 的正确批评）：继承框架类等于绑定 TP8 内部实现。缓解三条：`composer.json` 把 `topthink/*` **锁到精确版本**（框架升级走同一道生效值门禁 —— TP8 小版本改一个包内默认值，与上游带回一个 TP5 键是**完全相同的缺陷类**）；子类保持最小（生产默认只做 `set()` 校验，`get()` 未命中记录默认**零开销**，只在 strict 或按请求采样时开——每请求上千次配置读取的热路径上，这个细节决定门禁能不能长期留在生产）；CI 加一条「Config 子类契约测试」，框架改了 `get`/`lazy` 结构立刻红。
4. **别名层（绞杀环的并存相）**：`app\kernel\Cfg` 门面把 TP5 扁平路径（`database.prefix` / `database.database` / `database.hostname` / `database.hostport` / `'template'` 域）映射到正确路径并返回正确值，同时向 drift 记 `legacy_config_path` 事件（含调用栈）。已知 8 处扁平读法（`Safety.php:84`、`Annex.php:241`、`Update.php:133`、`Tune.php:178`、`MeilisearchService.php:40-57`、`Database.php:77-79`、`DbSearchReplace.php:42`、`DbExport.php:30`）**本阶段不改代码**，靠别名层兜住——这保证本阶段零行为退化。**登记进 `docs/strangler-ledger.md`，拆除条件见 ⑤。**
5. 修 `SiteInstall.php:160` 的字面量扁平键（连同上方 8 行论证它为什么正确的注释一并订正）。

**判据**：
① 删除 13 个桩后 `mac:effective --all --diff <S0 基线>` 输出**空 diff**（逐键生效值不变，证明装载器等价）；
② 契约中「无落点」的键数从 N 降为 0；`curl -I` 实测 `PHPSESSID` 与 `user_check` 两个 cookie **同时**带 `HttpOnly` 与 `SameSite=Lax`；
③ 新建一个 `application/extra/_probe.php` 后无需任何桩即被加载、且不被 `Begin.php` 删除，selfcheck 通过；删除后复原；
④ 负例：把任一 `Config::set` 的域名改成 `'template'` 或含点号 → 运行期异常 + selfcheck FAIL；
⑤ **切流开关条件**：`legacy_config_path` 事件在两站连续 **7 天为 0**（后台稀有路径按 **30 天**，见「drift 是下界不是证明」）之后，才允许把别名层从「兼容并记录」切成「抛异常」——切换本身是独立 commit，账本对应条目同时销账。

**回滚**：13 个桩保留在 git 历史；别名层是纯加法；三个新 config 文件各自独立 commit 可逐个 revert；MacConfig 绑定从 provider.php 移除一行即回退。
**停机**：无（graceful reload）。

---

### S1b · URL 形状恢复【独占窗口 · 整个计划里唯一有真正时间压力的一步】

**为什么单拎出来**：URL 同时被浏览器、搜索引擎、**静态发布器**三方消费（`Make.php:376` 用 `mac_url_type(...,['id'=>$id,'page'=>$i])` 作为它去抓取并写盘的链接）。方案 3 把它和 cookie 属性、死文件删除、安装器改写打成同一个 revert 单元，而同阶段又要求「完成后必须做一次全量静态重发布 + sitemap 重提交」—— **`git revert` 不会把 18.2 万条重写出来的静态产物和已提交的 sitemap 收回去**，revert 之后站点会处于「动态 URL 是新形状、静态产物是旧形状」的混排态，比不改更糟。所以它必须是一个自带维护窗口、自带产物快照、自带 301 的独立阶段。

**动作**：新增 `config/route.php`：`url_common_param=false`、`url_html_suffix='html|htm|shtm|shtml|xml'`、`pathinfo_depr`（沿用 AppInit 现值 `/`）、`empty_controller` 显式指回 `Myerror`（今天落回包内默认 `'Error'`，而 `app\index\controller\Error` 不存在 → 直接 404，`Myerror.php` 已是不可达代码）。同批：`tests/url_golden.php` 固定夹具集（≥40 条，含 `wd` 带 `/ ? # & %` 与空格、`vod/show` 的 11 参数过滤集、`mac_url_page` 的 `MAC_PAGE_SP.'PAGELINK'` 分支）。

**窗口内的四件事必须连做，缺一不可**：
1. 上线 `config/route.php` + reload；
2. 全量静态重发布（先首页 → 再列表 → 再详情，使入口页最先一致），发布前对整个静态产物目录做带时间戳的 tar 快照；
3. nginx 加 301：把 TP8 期间产生的 query-string 形态（`/vodshow/6.html?area=&by=time&...`）与 `.html` 形态的 rss/map 映射回新形状，保留至少 90 天；
4. sitemap 重提交。

**判据**：① golden URL 全绿且与 TP5 夹具逐字符一致；② `/map.xml` 与 `/rss.xml` 返回 200 且 `Content-Type: text/xml`（今天 404）；③ 前台随机抽 50 个页面的 href 与静态发布器抓取的 URL 完全一致；④ 抽样 20 条旧形态 URL 全部 301 到新形态。
**回滚**：`git revert` + 从 tar 快照整目录换回静态产物 + nginx 301 反向（快照换回是秒级，这就是为什么产物快照是本阶段的强制前置动作而不是建议）。
**停机**：无停机，但重生成期间有新旧混排窗口，选低峰。
**排期**：**必须在切 DNS 之前完成。** 现在是这件事唯一便宜的窗口；DNS 切过去之后它从「零成本」变成一次 SEO 事件。**这一条应该单独标在项目计划顶部。**

---

### S2 · 引导层与身份归一

**依赖**：S0-A（生产入口是随机名且被 rsync 排除，没有部署通道配套，这一步改完部署完线上还是坏的）、S0-C。

**动作**：

1. 新增 `application/kernel/Bootstrap.php`：**唯一**定义全部路径与环境常量 —— `ROOT_PATH`/`APP_PATH`/`RUNTIME_PATH`/`ADDON_PATH`/`MAC_COMM`/`MAC_HOME_COMM`/`MAC_ADMIN_COMM`/`MAC_START_TIME`/`IN_FILE`/`ENTRANCE`，外加今天六份手抄各缺一块的 **`IS_CLI`**（全仓零定义）、`install.php` 缺的 `ADDON_PATH`、`think` 缺的 `DS`/`EXT`；唯一决定资源上限（按入口区分）；唯一实例化 `\app\MacApp`；并用**同一个 `$entrance` 变量**同时 `define('ENTRANCE')` 与 `$http->name()` —— 把「靠人肉写成一样」的约定变成结构约束。加 `MAC_BOOT_CONTRACT` 版本号常量，由 dump 导出。
2. 新增 `app\kernel\Runtime`（容器单例，不可变值对象）：`entry` / `appName` / `sapi` / 五条绝对路径。**70 处 `ENTRANCE` 引用一行不改**（并存相），但 Bootstrap 在 define 之后立即断言 `ENTRANCE === $http->getName()`（CLI 例外规则显式声明），不等即 drift + selfcheck FAIL。
3. 五个入口 + `tests/http_smoke.php` 退化成 3 行；`think` 改用 `\app\MacApp`（拿到 getBasePath 覆盖与诊断降级），`ENTRANCE` 从谎称的 `'install'` 改成 `'cli'`。
   **这是本阶段最高风险点**：它会同时翻转 8 处以上分支的走向 —— `RequestSecurity.php:15`（install 分支跳过**全部** XSS 输入净化）、`SecurityHeaders.php:35`（install 放宽安全头）、`Collect.php` 的 7 处采集分支、`common.php:3553-3561` 与 `:2445`、`PighlPage.php:14`。方向上更安全，但**采集分支必须逐条核对并跑一次真实增量采集**，否则会在 18.2 万条数据上产生新的静默偏差。每一处显式决定 cli 走哪支并写进 commit message；Bootstrap 内留一个常量开关可切回 `'install'` 做 A/B。
4. 新增 `app\middleware\MacMultiApp extends \think\app\MultiApp`，override `setApp()`：保留 `setAppPath`/`setNamespace`/`setRoutePath`，但**不再**把 `runtimePath` 追加应用名，恢复 TP5 的全站唯一 `runtime/` 语义。一次性统一 `view.cache_path`、log path、session path 三者的落点。（`topthink/*` 已在 S1 锁精确版本，这是对 override vendor 类的保险。）
5. **部署面**（否则改完部署完仍然是坏的）：新增 `php think mac:entry:sync` / `mac:entry:verify` —— 前者按 canonical 模板生成**任意文件名**的入口（保留随机名），后者校验线上任意入口文件的 sha256 属于已知模板集合。操作顺序防呆（四份里最稳的一版）：**写新入口 → 保留 `.bak-<ts>` → curl 校验 200 → 才移除 `.bak`**，逐站串行。`bin/deploy-155.sh` 的 post-flight 强制跑 `mac:entry:verify` + 远程 dump 校验 `MAC_BOOT_CONTRACT` —— 常量证明「新引导已生效」，哈希证明「文件确实是我们生成的那份」，两者都要。

**判据**：① 五入口 dump 的 `runtime_path`、`view_root`、常量集三项完全一致，CLI 下 `IS_CLI === true`；② `curl /api.php/timming/index?token=<配置值>` 返回 200 且业务日志证明任务真的执行；③ 两站 `mac:entry:verify` 通过且 `MAC_BOOT_CONTRACT` 与仓库一致；④ `mac:effective --diff` 相对 S1 的差异**只有**显式声明的三项（cli 的 ENTRANCE、新增 IS_CLI、新增 MAC_BOOT_CONTRACT）+ runtime 路径统一；⑤ `runtime/` 下不再新建 `index/`、`admin/`、`api/` 子树（24h 后复查）；⑥ `php think mac:selfcheck / info / tune` 在 CLI 下不再抛 ErrorException。
**回滚**：入口在生产上有 `.bak-<ts>`，`mv` 回去秒级；`MacMultiApp` 回滚 = `middleware.php` 单行改回；Bootstrap/Runtime 是新增文件。
**停机**：无（rsync 临时文件 + rename 原子写 + 一次 reload）。**上线检查单必须显式勾选**：主站那个被 rsync 排除的随机名后台入口需人工跑一次 `mac:entry:sync`，漏跑 = 该站同时存在新旧两种引导形状（比现状更糟，因为两种形状定义的常量集不同）。

---

### S3 · 装配器归位：**按数据依赖三段切分**（修掉方案 2 最真实的一处时序错误）

**依赖**：S0-C（appPath）、S2（Runtime）。

方案 2 原案把 `domain.php` 覆盖与 wap 主题切换搬进 `AppInit` 监听器，这是**错的**：实测 `Console::__construct` 同样触发 `AppInit`，而 CLI 下没有 Host —— 静态生成与 `SeoAiGenerate` 会静默拿到错误域名的主题，而 <主站>/<API站> 恰好共用一份 `domain.php`。装配确实是三件事，必须按数据依赖切：

| 段 | 接缝 | 装什么 | 为什么是这里 |
|---|---|---|---|
| **A** | `application/service.php` 的 `register()` | `lang.default_lang` | 实测 `load()`（含 service register）**早于** `:480 loadLangPack()`。这是唯一早于语言包加载的接缝。后台语言下拉今天保存成功、界面不变、无报错，就是因为 `AppInit.php:172` 写 `'app'` 域、且时机也已经晚了 |
| **B** | `application/event.php` 的 `AppInit` 监听器 | 与请求无关的全部装配：12 个 `MAC_*` 常量、cache stores/default、session type、route 组、cookie 组、view 静态部分、`$GLOBALS['config']` 基线填充 | 实测在 `:483`，早于全部 initializers（含 BootService→ModelService→**cache 驱动构造**）与全部中间件；且 `Console::__construct` 同样触发 → **CLI 自动获得同一份装配**，RC2 的 CLI 撕裂在此闭合 |
| **C** | `application/event.php` 的 `HttpRun` 监听器 | 与请求相关的全部覆盖：`domain.php` 按 Host 覆盖、wap 主题切换、`__ROOT__`/`__STATIC__`/`__CSS__`/`__JS__` 占位符 | 实测在 `Http.php:193`，Request 已实例化、pipeline（含 MultiApp/SessionInit）尚未开始。CLI 不触发它——**这正是我们要的** |

**纪律：本阶段只搬不改。** 唯一允许的语义修正是那条 use-before-assignment（`$config = config('maccms')` 上移到读 `new_version` 之前），因为它就是 `tpl_replace_string` 叶子的全部内容。恢复迁移中丢失的 `Cache::forgetDriver()` 兜底（只留在死代码 `behavior/Init.php:124`）。`addons_boot()` 前移到 B 段末尾，并断言插件路由注册早于 `dispatchToRoute`。
`application/middleware/AppInit.php` **暂不删除**，改为幂等哨兵：检测到监听器已装配则 no-op 并记一条 drift，否则执行旧逻辑（并存相，一个环境变量即可切回）。**登记进账本，拆除条件：两站各 7 天零哨兵触发。**

`application/event.php` 与 `application/service.php` 在本仓库当前**不存在**，在上游的 TP5 布局里也不可能存在 —— 这是一次**零上游冲突面**的迁移。

**判据**：`mac:effective --all --diff <S2 基线>` 的 diff **仅**包含这五项预期变化，其余逐键相同：
① cache 的 file 驱动实测 `expire` 从 0 变为 `maccms.app.cache_time`（3600）；
② `session_type=redis` 时 handler 实例类从 `think\session\driver\File` 变为 `Redis`；
③ `site.new_version === '0'` 时 `__STATIC__` 正确解析为 `/static`；
④ 后台语言切 `en-us` 后 **界面真的变化**（不是「配置是对的」—— 这条判据必须是行为判据，方案 1 和方案 3 在这里都写成了配置值判据，于是会以「baseline 显示 lang.default_lang=en-us、界面不变」的形态绿灯上线）；
⑤ `mac:effective --entry=cli` 输出中 `$GLOBALS['config']` 非空且 12 个 `MAC_*` 常量齐备。
负例：把 A 段里 lang 的域写回 `'app'` → selfcheck FAIL。
另：CLI 下的静态生成产物必须与 HTTP 后台触发的产物一致（专门验证 C 段没有被误放进 B 段）。

**回滚**：`middleware.php` 恢复 AppInit 一行 + 删除 `event.php`/`service.php` 即完全回到 S2；并存相期间两者可同时在位（哨兵保证幂等），回滚窗口内无中间态。
**停机**：无。**这是全流程风险最高的阶段**（它改的是每一个请求的初始化路径），强制 <API站域名> 先发并观察 **48h**，主站滞后。

---

### S4 · 死平面封板（可与 S5、S6 并行）

**依赖**：S0-A（`REMOVED_PATHS`，否则删除永远到不了生产）、S0-E（空 diff 判据）。

**动作**：

1. **写入端先改道**（必须先于删除，否则后台会写一个不存在的文件）：
   - `application/admin/controller/System.php:360-377` 与 `application/common/util/PublishPage.php:515 mergePublishRoutes()` → 改为写 `application/data/route_rules.php`（**纯数据**，不是可执行路由 PHP），由 `application/index/route/web.php` 末尾唯一一处 `RouteRules::apply()` 转成 `Route::rule` 注册。跨应用共享的规则走 `RouteLoaded` 事件，避免再次按应用分裂。顺带消除一条「后台可写可执行 PHP」的持久化落点（对刚做完 cs_jump 取证的部署是实打实的收益）。
   - `application/install/controller/Index.php::mkDatabase()` → 改调 `(new \app\common\util\Installer())->writeDbConfig()` 写 `.env`（与 CLI 路径统一），停止写 `application/database.php`。
   - 先把仓库根 `route/index.php` 里比 `application/index/route/web.php` 多出的规则搬过去并逐条核对。
   - `security_check.php:174-186` 停止 grep `application/config.php` 并停止打印那条假绿灯（TP8 把 `var_method` 硬编码为 `'_method'` 且不可配置），改为消费契约。
2. **删除**（知识已在 S0-E 提取进契约）：`application/config.php`、`application/database.php`、`application/route.php`、`application/tags.php`、`application/command.php`、`application/common/behavior/`（8 个类）、仓库根 `route/`（`index.php` + `api.php`）。同步把这 14 条路径加进 `bin/deploy-155.sh` 的 `REMOVED_PATHS`。
3. `SelfCheck` 新增 `checkDeadPlaneResurrection`：上述任一路径重新出现即 FAIL；断言 `config/console.php` 是唯一命令表；断言全仓无 `common\behavior` 引用。

**判据**：
① `grep -rn "common\\\\behavior\|APP_PATH . 'route.php'\|application/config\.php\|application/database\.php\|application/tags\.php"` 在 `application/` + `security_check.php` + `bin/` 下 0 命中；
② **`mac:effective` 五入口与删除前基线逐字节相同**（这是「删掉的确实是死代码」最强的客观证明——任何一处不同都说明还有未知读者，必须查清。**正因为这条判据只有在本阶段单独存在时才成立，纪律 B 才是硬的**）；
③ 端到端：后台 URL/路由页新增一条 `test-route` 规则 → 保存 → `curl` 该 URL 返回 200；删除该规则 → `curl` 返回 404（今天两步都不变）；
④ 新增 CI job：从零跑一遍 web 安装器 `install.php` 直到 `install.lock` 生成、首页 200（今天 web 安装**永远无法完成**，会在导入 SQL 时报误导性的「install.sql 语句错误」，真因是 `.env` 从未被写过）；
⑤ 两站 `test ! -e` 逐条通过（证明 `REMOVED_PATHS` 传播真的发生了）。

**回滚**：删除类是 `git revert`；写入端改道各自独立 commit，且新旧写入可并存一个版本（同时写 `route.php` 与 `route_rules.php`，只有后者被读），确认稳定后再摘掉旧写入——这样回滚不会丢失运维在过渡期保存的路由规则。
**停机**：无。

---

### S5 · 视图/主题寻址收敛（**拆成两次可独立上线的变更**）

**依赖**：S2（绝对路径来自 Runtime）。这是绞杀模式在本仓库最能兑现价值的一处：方案 1/3/4 都断言这两件事必须在同一个 commit 里落地（方案 1 原话「这一条不能拆分成两次部署」），方案 2 证明了它可拆，而且步骤 A 有一条极漂亮的判据——**一个重构步骤的判据是「什么都没变」**。

**S5A（行为零变更，可独立回滚）**：把 5 个用裸模板名的后台控制器改成框架语义的显式 `admin@` 前缀，并删除它们那 5 处写死域 `'template'` 的 `Config::set` 空操作（`BatchPlayer.php:15`、`Help.php:17`、`Rep.php:14`、`ResourceHub.php:17`、`DataReplace.php:20`）。此时 `view_path` 仍为 `''`，产物逐字节不变。
**S5A 判据**：`mac:effective --diff` 为**空 diff** 且后台全部页面渲染产物 **byte-identical**。

**S5B（翻转）**：新增 `app\kernel\ViewLocator` 作为**唯一**决定「本次渲染用哪个根」的地方 —— 后台自身视图一律 `admin@` 前缀；前台与静态生成一律主题**绝对路径**（消灭 `Make.php:49` 那行相对路径 `'template/<t>/<h>/'` 对进程 CWD 的隐式依赖，FPM 与 CLI 的 CWD 不同）。恢复 TP5 语义：`view_path` 始终指主题目录，**仅当该目录不存在时**才回退为空（`behavior/Init.php:89-93` 的条件回退，迁移中丢失）。删除 `AppInit` 里按 ENTRANCE 分支写 `view_path` 的逻辑、删除 `Make.php:49` 的第三次覆盖，改由 `ViewLocator::renderAs(theme)` 作用域管理（进出成对，异常安全）。
`ExceptionHandle::htmlError()` 的 5xx/404 模板链路脱离 `view_path`（改绝对路径模板或纯 PHP 渲染）；同时在两站实测「线上主题 `template/<站点主题>/` 有没有 `error/404.html`」并把结论写进契约——仓库里无法回答这个问题。

**S5B 判据**（**不用「后台 vs api byte-identical」，那条今天就已经通过**）：
① 从 **CLI**（`php think` 触发的定时生成）与从后台入口触发的同参数生成，产物逐文件 sha256 一致 —— 这才是本阶段真正修的东西（相对路径 + CWD 差异）；
② 站点根 `index.html` 内容断言：含主题标记串，**不含** `layui` / `layui-layout-admin` / `ADMIN_PATH` / 任何后台入口路径；
③ `map/index`、`rss/{index,baidu,google,so,sogou,bing,sm}`、`vod/type`、`vod/detail`、`art/type`、`art/detail`、`topic/detail`、`label/*` 全部生成成功，`TemplateNotFoundException` 计数为 0；
④ wap 主题产物与 PC 产物**不再** byte-identical（今天它们相同，说明 wap 分支是空操作）；
⑤ dump 中 `view_path` 的绝对解析结果在 index/api/admin/cli 四入口相同；
⑥ selfcheck 新增两条静态检查全绿：全仓 `Config::set(..., 'template')` 命中 0；admin 控制器中不带 `@` 且不带 `/` 的 `fetch()` 调用数为 0（用一次故意注入验证守卫有效）。

**回滚**：A/B 两个独立 commit 各自可 revert；`ViewLocator` 内置 `MAC_VIEW_LEGACY=1` 环境开关走旧分支，无需回滚代码即可现场止血（**登记进账本**，到期删除）。执行前对两站静态产物目录做 tar 快照，回滚整目录换回。
**停机**：无。<API站域名> 先行验证，主站选低峰跑一次全量生成，全程保留上一版快照可秒级换回。**CI 永远无法验证这一步**（主题不在仓库），带主题的渲染冒烟只能在生产主机上做。

---

### S6 · 名字权威化（可与 S4、S5 并行）

**动作**：新增 `app\kernel\NameResolver`：以磁盘类名（PSR-4 唯一真值）为源，导出 URL 段（`Str::snake`）、视图目录（`Str::snake`）、权限键、语言键四条推导链。
- 权限比对两侧同源：`application/admin/controller/Base.php:96-121` 与 `application/admin/common/auth.php`（`:1631/:1638` 等）全部经 `NameResolver`；动作名恢复归一化不变量（Base 与 `application/index/controller/User.php:22` 统一归一，恢复 TP5 的 `url_convert` 语义）。保留 `admin_id=='1'` 短路，但增加 selfcheck 断言而不是靠它掩盖错配。
- 视图目录按 `Str::snake` 重命名：`batchplayer→batch_player`、`datareplace→data_replace`、`resourcehub→resource_hub`、`tplconfig→tpl_config`。**必须走两步 `git mv`**（先改临时名再改目标名），大小写不敏感的开发机或同步工具下一步 mv 可能丢文件；CI 断言目录列表。保留一层显式映射作为过渡（账本登记，确认无回归后摘除）。
- **`php think mac:auth-migrate`**（四份方案里只有一份意识到这件事）：权限键不只是代码，它是**已持久化在 `mac_admin.admin_auth` 里的数据**。改推导规则而不迁移数据 = 静默改变子管理员的实际权限。提供 dry-run（打印将被改写的行数与逐行 diff）与逆操作。
- `SelfCheck` 的 `checkMenuIntegrity` 从只覆盖 studly 一半扩展到五种拼写全量。

**判据**：① `mac:selfcheck` 的 naming 段零 FAIL 零 WARN，每个 admin 控制器的五拼写表零冲突；② **用一个非超管子账号（授予全部菜单权限）脚本化点完后台每一个 `show=1` 的菜单项，零 403 零 404** —— 这是权限错配至今未被发现的唯一原因（超管短路），也是唯一能证明它修好的方法；③ 在任一控制器插一个不带 `/` 的裸 `fetch()` → CI 必须 FAIL（故意注入验证）；④ URL 大小写变体 `/adm_x.php/ResourceHub/multiCollect` 与 `/adm_x.php/resource_hub/multi_collect` 得到同一鉴权结论；⑤ `mac:auth-migrate --dry-run` 的改写行数与人工核对一致。
**回滚**：目录重命名保留映射层（两者可共存）；权限比对是单点 revert；`admin_auth` 迁移有逆操作。回滚窗口内超管始终可用，不存在锁死后台的风险。
**停机**：无（`admin_auth` 迁移是一次 UPDATE，先 dry-run）。

---

### S7 · 站点可写配置：从可执行 PHP 变成数据，两条读路径收敛成一条

**依赖**：S3（装配点）、S1（装载器）。

**动作**：
1. `application/kernel/contract/site.php`：`extra/maccms.php` 全部段的 schema（键、类型、默认值、是否站点可写、消费者）。
2. 存储格式从可执行 PHP 改为 **JSON 数据**，落 `application/data/config/`；由 S3 的 B 段监听器**扫描目录**装载（文件名即组名，恢复 TP5「加了就生效」，**从此不需要任何加载桩，「加载桩」这个概念本身消失**）。三个顺带收益：JSON 不进 opcache → CLI 写完 FPM 立刻可见（「保存成功、行为不变」的第三个成因消失）；后台不再拥有写可执行 PHP 的落点；`Begin.php` 每请求 `scandir+unlink` 从**清除**动作降级为**只读告警**（新存储无可执行代码，删除失去意义，但入侵告警价值保留——告警必须真的接到人）。
3. `app\kernel\SiteConfig` 门面三件事：读取时与 schema 默认值**深度合并**（少写一段不再等于 undefined index）；写入时按 schema 校验 + 原子写（tmp+rename）+ 跨 SAPI 失效；`$GLOBALS['config']` 改为它提供的 ArrayAccess 代理 —— **723 处 application/ 调用点与 40 处 template/ 调用点一行不改**，但读到的与 `config('maccms.*')` 是同一个经 `domain.php` 覆盖与 wap 切换后的归一化值。
4. **保留 `mac_arr2file($path,$arr)` 的函数名与签名**作为写入 API（内部按路径映射写入新存储），这样上游 15 个控制器的调用点原样可合。写入统一走 `SiteConfig::patch(段,键值)`（局部更新而非全量覆盖），内部第一版实现为「读全量→合并→全量写」与旧行为字节等价。
5. 双写双读窗口：新存储为权威，旧 `extra/*.php` 继续被写入但不被读取（账本登记，两周后拆）。

**判据**：①  <主站>、<API站> 以及 `domain.php` 覆盖的第三个域名三种 Host 下，`config('maccms.site.*')` 与 `$GLOBALS['config']['site'][*]` 逐键相等（切换前必然分叉）；② 转换前后 `mac:effective` 的 maccms 组快照**字节一致**（格式迁移的正确性证明）；③ 在预发新增一个配置组文件，不建任何桩即被 `config()` 读到；④ `php think` 写入配置后**无需 reload**，下一个 FPM 请求即读到新值；⑤ 构造一个「写入方少写一段」的负例，`SiteConfig` 拒绝写入；⑥ 后台 15 个设置页逐页保存-回读-比对全绿，`extra` 顶层键集合 diff == 0；⑦ `application/extra/` 下不再有可执行 PHP。
**回滚**：把 `SiteConfig` 的读源切回 `extra/` 并恢复 13 个桩（保留在 `deploy/legacy-config-stubs/`）。双写窗口内两边都是最新的，数据不会丢。每次写入前自动留带时间戳的备份。
**停机**：无（原子的读源切换 + reload，先 <API站> 后  <主站>）。

---

### S8 · 框架替身归位（**方案 2 的杂物袋，必须拆成三个各自可证伪的阶段**）

方案 2 把「`All.php` 改 throw + composer autoload 改名 + helper shim 退役 + schema 契约 + `fields_strict` 收紧」塞进同一阶段，直接违反它自己在否决 8 里立的规矩。拆开：

**S8a · 控制流语义（全部四份材料里最危险的单点改动，必须独占一个阶段）**
`application/common/controller/All.php:1048-1064` 的 `error()`/`success()` 在 AJAX 分支也 `throw HttpResponseException`（恢复 TP5 Jump 的「任何响应类型都中断」语义）。**它会改变 11 处裸调用点之后所有代码的执行流**（`Meilisearch.php:16`、`Urlsend.php:248`、`Index.php:195`、`Database.php:585/599/601`、`Type.php:167`、`Link.php:98`、`index/controller/User.php:229`、`install/controller/Index.php:143/158`），任何依赖「守卫返回后继续往下跑」的控制器都会行为翻转。同批修掉 `All.php:301/342/415/493/545/585` 的 `echo $this->error(...); exit;` 污染写法。
**判据**：① 11 处调用点**逐点**回归用例（不是三个控制流用例）；② 越权负例：非超管以 AJAX 调 `admin.php/meilisearch/{save,sync,setup}` 全部非 2xx，`extra` 未被修改、索引文档数不变；③ 未登录跳登录页 / 任一 `error()` 提示 / CsrfGuard 拒绝三种情况的响应码与 body 正确；④ 子管理员维度跑一遍 `tests/admin_write_smoke.py` 全绿；⑤ 全量菜单遍历零 5xx。
**回滚**：单 commit revert（方向是「变严」，回滚变松）。**先 <API站> 48h**。

**S8b · 框架接管面回收（可与 S5/S6/S7 并行）**
① `ExceptionHandle` 改为先 `parent::render()` 放行 `HttpResponseException` 等控制流异常，再做脱敏/error_id/分级日志（今天是整段覆盖 `Handle::render()`，框架未来新增的分支会被整段吞掉）；`ExceptionHandle::isApiRequest()` 与 `All.php` 的 `Request::isAjax()` 两套口径合并成 `app\kernel\RequestKind`。
② helper shim 退役：`application/common.php:4418-4475` 的 `model()`/`input()`/`url()`/`mac_token()` 因 `App::load()` 先 include `common.php` 后 include `helper.php` 而**永久遮蔽**框架实现。逐个改调用点后删除；`url()` 的 `bool $suffix` 签名问题（把 `'xml'` 强转 `true`）在契约里显式声明期望行为后再动。订正 `mac_token()` 那条已与事实脱节的注释（它写着「本项目未注册 SessionInit」，而 `middleware.php:6` 已注册）。
③ **`think\` 顶级命名空间去劫持**：`composer.json` 的 psr-4 把 `"think\\": "application/common/addons/"` 改成独立命名空间 `macaddons\` + `class_alias` 兼容层（用方案 2 的迁移法，方案 1 的目标名）。这个映射今天**排在 `vendor/topthink/framework/src/think` 之前**，任何放进该目录的 PHP 文件都能静默遮蔽同名框架类，而该目录恰好在 `Begin.php` 白名单扫不到的地方 —— **对一台刚做完 cs_jump 取证的部署，这是一个有优先级保证的持久化落点，不是洁癖问题。**
**判据**：`vendor/composer/autoload_psr4.php` 中 `think\` 只剩 vendor 路径；负例：把一个 `Cookie.php` 放进旧 addons 目录，不再遮蔽 `think\Cookie`；helper shim 删除后三套 smoke 全绿。
**停机**：无，但**必须配 S0-A 的远端 `composer dump-autoload`**，先 <API站> 灰度。

**S8c · schema 契约单一化 + `fields_strict` 正向收紧**
表结构今天散在 `application/install/sql/install.sql`、`application/data/update/database.php`、模型构造函数（`SeoAiResult.php:11` 构造期 `CREATE TABLE`）、`mac_security_auto_migrate()`（每个后台请求都可能跑 `ALTER TABLE`）四处，互不知情。合并为单一迁移目录 + `php think mac:schema:check`（只读断言）；移除构造期副作用（`SeoAiResult.php:11`、`Base.php:19-27`、`admin/controller/Base.php:30`）；8 个把原始 POST 直接喂给模型写入的控制器（`Type`/`Actor`/`Card`/`Gbook`/`Link`/`User`/`Ulog`/`Visit`）前置 schema 驱动的 `filterFields()`；**两步走**：第一步只记 drift 不拦截，drift 连续 7 天（罕用后台表单按 30 天）为 0 之后，才把 `config/database.php` 的 `fields_strict` 从 `false` 翻成 `true`。
Meilisearch 收尾：两站 `index_uid` 显式化，**新索引 + 双写 + 别名原子切换**，旧索引保留一个周期 —— 22 万文档全程可搜，零「搜不到」窗口。
**判据**：`mac:schema:check` 在全新安装库与两站生产库上零差异；带额外字段的写入 fuzz 全部正常入库；后台请求不再触发运行期 DDL（慢查询日志 DDL 计数 0）；两站 Meilisearch index_uid 不同且搜索结果无交叉。
**回滚**：`fields_strict` 翻回 `false` 是一行；schema 生成器只产文件不自动执行 DDL；Meilisearch 切回旧别名。
**停机**：无（DDL 在低峰单独执行，先在生产库快照上演练）。

---

### S9 · 上游闸门固化 + 并存层账本清零

见第 4 节。**完成判据包含一条硬的**：`docs/strangler-ledger.md` 条目数归零（别名层、AppInit 哨兵、视图目录映射、`MAC_VIEW_LEGACY`、helper shim 并存、`class_alias`、extra 双写 —— 全部拆除）。这是防止绞杀模式退化成「一个挂着十来层半绞杀兼容层的代码库」的唯一 forcing function。

---

## 3. 验证体系：把「零报错但不对」变成会失败的检查

生产永远不会 fail-fast（RC8 的降级是必需品，第三方主题 + `mac_url` 的 130+ 处裸下标，去掉就是一个缺字段整页 500）。**因此全部保障压在发布前门禁上。** 六层，越靠前越便宜。

### 层 1 · 声明式契约（`application/kernel/contract/`）
7 个配置平面的唯一枚举。每键含期望生效值、所属平面、TP5 基线值 + file:line 证据、是否故意偏离 + 理由、判据。CODEOWNERS 必审文件。**这份文件的存在本身就消灭了「必须在 7 个平面 × 2 套读法之间人工交叉解算」这件事。**

### 层 2 · `mac:selfcheck` 的演进（**扩展现有命令，不另起炉灶**）

今天：5 条检查（配置基线、菜单键覆盖、`Str::studly` 控制器解析、语言键覆盖、extra 加载桩、已编译模板 htmlentities 哨兵），`FAIL 0, WARN 14`。
演进为 **10 组结构不变量**，全部静态、不需要 HTTP/会话/凭据：

| # | 检查 | 新增于 | 取代了什么 |
|---|---|---|---|
| 1 | 配置基线断言 | S0-E 改造 | 从硬编码 5 个键改为**契约驱动**，五入口各跑一次 |
| 2 | 死平面检测 | S4 | 已删路径不得复活；无第二命令表；无 `common\behavior` 引用；`REMOVED_PATHS` 与 git 删除记录一致 |
| 3 | 配置域合法性 | S1 | 全仓扫 `Config::set` 第二参数：不在白名单或含点号即 FAIL；全仓 `Config::set(...,'template')` 零命中；扁平 `config('database.<键>')` 零命中 |
| 4 | 五拼写一致性 | S6 | 今天只覆盖 studly 一半 → 覆盖 studly/snake/authKey/langKey 四条推导链全量 |
| 5 | 视图寻址 | S5 | admin 控制器无裸 `fetch()`；view_path 必须绝对路径 |
| 6 | 契约是 extra 的唯一名单 | S1/S7 | 取代今天「13 个桩 vs 16 项白名单」两份人工名单的比对（今天正在报 3 条 WARN） |
| 7 | 引导契约 | S2 | 五入口 stub 内容一致；`MAC_BOOT_CONTRACT` 一致；`ENTRANCE === Runtime::entry() === getName()` |
| 8 | runtime 单树 | S2 | `runtime/` 下不得出现 `*/temp`、`*/log`、`*/session` 子树 |
| 9 | 菜单/语言键覆盖 | 保留 | — |
| 10 | 已编译模板 htmlentities 哨兵 | 保留 | — |
| 11 | schema 声明一致性 | S8c | `mac:schema:check` 并入 |

新增 `--strict`（WARN 视为 FAIL，需显式白名单条目）与 `--entry=` 选项。

### 层 3 · 生效值快照与 diff（`mac:effective`）——**本方案的核心创新**
按 5 个入口真实引导应用，导出**已实例化组件的实际状态**而非配置数组。它同时终结三类历史失效：`security_check.php` 对死文件发绿灯（它 grep 文件，dump 读组件）；`Config::set` 成功但组件不重读；「TP5 的键在 TP8 没有落点」（组不存在会被直接判出，而不是静默继承包内默认值）。
基线拆两半（golden.json 入库 / `<site>.json` 只留在各站机器上）—— 这是「主题不在仓库 + 两站配置天然不同 + `bin/deploy-155.sh` 排除了 `tests/` 与 `docs/`」这三条事实的唯一正确答案。

### 层 4 · drift channel（生产运行期唯一能发现未知调用者的机制）
在 723 处 `$GLOBALS['config']` + 123 处 `config('maccms.*')` + 70 处 `ENTRANCE` 的代码库上，grep 恰恰是本次迁移已经踩过的那种失效工具。drift 用**生产流量**证明没有别的读者，而不是靠推理。
**规则是硬的**：任何「旧路径 → 硬错误」的切换，前置条件是该事件在两个生产站点连续 **7 天为 0**。
**但 7 天是下界，不是证明**：它只覆盖被流量走到的路径。月度 cron、季度报表、七天内没人点的后台页都不可见。所以：**后台稀有路径按 30 天**，并且**必须补一次脚本化全菜单遍历 + 全 CLI 命令 dry-run**（层 5 里已有子管理员维度的全菜单遍历，把两者显式关联）。

### 层 5 · 行为级测试（重点补「跨入口等价性」）
现有 CI 已有 php-lint / schema-load / http-smoke / admin-smoke / admin-write-smoke / shellcheck，底子很好。缺的是**跨入口等价性**——本次最贵的两族缺陷（`view_path`、`ENTRANCE`）的共同特征是「只对一部分入口错」，而「我这边是好的」永远成立。
新增：(a) 同一逻辑分别经 index / api / admin / **CLI** 触发，产物逐字节一致（静态生成是最强样本）；(b) **子管理员维度**（非 `admin_id=1`）跑一遍后台写入冒烟，专抓被超管短路掩盖的权限错配；(c) `tests/url_golden.php` 逐字符对 TP5 夹具；(d) CLI 全部命令的 `--dry-run`（断言 `db:export`/`db:search-replace` 的表清单全部 `mac_` 开头、前缀为空时拒绝执行）；(e) 后台写路径断言**副作用真实发生**（数据库有行、文件 mtime 变化），不是断言 HTTP 200。

### 层 6 · 门禁与生产巡检
- **CI**：`selfcheck --strict`（五入口）+ `baseline-check` + `url-golden` + `install-wizard`（从零跑完 `install.php`）+ 已有 5 个 job。另加 `strict` job：`strict_php_errors=true` 下跑同一套 URL，`tests/baseline/known-notices.txt` **只能减不能加**（这是 `config/app.php` 补上那个从来不存在的键之后，把 fail-fast 能力放回 CI/预发的办法；生产保持 fail-silent）。
- **发布前**：`bin/deploy-155.sh` pre-flight = 本地 `mac:selfcheck --strict` + `mac:effective --diff-baseline`，任一非零即中止 rsync。
- **发布后**：远端 `sudo -u www php think mac:selfcheck --strict --entry=...` + `mac:entry:verify` + 回传 `mac:effective --json` 本地 diff；未声明漂移即告警并给出一键回滚提示。
- **生产持续**：`mac:diag` 每日输出 diagnostics 通道的 TOP-N `file:line` 聚合（替代噪声海）；**保存即自检** —— 后台任何一次 `mac_arr2file`/`SiteConfig::save` 写入后自动跑一次轻量 selfcheck，把「保存成功但不生效」在保存的那一刻变成可见的 WARN，而不是等几周（这条极便宜、极高产，而且它把验证挂在了历史上产生静默失败的那个确切用户动作上）。**注意**：只跑与该配置组相关的子集，绝不把全仓静态扫描塞进 FPM 的保存请求路径。

**唯一的单点失效**：有人绕过 `bin/deploy-155.sh` 直接 rsync 或在服务器上手改文件，全部验证立即失效。缓解：deploy 脚本设为唯一通道 + 对 `<站点根>/` 的关键文件做 sha256 巡检告警 + `MAC_SKIP_GATE` 每次绕过写入审计日志并要求事后补说明。

**闭环判据**：任何一条已确认叶子，如果重新注入到代码里，必须在层 1–3 的某一层被自动抓到，且抓到的位置早于生产。S0-E 的 23/23 校准就是这个闭环的第一次验收。

---

## 4. 上游合并策略

**前提事实（已实测）**：`git remote -v` 只有 `origin = ACCS2024/maccms10`（fork 自身）。**今天连「上游改了什么」都不可计算。** S0-D 的第一件事就是补上这个。

**核心判断**：这个 fork 与上游的最大风险不是冲突，而是**没有冲突**。上游 maccms10 仍是 TP5 布局，它对 `application/config.php`、`database.php`、`route.php`、`extra/`、`common/behavior/`、`tags.php`、`command.php` 的任何改动都会**干净地合进来，然后完全不生效** —— 合并成功、行为不变、无任何提示。这是本仓库全部债务里最危险的一条回流路径，而且它至今是敞开的。

**五条机制**：

1. **把静默变成冲突。** S4 物理删除死平面之后，上游对它们的修改会产生 modify/delete 冲突。这是**设计意图**：一次必须有人裁决的冲突，胜过一次静默且不生效的干净合并。配套的 CI「死平面复活检测」保证合并者不会为了消灭冲突而顺手恢复文件。**残余缺口**：上游**新增**一个文件到死平面（例如新增 `application/extra/newthing.php`）会干净合入且静默失效 —— 由层 2 的第 6 组（契约是 extra 唯一名单）兜住，并把它从 WARN 提级为 FAIL。

2. **把裁决变成机械动作。** `docs/upstream/surface-map.yml` 为上游每条顶层路径标注 `TRACK`（跟随上游）/ `TRANSLATE`（上游的 TP5 形状文件在本仓有 TP8 对应物，合并时必须同步翻译，清单里写明对应物）/ `FORK`（刻意分歧）/ `DELETED`（平面已废，上游改动必须显式裁决）/ `IGNORE`（主题、vendor）。TRANSLATE 逐行写死：
   ```
   upstream:application/config.php        → config/{app,route,cookie,session,log,view}.php
   upstream:application/database.php      → config/database.php + .env
   upstream:application/route.php         → application/data/route_rules.php + application/index/route/
   upstream:application/tags.php          → application/event.php（AppInit + HttpRun 两个监听器）
   upstream:application/common/behavior/* → application/middleware/* + application/service.php
   upstream:application/command.php       → config/console.php
   upstream:application/extra/*.php       → application/data/config/*.json + contract/site.php
   ```
   `php think mac:upstream-audit <base>..<upstream>` 把上游 diff 逐文件分类，对每个 TRANSLATE/DELETED 条目打印「上游改了 X，本 fork 的对应实现在 Y」，未逐条签字则退出码非 0。**这正是本轮 43 个 agent 相当一部分工作量花在「确定哪份文件是权威」的那件事，被固化成一条命令。**

3. **把验收变成生效值。** 任何一次上游合并的完成判据是 `mac:effective --diff` 对合并前基线的输出：要么空 diff，要么每一条变化在契约里有显式声明与理由。这能抓住「上游继续按扁平路径写新代码，每次合并带回一批读 null 的调用点且不会冲突」这一族——因为读 null 一定会体现为某个契约键的生效值或某个 drift 事件。
   **同一道门禁也覆盖框架升级**：TP8 小版本改掉一个包内默认值，与上游带回一个 TP5 键，是**完全相同的缺陷类**。所以 `topthink/*` 全部锁精确版本，升级走同一条流程。这条把 23 条叶子里至少 8 条（`fields_strict`/`trigger_sql`/`url_common_param`/`url_html_suffix`/`cookie.httponly`/`auto_timestamp` 那族「包内默认值静默生效」）的复发通道一次性堵死，成本几乎为零。

4. **主动缩小分叉面。** 本 fork 的全部新增刻意落在上游不存在的路径上（`application/kernel/`、`application/event.php`、`application/service.php`、`application/MacConfig.php`、`contract/`、新命令），冲突面为零。对必须改的上游文件（`application/common.php`、15 个后台控制器、install 控制器）保持小而集中的 diff，并在文件头登记本 fork 的偏离点清单；`common.php` 里 fork 新增的函数搬到 `application/common/mac/*.php` 由末尾统一 require，使它尽量贴近上游原样。
   **刻意不做的三件事**（这是本方案里最强的上游推理，写进 `docs/DECISIONS.md`）：不把 `application/` 改名成 `app/`（rsync 不带 `--delete`，改名后旧目录会作为**可访问的 PHP 副本**留在 webroot 上 —— 对一台有 cs_jump 入侵史的机器这是净负债，不只是合并成本）；不做全仓格式化；保留 `mac_arr2file` / `mac_url` / `$GLOBALS['config']` / 控制器与模型的类名与文件位置（S7 换的是**存储格式**，写入函数的名字与签名原样保留，所以上游 15 个控制器的调用点原样可合）。
   与 fork 无关的纯 bug 修复（`IS_CLI` 未定义、`fields_strict` 写入过滤、Meilisearch 空库名守卫、`mac_filter_xss`/`mac_restore_htmlfilter` 的 no-op 转义链、`Myerror` 不可达）向上游提 PR —— 每被接受一条，长期分叉面就少一条。

5. **三条不可动摇的规则**（写进 `docs/UPSTREAM.md`）：(a) 永远不为了「减少冲突」而恢复任何已删除的 TP5 文件；(b) 上游新增的配置键必须进契约并进基线，否则 CI 拒绝合并；(c) 合并上游时**禁止「顺手修」** —— 上游带来的任何行为变化必须先落进契约再落进代码，否则它绕过了层 3 门禁，而绕过门禁的改动在这个 fail-silent 的运行时上是不可能被发现的。

**流程**：按固定 cadence（每月一次上游 tag），不做持续 rebase，merge base 清晰。四道门全绿才允许合：`mac:upstream-audit` 逐条签字 → `mac:selfcheck --strict`（五入口）→ `mac:effective --diff-baseline` → golden URL + 三套 smoke。
**S9 判据**：① 用上游最近一次真实提交做一次**演练合并**（不落地），三分类与人工复核一致；② 人为构造一次「只改 TRANSLATE 路径不改对应物」的 PR，CI 必须失败；③ 一次故意的「上游修改了 `application/config.php`」模拟，git 必须报 modify/delete 冲突而不是静默合并；④ `surface-map.yml` 无 `UNKNOWN` 条目；⑤ 账本清零。

---

## 5. 明确的「不做什么」清单

| # | 不做 | 理由 |
|---|---|---|
| 1 | **不打开 `view.default_filter` 全局转义** | 既定方针，不重新论证。审计里 6 项「这会引入 XSS」的候选**全部被独立 agent 驳回** —— TP 5.0.25 的模板引擎根本没有 `default_filter` 这个概念（`grep -c filter` = 0），转义从来不存在，`2a63bea` 补回 `''` 是**恢复平价**不是引入风险。主题是第三方产物、不在仓库里，打开全局转义会砸掉整个主题生态而且砸了也测不出来。清单里那几处真实的 XSS 沉降点（gbook/comment 的 no-op 转义链、采集字段进 HTML 属性）作为**独立的上游加固项**处理，不混进本次偿还 |
| 2 | **不恢复 TP8 的严格错误语义（移除 MacApp 的 `set_error_handler`）** | 最想要，但被实测硬约束否决： 第三方主题 <站点主题> 与 `mac_url()` 的 130+ 处裸下标在 PHP 8 下让「一个缺字段 = 整页 500」，实测前台详情页、文章分类页全部 500。**MacApp 的降级是必需品不是懒惰。** 替代：fail-fast 挪进 CI/预发（补上今天根本不存在的 `strict_php_errors` 键 + known-notices 只减不增），生产保持 fail-silent 但配上发布前的生效值断言与可计数、可告警的 drift/diag 通道 |
| 3 | **不按清单逐条打 23 个补丁** | 用户明确否决，我独立认同。三条证据：(a) 补丁互为前提 —— `view_path` 恢复 TP5 语义与 5 个裸模板名控制器互相是对方的前提，清单里那位 agent 自己撞上了这个死结；(b) 补丁不改变检出机制，RC8 原封不动，几周后长出第 24 条；(c) 补丁改叶子，上游合并会沿着根因把同类叶子重新种回来。现成的失败样本就在 git 里：`7d225bd` → `fcf6c91` 一来一回净变化为零 |
| 4 | **不把 `application/` 改名成 `app/`** | 见上游策略第 4 条：rsync 无 `--delete` → 旧目录作为可访问的 PHP 副本留在 webroot（有入侵史的机器上这是安全结论）；且改名把每一条上游路径都变成依赖 git 改名探测的合并。符号链接问题用 S0-C 的 appPath 覆盖解决，不用改目录名 |
| 5 | **不用框架自带的 `Config::hook()` 做配置读取观测** | 实测 `Config.php:186-190` 的 `return $result ?? ($value ?: $default);` + `if (is_null($result)) return $default;` —— 注册任何一个纯观察 hook 都会把 `''`/`false`/`0` 替换成 default，**注册的那一刻就当场复现刚修好的 `default_filter=''` 全站转义事故**。改用 `MacConfig extends think\Config` + provider 绑定 |
| 6 | **不用 `runtime/config.php` 配置缓存** | `App::load()` 里它会**整体短路** `config/` 的加载 —— 等于再造第 8 个平面，而且是一个会静默遮蔽全部配置的平面。基线检查里反而要**断言它不存在** |
| 7 | **不把配置迁进数据库表** | 致命循环依赖：数据库凭据本身是配置。安装期、DB 故障期、CLI 早期三条路径全部退化，而这个 fork 恰好在这三条上都踩过坑。配置的事实源必须是文件 |
| 8 | **不用 `.env` 承载全部配置** | `.env` 被 rsync 排除且不入库，会让「仓库里看不到生效值」，与层 3 的基线快照直接冲突 —— 等于把新的不可见平面换掉旧的不可见平面。`.env` 只保留凭据 |
| 9 | **不替换 think-multi-app、不自研 dispatch** | 用更多手写框架机制去治手写框架机制，正是本方案要消灭的病。改为保留 multi-app 负责分发与命名空间，用 `MacMultiApp` 只 override `setApp()` 的 runtimePath 一行 + 四条路径显式钉死，拿到 90% 收益、改动量是自研的 5% |
| 10 | **不做 Swoole/RoadRunner 常驻化** | 方向错误：`ENTRANCE` 是进程级 `define`，常驻化会让一个 worker 用一个 ENTRANCE 服务三个 app（`AppInit.php:102-113` 那排 `defined()||define()` 守卫已是前兆），把当前最难排查的那族缺陷放大成随机性缺陷。TP8 已经提供了正确的启动期扩展点（`service.php` register / `AppInit` / `HttpRun`），用它就够了 |
| 11 | **不一次性替换 70 处 `ENTRANCE` 引用** | 无法灰度、无法二分定位回归，且其中 `RequestSecurity.php:15` 与 `SecurityHeaders.php:35` 是安全分支。改为 Bootstrap 同源 define（消灭人肉同步）+ 一致性断言 + grep 门禁，替换本身慢慢做 |
| 12 | **不让 `session_type=redis` 变成真正的运行期开关** | **原则：运行期改不了的东西就不要提供运行期开关。** 它在 TP8 下是彻底的空操作（SessionInit 早已实例化 handler），要真生效必须在 boot 期决定。S3 让它在 boot 期生效之后，UI 上仍把它降级为**只读展示 + 真值在 `.env`**，避免下一批同类空操作开关。这条原则写进 `docs/DECISIONS.md` |
| 13 | **不把 PHPStan/Psalm 全量分析当主门禁** | 大量依赖 `$GLOBALS['config']`（723 处）、动态数组键、运行期 define 常量，基线噪声巨大，强上会立刻退化成「大家都习惯性忽略的红灯」。S8 之后可以 baseline 模式只卡新增代码 |
| 14 | **不在生产打开 debug 排查** | `ExceptionHandle` 是对外零信息泄露的安全边界；而且 `config/app.php:3` 的 `app_debug` 对框架是**死键**（`debugModeInit()` 在 `load()` 之前执行且只读 `env('app_debug')`），`index.php:49-51` 那段注释描述的机制并不存在，只是结果值恰好都是 false 所以从未暴露。排查靠 `mac:effective` 与 `mac:diag` |
| 15 | **不回滚到 TP5、不整体重写** | TP5 在 PHP 8.3 上不可用（我实测 `thinkphp_legacy_20260618/` 连 boot 都跑不起来）；`application/` 有 355 个文件、11.7 万行，主题是第三方契约，重写等于永久放弃上游合并 —— 把一个「可以逐步偿还」的债务换成一个没有退出条件的项目 |
| 16 | **不只做 S0 的基线而不做后面的重构** | 认真考虑过（成本最低、收益立竿见影）。否决理由：基线只能让漂移变响，不能阻止它再生。7 个平面还在、装配器还在中间件里、身份还有三套，基线会持续报出新 diff，最终退化成一份被无视的告警。**基线必须是重构的验收工具，不是重构的替代品** |

---

## 6. 立即可执行的第一步

### 今天下午就做，30 分钟，不需要写一行代码：**两站静态产物取证**

```bash
for s in <主站域名> <API站域名>; do
  echo "── $s ──"
  ssh root@<新机IP> "
    ls -la <站点根>/index.html 2>/dev/null
    grep -c 'layui\|ADMIN_PATH\|layui-layout-admin' <站点根>/index.html 2>/dev/null
    grep -o 'ADMIN_PATH[^;]*' <站点根>/index.html 2>/dev/null | head -3
    find <站点根> -maxdepth 2 -name '*.html' -newermt '2026-06-18' \
         -exec grep -l 'layui-layout-admin' {} + 2>/dev/null
  "
done
```

**为什么它排第一，而不是任何一个技术阶段：**

1. **它是清单里唯一一条正在对公网泄露的债务。** `application/admin/view/index/index.html` 是 37KB 的后台 layui 控制台外壳，里面带着 `ADMIN_PATH="/<改名后的后台入口>"`。webroot 的 `index.html` 优先于 `index.php` —— 一旦 TP8 期间有人点过「静态生成→首页」，公网首页就是后台面板**加上那个本来靠随机名保护的后台入口路径**。而这台部署环境刚经历过 cs_jump 入侵取证，后台入口改名正是当时的加固结论之一。这不是待办事项，是可能正在发生的事。
2. **它零风险、零依赖、零回滚设计。** 纯只读 ssh，不改代码、不部署、不需要门禁、不需要基线、不需要任何前置阶段。
3. **它的结论直接改变后面的排期。** 命中 → 当天删产物 + 重生成 + **后台入口再改一次随机名**（旧名视为已泄露）+ 查 nginx access log 判断是否已被扫到；未命中 → 说明只是 500 生成中断，`view_path` 降级为纯功能问题，S5 可以从容排。**这是整个计划里唯一一件「不先查清就不知道该多着急」的事。**
4. **它是分入口配置分叉这个根因最有说服力的证据，也是说服所有人接受后面九个阶段的那张图。** 同一份 `Make.php` 代码，经 `api.php` 触发完全正常，经后台点按钮把管理面板写成了公网首页 —— 两步（`AppInit` 按 `ENTRANCE` 置空、think-view 按 `getName()` 回退）各自看都对。没有比这更好的开场证据。

### 同一天并行启动（不冲突，不同人做）

- **S0-A 部署通道修复**（改 `bin/deploy-155.sh` 一个文件）—— 它是后面**每一个**阶段能否真正到达生产的前置条件。四份候选方案全都默认「删除会传播到生产」，而 `:68` 是 `rsync -a` 没有 `--delete`。不先做这一步，S4 之后每一次部署都会在生产侧亮红灯，门禁两周内变摆设。
- **S0-C MacApp 构造函数**（5 行）—— 解开 `provider.php` 对 `app -> application` 符号链接的依赖。它是 S3（本方案的主干）的地基，且今天的失败形态是「部署成功、`ExceptionHandle` 悄悄没绑上、脱敏 500 页换成框架默认错误页」，正是要消灭的那一类。
- **S0-D `git remote add upstream` + `upstream-base` tag**（2 分钟）—— 今天连「上游改了什么」都不可计算，而这是用户三条硬约束之一。

**第一周结束时应该拿到的东西**：一份线上取证结论、一个能真正把删除/composer/reload 传播到生产且以 www 身份跑远端 CLI 的部署脚本、六道止血闸（含 Make 写盘守卫）、一个不再依赖符号链接的内核、一个可计算的上游 diff base、以及 `php think mac:effective` 在五个入口下产出的、能独立复现清单全部 23 条 TP8 生效值的基线。**只有第六项通过 23/23 校准，S1 才允许开始。**

---

## 附 · 已核实事实清单（本方案的每一条判据都建立在这些之上，均为我在本次会话中实测）

| 事实 | 证据 |
|---|---|
| `App::__construct` 硬编码 `appPath = rootPath.'app/'` 并从那里加载 `provider.php` | `App.php:182, 185-186`；探针输出 `ctor appPath = /home/dev/maccms10/app/`、`getBasePath = .../application/`、`Handle = app\ExceptionHandle` |
| `common.php`/`event.php`/`service.php` **不**走符号链接（入口在 run() 前调了 `setAppPath`），**只有 `provider.php` 走** | `App.php:534 load()` 用 `getAppPath()`；探针 `after setAppPath = .../application/` |
| 启动顺序：`load()`（含 service register）→ `:480 loadLangPack()` → `:483 trigger(AppInit)` → `:488 initializers` | `App.php:458-495` |
| `Console::__construct` 同样触发 `AppInit`；`HttpRun` 在 `Http.php:193`，pipeline 在 `:195` | `Http.php:155/162/193/195` |
| `Config::lazy()` 的 `return $result ?? ($value ?: $default);` 会把 `''` 打成 default | `Config.php:186-190` |
| `'config' => Config::class` 在容器 bind 表里，可经 provider 覆盖 | `App.php:149` |
| `bin/deploy-155.sh:68` 是 `rsync -a`，**无 `--delete`**；`:47` 排除 vendor 但脚本无 composer；全文无 reload/opcache；`:27` ssh root；`:82` 每次 `rm -rf runtime/*`；`:45-46` 排除 `admin.php`/`adm_*.php`/`install.php`；`:49-50` 排除 `tests/`、`docs/` | 已通读全文 |
| `git remote -v` 只有 `origin = ACCS2024/maccms10` | — |
| `IS_CLI` 全仓零定义，唯一消费点 `api/controller/Timming.php:18` | grep |
| `ENTRANCE` 全仓 70 处 | grep |
| `think` 入口 `define('ENTRANCE','install')`、`new \think\App`、无 `DS`/`EXT` | `think:15,28` |
| 5 处 `Config::set([...],'template')` 仍在（BatchPlayer:15 / Rep:14 / ResourceHub:17 / Help:17 / DataReplace:20）；`Make.php:49` 已改 `'view'` 但仍是**相对路径**；`AppInit.php:128-132` admin 仍无条件置空 | grep + 通读 |
| `AppInit.php:29` 读 `$config`、`:53` 才赋值；`:172` 写 `'app'` 域的 `default_lang` | 通读 |
| `middleware.php` 顺序：MultiApp(1)、SessionInit(2)、SessionSameSite(3)、AppInit(4) | 通读 |
| config/ 下 **13 个** extra 加载桩；`Begin.php` 白名单 **16 项**；`extra/` 下 15 个文件；`queue.php`、`type_synonyms.php` 有文件无桩，`resource_sites_custom.php` 在白名单但文件不存在 | `ls` + grep + `mac:selfcheck` 实跑 |
| config/ 下**没有** `cookie.php`、`route.php`、`lang.php` | `ls config/` |
| `security_check.php:174-186` grep `APP_PATH.'config.php'` 后打印 `SAFE: _method 覆盖已禁用` | 通读 |
| `Base.php:96-98` 对 `$c`/`$a` 双侧 `strtolower()`；`auth.php:1631/1638` 是 `resource_hub` + `multiCollect` | 通读 |
| `mac:selfcheck` 今天 `FAIL 0, WARN 14`（5 条检查） | 实跑 |
| `thinkphp_legacy_20260618/` 在 PHP 8.2 下**跑不起来**（TP 5.0.25 静态调用致命错误） | 实跑探针 |
| `config/console.php` 12 条命令；CI 5 个 job | 通读 |
| 死平面全部存在：`application/{config,database,route,tags,command}.php`、`common/behavior/`（8 类）、仓库根 `route/{index,api}.php` | `ls` |