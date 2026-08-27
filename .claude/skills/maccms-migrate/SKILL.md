---
name: maccms-migrate
description: 迁移 maccms10(苹果CMS / ThinkPHP8)站群到新服务器(如 宝塔→aaPanel)、做 DNS/Cloudflare 蓝绿切换、或全新部署一个 maccms 站时使用。提供分阶段运行手册 + 本项目踩过的运维陷阱清单(Meilisearch 配置漂移致静默回落 MySQL 打满整机、CDN 缓存击穿、播放器/favicon/图床、主题泛用规则、安全清理、www 权限坑)。切换/退役/加固前必读。详细样例见 migration/SENLIN-CUTOVER、NEI-CUTOVER、HELP-MODULE-MIGRATION。
---

# maccms10 站群 服务器迁移 / 切换 运行手册

本 skill 是「流程骨架 + 陷阱清单」。具体到某次迁移的凭证、域名清单、进度，见记忆
`project-senlin-migration-2026-08` 与 `migration/*-CUTOVER-*.md`。**原则：中毒/脏机只搬数据，
代码一律用本仓库全新部署，admin 表重建——天然甩掉后门。**

## 0. 凭证与前置(先收集齐)
- 源机 / 目标机：SSH、面板端口 + 随机入口、MySQL root、磁盘/内存/PHP 版本(TP8 需 8.x)。
- 图床 FTP(host/port/user/pwd/url)、Cloudflare(若域名走 CF)、各站**域名决策**(沿用切 DNS 还是临时域名)。
- 把本机出口 IP 加入目标机面板/防火墙白名单。

## 1. 探源 + 验目标
- **源机中毒排查**：maccms 常见 `application/extra/addons.php` 被 ThinkPHP addons 后门劫持;
  查 rogue admin、`vod_jumpurl` 注入、异常 cron。结论写清"已中和/仅搬数据"。
- **目标机就绪**：PHP 8.x;内存/核数(装 Dragonfly 必须限 `proactor_threads`,多核否则要十几 G 内存拒启)。

## 2. 基础设施(目标机)
装齐 4 样:**MySQL 8.0、php-redis、Meilisearch(搜索)、Dragonfly(缓存,Redis 协议)**。前两个走面板装;后两个用
仓库 `migration/infra/` 下的一键脚本(裸机二进制 + systemd,幂等,`install/status/upgrade/uninstall` 子命令,
secrets 运行时 `openssl rand` 生成、不入库)。

### Dragonfly(缓存/会话) — `migration/infra/dragonfly.sh`
```bash
sudo bash migration/infra/dragonfly.sh install   # 装+起(自动按机器资源算 maxmemory/proactor_threads)
sudo bash migration/infra/dragonfly.sh status    # 版本/健康/口令位置
```
- 版本锁 `DF_VERSION`(当前 **v1.40.1**);监听 **127.0.0.1:6379**;systemd 服务 `dragonfly`(User=dragonfly)。
- flagfile `/etc/dragonfly/dragonfly.conf`:`--requirepass`(口令存 `/etc/dragonfly/password`,640 root:dragonfly)、
  `--maxmemory`、`--cache_mode=true`、`--proactor_threads`、`--dir=/var/lib/dragonfly`。
- **`proactor_threads` 必须限**:脚本保证每线程 ≥256MiB,否则高核机(如 56 核)要十几 G 内存**拒启**。
  覆盖:`sudo DF_MAXMEMORY_MB=4096 DF_PROACTOR_THREADS=4 bash dragonfly.sh install`。

### Meilisearch(搜索) — `migration/infra/meilisearch.sh`
```bash
sudo bash migration/infra/meilisearch.sh install  # 全新装(生成 master key,起服务)
sudo bash migration/infra/meilisearch.sh status   # 版本/健康/文档数 + "后台该填什么"
sudo bash migration/infra/meilisearch.sh upgrade  # 仅在改了顶部 MEILI_VERSION 后:dump→迁移→导入新版(失败自动回滚)
```
- **版本锁死**(`MEILI_VERSION`,当前 **v1.47.0**),systemd 托管,**绝不自动升级**——防「被动升级后 data.ms 版本
  不兼容拒启」。升级只改这一个变量再 `upgrade`,走官方 dump→import 迁移。
- 监听 **127.0.0.1:7700**;env `/etc/meilisearch/meilisearch.env`(含 `MEILI_MASTER_KEY`);数据 `/var/lib/meilisearch`。
- **maccms 与 Meili 不同机**:`sudo MEILI_BIND=0.0.0.0 bash meilisearch.sh install` + 配防火墙白名单。

### 装完接进 maccms(别漏)
- **缓存**:`config`/`.env` 把 cache 驱动指向 Redis `127.0.0.1:6379` + Dragonfly 口令(取自 `/etc/dragonfly/password`)。
- **搜索**:`application/extra/maccms.php` 的 `meilisearch` 段填 host=`127.0.0.1:7700` + master key(取自 env 文件),
  然后**全量重建索引**(后台搜索设置触发)。`meilisearch.sh status` 会直接打印后台各字段该填的值。
- 🔴 **填完必须实测「配置指向的索引真的能用」,不能只看后台显示"已启用"**。填错 key 或 index_uid 时
  maccms **不会报任何错**,只会静默回落 MySQL(见陷阱 #1)。两条命令验完再走:
  ```bash
  MK=$(grep ^MEILI_MASTER_KEY= /etc/meilisearch/meilisearch.env | cut -d= -f2- | tr -d "\"'")
  curl -s -H "Authorization: Bearer $MK" http://127.0.0.1:7700/indexes            # 真实存在的索引名
  php -r '$c=include "application/extra/maccms.php";$m=$c["meilisearch"];
    $ch=curl_init(rtrim($m["host"],"/")."/indexes/".$m["index_uid"]."/stats");
    curl_setopt_array($ch,[CURLOPT_RETURNTRANSFER=>1,CURLOPT_HTTPHEADER=>["Authorization: Bearer ".$m["api_key"]]]);
    echo curl_exec($ch),"\n";'                                                    # 必须 200 + numberOfDocuments>0
  ```
  两者的索引名必须**完全一致**;第二条返回 403(key 失效)或 404(索引不存在)就是没配好。

## 3. 干净部署 + 导数据
- 本仓库 CLI `bin/maccms`：`new <路径> --db-name --site-name`(部署+装)；
  `db:import --src-prefix mac_ --dst-prefix ...`；`db:search-replace <换域名>`；`admin:reset-password`。
- **admin 表重建**,不导旧 admin。各站 `.env` 配 DB(`DB_PREFIX=mac_`)。
- `application/extra/*.php`(maccms/vodplayer/bind/…)用 `migration/merge-extra-config.php` **逐键合并**,别整包覆盖。

## 4. 切换(蓝绿, 无双写)
顺序:**停源采集 → 末次数据同步 → 切 DNS/Cloudflare → 观察 → 停源**。详见 `NEI-CUTOVER`「无双写切换顺序」+「回滚条件」。
CF 域名注意静态资源缓存(见陷阱 1)。

## 5. 上线验收 + 加固
- **改后台入口名**(admin.php → 随机名,防扫描入侵——安全硬要求)。
- 首页 / 详情 / 播放 / 采集 / 搜索 全绿;清 `runtime/*/temp/*.php` 模板缓存;`opcache` validate_timestamps 或 reload php-fpm。

---

# ⚠️ 运维陷阱(本项目血泪，逐条核对)

1. 🔴 **Meilisearch 配置漂移 → 静默回落 MySQL → 整机熔断(2026-08-26 乐播,load 298)**。
   `application/extra/maccms.php` 的 `meilisearch.api_key` 失效、或 `index_uid` 指向不存在的索引时,
   **Meili 每次调用都 403/404,而代码一层不报**:`MeilisearchService::search()` 只 `return ok=false`,
   `MeilisearchListBridge` 返回 `null`,`mac_meili_api_apply()` 外面还套 `catch(\Throwable){return false}` ——
   三层吞掉,全站无声回落 MySQL。回落路径正好是最慢的那条(`SELECT *` + 深 offset + 优化器误选
   `idx_st_level_time` 做 filesort),于是**正常采集流量就能把 56 核打满**,日志里一行错都没有。
   - **成因**:`index_uid` 的历史共享默认名 `maccms_contents` 曾被硬编码成兜底值。真实索引名应是
     按库名派生的 `maccms_<dbname>`(`MeilisearchService::defaultIndexUid()`)。共享名还会让多站
     共用一台 Meili 时**互相覆盖文档**(主键 `vod_<id>` 全局)。
   - **验**:照上面「装完接进 maccms」那两条命令比对索引名 + 拿站点自己的 key 打 `/stats` 要 200。
   - **巡检**:部署完挂一条 cron(样例见记忆 `project-lebozy-incident-2026-08-26`),
     每 10 分钟验 key 有效 / 索引存在 / Meili 与数据库条数漂移 <5%,**别等业务被拖垮才发现**。
   - **同类**:写入侧(`MeilisearchSync`)8 个调用点历史上同样不检查 `addDocuments()` 返回值、
     外面套空 catch → Meili 挂了新片永久不进索引。已加 `[MEILI-DOWN]` 限流告警,**别再退回静默**。
   - **另注**:纯列表深分页**不要走 Meili**,它的 sort+offset 是 O(offset)(offset 30 万实测 7.2s),
     比走对覆盖索引的 MySQL(0.22s)慢 33 倍。`search_only_wd=1` 的本意就是「列表给 MySQL,
     关键词给 Meili」,`applyForVodList()` 必须遵守该开关。

2. **CDN(Cloudflare)缓存击穿 —— 头号坑**。静态资源(player.js / playerconfig.js / main.css / favicon)
   被 CF 边缘缓存。若缓存串是 `date('Ymd')` 或**无版本串**,当天/长期吐旧文件,改了不生效、**强刷也没用**
   (强刷绕不过边缘)。修:缓存串改**文件 mtime**(`?t=filemtime(...)`)或 `?v=N`;页面 HTML 是
   `cf-cache-status:DYNAMIC` 恒新,故**热修优先内联进 DYNAMIC 页**(如主题 `public/include.html` 的 `<head>`)。
   诊断:`curl -sD- '<url>' -o/dev/null | grep -i cf-cache-status`(HIT=被缓存)。

3. **playerconfig.js 未重建**。后台 `application/extra/vodplayer.php` 加了自定义播放器后,前端
   `static/js/playerconfig.js` 需由 `admin/controller/Base.php::_cache_clear()`(后台**任意保存**触发)重建;
   否则前台报「不支持的播放来源 [xxx]」。该文件若是 root 属主(root 部署),后台 www 写不动 → `chown www`。
   CLI 重建:`include` 各站 `extra/{vodplayer,voddowner,vodserver}.php` 拼 `MacPlayerConfig.player_list=...`,
   用 `mac_get_body` splice 进 `//缓存开始`↔`//缓存结束`。

4. **自定义播放器白名单**。`static/js/player.js` 的 `_macAllow` 只认
   `parse/dplayer/videojs/iva/iframe/link/swf/flv`;自定义源(如 slm3u8)必须 **`ps=1` + 填解析地址**,
   Init() 才会把 `PlayFrom` 改写成 `parse` 走解析播放。

5. **favicon 三连坑**。(a) nginx `extension/<域名>/maccms-legacy-noise.conf` 里的
   `location = /favicon.ico { alias .../template/default/asset/img/favicon.ico; }` 会**盖过 webroot 物理文件**
   (一直吐 maccms 默认绿苹果)→ 把 alias 改指站点自己的 favicon,`nginx -t` 通过再 reload;
   (b) 无版本串被 CF 缓存 → 主题头引用 `href="{$maccms.path}favicon.ico?v=N"`;
   (c) 主题头默认没有 favicon 引用 → 在 `public/include.html` 补(泛用,各站放各自 webroot 图标)。

6. **图床 FTP 被动模式**。`application/common/extend/upload/Ftp.php` 的 `submit()` 要开 `ftp_pasv`,
   否则图床在 NAT 后、主动模式 `ftp_put` 静默失败 → 图片只落本地、进不了图床(表现"下载成功却没进图床")。

7. **www 权限坑(高频)**。**别用 root 跑会写 `upload/` `runtime/` 的脚本**——会留 root 属主目录,
   php-fpm(www)写不进 → 前台"下载失败"。用 `sudo -u www` 跑,或事后
   `find $ROOT/upload $ROOT/runtime -not -user www -exec chown www:www {} +`。
   CLI bootstrap 时 `$GLOBALS['config']` **不会自动设**,要手动 `= config('maccms')`,否则 Ftp 上传类读空配置只落本地。

8. **死图 / 坏封面清理**。判据用 **`vod_pic LIKE '%#err%'`(系统下载失败标记),不是按 IP 一刀切**;
   清理前先 `curl` 验源可达性——同一图源机不同端口活死不同(实测 `:2100` 活、`:2101`/无端口 死)。
   先备份 TSV(`SELECT vod_id,vod_pic ...`)再 `UPDATE mac_vod SET vod_pic='' WHERE ...`(前台回落主题默认封面)。

9. **泛用模块必须沿用各站主题**。替换助手(/index.php/macrep.html, `index/Rep`)、帮助中心等**共享模块**,
   一律走各主题 `public/head`+`public/include` 与主题原配色,**不能塞独立皮肤(自选字体/品牌色)**——
   否则和站里其它页格格不入。内容按数据(如 `rep_type`)驱动、**零站点硬编码**;站点专属资产(favicon 图标)各站各放,不入通用模块/仓库。

10. **CSRF**。`CsrfGuard` 要求 POST 带 `__token__`(param)或 `X-CSRF-Token`(header);`admin_common.js`
   只给 `XMLHttpRequest` 注 header、**不给 `fetch()`** → 表单补 `<input type=hidden name=__token__ value="{:mac_token()}">`。

11. **TP8 `url()` 掉控制器**。model 上下文里 `url('api')` 会掉控制器变成 `/api.html`(应 `url('collect/api')`);
    采集报「链接有误或不能为本地链接」多半是这个。

12. **物理 `help/` 目录遮蔽路由**。webroot 里残留的静态 `help/` 会被 nginx `try_files` 直接吐,maccms `/help`
    路由永远跑不到(表现"help 像写死、内容是旧品牌")。删/移走它;`mac_help_url` = `/index.php/<help_path>.html`。详见 HELP-MODULE-MIGRATION。

13. **bind.php 采集分类绑定**。key = `<cjflag>_<源分类id>` => `<本地分类id>`,`cjflag = md5(collect_url)`;
    清孤儿 = 删掉 `mac_collect` 里已不存在的 cjflag 条目(`php -l` 校验后 `chown www`)。

14. **改主题文件保留原行尾**。用 `str_replace`/`perl` 逐串替换,别用会翻转 CRLF↔LF 的编辑器整文件重写,否则 diff 全是行尾噪声。

# 老机退役
- 退役前 `curl -sD-` 验主站已**零真实流量**(只剩 CF 探测 + `.git`/`wp-login` 类爬虫扫描 = 正常噪声,可放心退)。
- 把老机备份(`/www/backup`、`/home/{migration,dbbak}`、`wwwroot_*.tar.gz`、`rclone.conf`、`safemac` 隔离体)
  **压缩挪到新机冷存**(新机 pull:装 sshpass → `ssh 老机 'tar cf - <paths>|gzip -1' > 新机/dr-archive/x.tar.gz`),
  旁边配 README(来源/日期/含凭证与隔离恶意样本的提示/长期不用即删)。
- Cloudflare 上把老 `help.<域>` 子域 **301 到新 `/index.php/help.html`**,退掉老 help 机。

# 关联
- `migration/infra/dragonfly.sh`、`migration/infra/meilisearch.sh` — 缓存/搜索一键部署脚本(install/status/upgrade/uninstall)
- `migration/SENLIN-CUTOVER-2026-08.md` — 主站切换样例(范围/域名决策/最终切换/回滚/DNS CNAME)
- `migration/NEI-CUTOVER-2026-08.md` — 独立站蓝绿切换 + 无双写顺序 + 回滚
- `migration/HELP-MODULE-MIGRATION.md` — 帮助中心站内化(删 help/、mac_help_cfg、mac_help_url)
- `migration/PITFALLS.md` — TP5→TP8 **代码级**陷阱(与本 skill 的**运维级**陷阱互补)
- 记忆 `project-senlin-migration-2026-08` — 本次凭证/站点清单/进度/所有热修记录
