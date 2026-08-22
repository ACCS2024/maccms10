# 森林站群主站迁移运行手册

更新时间：2026-08-22

## 范围与原则

- 源机：`23.225.73.50`，CentOS 7 / PHP 7.4 / MySQL 5.7。
- 目标机：`23.225.113.34`，Debian 12 / PHP 8.3 / MySQL 8.0。
- 第一阶段迁移共享主站程序、数据以及仍在使用的 `beiyong.slapibf.com`、`slapibf.com`、`senlinzy*.com` SAN 别名。
- PHP 代码、vendor、框架和后台入口不从源机复制；目标机使用 `feat/tp8-migration` 的干净代码。
- 只迁数据库业务数据、上传文件和业务配置。明确排除 `mac_admin`、`addons.php`、版本文件、runtime、日志和历史备份。
- 森林旧版 `ff.senlinzy.com`（MacCMS 8）和内网站 `nei.selangzy.com` 后置处理。

## 已确认的域名决策

- 2026-08-22 用户确认永久放弃 `selangzy.com` 和 `www.selangzy.com`。两条记录不切 CNAME、不切入新机对外服务、不作为共享主站迁移验收或回滚条件，后续操作不得再次把它们加入待切域名清单。
- 共享主站继续通过已经命中新机的 `beiyong.slapibf.com`、`slapibf.com` 和 `senlinzy*.com` 别名提供服务；应用未配置强制主域，页面使用相对链接，不依赖已放弃域名。
- `nei.selangzy.com` 是独立内网站和共享主站的采集源，拥有独立程序/数据库，尚未迁移。该子域名不在本次放弃范围内，完成独立迁移前不得修改其 DNS。
- `ff.senlinzy.com` 是独立 MacCMS 8 旧站，尚未迁移；不得与当前共享主站数据库合并。
- `slapibf1.com` 的目标站 vhost 已准备，但域名没有公开解析；它属于“未启用域名”，不是数据或程序迁移阻塞项。

## 已完成

### 基础设施

- 目标机 PHP 8.3 所需扩展齐全，包含 `pdo_mysql`、`mbstring`、`curl`、`gd`、`zip`、`redis`。
- MySQL 8.0 正常；主站使用独立库 `selangzy`，森林预留库 `sl` 未改动。
- Meilisearch 1.47.0 正常，仅监听 `127.0.0.1:7700`。
- Dragonfly 1.40.1 正常，仅监听 `127.0.0.1:6379`，自动配置为 4096 MiB / 4 线程。
- Dragonfly 自适应部署脚本见 `deploy/dragonfly/dragonfly.sh`。

### 干净部署与预迁移

- 代码源位于目标机 `/opt/maccms10`，站点位于 `/home/wwwroot/selangzy.com`。
- aaPanel 已按证书边界注册三个共享同一 webroot 的站点：
  - `selangzy.com`：主站和全部 SAN 别名，HTTP/HTTPS。
  - `beiyong.slapibf.com`：独立 SNI，HTTP/HTTPS。
  - `slapibf.com` / `slapibf1.com`：HTTP；旧证书已过期，DNS 切换后重新签发。
- 主站有效证书和 beiyong 有效证书已安全迁移，均到期于 2026-11-05。
- 临时 IP/Host 验证通过：首页、分类、详情、provide API 全部 HTTP 200；主站 SAN 和 beiyong HTTPS 证书验证结果为 0。
- 新管理员已创建，旧 `mac_admin` 未迁移。默认后台入口已改为随机文件名。
- 管理员凭证保存在目标机 `/root/selangzy-install.json`，后台入口名保存在 `/root/selangzy-admin-entry`，权限仅 root 可读。
- 后台真实登录、首页加载、Dragonfly 会话和退出全链路通过；最终验证码配置保持开启。
- 源站桌面主题 `demo/html` 已单独审计并迁入，共 54 个模板和静态资源文件；随机后缀压缩备份与未引用的外部抓取 PHP 文件未上线。
- 旧主题 5 处 PHP 7 风格日期过滤器已改为 PHP 8 兼容语法，并补齐缺失的 `public/image` 模板。首页、分页、视频分类/详情/播放/搜索、文章分类/详情、专题、留言、会员登录和 provide API 均已在 PHP 8.3 下通过。
- 已移除旧主题顶部硬编码日期、持续发光的大块替换公告，改为右上角动态“域名替换 + 最后更新时间”入口；同时从 `vozy` 适配 `rep/index` 替换助手模板，入口和页面均已在目标机验证为 HTTP 200。
- 旧主题 header 的影片总数/今日更新会在数据统计缓存失效时形成并发缓存击穿，已改为无数据库查询的“资源持续更新中”；爬虫洪峰下约 300 条相同 `COUNT(*)` 查询清理后，首页、API 和备用域名均恢复到 0.2 秒内。
- 老站没有 `mac_rep` 表；从静态 `replace.html` 解析并导入了 2 条历史替换通知。导入前确认旧播放域名/解析接口均已无命中，新地址已生效，因此记录标记为已执行；幂等脚本见 `migration/import-senlin-legacy-rep.sql`。
- 目标站桌面主题已正式切换为 `demo/html`；源站移动主题功能原本关闭，因此保留目标 `default` 目录且不启用移动主题覆盖。
- demo 会员模板原包缺失 `member.css` 和会员图片；已从仓库删除前的 `default_pc` 历史版本确认 DOM 完全一致后恢复样式，并用现有主题 logo/CSS 符号替代丢失图片。桌面和 390px 移动宽度均通过 Chromium 验证。播放、收藏和下载记录已统一使用安全事件代理，修复下载记录单条删除原为空链接的问题；会员验证码和搜索表单不再使用内联事件。
- demo 的留言、报错、评论原先调用未加载的 `MAC.Gbook/Comment`；已改为最小 `public.safe.js`，不再引入含 `eval` 的旧 `static/js/home.js`。报错弹窗使用 DOM API 写入视频名，详情复制改用原生 Clipboard API 与安全回退。
- demo 前端依赖已收口：jQuery 3.7.1 和 jQuery Lazy Load 1.9.7 使用官方构建、本地固定版本及 SRI；删除被修改的整套 Layui，仅保留实际用到的最小样式。专题详情仍保留 JuicyAds 广告脚本，属于待业务确认的站外执行风险。
- 替换助手已移除所有内联事件，后台可编辑的 `rep_type` 不再进入 JavaScript 属性；列表 JSON 使用完整 `JSON_HEX_*` 编码。两条历史记录和页面交互通过 Chromium 验证。

### 数据和配置

- 2026-08-22 02:30 源库备份已传到 `/home/migration/selangzy-20260822-0230.sql.gz`。
- 源/目标 SHA-256 一致，gzip 完整性通过。
- 备份先导入隔离库 `selangzy_legacy`，再按共有字段复制 25 个业务表到干净库 `selangzy`。
- `mac_admin` 保持目标新建的 1 行；旧版 `mac_tmpart`、`mac_tmpvod` 未迁移。
- 2026-08-22 13:06 已完成第二次不停机事务快照和预同步：源/目标均为视频 251606（max id 284544）、文章 80299（max id 80321）、分类 56（max id 77），新管理员仍为 1 行。源站尚未冻结，正式切换前仍需再次核对差量。
- 2026-08-22 切换前第三次增量核对：旧库迁移范围内的 25 张业务表与目标逐表精确行数、主键最大值全部一致；视频、文章、分类最大更新时间也一致，当前待写入增量为 0。目标额外的 29 张 TP8 功能表不参与旧库覆盖。
- 9 个高频查询性能索引已全部创建；其中 `idx_vod_status_recycle (vod_status, vod_recycle_time)` 用于避免 API/列表分页总数统计扫描体积较大的时间索引。
- Meilisearch 使用站点唯一索引 `maccms_selangzy_e33613`，第二次预同步后为 331905 文档；内网站首轮采集后为 331933 文档，待处理/失败任务均为 0。
- 源配置先转 JSON，再由 `migration/merge-extra-config.php` 合并，目标端没有执行源机 PHP。
- 已迁播放器、下载器、服务器、域名、FTP/上传、验证码、定时任务等业务配置。
- 新数据库连接和新安全密钥被保留；缓存/会话显式接入 Dragonfly，搜索接入唯一 Meilisearch 索引。主题在完成隔离审计和 PHP 8 适配后单独切换为旧站 `demo/html`。
- 配置回滚备份位于目标机 `/home/migration/extra-before-merge*`。
- 主站 `upload/` 只有 20 个空占位文件；数据库图片主要是外链，已同步全部 upload 内容。
- 原迁移配置中的 FTP 主机、账号和密码已经过期，因此此前连接测试超时。2026-08-22 使用用户确认的新 FTP 信息从本机、源机和目标机三处均登录成功；目标配置已修正并保留原远程目录/访问 URL，上传、下载、SHA-256 校验和远端删除闭环测试全部通过。
- 2026-08-22 14:55 再次使用应用实际配置字段 `upload.api.ftp.pwd` 登录成功；目标密码哈希与用户确认值一致。注意该字段名是 `pwd`，误用 `pass` 会得到假失败。

### 定时采集

- 老机 root crontab 没有主站采集任务；其中每 5 分钟任务只是宝塔日志切割，其余为数据库/站点备份、rclone 和证书续签，均未误迁为业务采集。
- 主站 `mac_collect` 唯一资源为 `https://nei.selangzy.com/api.php/provide/vod/at/xml`：XML、视频、新增并更新、图片同步选项 2。该 URL 的 MD5 与旧站 `bind.php` 分类绑定前缀一致，主站最近 100 条名称在内网站 100% 命中，确认主站确实采集内网站。
- 目标新增并启用 `nei_internal_vod`，每 5 分钟由本机 cron 检查、同一小时最多执行一次，每次拉取最近 2 小时；使用 `flock` 防重入，日志每天轮转并保留 14 份。2 小时窗口覆盖延迟数据，在当前源 API 为 13 条/1 页；原 24 小时窗口会重复递归处理 233 条/12 页，已停止使用。
- 调度请求只走 `127.0.0.1`，鉴权令牌通过请求头发送且已轮换，不写入 crontab 或新 access log。内网站 XML API、目标调度入口和自动跳过重复执行均验证通过。
- 首轮共处理 12 页，新增 28 条：目标视频由 251606 增至 251634，max id 由 284544 增至 284572，最新时间为 2026-08-22 13:48:35；对应 Meilisearch 增至 331933 文档。
- 修复两处 TP8 采集兼容问题：远端辅助字段入库前按真实表列白名单过滤；旧版 `insert($data, false, true)` 全部改为 `insertGetId()`，确保新增主键和 Meilisearch 增量同步正确。
- 修复定时任务失败语义：任务抛异常、发生 PHP fatal 或配置了不存在的 handler 时，`runtime` 自动恢复为执行前值，下一次 5 分钟检查会重试；runner 对空 HTTP 200 和应用 JSON 错误均返回非零。临时故障任务验证结果为退出码 1、runtime 保持 0。
- 2026-08-22 14:43 使用 2 小时窗口真实执行 1/1 页成功，随后同小时检查均正常跳过；15:00 跨小时再次自动执行 1/1 页成功，15:05 正常跳过。目标 `mac_vod` 当前 251642 条、max id 284580；老主库仍为 251606 条、max id 284544，目标多出的 36 条均来自新机内网站采集。文章 80299/max 80321、分类 56/max 77 两边一致，老主库没有新的待合并增量。

### 上线观察

- 2026-08-22 15:18 至 15:38 连续观察 20 分钟，每 5 分钟检查 Nginx、PHP-FPM、MySQL、Dragonfly、Meilisearch、采集心跳和四个公网入口。四轮中 `beiyong.slapibf.com`、`slapibf.com`、`senlinzy.com`、`www.senlinzy10.com` 均为 HTTP 200，响应时间 0.20 至 0.30 秒；15:20、15:25、15:30、15:35 的采集检查均正常。
- 观察期内 PHP 慢请求、MySQL 错误、Dragonfly/Meilisearch 错误和业务 FastCGI/upstream 错误均为 0。新增 78 条 Nginx error 全部是针对 `.env` 或随机不存在路径的机器人扫描，均被现有规则拒绝，不属于应用故障。
- 三个共享 webroot vhost 已加载 `deploy/nginx/maccms-legacy-noise.conf`：`/favicon.ico` 映射到仓库内现有图标；已撤销的 `/selangadmin.php` 返回 410 且不进入 PHP。直连目标机验证首页 200、favicon 200、旧入口 410，Nginx 配置测试通过并已 reload；回滚备份位于 `/home/migration/nginx-noise-before-20260822-1518/extensions.tar.gz`。

## 最终切换

共享主站不再等待 DNS 切换。2026-08-22 的实际状态是：`beiyong.slapibf.com`、`slapibf.com` 和抽查的 `senlinzy.com`、`senlinzy1.com`、`senlinzy10.com` 及 www 别名已命中新机资源标记；`selangzy.com`、`www.selangzy.com` 已确认放弃；`nei.selangzy.com`、`ff.senlinzy.com` 按计划留在老机；`slapibf1.com` 仍无公开解析。

1. 至少提前一个 TTL 周期把所有待切域名的 A 记录 TTL 降至 300 秒。
2. 记录源库 `mac_vod`、`mac_art` 的精确 count/max(id)/max(time)，作为最终验收基线。当前基线见“定时采集”最后一条；切换窗口仍需再读一次。
3. 暂停源站内容写入：停采集/推送任务、禁止后台编辑和写接口；旧站 GET 继续服务，因此读流量不中断。
4. 在源机执行新的 `--single-transaction` 全库备份，完成后再次确认写入仍冻结；该备份只作为审计、增量提取和回滚依据，不直接恢复到目标生产库。
5. 把最终备份传到目标机并校验 SHA-256、`gzip -t`，随后只导入隔离暂存库。
6. `nei_internal_vod` 启用后目标 `mac_vod` 已包含新采集数据，禁止用旧库全量覆盖任何目标业务表。若旧机出现新写入，只按业务键/更新时间生成并复核增量 SQL，再按字段交集合并；继续排除 `mac_admin` 和目标新增的 TP8 功能表。
7. 核对源/目标所有业务表行数，并重点核对 vod/art/type 的 count/max(id)/max(time)；目标由新机采集产生的可解释领先属于正常状态。
8. 清应用缓存，抽查首页、随机分类、随机详情、provide API、播放器配置和后台登录。
9. 对唯一 Meilisearch 索引执行全量重建；索引未完成时应用可回退 MySQL 搜索，不阻塞切 DNS。
10. 不再修改 `selangzy.com`、`www.selangzy.com`；已命中新机的共享主站域名也不要重复改动。旧机继续承载尚未迁移的内网站和 MacCMS 8 站点。
11. DNS 生效后为 `slapibf.com` / `slapibf1.com` 在 aaPanel 重新签发证书，再启用 HTTPS。
12. 连续观察新机 Nginx 5xx、PHP 错误、MySQL 慢查询、Dragonfly 和 Meilisearch 任务至少 2 小时。
13. 旧机至少保留 48 小时，不删除数据；确认无回滚需求后再下线。

## DNS CNAME 方案

- 在 `slapibf.com` 区域新建唯一入口：`A  origin  23.225.113.34`，必须设为仅 DNS（灰云），TTL 300 秒或 Auto。
- 下列根域名使用 Cloudflare CNAME Flattening，记录名为 `@`，目标统一为 `origin.slapibf.com`：`senlinzy.com`、`senlinzy1.com` 至 `senlinzy10.com`、`slapibf.com`、`slapibf1.com`。
- 下列子域名直接 CNAME 到 `origin.slapibf.com`：`www.senlinzy.com`、`www.senlinzy1.com` 至 `www.senlinzy10.com`，以及 `beiyong.slapibf.com`。
- `selangzy.com` 和 `www.selangzy.com` 已永久放弃，禁止添加到本 CNAME 方案。
- `nei.selangzy.com` 和 `ff.senlinzy.com` 是独立程序/数据库，本阶段禁止修改，继续留在旧机。
- `slapibf1.com` 当前没有公开 NS/A 记录；若要启用，需先在注册商完成 Cloudflare NS 委派，再添加上述根 CNAME。
- 唯一入口保持灰云可避免跨 Cloudflare 区域的代理 CNAME 风险；各业务记录继续沿用其当前代理状态。DNS 修改后立即在目标机为 `slapibf.com` / `slapibf1.com` 签发证书并复查 Cloudflare SSL 模式。

## 回滚条件

出现下列任一情况时，把 DNS A 记录切回源机，并保持目标机数据不动用于排查：

- 首页/API 持续 5xx，且 10 分钟内无法恢复。
- 目标 vod/art/type 出现无法解释的缺失，或数据时间明显落后于最终源快照。
- 播放器、FTP/图床配置缺失，导致核心业务不可用。
- 新管理员无法登录，或会话无法在 Dragonfly 持久化。
- Meilisearch 不可用本身不是回滚条件，应用应先回退 MySQL 搜索。

## 部署注意

- 后续 rsync 必须排除 `.env`、`application/extra/maccms.php`、`upload/`、`runtime/`、随机后台入口和 `admin.php`。
- 不要把默认 `admin.php` 再同步到线上；后台入口以 `/root/selangzy-admin-entry` 为准。
- 不要使用共享 Meilisearch 索引名 `maccms_contents`；每个站必须使用按数据库连接派生的唯一名称。
- 迁移工具和运行手册不保存数据库、SSH、Dragonfly、Meilisearch 或管理员口令。
