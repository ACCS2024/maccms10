# nei.senlinzy.com 独立站迁移运行手册

更新时间：2026-08-22

## 边界

- 源机：`23.225.73.50`，旧站目录 `/home/www/wwwroot/nei.selangzy.com`。
- 目标机：`23.225.113.34`，新站目录 `/home/wwwroot/nei.selangzy.com`。
- `nei.senlinzy.com` 是迁移后的正式域名；站点继续使用独立数据库，也是共享主站的采集源。
- 迁移只搬业务数据、白名单配置和 JPG 上传资源。旧 PHP、旧 `RX03` 主题、旧框架、旧 `vendor`、日志、runtime 和 `mac_admin` 均不迁移。
- 不复制旧站单文件 `Yzm.php`。当前系统继续使用集成的 Ppvod 控制器、历史路由和 JSON 响应契约，并通过默认关闭的站点级兼容开关承接旧报文语义。
- DNS 切换前旧站继续接收推送；正式切换必须先把旧 vhost 整站反代到新机，避免双写并确保主站采集不会读到停止更新的旧库。

## 已完成

- 目标代码从 `feat/tp8-migration` 独立部署到 `/opt/maccms10-nei`，运行时代码包含兼容提交 `b0bd513` 和日志修复 `80746e7`；没有改动已有的 `/opt/maccms10`。
- 新建独立数据库 `nei_selangzy` 和最小权限应用账号；新管理员随机生成，旧 `mac_admin` 未迁移。
- 安装记录和随机后台入口分别保存在目标机 `/root/nei-selangzy-install.json`、`/root/nei-selangzy-admin-entry`，权限为 `0600`。
- 旧库快照先导入隔离库 `nei_selangzy_legacy`，再按共有字段迁入 25 张业务表；旧 `mac_tmpvod` 未迁入，新版功能表保留。
- 快照基线为视频 `250764` 条、最大 ID `483729`；首轮增量后为 `250766` 条、最大 ID `483731`。
- 42 个分类和全部旧业务配置通过纯 JSON 白名单合并。数据库连接、新安全密钥和当前系统主题 `vozy` 保持新安装值。
- 已逐行核对旧单文件 `Yzm.php` 与当前 Ppvod：本站私有配置开启 `legacy_compat=1`，恢复报文 `domain/picdomain/mp4domain`、MP4 下载地址、采集发布状态和未知分类栏目 20 兜底；仓库及其他站点默认均为关闭。
- 兼容分支保留当前系统的常量时间密码校验、参数化判重、回收站语义、注入拦截、JSON 回执和 Meilisearch 增量同步；报文域名只允许 HTTP(S)，路径和标识符进入数据库前会严格校验。
- 上传资源已同步 `27746` 个 JPG，共 `3361874498` 字节；源目录没有 PHP、脚本或软链接。
- FTP 使用目标站实际配置从新机登录成功。
- Dragonfly 健康检查为 `PONG`；Meilisearch 使用独立索引 `maccms_nei_selangzy`，已重建 `250766` 个视频文档。
- 目标 vhost 使用 PHP 8.3 和独立日志，证书有效至 2026-11-05；敏感目录和上传脚本请求被 Nginx 拒绝。
- 目标 aaPanel 已登记独立站点和 `nei.selangzy.com` 域名记录；登记前面板数据库备份保存在目标机 `/root/default.db.before-nei-registration-20260822`，现有已验证 vhost 未被面板重建。
- 首页、provide XML API 均为 HTTP 200；新旧最近两小时 API 的记录数和视频 ID 集合一致。
- 最新真实推送报文在目标历史路由重放返回 `duplicate`，活跃同名记录前后均为 1；其封面、播放、MP4 下载、状态、分类和播放器 6 项均与旧版兼容构造结果一致。
- 恶意 `javascript:` 报文域名实测返回 `rejected/domain`。Ppvod 独立日志已改到 Nginx 禁止访问且运行用户可写的 `runtime/api/ppvod/`，部署后 PHP/runtime 致命和未定义变量错误均为 0。
- 旧机反代后、兼容代码部署前的 17:09 有一条过渡窗口入库（`vod_id=483732`）：只进入目标库，源库仍停在 `483731`，Meilisearch 文档存在。该行沿用当时现版本的分享下载地址；按老公式重建出的 MP4 候选当前返回 404，因此保留可用地址，不做猜测性覆盖。
- 兼容开启后的首条真实推送已入库为 `vod_id=483733`：日志回执为 `inserted`，名称、封面、播放、MP4 下载、采集状态、分类、播放器和活跃状态均与原始报文按旧 `Yzm.php` 公式构造的结果一致；Meilisearch 文档同步成功。
- 新域名 `nei.senlinzy.com` 已加入站点 vhost 和宝塔站点 ID 5，DNS 直达目标机；Let's Encrypt 证书仅签发新域名并通过严格主机名校验，有效期至 2026-11-20。
- 站点私有 `site_url` 和 `site_wapurl` 已改为 `nei.senlinzy.com`。旧 `nei.selangzy.com` 仅保留在 `server_name` 中兼容残余请求，不再作为正式域名或证书域名。
- 随机后台入口、验证码、随机管理员、Dragonfly 会话和仪表盘真实登录通过；默认 `admin.php` 返回 404。
- 旧站两个历史定时任务 `aa`（采集）和 `bb`（生成）均为关闭，宝塔无启用的 nei 计划任务，因此不复制。
- 官网原 MacCMS 任务 `nei_internal_vod` 已从 `application/extra/timming.php` 删除；官网与内网站以后只在后台按需手动同步，不再定时采集。宝塔证书续签、数据库备份和 MacCMS 运营统计任务不受影响。

## DNS 与域名现状

- `nei.senlinzy.com` 已解析到目标机 `23.225.113.34`，HTTP、严格 HTTPS、首页和 provide API 均为 200。
- `selangzy.com` 已到期并明确弃用，不再等待或修改其根记录、`www` 或 `nei` DNS。
- Nginx 当前保留 `server_name nei.selangzy.com nei.senlinzy.com;`，正式访问和应用生成链接统一使用 `nei.senlinzy.com`。

## 蓝绿切换记录

- 2026-08-22 约 17:00，旧机 `nei.selangzy.com` vhost 已启用 `nei-cutover-proxy.conf` 并 reload；公开 DNS 虽仍指向旧 IP，但旧 IP 的整站读写已经由新机处理。
- 启用前距离上一条源站推送超过 20 分钟，源/目标均为视频 `250766` 条、最大 ID `483731`、最大时间 `1787387669`。
- 等待旧 PHP-FPM 在途请求退出后再次核对，源库新增为 0，源/目标 count、max ID、max time 完全一致，最终待导入增量为 0。
- 经旧 IP 请求 provide API 与直连新机的记录数、视频 ID 集合完全一致；经旧 IP 重放真实 Yzm 报文由新机返回 `duplicate`，目标行数不变。
- 旧后台 `selangadmin.php` 的遗留浏览器轮询已在目标 vhost 返回 410，不再进入 PHP-FPM；随机新后台入口不受影响。
- 17:02 至 17:05 清理预检日志后观察：旧/新 IP 首页和 API 持续 200，Meilisearch 失败任务为 0；跨过两轮旧后台轮询后 Nginx error 和应用 error 均为 0。
- 旧机代理在 DNS 改为 CNAME 后仍需保留至少 48 小时，期间禁止恢复旧站本地 PHP 写入。

## 当前剩余动作

- 业务迁移、采集兼容、新域名 DNS、vhost、宝塔登记和 HTTPS 均已完成。
- 持续观察 `mac_vod` 最大 ID、Ppvod 日志和 Meilisearch 任务；首条兼容模式真实 `inserted` 已验证，无需向生产库制造临时测试内容。
- 旧域名和旧机资源暂不删除，待确认没有残余请求后再下线。

## 无双写切换顺序

1. 再核对源/目标 `mac_vod` 的 count、max ID、max time；目标不得落后于上一次已同步基线。
2. 把 `migration/nei-cutover-proxy.nginx.conf` 放到旧机 `nei.selangzy.com` vhost 的 extension 目录，执行 Nginx 配置测试后 reload。旧域名此时所有读写均由新机处理。
3. 用已导入目标库的真实报文请求旧域名；应由目标接口返回 `duplicate`，目标行数不变；首页和 provide API 也应返回新机资源标记与数据。
4. 等待 15 秒让 reload 前已进入旧 PHP-FPM 的请求结束，再从旧库导出 `vod_id > 目标最大 ID` 的最终增量并导入目标库。
5. 再次确认源/目标 count、max ID、max time 和最近两小时 API ID 集合一致。
6. 原计划修改旧 `nei.selangzy.com` CNAME，现因 `selangzy.com` 到期取消；改用已直达新机的 `nei.senlinzy.com`。
7. 从公共解析器确认 `nei.senlinzy.com` 命中新机；验证首页、provide API、Yzm 重放、后台、FTP 和 Meilisearch。
8. 旧机反代至少保留 48 小时，吸收仍缓存旧 A 记录的推送方；旧站和旧库同时保留，不删除。
9. 观察新机独立 Nginx/PHP 日志、数据库最大 ID 和推送间隔。确认稳定后撤销一次性迁移 SSH 公钥。

## 回滚

- 页面/API 持续 5xx、关键数据缺失或推送持续失败时，先停止 DNS 继续扩散。
- 因旧写入口已反代到新机，回滚 DNS 前必须把切换后目标新增行同步回旧库，避免丢失推送。
- 数据回补完成后把 `nei` 恢复为 `A 23.225.73.50`，移除旧机反代 extension，执行 Nginx 配置测试和 reload。
- Meilisearch 故障不是单独回滚条件，应用应回退 MySQL 搜索。

## 安全注意

- 不把 SSH、数据库、FTP、接口、Dragonfly、Meilisearch 或管理员口令写入仓库和日志摘要。
- 不把默认 `admin.php` 再同步到目标站。
- 后续代码 rsync 必须排除 `.env`、`application/extra/`、`upload/`、`runtime/` 和随机后台入口。
- 切换反代只作用于旧 `nei.selangzy.com` vhost，不影响其他站点或当前系统代码。
