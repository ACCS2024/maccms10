# 帮助中心「站内模块化」迁移方法（155 / 任意站通用）

更新：2026-08-22　　适用：把某个站的帮助中心从「外链子域 / 物理静态目录（常是 155 品牌）」
切换成**站内、配置驱动、多租户隔离**的帮助模块。森林（selangzy）已按本法全量落地并验证。

---

## 0. 结论先行：帮助中心本来就是站内模块，被两件事遮蔽了

代码里早已有完整模块：`mac_help_cfg` 表 + `HelpCfg` 模型 + `index/Help::index()` 控制器
+ 路由 `Route::any(help_path,'help/index')` + 后台配置页 + 权限节点。真正的坑是两处：

1. **物理 `help/` 目录遮蔽路由**（**头号根因**）：仓库历史带了个 155 品牌静态站 `help/`，
   部署进 webroot 后，nginx `try_files $uri $uri/` 会直接吐 `/help/index.html`（155 静态），
   **maccms 的 /help 路由永远跑不到**。表现＝「help 像写死、内容是 155」。
2. **`mac_help_url()` 生成的 URL 不匹配本站 URL 方案**：老实现返回裸 `/help`，而本项目默认是
   `/index.php/xxx.html`（无伪静态 rewrite），裸 `/help` 直接 404。

两者已在 canonical 仓库修复（commit `40721a5`、`daebfb3`）。**新部署自动带上修复**；已在运行的老站
需按下面「部署层 + 配置层」补做两步。

---

## 1. 代码层（一次性，已在仓库，确认即可）

- `mac_help_url()` = `'/index.php/' . help_path . '.html'`（与 `mac_rep_url()` 同约定；伪静态站也可达）。
- 仓库根 **155 静态 `help/` 目录已删**（`daebfb3`）——今后 rsync/部署不再把它带进 webroot。
- 当前 PC 主题（demo）已有自包含帮助模板 `template/demo/html/help/index.html`（内联样式 + `{$cfg.*}`
  配置驱动，不依赖任何静态目录）；移动端 vozy 早已有。
- 主题里**不得硬编码任何 `help.xxx` 外链**，一律 `{:mac_help_url()}`。
  自查：`grep -rn 'help\.senlinzy\|help\.selangzy\|https\?://help\.' template/<该站主题>/`

> 若 155 用的是别的主题（另一个 agent 会升级它），**该主题也要**：① 有 `html/help/index.html`
> （从 `template/demo/html/help/index.html` 或 vozy 版移植，自包含）② head/notice 等处改 `{:mac_help_url()}`。

## 2. 部署层（每站，**关键**）

```bash
ROOT=/home/wwwroot/<该站目录>
# ① 删除 webroot 里的物理 help/ 目录（否则继续遮蔽 /help 路由）——移走留证，不直接删
[ -d "$ROOT/help" ] && mv "$ROOT/help" /root/help_static_backup_$(basename $ROOT)_$(date +%Y%m%d-%H%M%S)
# ② 确保当前 PC 主题有帮助模板（没有就从 demo 拷）
[ -f "$ROOT/template/<主题>/html/help/index.html" ] || \
  { mkdir -p "$ROOT/template/<主题>/html/help"; cp <canonical>/template/demo/html/help/index.html "$ROOT/template/<主题>/html/help/index.html"; }
# ③ 确认 common.php 的 mac_help_url 是 /index.php/*.html 版（老站若未随代码更新，按本法补丁）
grep -q "index.php/. . ltrim(\$path" "$ROOT/application/common.php" || echo "需要更新 mac_help_url"
# ④ 清模板编译缓存
find "$ROOT/runtime" -type d -name temp -prune -exec sh -c 'rm -f "$1"/*.php 2>/dev/null' _ {} \;
```

## 3. 配置层（每站，多租户隔离——这是"智能个性化"的来源）

在该站 DB 的 `mac_help_cfg` 填**该站自己的**值（key-value），或走后台「帮助中心」配置页：

| cfg_key | 含义 | 155 该填什么 |
|---|---|---|
| `site_name` | 站点名 | 155 的站名 |
| `site_host` | 站点地址 | 155 人可见主域 |
| `api_host` | **主采集接口**（下游据此采集） | 155 对外采集域名，以 `/` 结尾 |
| `api_host_backup` | 备用采集接口 | 155 备用域名 |
| `parse_host` / `player_host` | M3U8 解析地址 | 155 的解析地址（如 `https://x/?url=`） |
| `player_flag` / `player_code` | 播放器标识/自定义代码 | 155 的播放器 |
| `newart_enabled` / `newart_api_host` | 新闻/演员接口 | 按需 |
| `tg_url` / `notice` | TG群 / 公告 | 155 的 |
| `enabled`(=1) / `help_path`(=help) | 开关 / 路由前缀 | 保持默认 |

```sql
UPDATE mac_help_cfg SET cfg_val='<值>' WHERE cfg_key='<key>';   -- 逐项；库为 utf8mb4
```

> **值从哪来**：优先取老站真实值——老 `help.<站>.com` 静态页里 baked 的采集接口/解析地址，
> 或该站 `application/extra/maccms.php` 的 site_name / ppvod play_domain / player_flag。
> **保持采集接口 URL 与老站一致**（下游合作方已配置，别乱改 = 业务连续性）。

## 4. 验证（三态 + 不塌站）

```bash
H='-H Host:<主域>'
# a) 首页帮助链接 = /index.php/help.html 且 200、内容是本站（无 155）
curl -s $H http://127.0.0.1/ | grep -oE '/index.php/help.html'
curl -s $H http://127.0.0.1/index.php/help.html | grep -oE '帮助中心 - <站名>|<本站采集域>|155资源'
# b) 首页 + 任意 vod 页仍 200（帮助改动不许影响正站）
curl -s $H http://127.0.0.1/ -o /dev/null -w 'home %{http_code}\n'
```
预期：链接 `/index.php/help.html` → 200，标题「帮助中心 - <站名>」，采集接口是本站的，**无 155 字样**；
首页/vod 200。帮助中心关闭（`enabled=0`）应 404 而非 500（`HelpCfg` 已失效降级）。

## 5. 收口老外链（P1，可选）

老 `help.<站>.com` 子域：**301 或反代到 `/index.php/help.html`**；老静态帮助站退役。
新机不再需要独立的 help 子域机器。

---

## 为什么这套能对抗 review

- **零硬编码域名**：帮助内容全部来自本站 `mac_help_cfg`，代码 `grep` 不到任何站点域名。
- **多租户天然隔离**：每站自己的 `mac_help_cfg`——155 用 155 的，森林用森林的，绝不串。
  新机接入＝部署代码 + 删物理 `help/` + 填 `mac_help_cfg`，**三步**，无需改代码。
- **失效降级**：`HelpCfg::get` try/catch，表缺/库挂只废帮助中心，不塌全站；关闭＝404 非 500。
- **自包含模板**：帮助页内联样式 + `upload/help/` ZIP，不依赖被删的静态目录，主题无耦合。
- **业务连续**：采集接口 URL 沿用老站值，下游合作方零改动。

## 155 专项提醒（交给升级 155 的 agent）

1. 先把 155 站升级到含帮助模块的 tp8 代码（`index/Help` + `HelpCfg` + `mac_help_cfg` 表 + 路由 + 修好的 `mac_help_url`）。
2. **务必删掉 155 webroot 里的物理 `help/` 目录**（它就是 155 静态帮助本体，不删＝继续遮蔽）。
3. 155 的主题若非 demo/vozy，按 §1 note 给它补 `html/help/index.html` + 改硬编码外链。
4. 用 155 自己的采集接口/播放器/站名填 `mac_help_cfg`。
5. 按 §4 验证。
