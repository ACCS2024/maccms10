# cs_jump 跳转木马 —— 取证结论与本地检测引擎设计

> 事件源站：老宝塔机 `23.225.113.26`（主 maccms 站 `/home/wwwroot/155new.com`，DB `155zy_com`，前缀 `mac_`）。
> 处理时间：2026-08-10。本文供后续开发「反病毒 / 本地扫描引擎」参考。

## 1. 病毒本质（一句话）

**不是 webshell、不是被篡改的 PHP 文件，而是对数据库合法字段 `vod_jumpurl` 的滥用。**
攻击者往 `mac_vod` 插一条视频记录，把 `vod_jumpurl` 设成外部恶意 URL，访客打开该视频页就被 JS 自动跳转出去。这是黑帽 SEO 流量劫持（寄生虫）。

### 触发点（本仓库代码）
- `template/default/html/vod/play.html:380-381`
  ```smarty
  {if condition="$obj.vod_jumpurl neq ''"}
  location.href='{$obj.vod_jumpurl}';
  ```
- `template/default/html/vod/copyright.html:17-26` 同样把 `vod_jumpurl` 渲染成跳转链接。
- 字段本身是 maccms 合法功能（原用于「版权问题跳转」），`vod / art / actor / type / website / manga` 各表都有对应 `*_jumpurl`。**任何一个都可被同样滥用。**

## 2. 样本（本次实际捕获）

| 字段 | 值 |
|---|---|
| 表 / 记录 | `mac_vod` / `vod_id=184404` |
| `vod_name` | `cs_jump_1786300836`（`cs_jump_` + 10 位 Unix 时间戳） |
| `type_id` | `1` |
| `vod_jumpurl` | `https://xiazai.it.com`（落地走 Cloudflare 前置） |
| `vod_content` | `c`（单字符填充） |
| `vod_play_url` / `vod_down_url` / `vod_remarks` | 空 |

**样本特征**：除了 `vod_name`、`type_id`、`vod_jumpurl` 外几乎全空，是个「只为跳转而存在的空壳记录」。

## 3. 投放方式与入侵路径

- **投放方式**：攻击者用后台**管理员账号**登录（后台入口 `adminz.php`，跑在 `:2277`），直接在后台新建 / 编辑 vod 记录写入 jumpurl。**不走 API、不走采集**——所以站长「关闭 API 发布权限」无效。
- **持久化后门 = 一个 rogue 管理员账号**：`mac_admin` 里 `admin_id=2 / admin_name=155palyer`，从法国 Scaleway `163.172.53.62` 登录，累计 703 次；权限串 `admin_auth` 长 853 字符（站长本账号仅 15），含 `upload/upload`、`annex/file|check|init|del`（**具备后台上传文件能力**，可进一步传 webshell）。
- **口令强度**：登录校验为 `admin_pwd != md5($password)`（见旧站 `application/admin/controller/Index.php`），**无盐 MD5**，易离线爆破。
- **源头（最初怎么进来的）**：**不可考**。nginx 日志只回溯到 2026-07-05，DB 备份从 2023-12 直接跳到 2026-07（中间轮转丢失）。已知：`155palyer` 在 2022–2023 全部备份中不存在、2024 年出现 → **账号创建于 2024 年**；日志窗口内无爆破痕迹，说明攻击者早已持有有效口令。最可能是 2024 年一次 getshell / SQLi / 弱口令 / 脱库离线破解，但对应证据已随日志轮转灭失。

## 4. IOC 清单

```
# 跳转落地域名
xiazai.it.com                     (Cloudflare 前置)
# rogue 管理员
mac_admin.admin_name = 155palyer  (admin_id=2, admin_auth 长度 853)
# 攻击者来源 IP / 运营商
163.172.53.62    Scaleway / Online SAS   AS12876   (开过 admin/vod/data.html)
172.105.219.210  Linode / Akamai         AS63949
192.154.96.154   Nexeon / ColoCrossing   AS20278   (挂后台标签轮询 5.4 万次)
# 样本命名特征
vod_name ~ ^cs_jump_[0-9]{10}$
```
> 注：`66.245.220.233` 是站长本人出口，**非攻击者**。

## 5. 本地检测引擎设计（可直接实现）

### 5.1 数据库扫描（核心 —— 这才是真正的感染面）

**规则 A：跳转字段外链检测（最高优先级）**
对以下每张表的 `*_jumpurl` 字段，凡非空且指向「站点自身域名白名单之外」的，一律告警：
```sql
-- 对 vod / art / actor / type / website / manga 各跑一遍
SELECT vod_id, vod_name, vod_jumpurl FROM mac_vod
 WHERE vod_jumpurl <> ''
   AND vod_jumpurl NOT REGEXP '^https?://(www\\.)?(你的域名1|你的域名2)(/|$)';
```
清空 / 删除即消毒：`UPDATE ... SET *_jumpurl='' WHERE ...`（或删除空壳记录）。

**规则 B：空壳记录启发式**
`*_jumpurl` 非空 **且** 内容字段近乎为空（`LENGTH(vod_content) <= 2` 且 `vod_play_url=''`），基本可判定为纯跳转木马。

**规则 C：命名 / 批量时间特征**
- `vod_name REGEXP '^(cs_|jump_|tiaozhuan)'` 或 `vod_name REGEXP '_[0-9]{10}$'`
- 同一秒内批量插入的同类记录（`GROUP BY vod_time HAVING COUNT(*)>N`）。

**规则 D：正文注入检测**
`vod_content / art_content` 内出现 `window.location`、`location.href`、`<script`、`<iframe`、`document.write` + 外链域名 → 告警。

### 5.2 管理员账号审计

```sql
SELECT admin_id, admin_name, admin_status, LENGTH(admin_auth) auth_len,
       admin_login_ip, admin_login_num
FROM mac_admin;
```
告警条件：
- 账号数量 > 预期；出现未知 `admin_name`；
- `LENGTH(admin_auth)` 异常偏大（本例 853 vs 正常 15）；
- `admin_login_ip` 归属为**海外 / 数据中心 ASN**（Linode/Scaleway/Nexeon/DigitalOcean/OVH…）；
- **强制加盐哈希**：把登录改为 `password_hash()` / `md5(salt+pwd)`，淘汰无盐 md5。

### 5.3 文件扫描（辅助）

- **改名后台入口**：扫描 web 根目录下所有 `*.php`，凡包含 `define('ENTRANCE','admin')` 或 `require .../thinkphp/start.php` 且文件名不在白名单者告警（应只有你自己改名的那一个）。本例发现遗留旧入口 `adhuyRB2Ts9mQT6mFin.php`。
- **上传目录含可执行脚本**：`upload/`、`annex/` 下出现 `*.php / *.phtml / *.php5` 一律告警（上传目录永不应有脚本）。
- **webshell 特征正则**（对 php 文件）：
  ```
  @?(eval|assert)\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)
  \$_(POST|GET|REQUEST)\[[^]]*\]\s*\(
  create_function\s*\(
  preg_replace\s*\(\s*['"].*/e
  gzinflate\s*\(\s*base64_decode | str_rot13\s*\(\s*base64_decode
  ```
- **核心文件完整性**：对 maccms 核心 php 做已知良好哈希比对，检出被篡改文件。

### 5.4 代码侧加固（本仓库——已实现 ✅）

已落地（2026-08-10），**不向后兼容**：非 http(s) 干净绝对地址的 `*_jumpurl` 一律在入库与输出两端被清空。

- 新增中央净化函数 `mac_safe_jumpurl($url)`（`application/common.php`）：仅放行 `^https?://` 且不含引号/尖括号/空白/反斜杠/反引号/控制字符、长度 ≤150 的 URL，其余返回空串（杀 XSS 引号闭合 + `javascript:`/`data:` 伪协议）。配套 `mac_clean_jumpurl_fields($row)` 批量净化一行的 6 个 `*_jumpurl`。
- **入库全路径覆盖**：
  - 后台保存：6 个模型 `saveData()`（Vod/Art/Actor/Type/Website/Manga）各加 `mac_safe_jumpurl`。
  - 采集/接收：`Collect.php` 的 10 个 `insert()/update()` 写库点前置 `mac_clean_jumpurl_fields()`（Receive 接口经 Collect 间接覆盖）。
- **输出兜底**：`template/default/html/vod/play.html`、`copyright.html` 渲染改为 `mac_safe_jumpurl(...)`，连存量脏数据也净化。
- 待办（部署侧，非代码）：后台入口端口默认不对公网开放，仅内网 / 指定 IP / SSH 隧道访问。

## 6. 本次已做处置（回顾）

- 删除病毒记录 `vod_id=184404`；全站 `*_jumpurl` 非空数归零。
- rogue 账号 `155palyer` 置 `admin_status=0` 并随机化口令（**保留账号行留证，未删除**）。
- 清后台登录会话；`iptables` 封 2277（仅放行站长出口）+ 封攻击者 IP/运营商段（ipset `badnet`）。
- 证据留存：服务器 `/root/cs_jump_forensics.json`、旧后台入口文件原样保留。
- **注意**：防火墙规则为内存态，重启失效（该机将弃用未持久化）。迁移新机时勿沿用旧 `mac_admin` 数据 / 旧后台名 / 弱口令。
