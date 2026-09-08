---
name: lebozy-image-replace
description: 乐播站群(lebozy.com,采集 API 站,主题 stui_tpl)封面图床域名收敛/迁移时使用 —— 把 mac_vod.vod_pic 里那一堆 lb* 轮换域名批量归一到一个新图床域名,并同步更新 upload.remoteurl(管相对路径老封面 + 今后新图)与前台「替换助手」mac_rep。含最关键的安全闸(逐域名分三类:同图可换/旧死新活=恢复/旧活新无=需先同步),强制收敛策略,vip3 式"待同步清单"导出,备份与回滚。是 maccms-replace 针对乐播的落地特化;通用框架见 maccms-replace,155 版见 155-image-replace。
---

# 乐播封面图床域名收敛运行手册

乐播的封面图床是一批**同一运营方的轮换域名**(`jh.lb260522.top`、`fmlb.netlbtu.com`、
`lb260817.top`、`f.lbp2025.com`、`fw.lbbf9.com`…),隔一段时间换一个。任务通常是
**把它们全部归一到当前那个活的新域名**(2026-08 是 `lb260817.top`;**2026-09 已轮到 `lb260908.top`**,域名按 `lbYYMMDD` 命名=当月轮转日)。

**目标是所有封面收敛到一个域名 + 今后新图也走它。** 两处一起改才算完整:
1. `mac_vod.vod_pic` 存量(SQL REPLACE);
2. `upload.remoteurl`(那 52% 相对路径 `upload/vod/...` 靠它补域名,新图也靠它)。
外加前台 `mac_rep`「替换助手」登记,引导下游采集方跟着换。

## 乐播现场速查(实测 2026-08)
- 新机 `85.149.233.11`,webroot `/home/wwwroot/lebozy.com`,主题 `stui_tpl/html`。
- `mac_vod` 约 32.75 万条。**约 52% 的 `vod_pic` 是相对路径** `upload/vod/...`(不带域名,
  `mac_url_img()` 用 `upload.remoteurl` 补);其余是完整 `http(s)://域名/...`。
- `stui_tpl` 走 `mac_url_img()` 读配置取图(不像 vozy 在模板里硬编码图床前缀)。
- DB 只读跑 SQL:服务器上有 `/root/lb_ops.php "<SQL>"`(用 .env 里 app 账号,能 UPDATE/INSERT)。
- 相关记忆:`project-lebozy-theme-stui-tpl`(图床=remoteurl 那段)、`project-lebozy-incident-2026-08-26`。

## 0. 安全闸(最关键——**逐域名分三类,分类决定动作**)
先列当前所有域名 + 数量:
```sql
SELECT SUBSTRING_INDEX(SUBSTRING_INDEX(vod_pic,'/',3),'//',-1) d, COUNT(*) c
FROM mac_vod WHERE vod_pic LIKE 'http%' GROUP BY d ORDER BY c DESC;
```
对**每个**源域名 D,取 2~3 张真实封面,把域名换成新域名 B、路径不动,`curl` 比对:
```bash
# 旧 vs 新,各拿 http码/大小
O=$(curl -sm10 -o/dev/null -w '%{http_code}/%{size_download}' "$OLD_URL")
N=$(curl -sm10 -o/dev/null -w '%{http_code}/%{size_download}' "$(echo "$OLD_URL"|sed "s#//$D#//$B#")")
```
> 脚本 `scripts/classify.php` 会一次性把所有域名跑完并打分类。

分三类,动作不同:
| 分类 | 判据 | 动作 |
|---|---|---|
| ✅ **同图可换** | 旧 200、新 200 **且大小相同** | 直接 REPLACE |
| 🔵 **旧死新活=恢复** | 旧 404/000、新 200 | REPLACE(顺带把坏图修回来) |
| ❌ **旧活新无=需先同步** | 旧 200、新 404/000 | **默认排除**;若站长要强制收敛→导出「待同步清单」交图床方,再强制 REPLACE |

**注意各域名路径结构可能不同**(`jh.` 用 `/upload/vod/`,`fmlb.` 用 `/images/`,`f.lbp` 用 `/日期/hash/`)——
好在同运营方的新域名通常**三种路径都能命中**;但正因如此,必须逐类实测,不能想当然。

### 强制收敛策略(乐播站长明确要求)
- **连不上的域名一律强制替换**,别管当前行不行(反正已经是坏的,收敛到新域名便于管理)。
- **"旧活新无"型(如 vip3.lbbf9.com)**:先 `scripts/export_tosync.php` 导出那些图的真实 URL 清单
  → 交图床运营方同步到新域名同路径 → 再强制 REPLACE(站长语:"同步完就是新的了")。
  清单存 `/root/lebozy-incident-*/backups/`,别丢。

## 1-3. 执行(一条命令跑完,全程幂等)
🔴 **封面分两批,replace.php 一次都覆盖**(别只改一批):
- **写死域名的**(`https://旧域名/...`,乐播约 16 万行)→ SQL REPLACE(步骤 2)
- **相对路径的**(`upload/vod/...` 不带域名,约 52%/17 万行)→ 靠本站 `upload.remoteurl` 拼域名 → 改配置(步骤 3)

```bash
# ① 备份将被改的行(vod_id+vod_pic,gz)——真反悔时按主键回灌
php scripts/backup_rows.php <webroot> <旧域名逗号分隔>   # 写 /tmp 再由 root mv 到 /root
# ② 主替换:改脚本头 CONFIG($NEW/$domains/$repRegister)后跑,一次做完 5 步:
php scripts/replace.php <webroot>
#    1 mac_rep 登记  2 vod_pic 域名替换  3 upload.remoteurl 改+chown www  4 清缓存/影子  5 域名分布
```
`replace.php` 的每一步都是**幂等**的(已登记则跳过、无待迁域名则 0 行、remoteurl 已改则不动),
重复跑安全。要点:
- vod_pic 的 UPDATE **把 http 和 https 一并归一到 `https://B`**(老域名常是 http),
  **全域名带 scheme 匹配**(`https://D`/`http://D`),只碰 host 位,**不会误伤路径里的数字日期**
  (番号站踩过裸 `REPLACE('2607')` 毁 `20260701` 的坑,本脚本没有)。
- 步骤 3 改完配置**自动 `chown www:www`**——踩过的坑:root 写过的 `maccms.php` 若不 chown 回 www,
  **后台/采集/上传保存全静默失败**;并带 `php -l` 语法自检,改坏就放弃写入保原样。
- `upload.api.ftp.*` 乐播是**空的**(新采集封面是完整 URL,不走 FTP 回传),故只需 `remoteurl`;
  若哪天启用 FTP 图床,`api.ftp.url` 也要一起改。
- **前置**:跑前 classify.php 已确认 B 能返回相对路径那批图(`curl https://B/upload/vod/2019/.../x.jpg`=200)。

## 4. 前台「替换助手」mac_rep 登记(replace.php 步骤 1 已自动做;此处讲原理)
```sql
INSERT INTO mac_rep (rep_type,rep_original,rep_replacement,rep_note,rep_status,rep_applied,rep_applied_time,rep_create_time)
VALUES ('视频封面替换','<旧大域名>','<B>','封面图床域名迁移至 <B>',1,1,UNIX_TIMESTAMP(),UNIX_TIMESTAMP());
```
- **只登记体量大的那 1~2 个域名**(乐播是 jh.lb260522.top、fmlb.netlbtu.com);
  **杂七杂八很少的(几十上百条的)不用写**——站长明确要求,免得替换助手一堆噪声记录。
- 前台 `index/Rep` 按 rep_type 取「该类最新一条的 replacement」当「当前生效值」,所以登记后自动显示 B。

## 5. 验证(权威=详情页 + 首页封面直连;清缓存 replace.php 步骤 4 已做)
```bash
# 域名分布应只剩 B(+ 明确排除项)—— replace.php 步骤 5 已打印,也可自己再查
SELECT SUBSTRING_INDEX(SUBSTRING_INDEX(vod_pic,'/',3),'//',-1) d,COUNT(*) c
FROM mac_vod WHERE vod_pic LIKE 'http%' GROUP BY d ORDER BY c DESC;
# 首页/详情页 img 全是 B 且 200
curl -s -H 'Host: www.lebozy.com' http://127.0.0.1/ | grep -oE 'src="https://B[^"]*"' | while read u; do curl -s -o/dev/null -w "%{http_code} $u\n" "$u"; done
# 详情页取【相对路径片(走 remoteurl)+ 完整URL片】各一,确认 200 —— 两批都要验
# /index.php/macrep.html「当前生效值」已是 B
```
opcache 若 `validate_timestamps=On`(乐播是)则配置改动自动生效,无需 reload php-fpm;关掉的话要 reload。

## 回滚
- vod_pic:`UPDATE mac_vod SET vod_pic=REPLACE(vod_pic,'B','<某旧域名>') ...`——但多域名归一后
  无法从 B 反推原域名,**真要精确回滚就按 §1 的 gz 备份逐行回灌**(vod_id 主键)。
- remoteurl:改回 `application/extra/maccms.php` 备份(`backups/maccms.php.bak-remoteurl-*`)。
- mac_rep:`rep_status=0` 或删除对应行。

## 关联
- 通用框架 `maccms-replace`(rep_type↔字段映射、Rep::checkExecutable 最小长度、plan 分批)。
- `155-image-replace` —— 155(PPVOD 入库)版,额外要改 `ppvod.pic_domain`。
- 脚本 `scripts/{classify,backup_rows,replace,export_tosync}.php`(参数化,改站改域名即可复用)。
- 记忆 `project-lebozy-theme-stui-tpl`。
