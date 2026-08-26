---
name: maccms-replace
description: maccms 站群做一次"内容/域名替换任务"时使用 —— 封面图床域名替换(vod_pic)、播放链接域名替换(vod_play_url)、播放器解析替换、整站域名替换等。标准两步:①往前台「替换助手」(/index.php/macrep.html 背后的 mac_rep)登记一条对应类型记录给采集方看;②对应字段跑 SQL REPLACE 更新本站存量。含安全前置(验新域名可达/判重/范围)、rep_type↔字段映射、关联配置(图床 FTP url、播放器解析)与回滚。
---

# maccms 通用替换任务(替换助手)运行手册

站长发布一次数据替换时,**既要在前台「替换助手」登记给下游采集方看,又要更新本站存量数据**。
两件事一起做才算完整。官网 + 内网(及任何有该串的站)通常都要做。

## rep_type ↔ 替换字段 映射(核心，等于 `Rep::$typeMap`)
| 用户口语 | rep_type | 替换字段(表.字段) | 备注 |
|---|---|---|---|
| 封面/图片替换 | `视频封面替换` | `mac_vod.vod_pic` | 图床域名迁移最常见 |
| 播放链接/播放地址替换 | `视频播放地址` | `mac_vod.vod_play_url` | 播放域名迁移 |
| 播放器替换 | `播放器替换` | `mac_vod.vod_play_from`, `vod_play_server` | 多数只在后台改播放器解析,未必动库 |
| 文章图片替换 | `文章图片替换` | `mac_art.art_pic`, `art_content` | |
| 域名替换(全站) | `域名替换` | `mac_vod.vod_play_url`+`vod_pic`, `mac_art.art_content`+`art_pic` | 一次动多字段 |
前台 `index/Rep` 按 rep_type 分组、算「当前生效值 = 该类最新一条的 replacement」,所以登记记录后前台自动更新。

## 流程（以"封面 A→B",A=旧域名 B=新域名 为例）

### 0. 安全前置（必做，都是踩过的坑）
- **验新域名可达**（最关键）：取一条现有值，把域名换成 B 后 `curl`，必须 **200 且大小与旧域名一致**
  （证明 B 是同一图床/CDN 的新域名，不是空壳）。不通就**停手**，否则整站封面/播放全挂。
  ```bash
  S=$(mysql -N <db> -e "SELECT vod_pic FROM mac_vod WHERE vod_pic LIKE '%A%' LIMIT 1")
  curl -sm10 -o/dev/null -w '%{http_code} %{size_download}\n' "$(echo $S|sed 's/#.*//' | sed 's/A/B/')"
  ```
- **原文 ≥4 字符 且 原≠替换**（`REPLACE()` 是无边界子串替换，太短会误伤正文；见 `Rep::checkExecutable`）。
- **判重**：`SELECT COUNT(*) FROM mac_rep WHERE rep_original='A' AND rep_replacement='B'` >0 就别重复插。
- **定范围**：逐站 `SELECT COUNT(*) FROM mac_vod WHERE vod_pic LIKE '%A%'`，确认哪些站要做。

### 1. ① 前台登记（每个受影响的站）
```sql
INSERT INTO mac_rep (rep_type,rep_original,rep_replacement,rep_note,rep_status,rep_applied,rep_applied_time,rep_create_time)
VALUES ('视频封面替换','A','B','<备注,如 封面图床域名迁移>',1,1,UNIX_TIMESTAMP(),UNIX_TIMESTAMP());
```
`rep_applied=1` 因为随即执行；前台「当前生效值」立刻变 B。

### 2. ② 更新存量（映射表里该 rep_type 的**每个字段**都跑）
```sql
UPDATE mac_vod SET vod_pic=REPLACE(vod_pic,'A','B') WHERE vod_pic LIKE '%A%';
```
量大无妨（实测 25 万行 ~8s）。要极致平滑可按主键分批，逻辑见 `Rep::plan()`（主键开窗口，避免每批全表扫）。

### 3. ③ 关联配置（按类型，别漏——否则"新数据又变回老域名"）
- **封面/播放 = 图床域名迁移**：若 `application/extra/maccms.php` 的 `upload.api.ftp.url` 还是老域名 A，
  **今后新采集/上传的封面会继续打 A** → 按需把两站的 `upload.api.ftp.url` 改成 B（**前提：A、B 指同一图床**）。
- **播放器解析变了**：后台「播放器」改解析接口地址；自定义源要 `ps=1`+填解析（见 `maccms-migrate` 陷阱 2、3）。

### 4. ④ 收尾
- 清 runtime 缓存（both sites）：`find $ROOT/runtime -path '*cache*' -o -path '*temp*' -name '*.php' -delete`。
- 抽查前台封面/播放 200；`/index.php/macrep.html`（DYNAMIC）看「当前生效值」已是 B。
- CDN 站：静态资源另说，但封面/播放是数据、走 DB，无 CDN 缓存问题（HTML 页 DYNAMIC）。

## 回滚
反向 REPLACE：`UPDATE mac_vod SET vod_pic=REPLACE(vod_pic,'B','A') WHERE vod_pic LIKE '%B%';`
并把 mac_rep 那条 `rep_status=0` 或删除。（新老同床时即使不回滚也不至于挂图。）

## 关联
- 前台模块 `application/index/controller/Rep.php` + `template/*/rep/index.html`（泛用，沿用各站主题）
- 模型 `application/common/model/Rep.php`（`$typeMap` / `checkExecutable` 最小长度 / `plan` 分批 / `likePattern`）
- `maccms-migrate` skill —— 整体迁移 + 图床/播放器/CDN 陷阱
