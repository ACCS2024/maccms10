---
name: fanhao-image-replace
description: 番号站群(fhzy1.com / fhapi9.com / bjgx,主题 default_pc,新机 85.149.233.11)换**封面图床域名**或做**播放域名按月轮转**时使用 —— 批量改 mac_vod.vod_pic、往前台「替换助手」mac_rep 登记、并且**同步改发布程序 ffcore 的 picDomain**(最容易漏的一步,不改则下一批新内容又带回旧域名)。含安全闸(新域名必须返回同一张图,md5 比对)、三站共库但配置各一份的坑、相对路径封面靠 upload.remoteurl 的坑、缓存前缀分站清。另含播放域名轮转(vod_play_url,按 URL 路径里的内容日期定 26MM.fhbbff.com;裸 REPLACE 会毁数据,因为 2607 也出现在路径日期 20260701 里)。是 maccms-replace 针对番号的落地特化;通用框架见 maccms-replace,乐播版见 lebozy-image-replace,155 版见 155-image-replace。
---

# 番号封面图床域名迁移运行手册

## 涉及对象(2026-08-31 实测)

| 项 | 值 |
|---|---|
| 站点 | `fhzy1.com`(前台) / `fhapi9.com`(采集API) / `bjgx`(入库口 :35728) —— **三站共用库 `fhzy1_com`** |
| 机器 | 新机 `85.149.233.11`,webroot `/home/wwwroot/<站>`,PHP `/www/server/php/83/bin/php` |
| MySQL | root 口令取自 aaPanel:`sqlite3 /www/server/panel/data/default.db "select mysql_root from config"` |
| **要改的字段** | **只有 `mac_vod.vod_pic`**(16.7 万行)。实测 `vod_pic_thumb/slide/screenshot`、`mac_art.*`、`mac_topic/actor/role/website/type/link` **全为 0**,别浪费时间全表扫 |
| 相对路径封面 | 6.2 万行是 `upload/...`,**不带域名**,靠各站 `upload.remoteurl` 拼 —— 换的是那个域名才需要改配置 |
| 发布程序 | ffcore,在冒烟机 `216.180.225.138`,`/home/dev/ffcore`,服务 `ffcore-publisher.service` |
| 主题 | `default_pc`,公告区在 `template/default_pc/ht#E@8eml/public/head.html` |

**三站共库 = 改一次库三站都生效;但每站的 `application/extra/maccms.php` 和主题各一份,要分别改。**

## 0. 安全闸(不过就停手)

新域名必须是**同一图床的新域名**,不是空壳。取真实样本,把域名换掉后比对——
**HTTP 200 且字节数一致,再比 md5**:

```bash
mysql -uroot -pXXX fhzy1_com -N -B \
  -e "select vod_pic from mac_vod where vod_pic like '%旧域名%' order by rand() limit 6;" \
| while read -r p; do
    n="${p//旧域名/新域名}"
    printf "%s -> %s\n" "$(curl -sm20 -o/dev/null -w '%{http_code}/%{size_download}' "$p")" \
                        "$(curl -sm20 -o/dev/null -w '%{http_code}/%{size_download}' "$n")"
  done
# 再挑 2~3 条比内容:curl -s "$p" | md5sum 与 curl -s "$n" | md5sum 必须相同
```

顺带确认**旧域名是否仍可访问**:仍活着 = 即使漏改也不会挂图、回滚更从容;已死 = 必须一次做干净。

## 1. 执行(备份 → 登记 rep → 改存量)

```bash
bash scripts/replace.sh <旧域名> <新域名>        # 预演
bash scripts/replace.sh <旧域名> <新域名> --apply
```

脚本做四件事:备份受影响行的 `vod_id + vod_pic`、生成回滚 SQL、往 `mac_rep` 登记
(`rep_type='视频封面替换'`,判重)、跑 `UPDATE ... REPLACE()`。
16.7 万行实测 **2 秒**。

## 2. ★ 同步改发布程序(最容易漏的一步)

ffcore 的任务配置**存在 SQLite 里**(`server/data/ffcore.db` 的 `tasks` 表),
不是那个 `seed/legacy-config.json`——改 JSON 没用。番号任务是 `id=2 / name=fhm3u8`,
配置里的 `picDomain` 决定今后新采集内容的封面域名。

```bash
scp scripts/upd_publisher.js root@216.180.225.138:/tmp/
ssh root@216.180.225.138 'cd /home/dev/ffcore && node /tmp/upd_publisher.js 旧域名 新域名'          # 预演
ssh root@216.180.225.138 'cd /home/dev/ffcore && node /tmp/upd_publisher.js 旧域名 新域名 --apply'
```

服务每轮 `SELECT * FROM tasks WHERE id=?` 读配置,**改库即可,不用重启**。
下一轮跑批(每 2 小时一次,但上游每天只出一批,真正发布的是北京时间 14:20 那次)自动生效。

## 3. 关联配置(按情况)

- 换的是 `upload.remoteurl` 指的那个域名 → 三站**分别**改
  `application/extra/maccms.php` 的 `upload.remoteurl` 与 `api.vod.imgurl`。
  注意三站不一样:`fhzy1.com`/`bjgx` = 一个域名,`fhapi9.com` = 另一个。改错站 = 采集方拿到错域名。
- 换的只是 `vod_pic` 里写死的域名(本次情形)→ **不用动配置**。

## 4. 收尾

```bash
# 清模板缓存(三站)
for s in fhzy1.com fhapi9.com bjgx; do rm -rf /home/wwwroot/$s/runtime/*/temp/*; done
# 清 Dragonfly 缓存 —— 三站前缀不同,只删番号的,别动同机乐播的
#   前缀:fh1_ / fhapi_ / bjgx_
```

**Meilisearch 不用重建**:索引里没有 pic/img 字段(`curl .../indexes/maccms_fhzy1_com/stats`
看 `fieldDistribution` 可自证),封面改动与搜索无关。

## 5. 验证(权威是采集 API 和详情页)

```bash
curl -s "http://fhapi9.com/api.php/provide/vod/?ac=list" | grep -o '"vod_pic":"[^"]*"' | head -3
mysql ... -e "select count(*) from mac_vod where vod_pic like '%旧域名%';"   # 必须 0
curl -s https://fhzy1.com/index.php/macrep.html | grep -o 'fh[0-9]*\.top'    # 当前生效值=新域名
```
再随机抽 5 条新域名的封面 `curl` 一遍,要 200。

## 6. 主题公告怎么写(踩过的坑)

**不要把域名写死进 `head.html`。** 老版本里写死过
`www.fhtup.com替换为fengmian.fhfhtutu.com`,域名换了没人改,最后那四个域名在库里
一处都不存在,变成误导采集方的死信息(2026-08-31 已清理)。

正确做法:公告区只放**常驻入口**,值以替换助手页为准:

```html
<a target="_blank" href="/index.php/macrep.html" style="text-decoration:none"><font size="3" color="#FF0000"><b>【重要】封面 / 播放 / 域名变更公告 &mdash; 采集方请点此查看最新替换规则 &raquo;&raquo;</b></font></a>
```

改 `head.html` 时**务必带匹配次数校验和标签配平自检**(`<font>`/`</font>`、`<a `/`</a>` 数量相等),
匹配不到就整站跳过——这个主题是 2019 年的 SMZY 老模板,`<font>` 嵌套很乱,
删错一行会把整个公告区的标签拆坏。

---

# 附:播放域名日常轮转(vod_play_url)

封面之外,**播放域名是按月轮转的**,属于日常工作。命名规则 `26MM.fhbbff.com`
(26=年,MM=月),域名由**内容日期决定**,而内容日期写在 URL 路径里:

```
https://2607.fhbbff.com/20260701/dZCmzzHi/index.m3u8
        └─ 域名按内容月份  └─ 内容日期 YYYYMMDD
```

2026-09-03 实测的规则:5/6月→`2605`、7/8月→`2607`、9月→`2609`。

## 🔴 最大的坑:绝对不能用裸 REPLACE

用户说"把 2607 换成 2609",按字面写

```sql
UPDATE mac_vod SET vod_play_url=REPLACE(vod_play_url,'2607','2609.fhbbff.com');  -- ❌ 灾难
```

**会毁掉 6149 行**:`2607` 这四个字符同时出现在**路径日期** `/20260701/` 里
(`20260701` 的第 3~6 位就是 `2607`),替换后变成 `/202609.fhbbff.com01/`,整批播不了。

正确姿势:**WHERE 按路径月份限定 + REPLACE 只替换域名串**(域名带 `/` 边界):

```sql
UPDATE mac_vod SET vod_play_url = REPLACE(vod_play_url,'2605.fhbbff.com','2607.fhbbff.com')
WHERE vod_play_url LIKE '%2605.fhbbff.com/%'
  AND SUBSTRING(SUBSTRING_INDEX(SUBSTRING_INDEX(vod_play_url,'/',4),'/',-1),1,6) IN ('202607','202608');
```

## 用法

```bash
# ① 安全闸:每个迁移桶各抽 N 条,验「换域名后返回同一份 m3u8」(md5 + #EXTM3U 双重校验)
bash scripts/play-domain-gate.sh 4

# ② 执行(内置错配矩阵复核,改完打印"域名 × 路径月"是否全部一致)
bash scripts/play-domain-rotate.sh            # 预演
bash scripts/play-domain-rotate.sh --apply
```

规则变了就改 `play-domain-rotate.sh` 里那三行 `run_bucket`。

## 别忘了发布程序

`playDomain` 决定**今后新内容**的播放域名,和 `picDomain` 一样存在 ffcore 的 tasks 表里:

```bash
node scripts/upd_publisher.js 旧域名 新域名 --field=playDomain --apply
```

> 2026-09-03 这次:改库前去读是 `2605`,改完再读已经是 `2609` —— 用户自己先轮转过了。
> **所以每次都要先读一遍再决定改不改**,别照着记忆里的值动手。

## 实测数据(2026-09-03,供估算)

| 桶 | 行数 | 耗时 |
|---|---|---|
| 2605 → 2607(7/8月) | 9,789 | 合计 ~40s |
| 2604 → 2605(5/6月) | 1,082 | |
| 2605 → 2609(9月) | 260 | |

每行恰好一个播放地址(无多集/多播放组),所以 `REPLACE` 一次到位。
另注意:「九月更新」有两种口径 —— `vod_time>=9/1`(记录更新时间)是 376 行,
路径日期是 9 月的只有 260 行。**轮转按内容日期,取后者。**

未覆盖:路径月 `202602/202603/202604` 共 5,091 行的规则用户没给,保持原样。

## 回滚

```bash
mysql ... < /home/migrate-fanhao-20260828/imgrep-<时间戳>/rollback.sql      # 封面
mysql ... < /home/migrate-fanhao-20260828/playrot-<时间戳>/rollback.sql     # 播放域名
```
反向 `REPLACE` + 把那条 `mac_rep` 置 `rep_status=0`。
别忘了把 ffcore 的 `picDomain` 也改回去(备份在 `/home/dev/ffcore/server/data/task2-config-backup-*.json`)。

## 关联

- 通用框架 `maccms-replace`(rep_type ↔ 字段映射、最小长度闸、分批 plan)
- 乐播版 `lebozy-image-replace`(多轮换域名收敛,含三分类安全闸)、155 版 `155-image-replace`
- 番号站群全局背景、机器凭证、发布程序排查入口:记忆 `project-fanhao-migration-2026-08`
