---
name: fanhao-image-replace
description: 番号站群(fhzy1.com / fhapi9.com / bjgx,主题 default_pc,新机 85.149.233.11)换**封面图床域名**或做**播放域名按月轮转**时使用 —— 批量改 mac_vod.vod_pic、往前台「替换助手」mac_rep 登记、并且**同步改发布程序 ffcore 的 picDomain**(最容易漏的一步,不改则下一批新内容又带回旧域名)。含安全闸(新域名必须返回同一张图,md5 比对)、三站共库但配置各一份的坑、缓存前缀分站清。**封面分两批必须都换**:vod_pic 里写死域名的 16.8 万行(replace-multi.sh)+ 靠配置拼域名的 6.2 万行相对路径(upd_remoteurl.sh,一次改 upload.remoteurl / api.vod.imgurl / upload.api.ftp.url 三个键)。含全站残留扫描。另含播放域名轮转(vod_play_url,按 URL 路径里的内容日期定 26MM.fhbbff.com;裸 REPLACE 会毁数据,因为 2607 也出现在路径日期 20260701 里)。是 maccms-replace 针对番号的落地特化;通用框架见 maccms-replace,乐播版见 lebozy-image-replace,155 版见 155-image-replace。
---

# 番号封面图床域名迁移运行手册

## 涉及对象(2026-08-31 实测)

| 项 | 值 |
|---|---|
| 站点 | `fhzy1.com`(前台) / `fhapi9.com`(采集API) / `bjgx`(入库口 :35728) —— **三站共用库 `fhzy1_com`** |
| 机器 | 新机 `85.149.233.11`,webroot `/home/wwwroot/<站>`,PHP `/www/server/php/83/bin/php` |
| MySQL | root 口令取自 aaPanel:`sqlite3 /www/server/panel/data/default.db "select mysql_root from config"` |
| **要改的字段** | **实际只有 `mac_vod.vod_pic`**(16.8 万行)。⚠ `vod_pic_thumb`/`vod_pic_slide` **2026-09-08 起各有 6 万行非空了**(2026-08-31 时还是 0),但**几乎全是相对路径**,带域名的只有 17 行(全在 fhbf9,不迁);`mac_art.*` 与其它表仍为 0。**每次都要重新数一遍,别照抄这一行** |
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

## 0.5 🔴 两个必查的坑(2026-09-08 踩到)

### ① 逐域名分三类,不能一把梭
库里除了主力域名,总有一堆零散老域名。**必须逐个抽样判定**(和乐播那套一样):

| 判定 | 含义 | 动作 |
|---|---|---|
| 旧活 + 新同图 | 同一图床的新域名 | ✓ 换 |
| 旧死 + 新活 | 新图床有这批图 | ✓ 换,**顺带修好死链** |
| 旧活 + 新 404 | 新图床没有这批图 | ✗ **别动,换了就挂** |

2026-09-08 实测(总计 168,767 行迁移):

```
fh200831.top      168,494  旧活/新同图    ✓ 换
fh.lbfh2025.com       217  旧活/新同图    ✓ 换
fmtu.netfhtu.com       44  旧404/新200    ✓ 换(修好 44 张死图)
vip2.fhbf9.com         17  旧活/新404     ✗ 留
fh2.fhbf9.com           6  旧死/新404     ✗ 留(两边都没有)
```

### ② 域名互为前缀 → 无边界 REPLACE 会污染
库里有 12 行**畸形 URL**:`http://fmtu.netfhtu.comupload/vod/...`(少了域名后的 `/`)。
`fmtu.netfhtu.com` 是 `fmtu.netfhtu.comupload` 的**前缀**,所以

```sql
REPLACE(vod_pic,'fmtu.netfhtu.com','fh260908.top')   -- ❌ 得到 fh260908.topupload/vod/...
```

正确做法两条:
1. **替换串带边界**:用 `//fmtu.netfhtu.com/` → `//fh260908.top/`,不要裸域名;
2. **先修畸形再换规范形态** —— 顺序反了就污染。
   本次:`fmtu.netfhtu.comupload/` → `fh260908.top/upload/`(实测修好后 200,真图 120~185KB)。

执行前跑这条自检,**总命中 ≠ 规范形态 就说明有畸形行**:

```sql
select sum(vod_pic like '%<旧域名>%') 总命中, sum(vod_pic like '%//<旧域名>/%') 规范形态 from mac_vod;
```

改完再验一次没被污染:`sum(vod_pic like '%<新域名>upload%')` 必须为 0。

## 1. 执行(备份 → 登记 rep → 改存量)

```bash
bash scripts/replace.sh <旧域名> <新域名>        # 预演
bash scripts/replace.sh <旧域名> <新域名> --apply
```

脚本做四件事:备份受影响行的 `vod_id + vod_pic`、生成回滚 SQL、往 `mac_rep` 登记
(`rep_type='视频封面替换'`,判重)、跑 `UPDATE ... REPLACE()`。
16.7 万行实测 **2 秒**。

**但 `replace.sh` 是单域名 + 无边界 REPLACE** —— 遇到 0.5 节那两种情况会出事。
有零散域名或畸形 URL 时改用:

```bash
bash scripts/replace-multi.sh          # 预演
bash scripts/replace-multi.sh --apply  # 执行
```

它按桶执行、替换串自带 `//…/` 边界、每桶单独备份并追加 rollback、最后打印域名分布复核。
改 `NEW=` 和那几行 `run` 即可复用。

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

## 3. ★ 三站配置里的封面基址(三个键)

**这一步和第 1 步管的是两批不同的封面,都要做**:

| | 库里存什么 | 数量 | 靠什么定域名 | 用哪个脚本 |
|---|---|---|---|---|
| 绝对地址封面 | `https://<域名>/xxx.jpg` | 16.8 万 | `vod_pic` 里写死 | `replace-multi.sh` |
| **相对路径封面** | `upload/vod/xxx.jpg` | **6.2 万**(另 6 万 thumb/slide) | **配置拼** | **`upd_remoteurl.sh`** |

只做第 1 步 = 6.2 万张封面仍留在老图床上。

`upd_remoteurl.sh` 一次改三个键:

| 键 | 作用 | 现在会不会被读 |
|---|---|---|
| `upload.remoteurl` | 相对路径封面拼域名(`common.php` `mac_url_img`,`mode=='remote'` 分支) | ✅ 会 |
| `api.vod.imgurl` | 采集 API 吐给下游的封面基址 | ✅ 会 |
| `upload.api.ftp.url` | FTP 图床对外基址(`Ftp.php:61` `return $settings['url'].'/'.$file_path`) | ⚠ 只在 `upload.mode` 切成 `ftp` 时 |

**注意 `ftp` 挂在 `upload.api.ftp`,不是顶层 `api.ftp`** —— `Ftp.php:20` 读的是
`$GLOBALS['config']['upload']['api']['ftp']`,顶层 `$c['api']['ftp']` 是**不存在**的。
`Upload.php:38` 那句 `if(!in_array($config['mode'],['local','remote']))` 决定它走不走驱动;
三站现在都是 `remote`,所以这个键是**死配置**,一并填是为了将来后台切保存方式时
不会落到空基址(`url=''` 会拼出 `/upload/...` 指向本站)。
另外它的值**不带尾斜杠**(Ftp.php 自己拼 `'/'`),和另外两个键不一样。

```bash
bash scripts/upd_remoteurl.sh <新域名>          # 预演
bash scripts/upd_remoteurl.sh <新域名> --apply  # 执行
```

**三站配置各一份、值还不一样**(2026-09-08 之前:`fhzy1.com`/`bjgx` = `fan.lefhao20250923.top`,
`fhapi9.com` = `fh.lbfh2025.com`),所以脚本按**各站自己的当前值**去替换,不写死旧域名。

### 怎么改才安全(脚本已内建)

**不要用 `sed`。** 配置里 `'imgurl'` 出现 **6 次**,只有 `api.vod` 那处(约 449 行)有值,
其余 5 处(art/actor/role/website/link)是 `''`;`'url'` 更是遍地都是(ftp/qiniu/s3/upyun…)。
按名字匹配几乎必然误伤,**写脏 = 采集方拿到错域名**。而 `ftp.url` 本来是空串,
"按原值替换"这招也用不了。

脚本的做法是**整份配置数组 `var_export` 回盘** —— 这正是 maccms 后台保存自己走的路径
(`common.php` `mac_arr2file`:`var_export` + `opcache_invalidate`)。
实测该配置是纯 var_export 产物,**重新导出与原文件逐字节一致**(792 行只差结尾换行),
所以不会打乱格式。

**改的是被 `include` 的 PHP,写坏 = 整站 500**,所以每站都:
备份 → 改 → `php -l` → 重新 include → **逐键递归 diff,断言只有那 3 个目标键变了** → 否则立刻还原。
递归 diff 比数 grep 命中强:它能证明其余 780 行、包括那 5 个空 `imgurl`,一个值都没动。

### 安全闸

和第 0 节同理,但样本取**相对路径**的封面,把两个 base 分别拼出来比 md5:

```bash
# 每个 base 抽 10 条:https://<旧base>/<相对路径> 与 https://<新域名>/<相对路径> 必须同图
```

2026-09-08 实测 **20/20 同图**(两个 base 各 10 条),thumb/slide 的 GIF 也在新域名上 → 放行。

> 决策沿革:前两次轮转(fh260401→fh200831)没动 remoteurl,因为它看起来是另一套稳定图床。
> **2026-09-08 用户明确要求一并换过来**(同日又要求补上 `upload.api.ftp.url`,
> 目标是"保证对外渲染都是新域名"),此后这三个键就是轮转的固定一环。

## 3.5 收尾必做:全站残留扫描

改完跑一遍,证明"对外渲染无一漏网"。三处都要扫:

```bash
# ① 全库:枚举所有 varchar/text 列逐列 count,不要只盯 vod_pic
mysql ... -N -B -e "select concat(table_name,'|',column_name) from information_schema.columns
  where table_schema='<库>' and data_type in ('varchar','text','mediumtext','longtext');" |
while IFS='|' read -r t c; do
  n=$(mysql ... -N -B -e "select count(*) from \`$t\` where \`$c\` like '%<旧域名>%';")
  [ "$n" -gt 0 ] && echo "$t.$c : $n 行"
done
# ② 主题:grep -rlF <旧域名> /home/wwwroot/<站>/template/
# ③ 配置:grep -cF <旧域名> /home/wwwroot/<站>/application/extra/maccms.php
```

**`mac_rep` 命中是正常的,不要清** —— 那几行就是给采集方看的替换规则本身
(`老域名 → 新域名`),清了采集方就不知道该怎么改。

2026-09-08 实测结果:除 `mac_rep` 3 行外,全库 / 三站主题 / 三站配置**零残留**。

### 渲染面其实只有两处
`default_pc` 的**首页和列表页是纯文字列表,根本不渲染封面**(只有 logo、采集插件图
那类本站静态图)。封面只出现在**详情页**和**采集 API**。
验收盯这两处就够,别在首页 grep 不到图片就以为出错了。

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

## ⚠ 老月份不要"按命名规则归位"

路径月 `202602/202603/202604` 共 5,091 行,用户没给规则 —— **也不该给,实测证明必须原样不动**:

```
2602.fhbbff.com  连不上(已下线)
2603.fhbbff.com  连不上(已下线)
2604.fhbbff.com  存活
```

其中 31 行 2/3 月内容现挂在 `2605` 上并且**能正常播**。按命名规则"归位"到 2602/2603
会让它们**全部变死链**。→ **域名退役后内容被挪到活着的域名,那就是正确终态。**

所以轮转脚本只处理**当前在轮换中的月份**(本次是 5~9 月),老月份一律不碰。
真要动之前,先 `curl` 一下目标域名活不活。

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
