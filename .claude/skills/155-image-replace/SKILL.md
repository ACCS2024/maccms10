---
name: 155-image-replace
description: 155 站(PPVOD 入库)整站封面图床域名迁移时使用 —— 把 mac_vod 的 vod_pic/vod_pic_thumb 旧图床域名批量换成新域名,并**把三处配置全部收敛到新域名以保证对外渲染无一漏网:ppvod.pic_domain(PPVOD 新片封面)+ upload.remoteurl(相对路径封面 upload/vod/... 值里没域名靠它拼)+ upload.api.ftp.url(FTP 上传封面的对外前缀,常是另一个老图床域名、存量里也可能有)**。图床域名可能有多个来源,逐个查出来存量 REPLACE+配置改。含安全闸(新域名必须 HTTPS 可达且返回同图才动手)、mac_rep 登记、opcache/缓存刷新、mac:// 渲染坑、回滚。是 maccms-replace 针对 155 的落地特化;通用框架见 maccms-replace。
---

# 155 封面图床域名迁移运行手册

**适用**:155(PPVOD 入库站,webroot `/home/wwwroot/155zy.com`;IP/SSH 凭证见部署记忆 `project_smoke_deploy` 对应条目,**不入库**)。
把所有封面从旧图床域名 **A** 换成新域名 **B**(A、B 指同一图床/CDN、只是换对外域名——常因旧域名被墙/被封而轮换)。

**155 特殊点**:它是 PPVOD 入库站,除了改存量,**必须同步改入库配置 `ppvod.pic_domain`**,否则转码机新推的封面继续打 A。

## 涉及对象(155 实测)
- **存量字段(值里带域名,REPLACE 覆盖)**:`mac_vod.vod_pic`(~18.5 万) + `mac_vod.vod_pic_thumb`(~2400)。`vod_pic_slide`/`vod_pic_original` 一般空。
- **scheme 混合**:`https://A/<rpath>/1.jpg`(PPVOD 新片)、`http://A/...`、`mac://A/upload/vod/...`(老采集片)。约 https 5.5万 / mac:// 13万。`REPLACE()` 按子串换域名,三种全覆盖。
- **相对路径封面(值里【没有】域名 → REPLACE 碰不到!)**:少数封面存成 `upload/vod/...` 或裸文件名,渲染时域名由 **`upload.remoteurl`** 拼 → **必须一起改 `upload.remoteurl` 配置**,否则这批继续打旧域名。155 实测仅 58 条且多为历史裸 REPLACE 截断的**坏路径**(`uoad/vod`/`pload/vod`…,改域名也救不回=坏数据);但**乐播/番号占比极大**(番号 6.2 万行相对路径),**绝不能漏**。
- **要改的配置(都在 `application/extra/maccms.php`)—— 目标:对外渲染的每个图床域名都统一到 B**:
  - `ppvod.pic_domain = 'https://A'` —— PPVOD 新片封面域名(**必改**)。
  - `upload.remoteurl = '.../'` —— **相对路径封面**渲染域名,改成 `https://B/`。155 原是占位 `http://img.test.com/` 且 `upload.mode=Ftp`(mode≠`remote` 时相对封面走本地 `MAC_PATH`、不走 remoteurl)——改它是纠正占位+一致性兜底;`mode=remote` 的站(乐播等)是硬需求。
  - `upload.api.ftp.url = 'https://A2'` —— **FTP 上传封面**对外 URL 前缀,改成 `https://B`。今后采集/上传的封面靠它拼域名,不改则新上传又带回老域名。**它常是与 pic_domain 不同的【另一个】老图床域名**(155 是 `5.155260810.top`),而且**存量里也可能有**(155 实测 vod_pic_thumb 有 918 条在 `5.155260810.top`)→ 这个老域名也要进 REPLACE。
- **要点:图床域名可能有【多个】来源**(pic_domain 的域名 / api.ftp.url 的域名 / remoteurl)。先把它们**逐个查出来**(`SELECT DISTINCT SUBSTRING_INDEX(...) FROM vod` + dump 三处配置),**存量 REPLACE + 配置改,全部收敛到 B**,才能保证对外渲染无一漏网。`upload.api.ftp.host`(FTP 服务器 IP)是上传目的地、**不用改**(域名指向它即可)。

## 0. 安全闸(最关键——不过就停手)
新域名 B 必须 **HTTPS 可达 且 与旧域名返回同尺寸图**,否则一 REPLACE 下去 ~17 万条 https/mac 封面全裂。
> 真实踩坑(2026-08-26):B 挂到 Cloudflare 后 DNS/TCP 都通、但 **SSL 证书没签发** → `https://B` 握手失败(`sslv3 alert handshake failure`),而 `http://B` 却 200 同图。当时**停手**,等 CF Universal SSL 签好、多个样本 https 逐一 200 且 size 与旧域名相同,才动手。
```bash
# 取 3~5 个真实 https 样本,逐一比 旧 vs 新:两列必须完全一致(HTTP=200 且 size 相同)
#   SELECT vod_pic FROM mac_vod WHERE vod_pic LIKE 'https://A/%' LIMIT 3;
curl -skm12 -o/dev/null -w '旧 %{http_code}:%{size_download}\n' "https://A/<path>"
curl -skm12 -o/dev/null -w '新 %{http_code}:%{size_download}\n' "https://B/<path>"
```
另两个前置(见 maccms-replace):原文 ≥4 字符且原≠替换(域名 12+ 字符 OK);判重 `mac_rep WHERE rep_original='A' AND rep_replacement='B'`。

## 1-4. 执行(在 webroot 跑一个 PHP 脚本,全程备份)
把 A/B 换成实际域名。用 app bootstrap 连库(脚本内不含任何凭证)。
```php
<?php
define("ROOT_PATH",__DIR__."/"); require "vendor/autoload.php";
define("RUNTIME_PATH",__DIR__."/runtime/"); define("APP_PATH",__DIR__."/application/");
$a=new \app\MacApp(__DIR__."/"); $a->initialize(); use think\facade\Db;
// A 可能是【多个】老图床域名(pic_domain 的域名、api.ftp.url 的域名…先查出来全列上)
$OLDS=['旧域名1','旧域名2']; $B='新域名'; $pre=config('database.connections.mysql.prefix');
// ★安全闸(§0):每个老域名都要先验 https://B/<path> 与 https://OLD/<path> 同图,过了才往下。

foreach($OLDS as $A){
  // ① 前台登记 mac_rep(判重)——给下游采集站看
  if(Db::name('rep')->where('rep_original',$A)->where('rep_replacement',$B)->count()==0)
    Db::name('rep')->insert(['rep_type'=>'视频封面替换','rep_original'=>$A,'rep_replacement'=>$B,
      'rep_note'=>'封面图床域名统一 '.$A.'→'.$B,'rep_status'=>1,'rep_applied'=>1,
      'rep_applied_time'=>time(),'rep_create_time'=>time()]);
  // ② 存量替换(vod_pic + vod_pic_thumb 都要;18万行~8s)
  Db::execute("UPDATE {$pre}vod SET vod_pic=REPLACE(vod_pic,'$A','$B') WHERE vod_pic LIKE '%$A%'");
  Db::execute("UPDATE {$pre}vod SET vod_pic_thumb=REPLACE(vod_pic_thumb,'$A','$B') WHERE vod_pic_thumb LIKE '%$A%'");
}
// ③ 配置三处都收敛到 B(备份后改文件)
$cf=APP_PATH.'extra/maccms.php'; copy($cf,$cf.'.bak-pic-'.date('YmdHis'));
$s=file_get_contents($cf);
foreach($OLDS as $A) $s=str_replace('https://'.$A,'https://'.$B,$s);                    // pic_domain + api.ftp.url(都是老域名前缀)
$s=preg_replace("#('remoteurl'\\s*=>\\s*')[^']*(')#", '${1}https://'.$B.'/${2}', $s, 1); // upload.remoteurl → 'https://B/'
file_put_contents($cf,$s);
// ④ 复查:库+配置 老域名残留应全 0
foreach($OLDS as $A) echo "残留 $A: vod_pic=".Db::name('vod')->where('vod_pic','like','%'.$A.'%')->count()
   ." thumb=".Db::name('vod')->where('vod_pic_thumb','like','%'.$A.'%')->count()."\n";
echo "现有 B vod_pic=".Db::name('vod')->where('vod_pic','like','%'.$B.'%')->count()."; 生效值 ".mac_rep_notice()."\n";
$m=include $cf; echo "配置 pic_domain=".$m['ppvod']['pic_domain']." remoteurl=".$m['upload']['remoteurl']." ftp.url=".$m['upload']['api']['ftp']['url']."\n";
```
跑完在 shell 里:
```bash
# 清模板/缓存
find $ROOT/runtime -type d \( -name temp -o -name cache \) -prune -exec sh -c 'rm -f "$1"/*.php' _ {} \;
# ★必须 reload php-fpm(见下"坑·opcache")
/etc/init.d/php-fpm-83 reload || systemctl reload php-fpm-83
```

## 验证(权威=详情页,不是首页)
```bash
# 详情页封面应是新域名、且 200；15260817(旧)计数=0
curl -s -H "Host:<主域>" "http://127.0.0.1/index.php/vod/detail/id/<最新id>.html" | grep -oc 'B域名'
# /index.php/macrep.html「当前生效值」已是 B
```
- CLI 直验渲染:`mac_url_img($storedPic)` 输出应含 B 且 curl 200(https 片→https://B,mac://片→http://B)。

## 坑(155 实测)
- **opcache**:改完 `maccms.php` 后,同进程 re-include 仍拿旧值(opcache 缓存编译);生产 opcache 若不校验 mtime,**新请求也拿旧值** → **必须 reload php-fpm** 才让 `ppvod.pic_domain` 生效。
- **首页 grep 到 0 封面域名 ≠ 没换**:首页封面走 JS 懒加载,grep 抓不到;验证一律用**详情页/列表页**。
- **mac:// 渲染成 http**:`mac_url_img()`(common.php)把 `mac:` 换成 `upload.protocol`,155 该项为空→默认 `http`。故老采集封面渲染成 `http://B`(B 支持 http 即可;想全站 https 可把 `upload.protocol` 设 `https`,前提 B 的 https 已好)。
- **Meili**:若搜索结果封面取自 Meili 存量,改库后搜索页可能仍显示旧域名封面(旧域名还活着就不裂);**旧域名退役前**跑一次全量重建索引。
- **图床域名不止一个 / 相对路径封面(最易漏)**:REPLACE 只动值里带域名的封面。三处来源要各查各改:① `ppvod.pic_domain` 的域名(存量主力 vod_pic/thumb)② `upload.api.ftp.url` 的域名(**常是另一个老域名**,存量 thumb 里也可能有——155 实测 918 条)③ 相对路径封面(`upload/vod/...`/裸文件名,值里无域名)靠 `upload.remoteurl` 拼。**漏任一处 → 那批封面继续打老域名**。155 相对封面仅 58 条且多是历史裸 REPLACE 截断的坏路径(改域名也救不回),但乐播/番号相对路径占比极大。

## 回滚
- **配置**:从备份还原(`.bak-pic-*` / `.bak-picdomain-*` / `.bak-ftpurl-*` / `.bak-remoteurl-*`)并 reload php-fpm。
- **存量**:反向 REPLACE(多个老域名时只能逐个反向,无法从 B 分辨原属哪个老域名——所以**改前的整行备份/或直接靠配置回滚更稳**):
```sql
UPDATE mac_vod SET vod_pic=REPLACE(vod_pic,'B','A'), vod_pic_thumb=REPLACE(vod_pic_thumb,'B','A') WHERE vod_pic LIKE '%B%' OR vod_pic_thumb LIKE '%B%';
UPDATE mac_rep SET rep_status=0 WHERE rep_replacement='B';
```
**新老同床时旧域名还活着,封面不裂,存量不必急着回滚**;要紧的是配置别把新域名配错。

## 关联
- 通用替换框架 / rep_type↔字段映射 / Rep 模型:**maccms-replace** skill
- 图床/播放器/CDN 迁移陷阱:**maccms-migrate** skill
- 155 部署通道 `bin/deploy-155.sh`;凭证见部署记忆(不入库)
