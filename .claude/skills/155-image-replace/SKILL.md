---
name: 155-image-replace
description: 155 站(PPVOD 入库)整站封面图床域名迁移时使用 —— 把 mac_vod 的 vod_pic/vod_pic_thumb 旧图床域名批量换成新域名,并**同步更新 PPVOD 入库配置 ppvod.pic_domain**(否则转码机新推的封面继续打旧域名)。含最关键的安全闸(新域名必须 HTTPS 可达且返回同图才动手)、mac_rep 前台登记、opcache/缓存刷新、mac:// 渲染坑、回滚。是 maccms-replace 针对 155 的落地特化;通用框架见 maccms-replace。
---

# 155 封面图床域名迁移运行手册

**适用**:155(PPVOD 入库站,webroot `/home/wwwroot/155zy.com`;IP/SSH 凭证见部署记忆 `project_smoke_deploy` 对应条目,**不入库**)。
把所有封面从旧图床域名 **A** 换成新域名 **B**(A、B 指同一图床/CDN、只是换对外域名——常因旧域名被墙/被封而轮换)。

**155 特殊点**:它是 PPVOD 入库站,除了改存量,**必须同步改入库配置 `ppvod.pic_domain`**,否则转码机新推的封面继续打 A。

## 涉及对象(155 实测)
- **存量字段**:`mac_vod.vod_pic`(~18.4 万) + `mac_vod.vod_pic_thumb`(~800)。`vod_pic_slide`/`vod_pic_original` 一般空。
- **scheme 混合**:`https://A/<rpath>/1.jpg`(PPVOD 新片)、`http://A/...`、`mac://A/upload/vod/...`(老采集片)。约 https 4.2万 / http 1.2万 / mac:// 13万。`REPLACE()` 按子串换域名,三种全覆盖。
- **入库配置**:`application/extra/maccms.php` 的 `ppvod.pic_domain = 'https://A'`(唯一一处)。
- **不要碰**:`upload.api.ftp.url`(155 是**另一个**图床域名、走独立 FTP 图床机,是采集/上传落图路径,与 PPVOD 图床域名**无关**;具体值现场查配置)。

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
$A='旧域名'; $B='新域名'; $pre=config('database.connections.mysql.prefix');

// ① 前台登记 mac_rep(判重后)——给下游采集站看
if(Db::name('rep')->where('rep_original',$A)->where('rep_replacement',$B)->count()==0){
  Db::name('rep')->insert(['rep_type'=>'视频封面替换','rep_original'=>$A,'rep_replacement'=>$B,
    'rep_note'=>'封面图床域名迁移 '.$A.'→'.$B,'rep_status'=>1,'rep_applied'=>1,
    'rep_applied_time'=>time(),'rep_create_time'=>time()]);
}
// ② 存量替换(vod_pic + vod_pic_thumb 都要;18万行~8s)
Db::execute("UPDATE {$pre}vod SET vod_pic=REPLACE(vod_pic,'$A','$B') WHERE vod_pic LIKE '%$A%'");
Db::execute("UPDATE {$pre}vod SET vod_pic_thumb=REPLACE(vod_pic_thumb,'$A','$B') WHERE vod_pic_thumb LIKE '%$A%'");
// ③ 入库配置 ppvod.pic_domain(备份后改文件)
$cf=APP_PATH.'extra/maccms.php'; copy($cf,$cf.'.bak-picdomain-'.date('YmdHis'));
file_put_contents($cf, str_replace('https://'.$A,'https://'.$B, file_get_contents($cf)));
// ④ 复查
echo "残留A vod_pic=".Db::name('vod')->where('vod_pic','like','%'.$A.'%')->count()
   ." thumb=".Db::name('vod')->where('vod_pic_thumb','like','%'.$A.'%')->count()
   ."; 现有B vod_pic=".Db::name('vod')->where('vod_pic','like','%'.$B.'%')->count()."\n";
echo "生效值 ".mac_rep_notice()."\n";
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

## 回滚
```sql
UPDATE mac_vod SET vod_pic=REPLACE(vod_pic,'B','A') WHERE vod_pic LIKE '%B%';
UPDATE mac_vod SET vod_pic_thumb=REPLACE(vod_pic_thumb,'B','A') WHERE vod_pic_thumb LIKE '%B%';
UPDATE mac_rep SET rep_status=0 WHERE rep_original='A' AND rep_replacement='B';
```
入库配置从 `.bak-picdomain-*` 还原并 reload php-fpm。**新老同床时即使不回滚也不裂图**。

## 关联
- 通用替换框架 / rep_type↔字段映射 / Rep 模型:**maccms-replace** skill
- 图床/播放器/CDN 迁移陷阱:**maccms-migrate** skill
- 155 部署通道 `bin/deploy-155.sh`;凭证见部署记忆(不入库)
