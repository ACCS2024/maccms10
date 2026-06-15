# maccms10 Docker 部署(含性能基线:OPcache / Redis / InnoDB)

可复现的本地/演示环境,默认即开启 **OPcache**;并预置 **Redis** 与 **Meilisearch** 供"缓存/会话/搜索"按需启用。

## 启动
```bash
cd docker
docker compose up -d --build
# 浏览器打开 http://localhost:8088,首次进入安装向导:
#   数据库主机 db、库名 maccms、用户 root、密码 maccmsroot
```

## 性能项落地对照
| 项 | 如何启用 | 说明 |
|---|---|---|
| **OPcache** | 本镜像已默认开启(`php/opcache.ini` → 容器内 `conf.d/zz-opcache.ini`) | 字节码缓存,免每请求重编译。bare metal 见下 |
| **缓存切 Redis** | 后台「系统配置」缓存方式选 `redis`,主机 `redis`、端口 `6379` | 连接超时已修正为秒级,Redis 故障时快速降级不挂站 |
| **会话切 Redis** | `application/extra/maccms.php` 设 `session_type=redis`(复用上面的 Redis 连接) | 去除文件 session 写锁导致的同用户请求串行 |
| **InnoDB** | 后台「数据库」点"转 InnoDB" | MyISAM 表锁 → 行锁,根治采集/高并发锁表 |
| **Meilisearch** | 后台「Meilisearch」填主机 `http://meili:7700`、密钥 `maccmsMeiliKey123456`,初始化 | 关键词搜索;关闭则自动回退 LIKE |

## 在 bare metal(非 docker)启用 OPcache
把 `php/opcache.ini` 复制到 PHP 的 `conf.d` 目录后 reload:
```bash
# 以 Debian/Ubuntu PHP-FPM 7.4 为例
cp php/opcache.ini /etc/php/7.4/fpm/conf.d/zz-opcache.ini
systemctl reload php7.4-fpm     # 或 apache2(mod_php)
php -i | grep -i opcache.enable # 确认 On
```
默认 `validate_timestamps=1 + revalidate_freq=60`:`git pull` 升级 60 秒内自动生效。
追求极致可改 `validate_timestamps=0`,但每次部署后须 `reload` PHP 才加载新代码。
