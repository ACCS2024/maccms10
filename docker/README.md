# maccms10 Docker 部署(含性能基线:PHP 8.4 / MySQL 8.0 / OPcache / Redis / InnoDB)

可复现的本地/演示环境,默认即开启 **OPcache**;并预置 **Redis** 与 **Meilisearch** 供"缓存/会话/搜索"按需启用。

## 启动
```bash
cd docker
docker compose up -d --build
# 浏览器打开 http://localhost:8088,首次进入安装向导:
#   数据库主机 db、库名 maccms、用户 root、密码 maccmsroot
```

## Apache 默认访问边界

镜像使用 [apache/maccms.conf](apache/maccms.conf) 保护以仓库根目录为 DocumentRoot 的部署，支持 PHP 8.3/8.4。重新构建镜像后生效：内部配置、依赖、运行数据、点文件和备份文件禁止通过 HTTP 读取，上传脚本禁止执行，目录列表和符号链接访问关闭。

前台、根目录改名后的后台 `.php`、API/PATH_INFO 和漂亮 URL 默认可用。现有模板/插件静态资源、编辑器页面、上传图片及允许的下载文件保持原路径；模板 view 和插件配置不作为静态资源公开。

`.htaccess` 不再生效。部署自定义路由或新增插件资源类型时，请审查后修改镜像中的可信配置并重建，保留内部目录及上传执行限制。详见[审计范围与验证](../docs/audit/2026-09/apache-boundary.md)。

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
# 以 Debian/Ubuntu PHP-FPM 8.3 为例
cp php/opcache.ini /etc/php/8.3/fpm/conf.d/zz-opcache.ini
systemctl reload php8.3-fpm     # 或 apache2(mod_php)
php -i | grep -i opcache.enable # 确认 On
```
默认 `validate_timestamps=1 + revalidate_freq=60`:`git pull` 升级 60 秒内自动生效。
追求极致可改 `validate_timestamps=0`,但每次部署后须 `reload` PHP 才加载新代码。
