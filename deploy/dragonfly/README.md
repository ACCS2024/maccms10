# Dragonfly 缓存部署

此脚本为 maccms10 部署一个仅监听本机的 Redis 协议缓存，使用版本锁定的 Dragonfly 二进制和 systemd 托管。认证口令首次安装时生成，重跑脚本会复用，不会把口令输出到终端。

## 快速开始

```bash
sudo bash deploy/dragonfly/dragonfly.sh install
sudo bash deploy/dragonfly/dragonfly.sh status
```

maccms 配置使用：

- 缓存/会话类型：`redis`
- 主机：`127.0.0.1`
- 端口：`6379`
- 口令：读取 `/etc/dragonfly/password`

PHP 还需要安装 `redis` 扩展；脚本不会替 PHP 或宝塔安装扩展。

## 自适应规则

默认把总内存约 `1/16` 分配给 Dragonfly，最少 `512 MiB`、最多 `8 GiB`。线程数按每 `1 GiB` 缓存一个线程计算，并同时受在线 CPU 数和默认 `8` 线程上限约束。

脚本还会检查 `maxmemory >= proactor_threads * 256 MiB`。Dragonfly 在高核机器上默认按 CPU 核数创建线程，如果缓存额度较小，可能因每线程内存下限而拒绝启动；显式限制线程可以避免这个问题，也能减少与同机 PHP/MySQL 的资源争抢。

典型结果：

| 主机资源 | 自动 maxmemory | 自动线程 |
|---|---:|---:|
| 8 GiB / 4 核 | 512 MiB | 1 |
| 16 GiB / 8 核 | 1 GiB | 1 |
| 32 GiB / 16 核 | 2 GiB | 2 |
| 64 GiB / 56 核 | 4 GiB | 4 |

需要覆盖时使用 MiB 整数：

```bash
sudo DF_MAXMEMORY_MB=4096 DF_PROACTOR_THREADS=4 \
  bash deploy/dragonfly/dragonfly.sh install
```

## 运维命令

```bash
# 查看版本、systemd、PONG 和资源参数，不显示口令
sudo bash deploy/dragonfly/dragonfly.sh status

# 修改脚本顶部目标版本后升级；失败会自动切回旧二进制
sudo DF_VERSION=v1.40.1 bash deploy/dragonfly/dragonfly.sh upgrade

# 卸载服务和二进制，默认保留配置与数据
sudo bash deploy/dragonfly/dragonfly.sh uninstall

# 连配置、口令和缓存数据一并删除
sudo bash deploy/dragonfly/dragonfly.sh uninstall --purge
```

主要路径：

| 路径 | 用途 |
|---|---|
| `/usr/local/bin/dragonfly` | 当前版本软链 |
| `/opt/dragonfly/bin/` | 版本化二进制 |
| `/etc/dragonfly/dragonfly.conf` | 启动参数，权限 `640` |
| `/etc/dragonfly/password` | maccms 使用的认证口令，权限 `640` |
| `/var/lib/dragonfly/` | 运行目录 |
| `/etc/systemd/system/dragonfly.service` | systemd 服务 |

默认绑定 `127.0.0.1`。如需跨机访问，可以覆盖 `DF_BIND=0.0.0.0`，但必须同时配置主机防火墙，只允许应用服务器来源地址。
