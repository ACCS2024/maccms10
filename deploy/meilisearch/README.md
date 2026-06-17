# Meilisearch 一键部署 / 升级 / 迁移（裸机 + systemd）

为 maccms10 配套的 Meilisearch 运维脚本：**版本锁死、升级靠你显式触发、升级时自动迁移老数据**。
专治「Meilisearch 被动乱升级」和「升级后 `data.ms` 版本不兼容、服务直接拒绝启动」。

> 只有一个脚本：[`meilisearch.sh`](./meilisearch.sh)。需要 root（systemd / 写 `/usr/local/bin` / 建用户）。

---

## 为什么会“乱升级”，以及为什么不能直接升

Meilisearch 的磁盘数据 `data.ms`（底层 LMDB）**和二进制版本强绑定**。一旦运行的二进制版本和
`data.ms` 里记录的版本对不上，它会**直接拒绝启动**，报 `Your database version mismatch`。

所以「乱升级」基本来自这几种装法，本脚本都不用：

- 官方 `curl -L https://install.meilisearch.com | sh` —— 每次拉**最新版**；
- Docker 用 `:latest` 或 `:v1` 这种浮动 tag，一 `pull` 就变版本；
- 宝塔 / 包管理器 / 云市场自动更新。

正确姿势 = **锁版本** +（要升级时）**旧版导出 dump → 新版 `--import-dump` 导入**。
本脚本把这套官方流程自动化，并在任何一步失败时**自动回滚**到旧版本 + 旧数据。

---

## 快速开始（全新安装）

```bash
cd deploy/meilisearch
sudo bash meilisearch.sh install
```

它会：下载锁定版本二进制（默认 **v1.47.0**）→ 建系统用户 `meilisearch` →
生成 master key → 写 `/etc/meilisearch/meilisearch.env` 与 systemd 单元 → 起服务 → 健康检查 →
最后**打印你要填进 maccms 后台的 Host 和 Key**。

装完把它填进 maccms 后台「Meilisearch」：

| 后台字段 | 值 |
|---|---|
| 主机 Host | `http://127.0.0.1:7700` |
| API 密钥 | 安装结束时打印的 master key（也在 `/etc/meilisearch/meilisearch.env`） |
| index_uid | `maccms_contents`（默认，后台已预填） |

保存后依次点 **一键初始化索引 → 全量重建** 即可。

---

## 升级（你说了算，不会被动乱跳）

升级**永远只改一个变量**——脚本顶部的 `MEILI_VERSION`（或用环境变量覆盖），然后跑 `upgrade`：

```bash
# 方式一：临时指定目标版本
sudo MEILI_VERSION=v1.48.0 bash meilisearch.sh upgrade

# 方式二：改脚本顶部 MEILI_VERSION= 后
sudo bash meilisearch.sh upgrade
```

`upgrade` 会自动判断要不要升、并安全迁移老数据：

1. 比对「在跑版本 / 已装版本」与目标版本，**一致就空转退出**（幂等，可反复跑）；
2. 先下好新版本二进制（下载失败绝不动现网）；
3. 用**旧版**导出一份 dump（`POST /dumps`，等任务 `succeeded`）；
4. 停服务，把老 `data.ms` 改名备份到 `data.ms.bak.<旧版本>.<时间戳>`；
5. 切到**新版**二进制，`--import-dump` 把 dump 导入到全新 `data.ms`，等健康；
6. 起正式服务，校验版本号 == 目标版本；
7. **任何一步失败 → 自动回滚**：还原老 `data.ms`、软链切回旧二进制、重启服务。dump 与备份都保留，便于排查。

> 大库导入很慢，可调 `IMPORT_TIMEOUT`（秒，默认 3600）与 `DUMP_TIMEOUT`（默认 1800）。

---

## 常用命令

```bash
sudo bash meilisearch.sh status      # 已装/在跑/目标版本、健康、索引文档数、后台该填啥
sudo bash meilisearch.sh dump        # 手动备份一次（导出 dump 到 dump 目录）
sudo bash meilisearch.sh upgrade     # 升级 + 自动迁移（见上）
sudo bash meilisearch.sh rollback    # 回滚到上一版本（用最近一次升级留下的备份+旧二进制）
sudo bash meilisearch.sh uninstall   # 卸载，保留数据
sudo bash meilisearch.sh uninstall --purge   # 卸载并删除数据与配置
sudo bash meilisearch.sh help        # 用法
```

---

## 可配置变量（都能用环境变量覆盖）

| 变量 | 默认 | 说明 |
|---|---|---|
| `MEILI_VERSION` | `v1.47.0` | **锁定版本**。升级只改这个。取值见 [releases](https://github.com/meilisearch/meilisearch/releases) |
| `MEILI_BIND` | `127.0.0.1` | 监听地址。**默认只听本机最安全**；跨机访问改 `0.0.0.0` 并配防火墙 |
| `MEILI_PORT` | `7700` | 端口 |
| `MEILI_HOME` | `/var/lib/meilisearch` | 数据目录（含 `data.ms`、`dumps/`、备份） |
| `GH_PROXY` | 空 | GitHub 下载加速前缀，国内可设，如 `https://ghproxy.net/`（**注意结尾带 `/`**） |
| `HEALTH_TIMEOUT` | `60` | 启动健康检查等待（秒） |
| `DUMP_TIMEOUT` | `1800` | 等 dump 任务完成（秒，大库调大） |
| `IMPORT_TIMEOUT` | `3600` | 等 `--import-dump` 导入完成（秒，大库调大） |

例子（国内服务器、跨机访问、指定版本一把梭安装）：

```bash
sudo GH_PROXY=https://ghproxy.net/ MEILI_BIND=0.0.0.0 MEILI_VERSION=v1.47.0 \
  bash meilisearch.sh install
```

---

## 目录与文件落点

| 路径 | 用途 |
|---|---|
| `/usr/local/bin/meilisearch` | 软链 → 当前版本二进制（回滚=改软链） |
| `/opt/meilisearch/bin/meilisearch-<版本>` | 版本化二进制（保留旧版便于回滚） |
| `/etc/meilisearch/meilisearch.env` | systemd 读取的配置（含 master key，权限 600） |
| `/etc/systemd/system/meilisearch.service` | systemd 单元（含安全加固项） |
| `/var/lib/meilisearch/data.ms` | 数据 |
| `/var/lib/meilisearch/dumps/` | dump 备份 |
| `/var/lib/meilisearch/data.ms.bak.*` | 升级时挪走的老数据备份 |

---

## 排错

- **看日志**：`journalctl -u meilisearch -n 50 --no-pager`
- **导入日志**：升级导入阶段写在 `/tmp/meili-import.log`
- **`Your database version mismatch`**：典型「换了二进制但没迁数据」。用本脚本 `upgrade` 走 dump/import；
  若数据已被外部升级搞坏，可 `rollback`，或拿一份 dump 后 `--import-dump` 重建。
- **后台一直回退 LIKE 搜索**：多半是 Meili 没启用/连不上/key 不对。先 `status` 看 `/health`，
  再到 maccms 后台「Meilisearch」点「一键自检」。
- **下载慢/失败**：设 `GH_PROXY`，或手动把对应二进制放到 `/opt/meilisearch/bin/meilisearch-<版本>` 再跑安装。

---

## 多站点共用一个 Meilisearch（重要：避免串库）

一台 Meilisearch **可以**被多个 maccms 站点共用，但**每个站点必须用各自不同的 `index_uid`**，否则会串库：

- maccms 的文档主键是**全局**的（`vod_1`、`art_5`…，不含站点标识）。两个站若用同一个 `index_uid`，
  `vod_1` 就是同一条文档，**后写覆盖先写** → 搜索相关性错乱、命中数虚高、A 站删/下架会连带影响 B 站。
- 历史默认名是 `maccms_contents`（所有站一样），直接共用必然撞车。

**本仓库已内置防呆**（后台「Meilisearch」页）：

- 新装 / 未自定义时，`index_uid` 默认值改为**按本站数据库派生的唯一名**：`maccms_<库名>_<6位哈希>`
  （哈希取自 数据库 host+端口+表前缀+库名，两台不同 MySQL 即使库名相同也不会撞）。
- 若检测到仍在用共享默认名 `maccms_contents`，页面顶部**红色告警** + 一键「填入本站唯一名」按钮。
  点它 → 保存 → 再「一键初始化索引」+「全量同步」，即完成迁移到独立索引。
- 后台「检查版本」按钮：显示 Meili 当前运行版本、GitHub 最新稳定版、以及该在服务器上执行的升级命令
  （只读，不从网站执行系统级升级）。

> 改 `index_uid` = 换了一个新（空）索引，**必须重新「全量同步」**，老索引数据不会自动搬过去。
> 多个站点各自独立索引对 Meilisearch 毫无压力，这是它多租户的标准用法。

---

## 其它部署方式说明

- 仓库自带的 `docker/docker-compose.yml` 用的是 `getmeili/meilisearch:v1.6`（旧）。**Docker 用户别直接把 tag 改成新版**——
  那会触发同样的 `data.ms` 版本不兼容。Docker 下要升级，同样得「先在旧容器里 `POST /dumps` 导出，再用新版镜像
  `--import-dump` 启动到一个空的数据卷」，思路与本脚本完全一致。
- 本脚本与 maccms 代码**零耦合**：maccms 只通过 REST（`/indexes`、`/documents`、`/search`、`/settings`、
  `/tasks`、`/dumps`）访问 Meili，这些接口在整个 1.x 都稳定，所以锁定/升级到任意 1.x 都不影响 maccms 端代码。
