# FUNNULL / RingH23：代码检查、部署门禁与宿主机处置

本 fork 停用上游在线更新、插件下载、远程后台资讯/关键词等执行依赖；PHP 配置由 `DataConfig` 读取纯数组，不执行配置文件。浏览器脚本基线限制为本地脚本；私有主题使用的远程脚本应先审核并自托管。确需自有静态域时，在 `application/extra/maccms.php` 的 `app.security_script_sources` 设置受限 HTTPS origin 列表，不应允许第三方任意 CDN。跨域播放器 iframe 是独立的嵌入页面边界，允许播放域不等于信任其脚本在宿主页执行。

代码修复不能证明既有机器没有被植入系统持久化。尤其是历史已检出 RingH23、未知动态模块、`ld.so.preload` 或 udev 持久化的机器，应从可信环境保全证据、重建系统、轮换凭据；不要用“扫描通过”替代重建。

## 离线文件审计

审计器只使用 Python 标准库；纯配置语法检查使用独立提供的可信 `DataConfig.php`。它不启动应用、不连接数据库、不访问网络，不 include/eval 被检查的 PHP。PHP 使用 `-n` 忽略系统 php.ini，若 tokenizer 是共享扩展，只加载 tokenizer。Python、PHP 解释器及解析器本身必须来自可信环境。

在可信开发机生成审核后源码基线：

```bash
python3 tools/security/maccms_audit.py --root . --profile source \
  --data-parser application/common/util/DataConfig.php \
  --write-baseline /tmp/maccms-baseline.json --json /tmp/maccms-source.json
python3 tests/security_audit_supply_chain.py
```

读取离线站点副本，使用开发机生成的基线与解析器，不使用副本中的审计工具：

```bash
python3 /trusted/tools/security/maccms_audit.py --root /mnt/evidence/site --profile deployed \
  --baseline /trusted/maccms-baseline.json \
  --data-parser /trusted/DataConfig.php --json /trusted/site-report.json
```

报告只输出路径、规则名、域名/特征标记及必要元数据，不输出 PHP 内容、配置值、URL 查询参数或口令。退出码 `0` 表示所覆盖检查通过，`1` 表示需处置的发现，`2` 表示审计失败或参数错误；后两者都阻断部署。

覆盖范围：

- 报告披露的域名、两个 PHP 样本及系统植入样本 MD5、`system_optimization_signature` 和前端注入标记；检测明文与常见 base64、hex、百分号编码、HTML 实体、JS `\\xHH`/`\\u00HH`、字符串拼接，最多三层解码，不执行或模拟载荷。`mycj.top`/`mycj.pro` 作为已退役的上游云 loader 阻断，不据此声称它们是文章定性的恶意域名。
- 本次对旧主题发现的额外隐藏 loader 另记为本地取证：`towoo.net`、精确 `211.162.103.35/static/Device/learn.js` 载荷 URL，以及旧 jQuery/lazyload/Mybase 文件 SHA256。扫描器不会把仅出现该裸 IP 的数据自动认定为文章中的恶意 IOC；服务器出站策略可独立整体阻断该已观察地址。
- 部署站点的私有主题、JS/HTML/PHP、上传目录中的 PHP/双扩展 PHP、`.user.ini` 的自动 include 与 `.htaccess` PHP handler 配置。
- 不在源码基线中的可执行 PHP，以及部署后维护 PHP、JS、HTML、CSS 等资产的内容变化和缺失。明确动态配置（extra/、两份 playerconfig.js、.user.ini）不要求与开发机 hash 相同，但仍检查 IOC/配置语法。Composer 包源码在部署前、后都必须与可信基线 SHA256 一致；只豁免逐项列出的 Composer 自动生成装载映射、installed 元数据与 platform_check（仍检查 IOC/未知 PHP），`ClassLoader.php` 等实现代码不豁免。同路径包源码变化会阻断；`composer install` 不保证重装现存包，必须先保全证据并在干净目录从可信 lockfile 重建 vendor，不能用批准清单绕过包代码差异。
- `application/extra/*.php` 必须通过纯数据数组解析；正常较长的 addons Hook 配置不因长度或字符串中出现 `base64_decode` 一词被隔离。任何执行语句、函数调用或语法异常均阻断，原文件保留。
- 符号链接不跟随；除遗留的精确 `app -> application` 兼容链接外，受检树中的链接须人工审核。大小超过 32 MiB 的代码/配置资产报告覆盖不足并阻断。

源码模式过滤审计文档、测试夹具、工具源码及本地 runtime/upload/旧 TP5 归档。部署模式不按目录名跳过文件，`upload/docs/shell.php`、`tools/security/shell.php` 仍扫描；只有精确路径下与可信 baseline hash 一致的两个检测器文件，才豁免自身 IOC 常量命中。实际站点的 runtime、upload、vendor 和私有主题都进入扫描。已知 IOC 检测不是通用恶意软件识别器；未知变种、任意复杂编码、浏览器缓存/CDN缓存和内存植入不由本脚本证明安全。

## 已取得的数据导出

从可信备份流程取得 SQL/JSON/CSV 或文本导出后，单独放进离线目录，执行：

```bash
python3 /trusted/tools/security/maccms_audit.py --profile exported --root /mnt/exports \
  --json /trusted/export-report.json
```

此模式不要求 PHP 基线，也不执行 SQL、PHP 或导入数据库；按 4 MiB 分块并保留 256 KiB 重叠检查原始文本与常见编码，支持大 SQL 文件。压缩归档会报告未覆盖，必须先用可信工具解压到独立目录。部署模式也会扫描现存 `.sql/.txt/.csv/.json/.jsonl/.ndjson` 导出内容。命中不自动删除或修改任何业务字段；应定位相应记录并人工核对原始内容、来源、播放器配置、广告/统计字段和模板片段。未知 JS、超过重叠窗口的复杂编码及尚未导出的数据库内容仍需人工审阅，未检查线上数据库不能宣称数据已净化。

## 私有 PHP 的批准清单

站点私有插件或主题中的合法 PHP 需要先人工审阅，再在可信开发机制作独立清单。清单是相对路径到 SHA256 的映射，不能用线上即时扫描结果自动批准线上文件。例如：

```json
{"schema":1,"files":{"template/private/settings.php":"<审核后文件的64位小写SHA256>"}}
```

审计时传入 `--approved /trusted/site-approved.json`。批准仅允许该路径下精确 hash 的额外 PHP，不豁免 IOC、危险配置语法、上传 PHP 或符号链接检查。修改任何字节都需要重新审阅。随机名后台入口若与可信源码 `admin.php` 字节一致则自动识别；旧入口若仍使用 TP5 或不同启动逻辑，先保全并审阅，再部署当前可信入口，不用批准清单长期容忍旧框架。

## 已知遗留文件隔离

默认审计只读。`--quarantine-known /absolute/private/path` 是显式处置选项，仅限 `deployed` 模式；目标必须是 webroot 外、无符号链接的绝对目录，目录权限 0700。不会泛删上传、私有模板、未知 PHP，也不会因域名命中就移动 `maccms.php` 或正常 `addons.php`。

明确处理的路径：`application/extra/active.php`、`application/extra/system.php`、两份 `static*/js/update.js`、`application/data/update/database.php`、`application/admin/view/index/update.html`、已退役的 `application/admin/view/mycj/` 和 `static_new/mycj/` 云客户端、`template/m1938pc3_v2/js/js-sdk-pro.min.js` 与 `template/m1938pc3_v2/help/static/js/js-sdk-pro.min.js` 两份统计 SDK；存在安装锁时处理根 `install.php`；处理根 `thinkphp/` 与精确 `thinkphp_legacy_YYYYMMDD/` 旧框架目录。含链接或特殊文件的遗留路径拒绝自动操作，改为可信环境人工取证。

每次隔离建独立目录，移动前写 `manifest.json`，记录原路径、SHA256、大小、uid/gid、权限、mtime 和移动状态，然后移动原件；清单权限 0600。发生中断时可用 planned/moved 状态及源/目标内容恢复核对。隔离不是删除，不能直接把样本回拷到 webroot。

隔离发现 active/system 攻击路径仍返回失败，提示调查宿主机持久化；其他未知 IOC 或非法配置保留原件并阻断，避免 rsync 覆盖证据。跨文件系统移动不是原子操作，取证要求更高时应先在可信环境制作只读磁盘快照。

## 部署集成

`bin/deploy-155.sh` 在任何 SSH 前执行本地源码审计，生成独立基线。它把可信审计器、纯数据解析器、基线和可选批准清单放到远端 `/root/maccms-audit/<批次>/`；先审计所有目标站点，再进行任何站点代码覆盖。命中即退出，不能通过 `grep`/`tail` 管道掩盖 rsync、Composer 或自检失败。Composer 只安装锁定依赖且禁用 plugins/scripts。私有配置缺失、PHP-FPM reload 失败、API 冒烟不返回 200 同样使脚本失败。

SSH 强制 `StrictHostKeyChecking=yes`。首次使用应通过独立可信渠道核对主机指纹，预置 `$HOME/.ssh/known_hosts` 或用 `MACCMS_KNOWN_HOSTS=/trusted/known_hosts` 指定；脚本不会自动 `ssh-keyscan` 后直接信任。指纹变化或缺失必须先调查，不能为发版关闭校验。

脚本默认只读审计旧站点。已确认需迁出的上述明确遗留路径，可在实际部署时设置 `MACCMS_QUARANTINE_KNOWN=1`，证据落在 `/root/maccms-quarantine/<站点>/`；私有 PHP 的批准清单通过 `MACCMS_AUDIT_APPROVALS=/trusted/site-approved.json` 传入。前后两份 JSON 报告均位于该批次审计目录，源审计报告保留在本地 `maccms-deploy-audit.*` 临时目录。部署前报错时，不应为了“先发上去”跳过审计。

rsync 继续不使用 `--delete`，保留业务私有文件；已知危险旧路径从普通删除名单迁到证据隔离流程。部署后重新扫描真实文件并核对已部署维护 PHP 的内容，再运行框架自检。新增文件、新的入口改名、私有模板升级和删除源码时，都应复核前后报告。脚本不会自动恢复遭入侵机器的可信状态，也不是原子发布系统；生产发布应在上游维护窗口或下线实例中完成，防止覆盖过程中的并发请求。

HTTP 部分仍只是有限冒烟：API 的 200 检查不验证业务响应体，站点根路径状态只记录（允许站点自己的重定向），未覆盖后台登录、私有主题、全部播放器、数据库内容、CDN 节点与持久连接。即使脚本退出 0，也不能据此声称全部用户功能、缓存或宿主机已完成发布验收；应另行用真实业务验收与外部观察确认。

现有脚本仍将 webroot 属主统一设为 `www:www`，这是源码可写的既有风险，本次没有盲改权限破坏后台模板/插件编辑。正式加固应在审核这些写入功能后，把入口、application 业务源码、vendor、静态 JS 和模板代码归属部署用户/root，PHP-FPM 仅获读取权限；仅给 runtime、upload、log、必要 application/data 目录及确需在线修改的配置文件写权限。extra 配置、插件 config/info 与模板编辑要逐项决定改由部署发布还是受控写入，不能为兼容某个编辑器恢复整站可写。对已受入侵系统，应先可信重建再落实权限，在线 chmod/chown 不能移除系统持久化。

## RingH23 宿主机只读检查

优先在可信救援系统挂载只读磁盘，运行审计器检查目标根目录；不要执行疑似主机的 nginx、systemctl、ldconfig 或其他可被替换的程序：

```bash
python3 /trusted/tools/security/maccms_audit.py --profile host --root /mnt/host \
  --json /trusted/host-report.json
```

检查并生成内容 hash 清单：`/etc/udev/rules.d`、`/usr/lib/udev/rules.d`、`/lib/udev/rules.d`、`/etc/ld.so.preload`、标准/aaPanel nginx 配置与常见模块目录、系统和用户 cron、systemd unit、文章提到的 `/var/adm`。对 `module.so`、`libutilkeybd.so`、`ring04h_office_bin` 文件名给出审阅提示，结合完整样本 hash 区分强证据；只枚举这些有限位置，不做无限全盘扫描。非空 preload 列表、nginx `load_module`、持久化配置里的下载/解码/临时目录命令会要求人工核验，可能包含合法配置，不能仅凭命中删除。符号链接目录不跟随，报告记录未覆盖路径；需要结合可信包清单逐一检查真实目标。

进一步保全并核对 preload 指向的共享库、nginx 动态模块、nginx/PHP/SSH 和系统命令本体、监听/出站连接、进程映射、启动项、管理员/SSH key、容器与计划任务。脚本不会执行这些程序获取运行时数据，也不能检测所有内存注入或内核隐藏。宿主机强 IOC 或未授权持久化一旦确认，应下线隔离、保全磁盘/日志、在可信镜像上重建，并从干净端轮换管理员、数据库、SSH、对象存储及第三方 API 凭据；只恢复审核后的内容和必要数据。

依据：[奇安信 XLab 对 FUNNULL / RingH23 / MACCMS 的技术分析](https://blog.xlab.qianxin.com/exposing-funnull-how-ringh23-maccms-are-poisoning-the-web/)。IOC 与策略需随新证据更新，正常站点域名、已批准资产和依赖更新仍需独立审阅。
