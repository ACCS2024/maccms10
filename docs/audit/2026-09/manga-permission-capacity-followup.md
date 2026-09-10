# Manga 大权限配置的独立容量复核

日期：2026-09-10。先只读核验已冻结的 Manga 读取实现，随后按根授权在同一读取批加入 Manga-only 当前分类权限投影；未修改共享 User 身份入口。证据目录：`/tmp/maccms-audit-20260910/manga-group-capacity`，包括独立 PHP fixture、runner、实际日志和生产源码哈希。

## 范围与数据

采用实际安装 DDL，在隔离 MySQL 中建立普通有效数据：Group 的 `group_popedom`、`group_type` 均为 TEXT，User 的多组字段为 VARCHAR(255)。权限 JSON 模拟后台勾选分类权限，既测全部五种权限，也测每分类只勾阅读；没有恶意 JSON、异常嵌套或超列数据。

所有行均启用。最大样本 32 个组，每组 3920 个分类的阅读权限 JSON 为 65534 字节，分类列表为 65533 字节，组成员串 127 字节，都能原样写入安装表。作品同时包含 20000 个非空章、8MiB 原始目录和 1MiB 简介。

为了准确归因，此探针从已可信的服务端用户身份开始，以真实 Request 调用真实 `Manga::get_chapter`；不执行 `User::finalizeUserLoginPayload`。展示 Group cache 保留小型夹具，32 个大权限组只由新 `mangaPermissionGroups` 从主库读取。此次结果不能作为旧身份组缓存入口的容量证明。

## PHP 128M 实测

各案例使用独立 PHP 进程，业务读取前分配器基线均为 16MiB。PHP 8.3.33 和 8.4.25 的结果一致；每案例均成功返回实际第 20000 章的一张图片，不返回其他章图片。

| 组数 | 每组分类权限 | JSON 字节/组 | 分类列表字节/组 | 峰值 |
|---:|---|---:|---:|---:|
| 1 | 1 分类，五种权限 | 47 | 3 | 78MiB |
| 32 | 1000 分类，五种权限 | 47894 | 3894 | 92MiB |
| 16 | 3800 分类，只勾阅读 | 63494 | 17894 | 94MiB |
| 32 | 3800 分类，只勾阅读 | 63494 | 17894 | 112MiB |
| 32 | 3920 分类，只勾阅读 | 65534 | 65533 | 116MiB |

最后一行每版实际约 0.4 秒。没有触发 128M 超限，但只剩约 12MiB 余量。原读取矩阵的 102.01MiB 是该矩阵小权限配置及其运行上下文的实测，不能推广为所有权限配置统一上限；两份夹具的初始分配与存活变量不同，不能简单相加减推导线上峰值。线上其他中间件、日志、模板和身份缓存也会占用内存。

## 已实施的读取内存收敛

原 helper 会将 32 个组的全部解码权限树保留到返回。本次已改为传入实际 `type_id`：逐组解码有效 JSON 后，只保留当前分类的权限子数组，及时释放完整树。各组启用状态、缺失组判断、组 ID 规范化以及分类列表匹配仍保持；不依赖数据库 JSON 函数，也不改变 Vod/Art 规则。一次最多保留一组完整解码树，可减少累积内存。

同一最大样本、相同 16MiB 初始分配基线复核：PHP 8.3 从 116MiB 降至 **84MiB**，PHP 8.4 从 116MiB 降至 **86MiB**，均正常返回当前章。原 555 项矩阵先完整通过，再补当前分类/多组反例及该大配置样本进入常规 fixture：最终每 PHP、每根/子目录组合 **561 项**加 JS41 均通过。该连续矩阵保留其他夹具分配，容量样本初始分配 80MiB、峰值 **106.01MiB**；不同夹具初始状态单独记录，不能与独立进程结果混算。共享 `User::finalizeUserLoginPayload` 先加载完整 Group cache 的容量与可信身份入口问题继续独立处理；不能据本次隔离结果宣布真实身份全链在最大权限配置下必然低于 128M。

## 购买浏览器夹具的提交依赖

读取批修改 `template/default/html/widget/popedom_upgrade_gate.html` 的漫画分支，要求真实 `manga_access.purchase_supported/purchase_sid/purchase_nid`。旧 `tests/fixtures/purchase_csrf_http.php` 只传 `obj/param/popedom`，新 gate 会禁用按钮，使 `tests/browser/purchase_csrf_php.cjs` 的两次 `.js-popedom-buy-btn` 交互失败。

购买批的新 `tests/fixtures/purchase_csrf_http.php` 调用真实读取权限，并依赖 `tests/fixtures/purchase_csrf.php` 新增的 `MANGA_PURCHASE_AUDIT` 模式、漫画实际表和种子。该模式是为新锁内购买服务准备的；旧购买仍走 `Manga::infoData`，又依赖夹具当前没有的 `Type` 表及 `app.cache_core`，不能只提前复制这两个夹具便声称阶段验证成立。

根最终决定保留读取 widget 同批：先在旧普通 HTTP 夹具中为其既定的有效漫画坐标提供 literal `manga_access` 门禁显示数据，维持旧阶段浏览器表单合同，不把它描述为新 Manga 数据库授权证明。新真实 Manga 模式与锁内服务仍随购买批提交验证。这样无需提前导入依赖旧模型额外表/配置的整套新夹具，也不延迟整部替代购买入口 UI。该前置夹具 hunk 由根处理，本代理没有修改购买文件。
