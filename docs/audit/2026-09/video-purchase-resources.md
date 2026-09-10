# 视频购买与实际资源权限闭环

旧购买入口只从 `Vod::infoData` 读取价格，再写入积分凭据。它没有验证购买的线路或选集是否存在、视频是否已发布或进入回收站，也没有确认内容密码、分类权限和 VIP / 免费权限。即使浏览器身份和 CSRF 验证正确，仍可能出现扣费后无法访问，或本来可访问却被重复收取积分的情况。

本组只改变视频（mid=1）的购买决策。文章与漫画保持既有调用合同。`index/User::ajax_buy_popedom` 和 `api/Payment::buy_popedom` 继续使用此前已验证的 POST 正文、MemberWrite 身份与 CSRF；视频分支交给新 `VideoPurchase`，并把现有 `check_vod_resource_access` 作为服务内部的权限回调。没有修改 `All`、覆盖共享权限缓存或另写一套扣费逻辑。

## 锁内报价与事务

`ContentPurchase` 增加内部视频报价入口，复用原有账户扣款、精确读回、买家账本、推荐奖励与 Ulog 保存事务。顺序为：

1. 拒绝已有外层事务；确认 User / Vod / Group / Plog / Ulog 全部支持事务。MySQL 必须为 InnoDB，SQLite 用于隔离回归。
2. 锁定实际账户，重新读取状态和余额，并比对授权时的 `user_random`。等待锁期间撤销的会话不能继续购买。
3. 锁定实际 Vod 行，重新解析 `mac_play_list`，通过 `ContentResource::vodContext` 解析所选资源和服务器价格。不会使用详情缓存中的旧视频行。
4. 根据锁内最新 `group_id / user_end_time` 计算有效组。过期 VIP 只在本次权限判断中按普通组处理，不把降级写回账户。锁定当前启用组定义；组删除或禁用受控拒绝。
5. 比较当前分类、当前播放/下载操作的数据库权限和现有 policy 缓存语义。失配时返回“权限已更新，请刷新后重试”，不扣费；无关操作权限变化不阻止正常购买。随后临时使用锁内账户执行现有权限判断，并在 `finally` 恢复原 GLOBALS。
6. 只有播放的 3003、下载的 4003 且明确 `confirm=1`，同时没有密码拒绝或试看限制，才进入收费。已可访问、免费、VIP 或已有匹配凭据返回成功，零扣款、零新账本、零假凭据。

收费时仍由同一 ContentPurchase 事务完成：当前价格匹配凭据判重、余额检查、扣款精确读回、Plog 保存与读回、推荐奖励、Ulog 保存。提交前任何写入失败都会回滚；并发重复请求只提交一次收费。若 COMMIT 的成功回执丢失，数据库可能已实际提交，客户端会收到受控失败；应先核对现有凭据和余额，不能声称该笔已经回滚。余额不足保持 index 的 2002 和 API 的 1005 协议。

既有 `ContentPurchase::buy($uid, $pricedRecord)` 合同不变，仍支持其原有调用者事务及非视频的已定价记录。视频回调仅由服务器内部提供，不能从 HTTP 请求指定。拒绝嵌套事务只适用于新视频入口。

## 资源与坐标合同

- 只支持 type=4 播放、type=5 下载；价格必须为当前数据库中的合法整数，并符合安装 Ulog 的 unsigned smallint 上限 65535。缺少必要旧库字段、负数、非整数或超界价格均受控拒绝，不将坏价格改成免费。
- 必须是已发布、未回收的视频，并存在实际选中的非空线路/选集资源。空集保留原键，不压缩编号或改选相邻集。
- 正文省略 sid / nid 时采用阅读 API 的默认 1 / 1；显式 0、负数、数组或超出 sid≤255 / nid≤65535 的值拒绝。旧 API 客户端曾发送的显式 0 需要改为实际正坐标；当前六份前端客户端均使用实际坐标。
- 整条计费也先验证用户选择的实际线路和集数，只把最后的购买凭据规范成 0 / 0。不能用 0 或不存在的选集绕过资源验证。
- 内容密码与购买凭据独立。未验证密码时零写拒绝；正常通过现有 ContentPassword 验证后可以购买。密码改变后旧 session grant 不再有效，已有购买凭据不会绕过新密码。
- 响应仅返回受控 code / msg 和必要积分信息，不包含锁内账户行、密码、session 随机数、原始媒体地址或内部报价记录。

## 验证

`tests/fixtures/purchase_csrf.php` 已去掉 Vod metadata alias，使用真实安装 Vod DDL、生产资源解析和权限策略；Art / Manga metadata 隔离仍保留。原有 492 项 Cookie / Bearer / CSRF / 方法覆盖 / Session / 零写检查保留。旧 `security_audit_content_purchase.php` 的少量控制器基础合同改用既有 Art fixture，继续验证服务器定价和实际账户；视频实际控制器行为由真实 Vod 路由回归承担。

新 `framework_audit_video_purchase.php` 覆盖两个入口、播放/下载、单集/整条计费、实际购买后可读、重复提交、下架/回收/空资源、无效及缺省坐标、免费/VIP、分类拒绝、组禁用/删除、内容密码与密码变化、过期会员只读判断、真实安装字段及旧库宽字段的错误价格、事务故障和非 InnoDB 拒绝。

MySQL 并发测试通过独立 PHP 进程调用真实路由，并查询目标连接的 PROCESSLIST 确认其正在等待指定 User / Vod 的 `FOR UPDATE`，随后提交正常后台状态变化：改价、下架、回收、删线路/集、改密码、改会员组、VIP 到期、改分类或具体权限、组删除/禁用、余额降低、会话撤销或账号禁用。请求恢复后必须按新状态决定且没有误扣。另有四个同时购买同一资源、以及不足以购买多个不同资源的并发场景。

实际 Chromium 的六份客户端及购买 gate 继续连接 PHP Session / 控制器 / 真实 Vod 与金融 ORM，验证 GET 取 token → 单次 POST → 实际只扣一次，而非 mock 成功响应。所有服务与数据均为隔离本地 fixture，不连接真实账号或媒体地址。

| 测试 | PHP 8.3 | PHP 8.4 |
| --- | --- | --- |
| 视频资源 SQLite | 1180 | 1180 |
| 视频资源 MySQL 非严格模式（含并发） | 1300 | 1300 |
| 原购买 CSRF 路由 SQLite / MySQL | 492 / 492 | 492 / 492 |
| 既有 ContentPurchase SQLite / MySQL | 78 / 110 | 78 / 110 |
| 真实 PHP Chromium 购买客户端 | 61 | 61 |

运行入口：

```sh
php tests/framework_audit_video_purchase.php
php tests/framework_audit_purchase_csrf.php
php tests/security_audit_content_purchase.php
node tests/browser/purchase_csrf_php.cjs
```

视频 MySQL 回归使用 `PURCHASE_CSRF_MYSQL=1`、`FRAMEWORK_AUDIT_HOST`、`FRAMEWORK_AUDIT_PASSWORD`，只操作专用 `maccms_audit_purchase_csrf` 库。旧 coordinator MySQL 回归继续使用原 `MEMBERSHIP_AUDIT_*` 参数和专用 membership 库。两种测试的独立库必须各自互斥运行；SQLite 和各浏览器 fixture 使用临时目录隔离。

本组保证购买不使用过期的相关权限缓存收费；纯读取路径仍沿用原有 Group cache，缓存一致性的全面治理另列后续。站点计费模式和播放器配置仍是当前请求加载的配置快照，未把文件配置变更纳入数据库事务。此组也未把文章或漫画迁入新的视频资源校验流程。
