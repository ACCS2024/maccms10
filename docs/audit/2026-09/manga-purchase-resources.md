# 漫画购买的实际章节、权限和事务

旧前台 mid=12 购买从 `Manga::infoData` 取得价格后直接进入扣费，没有先验证实际来源、章节、图片、发布/回收状态、内容密码或当前免费阅读权。本组以 `MangaPurchase` 接入已经存在的财务协调器，报价、权限与扣费使用同一锁内资源。API Payment 仍明确拒绝 mid=12，没有新增未支持的 API 购买入口。

本组依赖漫画阅读组提供的真实 `ContentResource::mangaContext`、`ContentPassword::mangaState/verifyManga` 与 `All::check_manga_resource_access`。阅读控制器、模板、密码入口及公开资源 loader 由阅读组负责；本组没有替换那些策略或用 stub 模拟尚不存在的接口。

## 购买合同

- 前台 `user/ajax_buy_popedom` 继续使用真实 POST 正文和 MemberWrite 的已验证 Cookie/Bearer 身份；Cookie 使用同一真实 Session 的 CSRF token。query 不能提供或覆盖坐标、身份和客户端价格。
- 仅 `mid=12,type=1`。省略 sid/nid 为 1/1；显式 0、数组、超出 sid≤255 / nid≤65535 的输入受控拒绝。漫画缺章保持缺章，不采用文章的末章截断，不把实际稀疏列表压缩成另一收费坐标。
- 单章使用当前真实 sid/nid；整部最后保存 0/0 凭据，但必须先验证请求选择的真实非空章节。0/0 不是可提交的实际章节。阅读端给出的 `purchase_sid/purchase_nid` 可以指向首个可购买的非空章，再通过整部凭据阅读其它章。
- 必须已发布、未回收，且当前章有经过阅读端策略归一的图片。目录、图片预算超限整体拒绝，逗号图片列表中任一非法地址也使整章不可购买，不能只过滤一个片段后收费。`Two$` 这种有标题但明确空地址的章节由 Manga 专属解析保留空图片；不会把标题变成收费的相对图片地址。
- 整部价格使用 manga_points；单章使用正 manga_points_detail，为零时沿用 manga_points 回退。实际收费字段必须为精确非负整数且不超过凭据字段 65535，缺字段及旧宽字段中的无效价格受控拒绝。
- 漫画沿既有文章式分类规则：已登录会员可以购买本人同价同章节凭据取得原本受限的分类阅读权。VIP 仍需分类阅读权限才能免费；无分类权的 VIP 可以正常付费取得对应凭据。内容密码独立，购买无法跳过密码验证。
- 已可读、免费、当前有分类权的 VIP，以及本人同价同坐标已购请求返回成功，不新增扣费、账本或零价假凭据。零价旧凭据不解锁原策略拒绝的免费分类。只有实际策略明确返回 3003、confirm=1，资源/策略均支持购买且价格大于零才收费。
- 返回受控 code/msg 和必要积分信息；不返回原始图片地址、章节字段、密码、账号随机数或内部报价。余额不足保持前台 code2002；API 的既有拒绝合同不变。

## 锁与失败处理

锁顺序为 User → Manga → 当前 Group → Ulog。`ContentPurchase::buyManga` 只增加固定 mid/table 映射，保留普通 buy、Video 和 Art 的合同，并复用同一精确扣费、买家及推荐积分账本、Ulog 保存和读回实现。

先锁当前启用账号并核对授权时随机数，再从 master 锁真实 Manga 行、解析当前图片和价格。使用锁内账号的组与到期时间，过期会员只在本次授权中按普通组处理；拒绝请求不持久化降组。所有有效组必须存在并启用，活跃多组中缺失/禁用的组不被静默丢弃。漫画实际阅读策略也从 writer 读取已启用的 Group 与 Ulog；购买仅采用已锁定的当前组权限，不再把旧 Group cache 当作准入条件。缓存提前滞后或在回调期间改变都不影响当前免费/付费决定。数据库权限变更按现行漫画规则拒绝或重新报价，删除/禁用组仍零写拒绝。前导零及等价重复组表示（02、2,02）在实际阅读中规范为同一组，不会出现购买返回免费成功但读端仍拒绝的分歧。实际策略临时使用锁内账号，finally 恢复原 GLOBALS。

MySQL 的 User/Manga/Group/Plog/Ulog 必须全为 InnoDB；不要求无关 Vod/Art 表的引擎。SQLite 使用真实事务。报价入口拒绝已有外层事务并保留调用者事务，即使 ORM 当前连接是 reader、另一个 master PDO 已有原始事务也不能接管或提交它。正常提交前失败可回滚所有账号、凭据和账本；重复并发只扣一次，余额只够一章时其余不同章购买受控失败。

COMMIT 成功回执丢失时，数据库可能已经提交，客户端应核对当前凭据与余额后重试。本组没有改动协调器 rollback 自身抛异常的已知金融故障待办，也不将连接异常声称为“已经回滚”。站点计费配置仍使用当前请求加载的快照，没有把配置文件纳入数据库事务。漫画实际读权限已由阅读组闭合 writer Group/Ulog；其它资源与账号展示资料的全部 Group cache 一致性不属于本组结论。

## 真实回归和隔离

`tests/fixtures/purchase_csrf.php` 增加显式 `MANGA_PURCHASE_AUDIT=1` 模式：采用安装 SQL 的真实 Manga 表、明确已发布的图片章节，使用独立 `maccms_audit_manga_purchase` 数据库。HTTP 浏览器夹具显式启用真实 Manga 模式，gate 的 manga_access 由真实 Session 身份和 All 阅读策略产生，覆盖新购买坐标/资格字段；六客户端与漫画 gate 都经过实际扣费。默认非 HTTP 模式保留原 Video/Art/CSRF 用例和数据库；前置 ROOT_PATH/MAC_PATH 常量保持已提交版本。图片地址仅作为本地夹具元数据，从不请求外部内容。

`framework_audit_manga_purchase.php` 使用实际 PHP 路由、控制器、User/Manga/Group/Plog/Ulog 和实际阅读策略，覆盖购买前确认、买后可读、Cookie+Session token 与 Bearer、单章/整部、默认和稀疏坐标、价格回退、免费/VIP、分类限制、不同人/来源/章节/旧价凭据、空图/缺章/下架/回收、正常密码 grant 与密码变更、过期会员、宽字段无效价格、真实价格上限、目录/图片预算及无意义收费拒绝。

数据库故障既包含真实触发器抛错，也包含触发器将余额/账本/凭据静默改成另一个合法整数；必须完整拒绝并保留所有财务状态，撤掉触发器后正常请求可重试。使用 20000 章槽的真实安装字段确认长章坐标不压缩，20001 章、1025 图片以及超过1MiB的简介整体拒绝；不把超预算目录截断成可收费的另一资源。

MySQL 独立 worker 通过 PROCESSLIST 确认真实路由请求等待 User 或 Manga 的 FOR UPDATE，然后在持锁连接正常修改价格、回退价格、发布/回收/章节/密码、账号组/到期/余额/随机数/启用状态或相关组权限，验证请求恢复后使用当前值。另覆盖同章重复、不同章余额竞争、不同章节同时购买整部的幂等结果。worker 只使用专用库，不借用原 Video/Art 审核数据库。

`manga_purchase_replica.php` 在同一隔离 MySQL 的专用 writer/read 两个数据库配置实际 ORM 读写分离，覆盖隐藏的原始 master 事务保留、reader 没有当前凭据时从 master 正常购买和判重。它验证真实连接路由，未宣称启动复制进程。

```sh
php tests/framework_audit_manga_purchase.php
PURCHASE_CSRF_MYSQL=1 php tests/framework_audit_manga_purchase.php
php tests/framework_audit_purchase_csrf.php
php tests/framework_audit_art_purchase.php
php tests/framework_audit_video_purchase.php
php tests/security_audit_content_purchase.php
node tests/browser/purchase_csrf_php.cjs
```

漫画测试入口自身设置 MANGA_PURCHASE_AUDIT=1；MySQL 使用 FRAMEWORK_AUDIT_HOST / FRAMEWORK_AUDIT_PASSWORD，只创建/重建 maccms_audit_manga_purchase 及临时 maccms_audit_manga_purchase_read。两版 MySQL 漫画测试必须顺序运行；它们与其它资源审核库隔离。

## 最终隔离验证

以已提交 ccb903c7 导出的独立树为基础，应用已冻结 parser 精确 hunk、本组修改和漫画阅读组的 ContentResource/ContentPassword/All 片段及 Manga writer Group/Ulog 查询分支、新 gate hunk。未复制其它工作树方法，使用干净 vendor。购买接口不依赖尚未完成的模板、独立 loader 或实际内容站点。

| 测试 | PHP 8.3 | PHP 8.4 |
| --- | --- | --- |
| 漫画购买，SQLite | 807 | 807 |
| 漫画购买，MySQL 非严格模式，含真实并发及主从连接 | 940 | 940 |
| 原文章购买，SQLite / MySQL | 1098 / 1273 | 1098 / 1273 |
| 原视频购买，SQLite / MySQL | 1180 / 1300 | 1180 / 1300 |
| 原 Cookie/CSRF 购买路由，SQLite / MySQL | 492 / 492 | 492 / 492 |
| 原财务协调器，SQLite / MySQL | 78 / 110 | 78 / 110 |
| 六客户端及实际 Manga gate 的 PHP Chromium 回归 | 61 | 61 |

本组8个 PHP 文件两版语法检查均通过。原资源和财务回归在共用协调器/夹具改动后完整通过；最后仅漫画阅读接口与 HTTP gate 夹具变化，又重跑漫画双版双数据库及真实浏览器。源码冻结及依赖 SHA 单独记录，CI/审核清单由主审分批接入。

浏览器61项验证六份购买客户端及实际Manga购买/充值gate，不包含新漫画密码输入表单的Chromium交互。密码 grant→购买→实际阅读已由本组真实PHP覆盖；密码表单另有阅读组的JS VM和PHP入口证据，不能混称为浏览器覆盖。
