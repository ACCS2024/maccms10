# 文章购买的章节、权限与事务一致性

旧文章购买接口从 Art metadata 取价格后直接生成 Ulog，没有先确认文章已发布、未回收、存在实际章节、内容密码已通过，或会员本来已有免费阅读权。API 对单章价格为零时还未采用阅读端的整篇价格回退，可能保存无法解锁实际内容的零价凭据。

本组将 mid=2 接入新 `ArtPurchase`，以同一实际文章和章节规则完成购买。文章分类拒绝与视频不同：登录会员可以购买本人对应章节的凭据取得阅读权，不能照搬视频的“分类拒绝一律不可购买”。内容密码仍然独立，购买凭据不能绕过它。本组不修改 All 的阅读策略、文章页解析或前端购买协议；漫画保留原调用合同，另组处理。

## 事务和当前权限

`ContentPurchase` 保留普通 `buy($uid,$pricedRecord)` 的现有事务与调用者外层事务合同；`buyVideo` 也保持原 API。新增 `buyArt` 使用固定 mid/table 映射复用同一协调器，内部报价必须返回对应资源种类的凭据，不能把文章报价写成视频凭据。

文章顺序为 User → Art → Group → Ulog。报价在锁定当前启用账号后才读取并锁定 Art，使用 `ContentResource::artContext` 解析当前正文、章节和价格；同时核对授权时的随机数，拒绝等待锁期间已撤销的会话。只接受已发布、未回收且所选实际章节非空的文章。收费字段缺失、无效或超出 Ulog 的 65535 上限均受控拒绝；单章价格零保留阅读端回退 `art_points` 的正常规则。

使用锁内账号的当前组和到期时间。过期 VIP 只在本次判断中按普通组处理，不在拒绝请求时写回会员组。实际有效组必须存在并启用；活跃多组账号中任一组删除/禁用也拒绝，避免静默丢组后收费。每个相关分类及阅读操作的数据库权限，与当前 Group cache 的阅读语义一致才继续；无关播放/下载权限变化不阻止文章购买。缓存失配提示权限已更新并零写拒绝；也覆盖权限回调期间缓存再次改变的场景，不能把当前 VIP 变成收费、或给当前受限会员返回虚假的免费成功。

临时以锁内账号执行原 `check_art_resource_access`，并在 finally 恢复 GLOBALS。未验证密码、无可购买权限或 `purchase_supported=false` 均不收费。当前已可读、免费、VIP 或本人同价同章节已有真实付费凭据，返回成功且不新增账本或假凭据。零价旧凭据不能解锁原策略禁止的免费分类。只有明确 3003 / confirm=1、受支持且价格大于零，才进入原有余额检查、精确扣费、买家及推荐账本、Ulog 保存和读回。

User / Art / Group / Plog / Ulog 都必须支持事务；MySQL 要求 InnoDB。文章不要求无关 Vod 表的引擎，视频也仍使用自己的表映射。新资源报价入口拒绝已有外层事务，且不结束调用者事务。提交前写入失败完整回滚；并发重复请求只收费一次。COMMIT 成功回执丢失时，数据库可能实际已经提交，客户端应核对已有凭据与余额后重试，不能承诺此类失败已经回滚。

## 章节与接口合同

- 两个入口继续使用真实 POST 正文、MemberWrite 的已验证 Cookie/Bearer 身份与既有 CSRF；query 不能供应或覆盖正文坐标、身份或价格。
- `mid=2,type=1`，`sid` 是文章章节，`nid` 必须为 0。省略 sid/nid 时为 1/0；显式 sid=0 或超过接口 sid≤255 上限的请求拒绝。不能用整体凭据的 0/0 作为实际章节。
- 在允许的输入范围内，Art 的既有最后一页截断规则保留：例如文章只有三章，sid=255 先解析为第三章，再检查/保存第三章凭据；不会保存255章的无效票据，也不会让读端用另一坐标查询。
- 整篇购买仍先确认本次选择的真实非空章节，最后凭据才规范为 0/0。默认 gate 已使用 `art_access.purchase_page`，所以超过255章的长文章可以传首个合规非空章购买整篇，随后正常阅读后面的章节；不支持的长文章单章购买仍受控拒绝。
- 购买状态保持 index 余额不足2002 / API1005。响应只返回受控 code/msg/必要积分信息，不透出正文、内容密码、账号秘密或内部报价记录。

## 验证

`tests/fixtures/purchase_csrf.php` 去掉 Art metadata alias，加入真实安装 Art DDL 和正文；只有漫画 metadata stub 保留。原有 CSRF 与视频回归继续使用同一真实财务和 Session 夹具。旧 coordinator 中的文章控制器基本断言也保留，改用实际 Art 表、正常 nid=0 和原阅读策略；普通 buy 的零价、推荐账本、外层事务和并发断言未删除。

新 `framework_audit_art_purchase.php` 使用实际 PHP 路由、控制器、User/Art/Group/Plog/Ulog，以及原文章阅读权限。覆盖购买前确认、买后实际可读、单章/整篇、正文截断、价格回退、免费/VIP、分类受限后正常购买、别人/其它章/旧价凭据不匹配、空章/回收/下架、密码正常验证与变更、过期会员零写、旧宽字段无效价格、真实字段上限、事务故障、有效重试及非 InnoDB。

MySQL 并发通过现有通用真实路由 worker `video_purchase_worker.php` 执行（文件名来自视频组，逻辑没有替换视频或文章业务）。通过 PROCESSLIST 确认其实际等待指定 User / Art 行的 FOR UPDATE，随后提交改价、价格回退、下架、回收、清空/缩短正文、改密码、组权限/类型/启用状态、余额、随机数或账号状态的正常夹具修改。请求继续后必须按新章节、新价格和新账号状态处理。另有跨两个入口的同章重复、多个输入截断为同一章，以及余额只够一章时的并发检查。

所有回归从独立已提交基线树覆盖本组精确修改、使用干净 vendor 执行，不借用并行中的头像/远端存储业务。purchase fixture 的两行入口常量同步来自头像组：ROOT_PATH 指向该 fixture 临时目录，MAC_PATH 与现有 /fixture/ 一致；没有改变生产头像逻辑。

运行：

```sh
php tests/framework_audit_art_purchase.php
PURCHASE_CSRF_MYSQL=1 php tests/framework_audit_art_purchase.php
php tests/framework_audit_video_purchase.php
php tests/framework_audit_purchase_csrf.php
php tests/security_audit_content_purchase.php
node tests/browser/purchase_csrf_php.cjs
```

文章/视频/CSRF 共用专用 `maccms_audit_purchase_csrf`，通过 FRAMEWORK_AUDIT_HOST / FRAMEWORK_AUDIT_PASSWORD 连接；必须互斥运行。旧 coordinator 使用自己的 membership 专用库和原 MEMBERSHIP_AUDIT_* 参数。SQLite、浏览器及 worker 文件均位于本次临时目录，服务只使用隔离数据和本地资源，不连接真实账号或外部内容。

本组避免文章购买按过期权限缓存收费；纯读取路径的 Group cache 全面一致性仍列后续，未宣称本组修复所有读取授权。站点计费配置使用当前请求加载的配置快照，没有把文件配置变更纳入数据库锁；漫画也未进入新章节校验服务。

| 测试 | PHP 8.3 | PHP 8.4 |
| --- | --- | --- |
| 文章购买，SQLite | 1098 | 1098 |
| 文章购买，MySQL 非严格模式，含真实并发与读写分离 | 1273 | 1273 |
| 原视频购买，SQLite / MySQL | 1180 / 1300 | 1180 / 1300 |
| 原 Cookie/CSRF 购买路由，SQLite / MySQL | 492 / 492 | 492 / 492 |
| 原 ContentPurchase 协调器，SQLite / MySQL | 78 / 110 | 78 / 110 |
| 六份真实 PHP Chromium 购买客户端 | 61 | 61 |

8 个本组 PHP 文件在两版 PHP 均无语法诊断。新增文章矩阵全部重跑至最终多组和回调中断边界；视频、CSRF、协调器及浏览器在共享报价/真实Art夹具改动后完整通过，最后的文章专属判断没有修改这些既有契约。

## 读写分离的外层事务检查

`art_purchase_replica.php` 使用同一隔离 MySQL 容器的 `maccms_audit_purchase_csrf` 与 `maccms_audit_purchase_csrf_read`，真实配置 ORM 主/从连接。测试先让 master PDO 直接开启事务并修改一项未提交余额，再把当前 ORM PDO 切到 reader，明确断言 reader 不在事务中而 master 仍在事务中。`buyArt` 必须在调用报价前受控失败，购买 SQL 写入为零，master 的原事务与未提交值均保留，独立连接仍只能看到原已提交值，调用者可以自行回滚。

当前实现中，主库引擎查询切回已有 writer 后，PDO 拒绝再次 beginTransaction，协调器尚未取得事务所有权，因此返回失败并保留原事务；不依赖从库 PDO 的状态误判断言。本组另外验证正常读写分离的实际购买，以及从库尚无凭据时，重复请求通过当前主库凭据判重且不再次扣费。测试完成恢复原数据库管理器并删除本次专用读库。此验证针对真实连接路由，不声称启动了实际数据库复制进程。

现有故障测试证明可执行正常回滚时的原子性。协调器 catch 内再次调用 Db::rollback 本身若抛异常，目前仍会逸出，尚无受控回滚失败结果或连接失效治理；这作为独立金融连接故障边界记录，未在文章组扩展到所有财务流程，也不把该状态承诺成已回滚。
