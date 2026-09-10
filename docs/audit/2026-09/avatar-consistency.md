# 本地头像：不可变文件与事务指针

本组处理 `Upload::upload` 的 `flag=user`，仅限配置 `local` 与既有字面 `remote`（远程访问、本次仍本地存储）模式。服务器身份、管理员目标权限、POST 和 CSRF 规则沿用先前提交。真实云存储适配器、固定头像路径的远端删除及跨云端回滚留给下一独立组。

## 已确认问题与读取契约

原代码先把 `upload/user/{uid%10}/{uid}.jpg` 替换，再更新 User，最后登记 Annex；User/Annex 失败会留下已替换的头像。实际 SQLite 拒绝 User UPDATE 时旧图片已被覆盖。相同路径反复上传还会复用旧附件记录，大小可能过期。

`mac_get_user_portrait` 原来只检查上述固定文件，完全不读 `user_portrait`。API User/Auth、模型 Comment/Gbook/Chatroom、评论 API、模板与登录头像 cookie 都经此 helper 或使用它返回的 URL。只改上传文件名会导致这些读取方继续显示旧图。安装表中 `user_portrait` 是 `VARCHAR(100)`，新的最长规范路径为 61 字节，已有字段足够，不需要新列、表或旧数据迁移。

后台会员资料页同时提交可编辑的 `user_portrait`，打开的旧表单能够把新头像路径写回旧值。本组将其改为只读展示、取消提交名，后台 `info` POST 按大小写不敏感剥除该字段；真正的上传入口继续按已验证用户目标独立提交。

## 修复行为

复用 `LocalAttachment` 的暂存、文件扫描、Annex 精确读回、事务、独占发布与清理逻辑，增加服务端调用的头像分支：

1. 在私有临时目录接收真实 UploadedFile/base64，扫描并校验实际图像类型，按头像尺寸显式编码 JPEG。动画头像仍明确使用第一张合成帧；头像不应用内容附件水印和多缩略图配置。
2. 生成 `upload/user/{uid%10}/{uid}-{32位随机hex}.jpg`，禁止覆盖已有文件。旧固定图和此前所有版本均保留。
3. 要求 User 与 Annex 为事务存储，拒绝外层事务；事务内锁定实际 User 行，复核存在性及普通用户启用状态，保存并精确读回 Annex 类型、字节数、主键及时间。
4. 新文件完整发布、flush/fsync、长度和 SHA-256 检查后，更新 User 指针，检查影响行数及精确读回；最后一并提交。普通失败回滚并仅清理本次新文件。
5. 本人成功上传同步当前浏览器头像 cookie；管理员替其他用户上传不会修改管理员浏览器的头像 cookie。编辑器响应仍在事务及清理完成之后输出。

新 `UserPortrait` reader 仅接受本用户的规范随机本地路径，且拒绝符号链接；不存在/不符合规范时兼容本用户旧固定文件，再回退默认头像。历史任意 URL、其他用户路径、目录穿越不会被激活。查询失败退旧图/默认，不将页面变成异常响应。请求内用 WeakMap 缓存，事务成功清除当前请求该用户缓存。

Comment/Gbook/Chatroom 和 API Comment 在实际列表结果上批量预取用户路径，每批最多 500 个 ID 一次查询；模板继续使用原 helper。真实非空父子评论测试另复现旧 `think\Collection` 子项间接写入错误，故仅把该子查询结果转成数组，保持原筛选和内容加载行为。

## 并发、故障与恢复界限

MySQL 用同一 User 行锁串行提交并发上传，最后提交者成为当前头像；每个版本有不同文件，不会互相覆盖。SQLite 忙锁允许返回受控失败，失败事务不留下指针/附件差异。旧缓存 URL 始终保留；其他已登录浏览器的旧头像 cookie 在身份刷新前可能继续显示旧版本，聊天室已有响应缓存最多沿用原 5 秒策略。

实际 SIGKILL 测试在文件发布后、COMMIT 前、COMMIT 后分别中断独立 PHP 进程。前两种情况下指针和附件记录仍旧，读者看到完整旧图；第三种情况下二者均已提交，读者看到完整新图。崩溃可能留下本次私有暂存目录或未引用文件，但不会覆盖旧图。COMMIT 抛异常可能实际已提交，因此返回受控失败，并保留新文件及 `commit_outcome_unknown` manifest，不能盲删。

manifest 增加 owner ID 与实际 User 表名，已有附件路径/字节数/根目录信息不变。人工核对恢复时：

- User 当前指针等于 manifest 新路径：保留完整新文件及 Annex；可核对文件尺寸/源 SHA 后只清理暂存。
- 当前指针已被后续上传替换，但该路径仍有 Annex：保留该旧版本，已有客户端仍可能引用。
- 两处都没有引用：可识别为该次操作的候选孤立文件；本组不自动删除，也不扩大成历史附件清扫。

不要求额外数据库操作表即可保证已提交头像选择的一致性；既有 User 指针就是提交证据。临时 manifest 用于进程故障排查，并非保证主机重启后仍保留的持久作业队列。此验证不等于断电/磁盘损坏或所有文件系统的跨资源原子性保证；新文件与数据库也需要部署层备份。没有引入定时清理旧头像、读取时写磁盘、远程请求或应用启动恢复逻辑。

## 验证

`tests/security_audit_avatar_consistency.php` 在 PHP 8.3.33 / 8.4.25、SQLite / MySQL 非严格模式通过，分别 120 / 122 项（包含独立子目录进程的 18 项）：

- 正常不可变 JPEG、字节元数据、旧版本留存、本人 cookie、UINT32 最大用户目标；
- User/Annex 触发器拒绝、无异常忽略、数据篡改、非严格列截断、MyISAM、外层事务；
- 无效图像/尺寸、类型不符、扫描拒绝、短写、等长内容损坏及实际非特权文件发布失败；
- 三个真实进程强制终止点、COMMIT 前拒绝/实际提交后应答丢失、两个独立连接并发上传；
- 非空评论父子/留言/聊天室/API 评论每批一次用户查询，helper 缓存命中不重查、历史路径/符号链接/无效 ID；
- 真正后台资料保存拒绝三种大小写头像字段，以及模板输入只读且不提交；
- `MAC_PATH` 与 `install_dir` 均为 `/site/` 时，合法会员 `from=''` 成功后 cookie 带正确前缀；五类非空编辑器来源仍受身份边界拒绝，cookie 不变。

沿用 upload fixture 的独立 `maccms_audit_upload` 测试库与 `UPLOAD_AUDIT_MYSQL/HOST/PASSWORD` 环境；所有文件在随机临时根目录。新 worker/reads/subdirectory 是被主测试调用的 fixture，不应独立加入测试清单。执行示例：

```sh
docker run --rm --network none -v "$PWD:/work:ro" -w /work maccms-audit-image84:20260910 php tests/security_audit_avatar_consistency.php
docker run --rm --network container:maccms-audit-ordercreate-db-20260910 -e UPLOAD_AUDIT_MYSQL=1 -v "$PWD:/work:ro" -w /work maccms-audit-image84:20260910 php tests/security_audit_avatar_consistency.php
```

旧上传身份 205、CSRF 56 在双 PHP × 双数据库 × index/admin 格式通过；原本地附件 125/128、图片 111/38、TinyMCE 104 双版通过。实际 Chromium 上传客户端两版各 74 项通过，旧固定路径断言已改为验证本用户的新规范路径，正常 iframe/form/fetch/UEditor 上传仍成功。日志在 `/tmp/maccms-audit-20260910/avatar-consistency/`。

## 后续边界

云存储头像仍沿旧分支，本组不宣称其 User/远端对象一致性已修复。Annex 后台人工删除尚未阻止删除正在使用的头像或其他附件，也需要下一引用管理组单独处理。保留旧头像会增长存储；正式归档/清理应基于引用与审计策略另做，不用猜测的 TTL 删除在途或缓存引用。
