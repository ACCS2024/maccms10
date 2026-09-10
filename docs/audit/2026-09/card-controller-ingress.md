# 卡密控制器输入（F3c）

日期：2026-09-11。基于 `919b6b4c`，继模型逐字节凭据核对后的独立修复。

固定源对真实 API Payment::use_card / 前台 User::buy 方法、Think Request、验证器和 Card/Plog ORM 进行隔离调用，认证是受控夹具。双 PHP、双数据库各 13 条观察均确认：带字面百分号、加号、HTML 特殊字符或有效空格的原始卡密被转换后失效；字面 `%41` 等输入会被二次解码为另一张卡的凭据并成功兑换；数组参数触发 TypeError。API 方法收到 GET 时仍执行兑换。此证据是控制器输入合同，不声称已经绕过完整部署中的认证、路由或 CSRF 中间件。

新增 CardCredentials 统一模型、API 和前台的类型、UTF-8 与容量校验，保留已有整数转十进制字符串合同；对框架已经解码的请求参数不再 trim、urldecode 或 HTML 编码。API 在认证及兑换前拒绝非 POST，仍保留原登录检查和场景验证。缺失字段、数组、对象、布尔值、小数、坏编码与超容量值均在数据库写入前受控返回 1001。模型仍负责逐字节认证和整笔事务。

PHP 8.3.33 / 8.4.25 各自通过：

- 改动 PHP 编译；金融套件 24 个进程零失败。
- 新控制器输入 SQLite/MySQL 各 212 项。覆盖真实 Request 参数、显式表单编码/一次解码往返、百分号/加号/引号/中文/空格、容量边界、错误类型、不同字面值不可互换、非 POST 及 API 登录拒绝。
- 原兑换合同 SQLite/MySQL 各 40 项；owner/落库 SQLite 80 / MySQL 84 项。
- 前台表单 288 项；API 验证 149 项、41 个真实控制器动作。

入口 `tests/framework_audit_card_ingress.php` 已加入金融套件；MySQL 使用 `maccms_audit_card_ingress`，无生产写入。原始固定源信息与观察见 `/tmp/maccms-audit-20260910/card-followups/ingress-source.json`、`ingress-{sqlite,mysql}-{83,84}.log`；修复记录 `ingress-check1.log` 和验证树文件。控制器通过不代表批量发卡、后台字段编辑/删除、完整客户端页面或跨请求异常核对已经完成。

PHPDoc 后续（2026-09-11）：cc2d60bf 扫描中的 use_card 新返回提示源于旧文档把请求字段写成 PHP 参数、把 JSON 格式名称写成命名空间类。现将字段保留为请求说明，参数标注为实际 Request，返回标注为实际 think\response\Json，未修改方法体或加入原生返回类型。双版文件编译通过，PHPStan level 5 定向 Payment 文件从 44 条降为 37 条，该方法的 2 条参数解析、1 条返回类及 4 条返回值提示消除；其它方法的候选保留。证据为 /tmp/maccms-audit-20260910/card-followups/phpdoc-check1.log、phpdoc-static.json。此次为文档合同修正，未重复运行数据库回归来虚增验证范围。
