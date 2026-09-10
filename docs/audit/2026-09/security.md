# 当前代码安全与账务边界

日期：2026-09-10。对象是当前仓库及可复现的隔离部署，不以旧版本或历史审计文档推定当前漏洞。范围包含认证授权、请求/文件/出站边界、扩展依赖、支付和积分事务、配置完整性与部署暴露面。审计持续进行，以下区分已提交修复与尚待完成的工作。

## 已提交的修复

| 类别 | 根因与处置 | 主要验证 |
| --- | --- | --- |
| 管理员权限 | 子管理员可修改超管/扩大权限、危险控制器豁免、列表停用保护不足；按当前权限校验账号和操作目标 | `security_audit_admin.php`、`security_audit_bulk_forms.php` |
| 会话撤销 | 仅信 session 旧快照；每请求核查账号、状态、密码，刷新权限 | `framework_audit_admin_session.php`；真实后台登录/页面 |
| CSRF | 自动携带 Cookie 被作为显式令牌、原生 fetch 与中间件豁免不匹配；令牌必须显式提交并与 session 比较 | `security_audit_csrf.php`、`admin_write_smoke.py` |
| JWT/OAuth | 算法/密钥/时间字段、登录状态与回调 profile 类型的边界；拒绝非法值、绑定状态且不泄露 token | `security_audit_jwt.php`、`security_audit_oauth.php`、`security_audit_oauth_profiles.php` |
| 加密/XML | 密文异常、签名处理和不安全 XML 解析边界；明确失败与受限解析 | `security_audit_crypto.php`、`security_audit_xml.php`、`security_audit_wechat.php` |
| 文件路径 | 字符串前缀无法限制兄弟目录/符号链接；受管路径按规范化真实目录检查，空文件名拒绝，写失败不报成功 | `security_audit_paths.php`、`security_audit_dir.php`、`security_audit_annex.php` |
| 出站请求 | 任意远端抓取、重定向和 DNS 地址边界；公共请求限制目的地址/解析结果、超时/体积并保持 TLS 校验 | `security_audit_http.php`、`security_audit_tls.php`；本地传输夹具 |
| 扩展与供应链 | 更新锁定依赖、修复加载和输出协议、删除无调用的 Download/PclZip；普通百度推送固定 HTTPS，旧快收录受控退役 | `extensions_audit_*`、依赖审计；[Download](retired-download.md)、[PclZip](retired-pclzip.md)、[百度](baidu-urlsend.md) |
| 配置完整性 | Begin 在普通请求中删除/重写配置，可能损失业务及证据；改成只读提示与日志，不自动删改 | `security_audit_config_preservation.php`；[说明](config-preservation.md) |
| 输入与查询 | Receive 畸形输入、类别映射、TP8 请求缓存和删除条件失配 | `framework_audit_receive.php`、`framework_audit_request_security.php`、`security_audit_user_log_delete.php` |
| 支付渠道 | 微信/支付宝/Epay/Codepay/Zhapay/Jeepay 各自校验签名、订单/金额/业务状态与失败返回 | 六个独立 `security_audit_pay_*.php`；测试签名/本地响应 |
| 支付幂等 | 并发 pending→paid 缺少条件闸门；账变失败/Throwable 未完整回滚；状态迁移、余额和流水同事务 | `framework_audit_payment.php`、`security_audit_membership.php` |
| 精确计价 | 浮点少一积分、小数倍率截断、正积分零元订单、字段上界；有界整数十进制计价并同步展示 | `security_audit_order_amount.php`、`security_audit_order_create.php`、两套展示测试；[规则](order-amount.md) |
| 余额溢出 | 非严格 MySQL 截断余额但记录完整账变；订单和推荐奖励以同一 UPDATE 的上界条件阻止截断 | `security_audit_points_overflow.php`；[扩查清单](points-overflow.md) |
| 提现事务 | 按旧余额覆盖、审核重复扣冻结、批量范围更新和退款部分完成；行锁/条件状态与账变同事务 | `framework_audit_cash.php`；退款可用余额上界仍列下一批 |
| 安装表结构 | 订单号无唯一约束，流水积分 SMALLINT 小于余额/订单容量；新安装 DDL 修正，旧库提供只读预检/显式迁移 | `security_audit_payment_schema.php`；[迁移说明](payment-schema.md) |

以上测试在 PHP 8.3.33/8.4.25 上执行；适用的模型另用 SQLite/MySQL。具体版本、命令及隔离点见 [测试文档](../../../tests/README.md) 和各分项报告。早期临时 `security_audit_boundaries.php` 已拆成分组测试，不再作为复验入口。

## 此后独立提交的闭环

- 用户账变保留：前台仅隐藏自己的显示记录，后台仍可核验，普通删除/覆盖账变被拒绝；旧库提供只读预检与显式迁移。真实会员/后台37项HTTP检查验证余额及历史资金字段不变。
- 评论：公开写入只接收新评论字段，身份取真实认证结果，目标/父评论/审核状态统一校验；新增可信来源标记默认0，历史记录不被追认为可信。任务领奖只依据当日可信且已审核评论，在事务中再次锁证据校验。当前无法证明实际观看/分享的任务停止新领奖并明确返回不可用。
- 任务/签到/卡密：已处理入账上界、状态原子迁移及账变失败回滚；旧任务ready标志不再直接证明评论资格。管理端删除已付款任务/签到记录后的幂等性尚需独立留存处理。
- 公共SDK：七牛/又拍云不自动跟随带认证内容的重定向，使用真实TLS/cURL/Guzzle隔离传输测试；又拍云旧HTTP purge在默认安全模式下受控拒绝。没有假定第三方真实账号已验收。
- Apache部署：已提交精确文件访问边界并以两版生产Dockerfile构建验证201项；实际完整应用另外验证19项前台/API、32个后台页面、37项账变HTTP及中英文语言资源。
- 账号找回：验证码匹配收件人、用途、所属用户、有效期和未使用状态；密码重置与验证码消费、随机数轮换同事务，旧MyISAM表受控拒绝。真实SQLite/MySQL及旧JWT回归通过。

## 当前未关闭事项

- 提现退款可用余额上界、普通/OAuth注册邀请与访问/阶梯奖励的完整事务；已有订单/任务修复不能自动覆盖其他入账入口。
- 已登录改密的旧MD5协议、密保恢复会话撤销、资料字段缺省和联系方式绑定/验证码消费；正在拆分修复。
- 当前图片依赖GIF编解码器的PHP8语法错误；后续还须用真实图片证明格式、帧与变换结果，不能只改语法。
- CLI恢复解析、前缀改写和连接状态恢复；备份流程的产物完整性不等同于生产恢复演练或无限规模一致性。
- 留言模块已有静态候选；子任务动态复现被工具自动安全审查中止，原因“possible cybersecurity risk”。现有未完成的测试不计为通过，未据此宣布留言安全。
- 部分旧GET写入口、前台CSRF、可配置豁免和其他Vod列表过滤/参数边界；必须沿真实前端调用迁移，不能批量改方法导致已有任务失效。
- 静态工具剩余诊断继续分类；语言重复键、动态门面等可解释候选不等于漏洞，真实缺陷不能用全局忽略掩盖。

## 部署验证的边界

所有写入测试使用临时目录、专用测试库或容器内假站点；未使用生产商户 Token、真实支付回调、云存储账号或百度配额。第三方传输的失败契约已测试，真实账号可用性仍需部署配置验证。

当前仓库扫描不能证明曾感染的服务器已经清理。部署残留、计划任务、系统服务、数据库中的脚本/跳转字段、管理员状态、代理信任、备份恢复以及历史 MyISAM 表，需要在受控部署副本核验；不能通过检出几个字符串或删除可疑文件宣布“无毒”。配置检查现在不会自动销毁这些证据。

文件路径防护不能替代工作进程与代码目录的权限隔离。真实生产发布前仍需核查新旧表结构、启用的扩展/主题、密钥管理、备份恢复和服务故障行为。上述是当前证据的缺口，不是已完成的上线验收。
