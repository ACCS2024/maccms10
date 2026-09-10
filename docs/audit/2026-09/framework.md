# PHP 8.3 / 8.4 框架、模型与运行边界

本报告对应当前代码的分批修复，取代早期临时合并测试报告。维护下限为 PHP 8.3，主要运行版本为 PHP 8.4。实际验证版本为 8.3.33 / 8.4.25；数据库动态检查使用 SQLite 和隔离的 MySQL 8.0。没有审查 Git 历史，也没有修改用户原有的 `migration/lbjx9/index.php`。

## 方法与覆盖

先枚举当前 PHP、扩展、脚本和入口，再用原生编译、锁定版本的 PHPStan/PHPCompatibility 筛候选，沿实际调用复现。修复不是统一压制 Warning：E_ALL 下的语法、类型、字段缺省、框架 API、查询语义、事务失败和真实响应分别验证。默认运行模式保留现有日志兼容策略，CI 显式开启严格诊断。

每个提交只暂存该组文件或修改块，从暂存内容导出独立目录验证；依赖另以只读目录挂载。运行器不会借用同工作区其他尚未提交的修复。模型大多不启动应用，HTTP 使用单独的无生产配置副本；这些层次的限制在各脚本头部说明。

## 已处理的根因

| 类别 | 实际问题与处置 | 持续验证入口 |
| --- | --- | --- |
| 原生 PHP 兼容 | 方法签名、接口返回类型、隐式 nullable、动态属性和废弃调用按实际运行边界修复；维护中源码扫描遇额外诊断即失败 | `php_lint.php`；`core_audit_helpers.php` |
| ORM 行结果 | `toArray()` 后又调用行对象方法，非空列表崩溃；保留数组、分页与 transform | `framework_audit_lists.php` |
| 查询条件 | TP5 关联数组条件、tuple 键删除与 AND/OR 混用造成错误行集；修正实际条件结构并比较结果 | `framework_audit_queries.php`、`security_audit_user_log_delete.php` |
| 请求注入 | 旧 Request 参数类型/获取方式与 TP8 实际对象不符；控制器使用真实 `think\Request` | `framework_audit_request_injection.php` |
| 验证器 | 字符串调用短名误走 TP8 rule API、场景缺失、constructor 自定义选项丢失；恢复实际规则与选项 | `framework_audit_api_runtime.php`、`framework_audit_api_validation.php`、`validator_audit_chatroom_danmaku.php` |
| 参数缺省 | API 排序/页码、会员只读列表、后台非空用户模板和扩展列表因缺键/错类型失败 | `framework_audit_api_defaults.php`、`framework_audit_user_lists.php`、`extensions_audit_discovery.php`；后台 HTTP |
| 姓名关联 | Ulog 错误全用户查询与 999 截断；当前页只读取所需账号 ID/姓名，删除账号受控处理 | `framework_audit_ulog_users.php`；[分项报告](ulog-user-lookup.md) |
| 分类导航 | ORM Collection、JSON children、自定义表前缀处理不一致 | `framework_audit_type_navigation.php`；[分项报告](type-navigation.md) |
| 路由与模板 | actor/topic detail 被更短规则截获；旧 Ulog 页面无模板造成 500；会员订单返回 API 路径 | `framework_audit_detail_routes.php`、`framework_audit_ulog_template.php`、`security_audit_member_order_url.php` |
| 采集 | 失去继承的方法仍被调用、分页返回值丢失、website 误用 actor 分支、pending 集合缩小时 offset 跳过数据 | `framework_audit_collection_nodes.php`、`framework_audit_collection_paging.php`、`run_collection_audit.py`；[分项报告](collection.md) |
| 接收边界 | 缺失/数组密码、数组字段和未知分类在采集前崩溃；映射换行解析错误 | `framework_audit_receive.php`；[分项报告](receive-boundary.md) |
| 请求过滤 | 只改 superglobal 不改变 TP8 已捕获/合并的数据；更新真实 Request 并刷新参数缓存 | `framework_audit_request_security.php`；[分项报告](request-security.md) |
| 安装与命令 | 配置写入非原子、失败后残留，CLI 错误处理再次致命/退出码错误 | `framework_audit_install.php`、`framework_audit_cli_failures.php` |
| 并发计数 | Redis 点击计数领取/确认/恢复、MySQL 失败及重复刷入边界 | `run_hits_buffer_audit.py`；[分项报告](hits-buffer.md) |
| 扩展协议 | OAuth token/profile 类型、QR 核心及 HTTP 输出、上传结果结构、七牛文件名和文件句柄、百度响应统计/TLS | `extensions_audit_*`、`security_audit_oauth_profiles.php`；各扩展分项报告 |

资金事务与安全问题的分类见 [安全报告](security.md)，避免把同一缺陷按工具条数重复计算。

## 静态候选归类

审计工具、完整扫描范围和版本由 [tools/audit](../../../tools/audit/README.md) 的配置/锁文件保存。PHPStan 当前为 level 1，无 baseline/ignoreErrors；它不能代替更深的类型验证或实际执行。

固定提交 `a6de166` 的阶段扫描产生 1027 条候选（原生维护范围696个PHP文件，两版均无诊断），修复仍在继续，不能把这个中间计数当作最终状态或漏洞数量。主要类别如下：

- 643 条语言包重复键：PHP 取最后一项；需按最终文案核对。没有为了归零机械改翻译。
- 多数未定义变量来自被 include 的数据库迁移片段：`$pre/$sql` 由调用方提供。另有控制流分析未识别的互斥分支；逐条追踪定义，不能统一忽略该类别。
- `Db::query/execute` 等动态门面、ORM 字段属性、初始化后的 MAC 常量产生静态候选。以锁定依赖的真实转发与执行结果判定，不把不存在的方法警告一律归为框架问题。
- 真实缺陷包括已修复的 Qiniu 参数错位、Baidufast 未定义属性、查询 tuple 键处理和模型结果类型；这些候选需要行为回归才能关闭。
- 受保护的迁移脚本存在变量候选。本轮静态扫描使用HEAD快照，不能代替对用户未提交版本的独立审阅；用户工作区文件没有修改或纳入提交。

PHPCompatibility 的规则集为 alpha 版本。同一固定快照为0错误、8警告：7个构造函数终止请求提示及1个混合换行提示；这些是人工审查项，不能仅靠禁用规则宣称兼容。阶段原始报告在执行环境 `/tmp/maccms-audit-20260910/`，可用仓库工具重新生成。

## 运行与边界

实际命令、数据库隔离规则、固定测试种子及 CI 工作流见 [tests/README.md](../../../tests/README.md)。`run_audit.php` 是维护中的显式清单；早期临时的 `framework_audit_models.php`、`framework_audit_failures.php` 已拆成独立测试，不能再用旧文件名复验。

本地已跑过两版 PHP 的原生编译、独立回归、SQLite/MySQL、普通用户安装文件权限与真实 MySQL Web/CLI 安装，及 19 条前台/API、32 个登录后后台页面和 5 项持久化写入情景。HTTP 种子包含真实非空用户/内容；错误状态、错误正文和空 action 不算通过。生产 Dockerfile 的两版构建与 Redis/MySQL 并发、采集回归也已执行。远程 GitHub Actions 尚未运行。

Receive→Collect七模块最小入库137项、生产Apache边界201项及会员账变留存37项真实HTTP检查已分组完成。后台备份编解码、完整产物发布和CLI导出亦分别有独立MySQL验证；CLI恢复、其他积分来源与账号资料/改密继续扩查。完整覆盖所有路由输入组合、第三方账号、主题插件、历史数据库结构、长时压力与故障演练尚无证据。阶段回归通过不等于这些范围已经完成。

## 范围扩大后的新发现

工作区 `--all` 盘点覆盖5456个PHP文件（包含当前vendor、审计工具依赖及未跟踪旧框架归档；该盘点在持续修复期间进行，不是最终冻结版本）。8.3有7个、8.4有17个诊断文件：旧框架归档分别5/15个，当前 `topthink/think-image` GIF Decoder/Encoder各2个，后者是仍在实际图片处理调用链上的PHP8语法错误，已列为优先修复。依赖安装成功不代表每个延迟加载文件能编译。

沿Collection候选继续追踪发现首页视频四列表把Collection传入数组引用helper；已单独修复结果数组化及配置表前缀，并以非空/空行集验证。`MeilisearchSync` 的空Collection判断本身冗余，但循环末尾还有count退出条件，不能仅据empty诊断断言无限循环。Chatroom/Danmaku的相似空判断包裹foreach，空集合不执行循环体；缓存业务正确性仍需独立检验。

完整静态分组计数与闭环规则见 [候选分类](static-candidate-triage.md)。
