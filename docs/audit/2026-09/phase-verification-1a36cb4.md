# 阶段验证：1a36cb4

这是本地已执行的验证记录，范围固定在提交 `1a36cb4` 及其锁文件安装出的依赖。后续提交仍需各自验证；该记录不代表整项审计完成或生产可直接上线。

## 验证结果

| 检查 | PHP 8.3.33 | PHP 8.4.25 | 范围 |
| --- | --- | --- | --- |
| 原生编译，包含已安装依赖 | 5,244 文件，0 诊断 | 5,244 文件，0 诊断 | `php -n`、E_ALL，拒绝解析错误及弃用等额外输出 |
| 独立回归 `run_audit.php` | 97 进程，0 失败 | 97 进程，0 失败 | unit、models、financial；数据库默认 SQLite |
| 安装文件系统检查 | 22 项 | 22 项 | 以普通系统用户验证拒绝写入等边界 |
| 真实 MySQL 安装 | 41 项 | 41 项 | 专用安装库，普通系统用户 |
| 正式镜像图片处理 | 111 项 | 111 项 | GD/Imagick、动画、缩略、水印及文件失败 |
| 正式镜像上传/下载调用 | 38 项 | 38 项 | 真实 TP8 文件 API，外部传输和元数据持久化为 fixture |
| 正式镜像 Apache 边界 | 201 项 | 201 项 | 隔离假站点及实际 TP8 请求；不读取仓库秘密文件 |

原生编译的 5,244 文件来自**提交快照加锁定依赖**，不是在持续编辑的工作区上取样。它不包含工作区未跟踪的旧框架归档、生产运行文件或用户未提交修改；早前对整个工作区的扫描仍在旧归档中发现语法问题，不能把本次结果套用到那些文件。

这轮完整 97 进程回归已覆盖之前发现并修复的 Order GET/POST 测试契约问题。它不包含后来新增的绑定、API Collection、奖励凭证留存等组；这些使用独立冻结快照继续验证。MySQL 账务和消息组此前逐批执行的结果见各专项报告，这张表中的 97 进程不能替代它们。

## 可重复的检查

使用该提交的全新检出目录，根据锁文件安装依赖。PHP 需要 GD、Imagick 3.8.1 及 Composer 声明的其他扩展，SQLite 行为回归另需 pdo_sqlite。

```sh
composer install --no-dev --no-plugins --no-scripts --no-interaction
composer check-platform-reqs --no-dev
php tests/php_lint.php --all --json=/tmp/installed-php-lint.json
php tests/run_audit.php
```

安装、MySQL 专用数据库和完整 HTTP 测试的准备顺序见 [测试说明](../../../tests/README.md) 与 [CI 工作流](../../../.github/workflows/ci.yml)。容器集成使用 `docker/Dockerfile` 构建的实际 PHP 8.3/8.4 镜像；普通 CLI 测试镜像另装 pdo_sqlite。

原始日志保存在本地执行环境：`installed-tree-1a36cb4-php83.json`、`installed-tree-1a36cb4-php84.json`、`image-staged-full-83.log`、`image-staged-full-84.log` 和 `image-committed-server-matrix.log`，目录均为 `/tmp/maccms-audit-20260910/`。这是临时执行证据；可重复脚本、锁文件及覆盖边界已入仓库。GitHub 的远程 CI 尚未由本轮本地执行触发。

## 依赖安装与仍待处理的范围

工作区 `vendor` 已切换到新锁对应的干净依赖；旧目录完整保存在 `/tmp/maccms-audit-20260910/vendor-before-image-1a36cb4`。切换后平台要求检查通过。没有手工修补 vendor，也没有执行部署、推送或生产数据库迁移。

安全审计仍在继续。已发现而未在本快照处理的内容访问控制、资料绑定旁路、注册/邀请事务、奖励凭证留存等问题必须跟随专项提交闭合。静态分析候选仍需分类；源码编译通过不证明权限、账务或异常路径正确。留言模块原始动态复现受工具自动审核阻止，本轮只做静态修复与普通流程回归，不能声称该动态安全覆盖已经完成。
