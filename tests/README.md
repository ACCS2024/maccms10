# 测试 / CI

项目此前无自动化测试与 CI。这里提供一套**轻量但实用**的兜底,优先抓"改动把站点改崩"这类低级错误。

## 本地
```bash
bash tests/lint.sh      # 对 application/ 与入口文件做 php -l 语法检查（需 PHP 8.2+）
```

## CI(`.github/workflows/ci.yml`,push / PR 自动跑)
- **php-lint**:PHP 8.2 下 `php -l` 全量扫 `application/` 与入口文件 —— 拦截解析错误。
- **schema-load**:把 `application/install/sql/install.sql` + `initdata.sql` 灌入 MySQL 5.7,
  断言全部表为 InnoDB —— 拦截 SQL 语法错误,并守护"默认引擎 = InnoDB"不被改回 MyISAM。
- **shellcheck**:检查 `deploy/` 和 `tests/` 下的 shell 脚本。

> 说明:仓库框架为 ThinkPHP 8.1（已从 TP5 迁移），PHP 支持范围 8.2（Debian 12 默认）～ 8.4/8.5，
> lint 固定在 **PHP 8.2**（最低支持版本），只扫 `application/`（业务代码）。
> 后续若引入单元测试框架，可在此目录扩展。
