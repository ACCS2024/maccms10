# 测试 / CI

项目此前无自动化测试与 CI。这里提供一套**轻量但实用**的兜底,优先抓"改动把站点改崩"这类低级错误(历史上多次出现的语法/SQL 错误)。

## 本地
```bash
bash tests/lint.sh      # 对 application/ 与入口文件做 php -l 语法检查
```

## CI(`.github/workflows/ci.yml`,push / PR 自动跑)
- **php-lint**:PHP 7.4 下 `php -l` 全量扫 `application/` 与入口文件 —— 拦截解析错误。
- **schema-load**:把 `application/install/sql/install.sql` + `initdata.sql` 灌入 MySQL 5.7,
  断言全部表为 InnoDB —— 拦截 SQL 语法错误,并守护"默认引擎 = InnoDB"不被改回 MyISAM。

> 说明:仓库框架为 ThinkPHP 5.0.24(已 EOL、非 PHP8-clean),故 lint 固定在 **PHP 7.4**(线上目标版本),
> 且只扫 `application/`(业务代码),不扫 `thinkphp/` 等第三方目录。后续若引入单元测试框架,可在此目录扩展。
