# 可复现的当前代码静态检查

运行 PHP 8.3/8.4；生产依赖仍由仓库根 composer.lock 管理。本目录只放开发审计工具，独立锁定 PHPStan 2.2.13、PHPCompatibility 10.0.0-alpha2、PHP_CodeSniffer 4.0.4 和配套工具，不加载应用入口或本地站点配置。

```sh
composer --working-dir=tools/audit install --no-plugins --no-scripts --no-interaction
python3 tools/audit/run.py --output=/tmp/maccms-static-report
```

从仓库任意工作目录均可调用运行器。默认使用 PATH 中的 php，可通过 PHP_BINARY 指定解释器。输出包含两份原始 JSON、stderr 和 summary.json。返回 0 表示工具无诊断，1 表示完成扫描且有待分类诊断，2 表示未能完成；不会因内存不足或空扫描给出通过结果。每个分析器限时 600 秒、最大 PHP 内存 2 GB。

PHPStan level 1 扫描业务、框架适配层、扩展、配置、入口、CLI、部署及迁移脚本；引导仅加载 Composer 自动加载器，补充扫描当前框架 helper 定义。内嵌 Upyun vendor 由独立 Composer 审计、原生 lint 和真实传输回归负责。PHPCompatibility 指定 8.3–8.4，规则集为 alpha 版本，结果必须结合原生解释器和实际调用核实。

PHPStan 无 baseline/ignoreErrors。`think-facades.stub` 声明锁定 ORM 经 DbManager 转发的 query/execute 原生参数与返回合同；不会为任意未知方法放行。`runtime-constants.php` 仅通过 scanFiles 读取，不执行；常量类型对应维护中的前台入口、AppInit 与 User OAuth 初始化，dynamicConstantNames 避免代表值把条件分支误判为常量。没有经过这些初始化的独立入口仍需单独验证。AiTask 的属性声明对应已测试的实际 ORM 列。依赖、入口或表结构升级后应重新校准这些声明。

`ENTRANCE` 的动态类型同时包含 index、admin、api、install，对应四个维护中的 HTTP 入口；`think` CLI 使用 install。分析多个入口时不能把首先扫描到的 index 当作整个应用的常量值，否则后台/API 分支可能被错误裁剪。该声明只调整分析范围，不执行入口，不保证任意独立脚本已完成应用初始化。

其余动态调用、控制流和语言键覆盖继续保留诊断并逐项分类。声明已存在的运行时合同不等于修复漏洞，不能把诊断条数直接作为漏洞数，也不能仅为归零而改变业务行为。

全量原生编译和独立行为回归见 `tests/README.md`。临时报告可能包含本地文件路径和诊断内容，分享前检查；不要提交站点配置、凭据、数据库导出或运行日志。

语言键可独立执行 `php tools/audit/language_keys.php > /tmp/language-keys.json`。只读 token 分析平面字面量数组，不执行语言文件；支持默认九个全局语言包或命令行明确列出的文件。报告区分同值重复与不同文案覆盖，记录最终值和键顺序的哈希。返回 0/1/2 分别为无重复、存在重复、未完成；不会自动删除键。
