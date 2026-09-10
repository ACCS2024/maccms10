# 自定义采集工具与后台必要调用边界

## 当前引用与范围

`application/admin/controller/Cj.php` 导入 `app\common\util\Collection as cjOper`，在 `col_url`、`col_content` 和 `show_url` 中实际调用三个公开方法。因此保留并修复该工具，不能按未使用文件退役。本组仅覆盖采集工具及这三个后台动作的必要边界；没有修改数据库结构、节点保存、发布映射和其他采集器。

独立的旧 `Download` 类没有当前调用，退役理由另见 `retired-download.md`。两组可以分别提交。

## 已确认根因与处理

- 初始化可选配置和结果；保留标题、分类、自定义字段、正文以及时间字段。自定义字段 JSON 只在入口解析，分页递归使用规范化数组，不再将数组传给 `json_decode`。非法配置、截取标记缺失、正则错误、转码失败和请求失败返回 `false`，不产生未定义变量、数组偏移或 PHP 8 类型错误。
- 每次采集使用独立的已访问 URL 集合，消除连续调用相互污染；修正全部分页模式对已扁平化数组的错误访问，去重循环链接。单条内容最多抓取 100 页，超过上限返回失败，避免返回被截断的成功正文。子页抓取失败同样返回失败。
- 图片回调使用当前命名空间中的闭包；在每一页合并前解析该页的图片地址，保留 SVG 片段。URL 解析复用根项目已经声明和锁定的 `guzzlehttp/psr7`，处理端口、父目录、查询串和协议相对地址。采集链接仅保留 HTTP(S)，实际请求继续走项目既有 `mac_curl_get` / `PublicHttpClient` 的公共网络限制。
- RSS 使用项目现有 `mac_xml2array`，移除不存在的 PHPCMS `pc_base` 和 `array_iconv` 依赖。覆盖单条/多条 item、CDATA、有效空列表；无效 XML、非 RSS 结构、DTD 和外部实体声明受控失败。输出统一 UTF-8，不恢复旧站点 GBK 全局配置依赖。
- 序列网址要求有效整数、正步长、非倒序范围；最多生成 10,000 个网址。无效配置返回空列表供后台错误路径使用，避免零/负步长不终止和整数溢出。多网址支持 CRLF、LF、CR，并去掉空行。
- `Cj::col_url` 在 `count` 前处理失败，校验节点及页面索引；失败时不更新采集完成时间。`show_url` 校验嵌套输入和序列配置。
- `Cj::col_content` 将真实 ThinkPHP 8 查询集合转为数组，按 ID 顺序每次读取前 20 条待采集记录。记录成功后变成状态 2，因此继续使用偏移分页会跳过记录；现在每批从剩余待采集记录开始。抓取或 JSON 编码失败保持原行待采集状态，不写入 JSON `false`、不报告该条成功、不更新节点完成时间。

## 验证

仓库只读挂载，关闭 Docker 网络；远程 HTML 使用固定函数级传输替身，真实执行采集、编码、URL 解析和 XML 解析。后台回归执行真实控制器、真实 `Cj` 模型、ThinkPHP 8 集合及 MySQL 8。仅跳过后台登录初始化和模板渲染，捕获页面提示及跳转；没有伪造数据库查询结果。

```sh
docker run --rm --network none -v "$PWD:/app:ro" -w /tmp --entrypoint php maccms10-migration-check:latest /app/tests/extensions_audit_collection.php
docker run --rm --network none -v "$PWD:/app:ro" -w /tmp --entrypoint php maccms-audit-php84:20260910 /app/tests/extensions_audit_collection.php
python3 tests/run_collection_audit.py
```

- 工具回归：PHP 8.3.33 / 8.4.25 各 44 项，包含两种内容分页、跨调用去重隔离、100 页预算、子页失败、规则/正则错误、GBK、RSS/XXE 拒绝、URL 边界及整数最大值。
- 后台与 MySQL 回归：两版本各 30 项，包含真实 URL 入库、历史去重、无效预览/分页、请求失败、25 条待采集记录跨批处理、中途失败重试、不跳行、无效 UTF-8 保持待采集状态。
- 数据库回归启动独立 `mysql:8.0` 容器，只开放临时 Unix socket；使用随机 `maccms_audit_collection_*` 数据库及 `audit_` 表前缀。测试完成删除临时容器/目录，不使用现有站点或 `maccms_audit_models` 数据库。
- 目标文件 PHP 8.3 / 8.4 语法检查通过。PHPStan 中 Collection 原有 7 项诊断消除；Cj 的集合判断诊断消除，保留本组外 `program()` 中 `Db::query()` 的动态门面识别诊断，没有据此改写发布映射流程。

## 明确边界

这是当前可达采集方法的独立修复组，不代表整个 `Cj` 后台、定时任务到发布入库全过程已经完成端到端审计。未验证真实远端站点格式变化、完整后台登录/权限、节点配置保存、`col_all` 到 `content_into` 的映射和发布、并发采集去重事务。分页抓取预算是新增明确限制；需要超过 100 页或 10,000 个序列网址的节点应拆分配置。旧规则若依赖缺失标记仍被当作空字符串成功的行为，现在会收到受控错误并保留待重试记录。
