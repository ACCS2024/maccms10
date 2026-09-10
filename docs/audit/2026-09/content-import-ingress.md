# 内容导入接收及结果（I1b）

日期：2026-09-11。基于 `7778576e` 的已提交行准备及源行坐标；原始上传/返回故障证据冻结于 `3962133e`。本批接通 Art、Manga、Vod 的现有导入动作，不扩展至配置、采集或播放器导入。

旧入口调用实际 TP8 UploadedFile 不存在的 rule、validate、getInfo，抛出 Error；三个 importData 动作又丢弃 base_import 的返回值，成功和失败均变成 null。证明脚本和双 PHP 观察见 `/tmp/maccms-audit-20260910/import-followups/upload-proof.php`、`upload-{83,84}.log`。

现在只接受 POST 和现有 Token 校验，显式绑定当前 Request；通用动作限定 art/manga/vod。ImportUpload 要求单个有效 UploadedFile、普通非符号链接临时文件、受限原始文件名和 csv/txt/xlsx 扩展名，实际文件上限 20 MiB。只读取 PHP 管理的临时上传，依照现有解析器继续限制展开内容；没有以用户文件名生成站点文件，没有主动删除任意来源路径。MIME 标签不作为内容可信依据。

保存前在当前 writer 查询实际列信息并核对必需列，不以查询 master 选项误认为 getTableFields 的另一条元数据查询也强制使用主库。保留每行新模型的调用方式。明确的准备失败及模型 1001/1002 响应计为失败，继续其它行；错误消息仅使用受控语言项和源行号，最多列出 15 条。模型返回 1 的行计为已保存。视频保留完整目录标记失效，并传播目录待更新状态；后续缓存异常不会把已确认的保存伪装成未保存。

saveData 抛出 Throwable 或返回不符合既定合同的值时，立即停止后续行，不重试当前行。结果区分 saved、failed、unknown、unprocessed，并提供 unknown_row、status、repeat_index_pending 和受限 errors。结果不明使用失败响应，同时说明此前已保存数量，要求核对该行和已有记录，避免整份文件重导。诊断只记录模块、源行号和异常类，日志故障不替换原响应。三个实际动作返回 JSON；非 Ajax 继续通过既有 HTML 跳转响应显示结果。九种语言补齐结果不明及目录待更新提示。

PHP 8.3.33 / 8.4.25 各验证：

- 改动的 18 个 PHP 文件在 E_ALL 下编译通过；真实 TP8 上传对象与本机 multipart HTTP 共 36 项，包括 PHP 实际临时上传所有权、大小、扩展名、上传失败、数组及单文件形状。
- Art、Manga 的实际控制器各增加 81 项，分别在 SQLite 和安装 MySQL 通过；Vod 的实际控制器在安装 MySQL 增加 85 项。Token 使用真实 Request/Session，普通 CSV/TXT/XLSX、空正文、新建、部分成功、原始行号、全部失败、受限错误条数及 JSON/HTML 返回均经实际模型和数据库验证。
- 模型边界分别注入普通保存前、保存后异常及异常返回值；数据库观察确认保存后异常确有已写入记录，随后行未进入 saveData。另验证已保存视频的目录缺失和最终缓存异常。这里的故障是模型边界隔离注入，不宣称覆盖所有数据库网络故障。
- 前置模型回归继续通过：Art 191 SQLite / 三种 MySQL 模式合计 573 项；Manga 158 / 474 项；Vod 三种 MySQL 模式合计 507 项。原批量表单 29 项继续通过。

持续测试：`tests/framework_audit_import_upload.php`、`tests/fixtures/import_upload_http.php`、`tests/framework_audit_content_import.php art|manga|vod`。Vod 用 FRAMEWORK_AUDIT_MYSQL=1 和独立审计库运行；Art/Manga 默认为 SQLite。使用原 saveData 全量夹具作为前置检查，各自 MySQL 库互相独立。

`ingress-check1.log` 首次失败来自 CLI 夹具直接 new Request 未经过框架工厂，PUT 容器尚未初始化；改用实际 __make 初始化。check2 全部通过后，补充最终目录缓存故障及保持每行新模型的行为，check3 重新完整验证。上述日志及验证树位于 `/tmp/maccms-audit-20260910/import-followups/`。

边界：测试隔离后台构造器身份校验，未宣称完整登录中间件或完整浏览器上传流程通过；真实 multipart 与实际动作/模型两层分别覆盖。行模型返回 1 仍是本批计数依据，旧模型对已删除 ID 的零影响行、非严格数据库截断、分类当前值和写后其它副作用另需验证。没有引入整份文件事务，没有自动结束调用方事务；普通后台请求之外的事务内调用、持久导入任务 ID、跨请求核对及行原子性仍待设计。重复表头、未命名非空列、超出表头的列和短行造成的数据歧义列为 I1c；本批接收修复不代表这些内容合同已完成。
