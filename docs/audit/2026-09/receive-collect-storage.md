# Receive 到 Collect 的真实入库边界

`Receive` 的字段校验通过不等于采集成功。用真实 Request、七个 Receive 动作、Collect、ThinkORM 和当前安装 SQL 的 MySQL 表复现后，七个最小合法请求分别在 `vod_year`、`art_lock`、`actor_lock`、`website_lock`、`manga_pic`、`role_lock`、`comment_up` 的缺省读取处失败。

本组修复 `application/common/model/Collect.php`：

- 为可选字段和缺失模块配置补明确默认值，补齐严格 MySQL 下无数据库默认值的可选正文/标题等字段；视频接收所用空操作参数明确默认值。
- 七个模块在新增前按实际表字段筛选数据，保留 SQL 严格检查；关联名称、第三方元数据、漫画旧字段别名等不再成为未知 SQL 列，包含点号的来源键也不会被当成限定列名。
- 角色与视频评论支持协议已有的仅 `douban_id` 关联。关联编号要求正整数；不存在的显式关联 ID 受控失败。评论仅支持内容模块 1/2/3/8/9/11/12，补充漫画名称关联；豆瓣编号单独用于非视频评论时拒绝。
- 评论判重同时约束模块与关联 ID，避免不同内容表具有相同 ID 时发生跨模块判重。
- 记录源请求实际提供的字段。最小重复请求不清空已有正文或封面、不将已完结视频重置为未完结；明确提交空封面或 `vod_isend=0` 仍遵循原更新规则。
- 视频安全检查拒绝单条接收时立即返回原参数错误，不再落入需要分页元数据的批量处理末尾。既有安全检查条件保持不变。
- 多播放/下载组缺少可选 server/note 时按组补空值；漫画接受旧 `manga_play_*` 别名与当前 `manga_chapter_*` 字段。两套同时提交时保留旧别名优先的规则，不把当前章节值用缺省空字符串覆盖。

验证入口：`python3 tests/run_receive_collect_audit.py`，也可在命令后指定待测 Docker 镜像。它启动随机名称、随机数据库/密码的 MySQL 8.0，MySQL 和 PHP 容器均使用 `--network none`，通过临时 Unix socket 通信。测试仅接受 `maccms_audit_receive_<随机十六进制>` 数据库名，使用当前 `application/install/sql/install.sql` 创建所需真实表，启用 `STRICT_TRANS_TABLES` 和 ThinkORM 严格字段检查，完成后移除临时数据库容器和文件。

PHP 8.3.33 / 8.4.25 各 137 项断言通过，包含七动作最小入库及发布状态、真实字段值、可选正文/元数据、多组播放和下载 URL、两种漫画章节字段、豆瓣关联、所有支持评论模块、无效关联不写入、跨模块判重以及最小重复请求的字段保留。既有 `framework_audit_collection_paging.php` 在两版各 21 项断言通过。

此项省略 Receive 的站点视图/用户初始化与认证构造，认证及结构化请求边界由 `framework_audit_receive.php` 单独验证。分类目录为隔离缓存夹具；业务模型、数据库结构和 SQL 写入均为真实实现。公开示例配置关闭图片下载和搜索同步，媒体 URL 仅存储、不请求外部服务。本组不覆盖所有第三方资源协议、所有可选数值字段的数据库上限、远程图片处理或生产库旧表迁移，也不据此宣称整个 Collect 已完成全面安全认证。
