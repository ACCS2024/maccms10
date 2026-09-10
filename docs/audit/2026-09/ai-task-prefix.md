# AI 插件任务表前缀与 ORM 配置

当前安装和卸载直接使用 `mac_ai_task`。锁定的 Think ORM 4 已不再读取该模型旧的 `$table/$pk/$autoWriteTimestamp` 保护属性，模型实际上按类名与当前连接前缀查询。自定义前缀下，这会造成安装在默认表、模型找不到对应表；卸载还可能删除同库默认前缀站点的任务历史。

本组将模型声明改为 ORM 4 支持的 `getOptions()`，明确逻辑表 `ai_task`、主键 `id` 和手动时间戳；安装与卸载统一使用同一逻辑表名、当前连接解析出的前缀，并严格校验后再引用表标识。表尚未创建时不实例化模型，避免提前查询并缓存不存在的 schema。仓库安装 SQL 是单条 DDL，完整提交执行；丢失或不符合预期的 schema 文件明确失败，不能返回安装成功。

默认 `mac_` 站点的目标不变。自定义前缀站点不会自动重命名、迁移或删除旧 `mac_ai_task`，因为它可能属于另一个站点。已有历史的归属与迁移必须先单独确认，部署前应核对实际任务表；本组没有访问或迁移生产数据。静态资源部署/移除与数据库 DDL 仍非一个事务，文件生命周期、任务状态转换和分页上限仍是后续独立检查。

新增真实 ORM/插件安装卸载专项，分别运行默认和自定义前缀。MySQL 使用仓库原始安装 DDL；SQLite 使用同字段派生 DDL。另建带保留哨兵的其他前缀表，证明安装、创建、完成、失败、查询、重复安装及卸载均未改变其内容；验证当前表最终确实删除。零数据历史和实际分页保持数组格式，错误文案仍受 Unicode 长度限制。

```sh
php tests/framework_audit_ai_task.php
php tests/framework_audit_ai_task.php default-prefix
FRAMEWORK_AUDIT_MYSQL=1 FRAMEWORK_AUDIT_HOST=127.0.0.1 FRAMEWORK_AUDIT_PASSWORD=fixture-password \
  php tests/framework_audit_ai_task.php
```

固定测试库为 `maccms_audit_models`，只替换本专项的 `mac_ai_task`、`audit_ai_ai_task` 两表。每种前缀 16 项，PHP 8.3/8.4、SQLite/MySQL 共八次专项执行；另复核既有插件路由/权限/模板回归。CI models 清单包含两种前缀。

PHPStan 原有八条 AiTask 动态属性候选在此通过真实字段读写核对：status、result、error_msg、updated_at 都存在于安装 DDL，并能由锁定 ORM 完整持久化。没有通过添加同名 PHP 公共属性掩盖工具诊断，那会与 ORM 的属性访问机制混淆。
