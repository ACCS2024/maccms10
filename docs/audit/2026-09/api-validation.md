# API 参数校验迁移审计（2026-09-10）

实际 Composer 加载顺序使 `validate()` 来自 `vendor/topthink/think-validate/src/helper.php`，早于 framework 同名 helper。该实现对 `validate('Vod')` 只做 `class_exists('Vod')`；短名不存在时返回没有规则的 `think\Validate`，不会解析 `app\api\validate\Vod`。framework helper 因 `function_exists()` 跳过定义。因此控制器表面上执行 scene/check，实际未校验任何参数。

隔离 HTTP 复现：`api /vod/get_detail?id=1` 在严格错误模式返回 500，日志为 `Undefined array key "vod_id"`；反射所得 controller=`Vod`、action=`get_detail`、validator=`think\Validate`、rules=`[]`、sceneExists=`false`。按既有契约传 `vod_id=1` 才是详情正例；没有新增 `id` 别名。另一个独立 500 是 Art 列表直接读取缺失的可选 `orderby`。

修复采用显式 `new \app\api\validate\具体控制器名()`，与原有 Chatroom/Danmaku 控制器一致，不改 vendor，不依赖 helper 定义顺序。新实例默认 `failException=false`，保留控制器已有 `code=1001` JSON 错误分支；直接调用带完整类名的全局 helper 仍默认开启异常模式，不是等价替代。资金类接口仍先执行登录检查，再校验参数。

首批修复 Vod 详情、Art 列表后，剩余 39 处位于以下 16 个控制器：Actor、Art、Cash、Comment、Gbook、Link、Live、Manga、Order、Payment、Role、Topic、Type、User、Vod、Website；全部改用真实 API 验证器。每个调用对应的 scene 已核对，避免恢复校验后把其他动作必填字段带入当前动作。

恢复校验同时修正这些既存规则/scene 配置错误：

- User 的 `group_id` 从无效的 `number|1,500` 改为 `number|between:1,500`；列表 scene 使用控制器实际读取的 `time_start/time_end`，并加入已声明的 `orderby`。
- Website 的 `orderby` 从无效的 `in|...` 改为 `in:...`，纳入列表 scene；时间规则与 scene 对齐控制器实际读取的参数名。
- Link 列表纳入已声明的 offset/limit；Actor 列表纳入 time_start/time_end；Gbook 列表纳入 content/time_start/time_end。
- Order::create 补齐明确的 create scene 和 price 规则：正金额、最多十位整数及两位小数，对应安装表的 `DECIMAL(12,2) UNSIGNED`。在 float 转换和订单写入之前拒绝空值、负数、科学计数法、过多小数、数组及超范围金额；既有最低金额和积分比例继续由控制器应用。

测试与边界：

- `tests/framework_audit_api_runtime.php`：21 项，真实 Composer helper 负控、原两处 PHP 8 严格异常、详情参数契约与文章默认/显式排序。旧控制器挂载负控同时复现缺失 vod_id、orderby 并退出 1。
- `tests/framework_audit_api_validation.php`：148 项，真实 Container、Request、Validator、控制器及内存 SQLite。覆盖全部 41 个原短名 helper 动作的错误输入、合法 scene 参数、登录优先顺序、真实 Link 排序与 Order 最低金额/积分比例/落库。只替代用户身份和写入限流边界，不读取站点配置、不连接业务数据库。两套测试均在 PHP 8.3.33 和 8.4.25 通过。
- 专用 `maccms_audit_http` MySQL fixture、`APP_STRICT_PHP_ERRORS=true` 下，PHP 8.3/8.4 各 26 个 HTTP 用例通过：9 个带种子内容或成功码的公共列表/详情正例，17 个缺失详情 ID、非法排序/分页/类型的拒绝路径。错误输入确认 HTTP 200 且 JSON code=1001，不以错误页 200 充数。
- Constructor 参数兼容单独由 Chatroom/Danmaku 四验证器批次及 `tests/validator_audit_chatroom_danmaku.php` 覆盖。

另行跟进，不混入上述根因：若干列表仍裸读取可选 orderby，Manga 列表裸读取 page；Order 积分字段是 `MEDIUMINT UNSIGNED`，金额满足 DECIMAL 范围不代表乘积分比例后不会溢出；前台 actor/topic 首页路由会截获详情路由，须分别复现和修复。

前台精确证据：`/vod/type/id/6.html` 输出 data-type-id=6，默认模板确实通过 JavaScript 获取列表；`/actor/detail/id/1.html`、`/actordetail-1.html` 实际分派 Actor::index，输出“演员首页”、aid=80，缺少详情 data-detail-id。`/topic/detail/id/1.html`、`/topicdetail-1.html` 实际分派 Topic::index。Actor API 生成的链接为 `/actor/detail.html?id=1`。因此不能把首页正文当作详情正例；后续路由批次应断言真实 action、参数及详情模板 ID。
