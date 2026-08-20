# PPVOD 入库接口（yzmauto）响应契约

对接方：转码机 push 侧（另仓库 `ppvod-server`）。
入口（**路由名不可更改**，转码机侧写死）：

```
POST /api.php/yzm/yzmauto?ac=yzm&pass=<interface.pass>   （历史入口）
POST /api.php/ppvod/ingest?ac=yzm&pass=<interface.pass>  （规范入口，等价）
body: 转码产出 JSON（orgfile / suffix / rpath / category / shareid / metadata …）
```

## 背景：为什么要有回执

历史实现里 yzmauto 的**每一条路径都 `return;`（HTTP 200 + 0 字节）**——插入成功、
同名跳过、分类未知、被安全闸拒绝、密码错，响应体一模一样（都是空）。于是推送侧
**无法区分成功与失败**，只能把 HTTP 200 当成功，导致「一整批标绿、本站实际一条没进、
日志上还看不出」。本契约给每条路径一个稳定的机器可读回执来根治它。

## 契约

- **HTTP 状态码一律 200**。对接方**只看响应体 `code`**，不要用 HTTP 码分流
  （保持与转码机旧版 `2xx 即成功` 的判断兼容；旧版忽略 body，故新增回执向后兼容）。
- 响应体为 JSON：`{"code":<int>, "msg":"<token>", ...额外字段}`，`Content-Type: application/json`。

| code | 含义 | 推送侧应做 |
|---|---|---|
| `1` | 内容此刻确实在本站库中且活跃（本次插入，或同名已存在且不在回收站） | 判「已送达」，**不重投** |
| `0` | 未入库 / 不可见，`msg` 给确定原因 | 据 `msg` 告警或修配置 |

### code=1 的 msg

| msg | 额外字段 | 说明 |
|---|---|---|
| `inserted` | `vod_id` | 本次新插入 |
| `duplicate` | `vod_id`, `state`(`published`/`pending`) | 同名已存在且活跃，无需重复入库 |

### code=0 的 msg

| msg | 额外字段 | 触发 | 是否该重投 |
|---|---|---|---|
| `bad_action` | — | `ac` ≠ `yzm` | 否，修请求 |
| `bad_pass` | — | `interface.pass` 不匹配 | 否，修凭证 |
| `disabled` | — | 后台未开启 PPVOD 入库 | 否，开配置 |
| `config_incomplete` | — | 播放/图床域名或分类映射缺失 | 否，补配置 |
| `config_error` | — | `maccms.collect` 采集配置缺失 | 否，补配置 |
| `empty_body` | — | 请求体为空 | 可重投 |
| `bad_json` | — | 请求体非合法 JSON | 否，修 payload |
| `blocked_keyword` | — | 命中非法词黑名单 | 否（内容策略拦截） |
| `bad_category` | `category` | 分类不在 `category_map` 映射表 | 否，**补分类映射后**再推 |
| `rejected` | `field` | 安全闸判定字段含注入特征 | 否（安全拦截） |
| `duplicate_recycled` | `vod_id`, `state`(`recycled`) | 同名记录在**回收站**——当前不可见，且会被永久静默跳过 | 否，需先到回收站彻底清除再推 |
| `db_error` | — | `Db::insert` 返回假值 | 可重投 |
| `db_exception` | — | 入库过程抛异常（详情见站点 `log/YYYY-MM-DD.txt`） | 可重投 |

## 对接建议（推送侧）

1. 收到响应后**解析 body.code**，不要只判「非空即成功」——`{"code":0,"msg":"bad_category"}`
   也是非空 JSON，但它是失败。
2. `code=1` → 标已送达；`code=0` 且 `msg ∈ {empty_body, db_error, db_exception}` → 退避重投；
   其余 `code=0` → 停投并按 `msg` 告警（多为配置/内容问题，重投无益）。
3. 空响应 / 连接错误仍按原「未确认」处理（本站若被反代拦在到达控制器之前，仍可能拿到空体）。
