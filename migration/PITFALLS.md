# TP5→TP8 迁移陷阱汇总

> 本文档记录迁移过程中发现的所有 TP5→TP8 破坏性变更，包含规模统计、修复模式和风险级别。
> 每次发现新问题时更新此文档。已修复的问题打 ✅，待修复的打 ⚠️。

---

## 已修复问题汇总

| ID | 问题 | 文件范围 | 提交 |
|----|------|---------|------|
| F1 | Base.php `$this->name` → `$this->getName()` | Base.php | 04c79e4 |
| F2 | Base.php constructor `array` → `array\|object` | Base.php | 04c79e4 |
| F3 | OpenccConverter null-check 误判 cache miss | OpenccConverter.php | 04c79e4 |
| F4 | User.php `\think\Db::` 事务调用（非 facade 路径） | User.php | 04c79e4 |
| F5 | `\think\Cache::rm()` → `Cache::delete()`（PSR-16 重命名） | Chatroom, Danmaku, VodAiCover, common.php | 5c7f987 |
| F6 | `\think\Cache::init()->handler()` → `app('cache')->store()->handler()` | Chatroom, Danmaku, common.php, Search, api/Chatroom/Danmaku | 5c7f987 |
| F7 | OpenccConverter 方法体内 7 处 `\think\Cache::` 绝对路径 | OpenccConverter.php | 5c7f987 |
| F8 | `\think\Loader` 在 TP8 已移除 → PSR-4 shim | application/common/addons/Loader.php（新建） | 5c7f987 |
| F9 | common.php `\think\Db::query/execute` 绝对路径 | common.php | 5c7f987 |
| F10 | common.php `\think\Cache::get/set/has/rm` 绝对路径 | common.php | 5c7f987 |

---

## 待修复问题

### ⚠️ F-A: TP5 数组条件语法（**CRITICAL**，全站 ~526 处）

**危险级别：Fatal / 静默错误**

TP8 的 ORM `where()` 不再支持 TP5 的数组操作符格式。

**错误模式：**
```php
// TP5 写法 — TP8 中静默失败或抛 TypeError
$where['vod_id']     = ['eq', $id];          // = 条件失效
$where['vod_status'] = ['gt', 0];            // > 条件失效
$where['vod_name']   = ['like', '%test%'];   // LIKE 失效
$where['type_id']    = ['in', [1,2,3]];      // IN 失效
$where['vod_name']   = ['like', ['%a%','%b%'], 'OR']; // 多值 OR LIKE 失效
```

**修复方式：**
```php
// 方式 1：where() 链式（推荐，清晰）
->where('vod_id', $id)                          // = (eq)
->where('vod_status', '>', 0)                   // > (gt)
->where('vod_name', 'like', '%test%')           // LIKE
->whereIn('type_id', [1,2,3])                   // IN
->whereNotIn('type_id', [1,2,3])                // NOT IN
->whereLike('vod_name', ['%a%','%b%'])          // LIKE OR (同字段多值)
->where('vod_status', '<>', 0)                  // != (neq)
->where('score', '>=', 60)                      // >= (egt)
->whereNull('deleted_at')                       // IS NULL
->whereNotNull('vod_pic')                       // IS NOT NULL
->whereBetween('vod_score', [6, 10])            // BETWEEN

// 方式 2：字段数组（仅适用 eq 情况）
->where(['vod_id' => $id, 'vod_status' => 1])  // 多个 eq 条件
```

**TP5 操作符 → TP8 完整映射表：**

| TP5 | TP8 |
|-----|-----|
| `['eq', $v]` | `->where('f', $v)` 或直接 `['f' => $v]` |
| `['neq', $v]` | `->where('f', '<>', $v)` |
| `['gt', $v]` | `->where('f', '>', $v)` |
| `['egt', $v]` | `->where('f', '>=', $v)` |
| `['lt', $v]` | `->where('f', '<', $v)` |
| `['elt', $v]` | `->where('f', '<=', $v)` |
| `['like', '%v%']` | `->where('f', 'like', '%v%')` |
| `['notlike', '%v%']` | `->where('f', 'not like', '%v%')` |
| `['in', [1,2]]` | `->whereIn('f', [1,2])` |
| `['notin', [1,2]]` | `->whereNotIn('f', [1,2])` |
| `['between', [$a,$b]]` | `->whereBetween('f', [$a,$b])` |
| `['notbetween', [$a,$b]]` | `->whereNotBetween('f', [$a,$b])` |
| `['null', '']` | `->whereNull('f')` |
| `['notnull', '']` | `->whereNotNull('f')` |
| `['exp', 'expr']` | `->whereRaw('f expr')` |
| `['like', [$a,$b], 'OR']` | `->whereLike('f', [$a,$b])` |

**TP5 多字段 OR LIKE 语法（已完全移除）：**
```php
// TP5 中合法，TP8 中 BROKEN
$where['field1|field2'] = ['like', '%val%'];        // 多字段 OR
$where['field1&field2'] = ['eq', $v];               // 多字段 AND
$where['col'] = ['like', ['%a%','%b%'], 'OR'];      // 同字段多值 OR
```
TP8 替代：
```php
// 多字段 OR LIKE — 用 closure
->where(function($q) use ($val) {
    $q->whereLike('field1', '%' . $val . '%')
      ->whereOrLike('field2', '%' . $val . '%');
})

// 同字段多值 OR LIKE — TP8 支持数组
->whereLike('field', ['%a%', '%b%'])   // 等同于 field LIKE '%a%' OR field LIKE '%b%'
```

**规模统计（待修复）：**

| 目录 | 大约行数 | 任务 |
|------|---------|------|
| `application/common/model/` | ~306 | P1-08（新增） |
| `application/admin/controller/` | ~346 | P3-06（新增） |
| `application/api/controller/` | ~132 | P2-06（新增） |
| `application/index/controller/` | ~28 | P4-01 范围内 |
| `application/common.php` | ~22 | P1-08 范围内 |
| `application/common/util/` | ~88 | P1-08 范围内 |
| **合计** | **~922** | |

**最高风险文件：**
- `application/common/model/Vod.php` — 42 处
- `application/common/model/Website.php` — 30 处
- `application/admin/controller/Vod.php` — 51 处
- `application/api/controller/Provide.php` — 22 处
- `application/api/controller/Vod.php` — 21 处

---

### ⚠️ F-B: `mac_search_wd_like()` 返回 TP5 格式（**CRITICAL**，12 处调用）

**文件：** `application/common.php:2244`（函数定义）

**问题：** 函数返回 `['like', '%wd%']` 或 `['like', [$p1,$p2], 'OR']`，
被 admin/controller 11 个文件以 `$where['field'] = $like` 方式消费。
两种返回格式在 TP8 ORM 中均无效。

**调用方（11 处）：**
`admin/controller/{Website, Art, Actor, Manga, Topic, Role, Vod}.php`

**修复策略：**

**选项 A — 修改函数返回格式（推荐）：**
```php
// 将函数改为返回适合 TP8 ->where() 的 closure
function mac_search_wd_like_for(string $wd, string|array $fields): ?\Closure
{
    $patterns = \app\common\util\OpenccConverter::likePatterns($wd);
    if (empty($patterns)) $patterns = ['%' . $wd . '%'];
    $fields = is_string($fields) ? explode('|', $fields) : $fields;

    return function($query) use ($patterns, $fields) {
        $query->where(function($q) use ($patterns, $fields) {
            $first = true;
            foreach ($fields as $field) {
                foreach ($patterns as $p) {
                    if ($first) { $q->whereLike($field, $p); $first = false; }
                    else        { $q->whereOrLike($field, $p); }
                }
            }
        });
    };
}

// 调用方从：
$like = mac_search_wd_like($param['wd']);
if ($like) { $where['vod_name|vod_actor'] = $like; }
$model->where($where)->...

// 改为：
$likeClause = mac_search_wd_like_for($param['wd'], 'vod_name|vod_actor');
$query = $model->where($where);
if ($likeClause) { $likeClause($query); }
```

**选项 B — 只修调用方，保持函数不变：**
在每个调用方将 `$where['field'] = $like` 改为 closure。
11 处调用，工作量可控但需逐一处理。

---

### ⚠️ F-C: `allowField(true)` — 76 处（**待验证**）

**文件范围：** `application/common/model/` 25 个模型文件

**问题：** TP5 中 `allowField(true)` 表示允许全部字段写入。
TP8 中该签名可能已变更（需运行时验证）。

**验证方式：**
```bash
php -r "require 'vendor/autoload.php'; \$m = new \think\Model(); \$m->allowField(true);"
```

**如果报错则修复：**
```php
// TP5
$this->allowField(true)->insert($data);
// TP8 — 去掉 allowField(true) 即可（默认允许所有字段）
$this->insert($data);
// 或
$this->strict(false)->insert($data);
```

---

### ⚠️ F-D: `insert()` / `update()` 返回值语义变更（静默错误）

**问题：** TP5 的 `Model::insert()` / `Db::name()->insert()` 失败时返回 `false`。
TP8 失败时抛出 `\think\exception\DbException`，成功返回 `int`（受影响行数或 PK）。

**错误模式（变成死代码）：**
```php
$res = $this->allowField(true)->insert($data);
if ($res === false) {                             // TP8 永远不为 false
    return ['code' => 1002, 'msg' => '保存失败'];  // 此分支永远不执行
}
```

**正确的 TP8 错误处理：**
```php
try {
    $res = $this->insert($data);
    if ($res === 0 || $res === false) {
        return ['code' => 1002, 'msg' => '保存失败'];
    }
} catch (\think\exception\DbException $e) {
    return ['code' => 1002, 'msg' => '保存失败：' . $e->getMessage()];
}
```

**规模：** 约 50+ 处 `if ($res === false)` 检查在 common/model 中，
均为死代码（不会引起运行时错误，但错误无法被捕获）。

---

### ⚠️ F-E: `use think\Db;` 非 facade — admin/controller 47 个文件（P3-01 已知）

P3-01 任务已计划修复。详见 [P3.md](P3.md)。

---

### ⚠️ F-F: Safety.php / Annex.php TP5 数组条件（P3-06 范围内）

`application/admin/controller/Safety.php:127` 使用 `['like', ..., 'OR']`。
`application/admin/controller/Annex.php:216` 使用 `['eq', $tmp]`。
均属于 F-A 的一部分，P3-06 统一修复。

---

### ⚠️ F-G: Base.php `if (!$list)` 空集合判断（死代码）

**文件：** `application/common/model/Base.php` 约第 88 行

**问题：** TP8 `Model::select()` 返回空结果时不是 `false`/`null`，而是空 `Collection` 对象。
`if (!$list)` 对空 Collection 为 false（对象永远 truthy）。

```php
// 当前代码（死代码）
$list = $this->select();
if (!$list) { return ...; }   // 永远不执行

// 修复
if ($list->isEmpty()) { return ...; }
// 或
if (empty($list->toArray())) { return ...; }
```

---

## 已知的安全分析结论

| 问题 | 结论 |
|------|------|
| `config/database.php` 凭证 | 必须使用 `env('DB_PASS', '')` 空字符串默认值，禁止硬编码 |
| `\think\Loader` shim | PSR-4 路径已自动覆盖，无需修改 60 处调用方 |
| OpenccConverter cache miss | null = cache miss（正确），不应视为"功能不可用" |

---

## 迁移时序建议

由于 F-A（TP5 数组条件）贯穿所有模块，建议按以下顺序修复：

```
common/model/ (P1-08) → api/controller/ (P2-06) → admin/controller/ (P3-06) → index/controller/ (P4-01范围)
                              ↓
                     P2-05 API 回归测试
                              ↓
                     P3-05 Admin 回归测试
```

P1-08 是关键路径：`common/model/` 被 api 和 admin 共用，必须先修。

---

## 快速修复参考（批量 sed 示例）

> ⚠️ 以下仅覆盖最简单的单行 `['eq', $v]` 模式，复杂条件需手动处理。

```bash
# 简单 eq 替换（仅当 where($where) 且 $where 是纯 eq 数组时有效）
# 需结合 perl 处理捕获组，以下为示例思路

# 步骤1：先统计各文件的条件类型分布
grep -n "'\(eq\|neq\|gt\|egt\|lt\|elt\|like\|in\|between\)'" \
  application/common/model/Vod.php | head -20

# 步骤2：对 common/model 批量替换 ['eq', $var] → $var 直接值
# （只在 $where['field'] = ['eq', ...] 场景下安全）
perl -i -pe "s/= \['eq', (.+?)\];$/= \$1;/g" application/common/model/XXX.php
```

完整替换需用 PHP 脚本或逐文件处理，不建议无脑 sed 全量替换。

---

## 迁移「老站」时才会暴露的坑（2026-08-30 番号站群迁移新增）

> 上面 F1–F10 / F-A–F-G 是代码层的 TP5→TP8 破坏性变更。
> 下面这三条不同：代码本身没错，是**把一个 TP5 时代的老站搬进来**才触发的，
> 全新装的站不会遇到，所以之前几次迁移都没发现。

| ID | 问题 | 影响面 | 提交 |
|----|------|--------|------|
| M1 | 老主题 `\|date='Y-m-d',###` 编译成 PHP 语法错误 | 用到该写法的页面全部 500 | 49fe6e0 |
| M2 | `mac_vod` / `mac_art` 缺列表复合索引，而代码 `force()` 了其中一个 | 深分页直接 500（不是变慢） | 49fe6e0 |
| M3 | 内链形态从 TP5 pathinfo 变成短链 | 老站 SEO 重复收录 | 49fe6e0 |

### M1：`|date='...',###` —— think-template v3 的 date 特例

**危险级别：Fatal（页面 500）**

苹果CMS 老主题里 `{$vo.vod_time|date='Y-m-d',###}` 是标准写法（`###` 是
think-template 的变量占位符）。TP8 带的 think-template v3 在
`Template::parseVarFunction()` 里给 `date` 加了一个**特例分支**，而它跑在通用的
`###` 替换**之前**：

```php
case 'date':
    $name = 'date(' . $args[1] . ',!is_numeric(' . $name . ')? strtotime(' . $name . ') : ' . $name . ')';
    break;
```

`$args[1]` 是 `'Y-m-d',###`，于是编译产物变成：

```php
date('Y-m-d',###,!is_numeric($vo['vod_time'])? strtotime(...) : ...)
```

`###` 永远没被替换 → `ParseError: syntax error, unexpected token ";"`。
TP5 侧没有这个 `date` 分支，走通用分支，所以老站一直是好的。

**只有 `date` 受影响**：`str_replace='X',Y,###`、`explode=',',###` 走通用分支，
`###` 正常替换，**不要动它们**。

**修法**：删掉 `date` 过滤器后面多余的 `,###`（`date` 分支自己会把变量塞进去，
输出完全相同）：

```bash
php migration/normalize-legacy-theme.php --theme-dir=/path/to/template/xxx \
    --backup-dir=/somewhere/theme-backup [--dry-run]
```

幂等，可反复跑。番号站实测 81 个模板文件里 19 个命中、共 21 处。

**注意**：后台「模板管理」里重新上传原始主题会让问题复发，改完记得别再覆盖回去。

### M2：`force()` 了一个安装脚本从不创建的索引

**危险级别：Fatal（`SQLSTATE[42000] 1176`）**

`application/common/model/Vod.php` 的深分页快车道写的是：

```php
Db::name('Vod')->force('idx_vod_status_recycle_time')
```

而这个索引（连同另外 11 个列表用复合索引）**从来没有出现在 install.sql 里**。
乐播那台之所以没事，是因为 2026-08-26 熔断事故处理时手工建过。

也就是说：**任何按 install.sql 全新装出来的站，首页翻到第 2 页就 500。**
FORCE INDEX 指向不存在的索引不是"优化器少一个选择"，是直接报错。

已修：`install.sql` 补齐 `mac_vod` 9 个 + `mac_art` 3 个索引定义。
存量库用幂等脚本补（在站点根目录跑，自动读 `.env`）：

```bash
php migration/add-missing-list-indexes.php [--dry-run]
```

⚠️ 注意 `idx_st_level_time`（`vod_status,vod_level,vod_time`）是**有害索引**
（`vod_level` 基数常为 1，优化器会误选它去 filesort，正是乐播熔断的直接诱因）。
但代码里有 4 处引用了它，删掉会 500 —— 所以仍然建，靠别处的 FORCE INDEX 绕开。

### M3：内链形态变化导致重复收录

仓库默认注册的是短链（`voddetail/<id>`），TP5 时代的苹果CMS 生成的是
`/index.php/vod/detail/id/123.html`。两种形态**都能访问**（老形态由 TP8 自动路由
`controller/action/key/value` 接住），但 `url()` 反查走 `Url::getRuleUrl()`，它
`foreach` 规则表取第一条参数能满足的 —— 先注册的赢，所以内链默认输出短链。

苹果CMS 模板普遍不输出 `<link rel="canonical">`，靠自然搜索吃饭的老站内链一换形态
就是两套 URL 各自被收录。

**开关**：站点配置 `app.legacy_pathinfo_url = '1'`，TP5 形态提前注册。
默认关闭（新站保持短链更好看）。

⚠️ 两个实现细节，踩过：

1. **multi-app 模式下 `Http::loadRoutes()` 只加载 `application/<app>/route/`**
   （`MultiApp` 在中间件里把 routePath 改掉了）。根目录 `route/index.php` 在 web
   请求里**根本不生效** —— 往 `route/` 目录里另放文件也不会被加载。
   开关必须写在 `application/index/route/web.php` 里。
2. 打开后会暴露 `mac_url()` 拼出空 `?page=` 的老问题：第 1 页被归一成空串，短链路由
   的 `<page?>` 是可选变量、分隔符是 `-`，TP 的 `rtrim($url,'?-')` 连分隔符一起吃掉，
   所以从没暴露；TP5 形态的 `/id/<id>` 规则里没有 page 变量，空串就被当剩余参数拼成
   `?page=`。已在 `mac_url()` 收口处统一抹掉。

### 附：写注释时别把 PHP 标签写死

这次连续踩了两次同一个低级错误：注释里引用老代码写了 `<?php echo $x;?>` 或
路由变量 `<page?>`，其中的 `?>` **会直接关闭 PHP 标签**，即使在 `//` 注释里也一样。
表现是文件后半段被当成 HTML 原样输出、或报 "Unclosed '{'"。
注释里要提 `?>` 就转写（例如写成 `{echo $x}`），改完 `php -l` 一遍。
