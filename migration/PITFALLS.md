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
