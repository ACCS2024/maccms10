<?php

namespace app\common\model;

use think\facade\Config as ThinkConfig;
use think\Model;
use think\facade\Db;
use think\facade\Cache;

class Base extends Model
{
    protected $tablePrefix;
    protected $primaryId;
    protected $readFromMaster;
    protected string $_error = '';

    public function __construct(array|object $data = [])
    {
        parent::__construct($data);
        $conn = ThinkConfig::get('database.default', 'mysql');
        $this->tablePrefix    = $this->tablePrefix    ?: ThinkConfig::get("database.connections.{$conn}.prefix", '');
        $this->primaryId      = $this->primaryId      ?: ($this->getName() . '_id');
        $this->readFromMaster = $this->readFromMaster ?: false;
        if (method_exists($this, 'createTableIfNotExists')) {
            $this->createTableIfNotExists();
        }
    }

    public function getError(): string
    {
        return $this->_error;
    }

    protected function setError(string $msg): void
    {
        $this->_error = $msg;
    }

    public function getCountByCond($cond)
    {
        $query_object = $this;
        if ($this->readFromMaster === true) {
            $query_object = $query_object->master();
        }
        // COUNT 缓存:列表总数非敏感、变化缓慢;短 TTL 缓存以削减 API/列表对全表 count 的重复开销,
        // 防高频接口把 count(*) 刷爆 CPU。readFromMaster(刚写需实时)或 count_cache_sec<=0 时不缓存。
        $ttl = isset($GLOBALS['config']['app']['count_cache_sec']) ? (int)$GLOBALS['config']['app']['count_cache_sec'] : 60;
        if ($ttl > 0 && $this->readFromMaster !== true) {
            try {
                $flag = isset($GLOBALS['config']['app']['cache_flag']) ? $GLOBALS['config']['app']['cache_flag'] : 'mac';
                $key = $flag . '_cnt_' . md5(get_class($this) . '|' . serialize($cond));
                $c = \think\facade\Cache::get($key);
                if (is_int($c) || (is_string($c) && ctype_digit($c))) {
                    return (int)$c;
                }
                $n = (int)$query_object->where($cond)->count();
                \think\facade\Cache::set($key, $n, $ttl);
                return $n;
            } catch (\Throwable $e) {
                // 缓存层异常 → 回退直查
            }
        }
        return (int)$query_object->where($cond)->count();
    }

    public function getListByCond($offset, $limit, $cond, $orderby = '', $fields = "*", $transform = false)
    {
        $offset = max(0, (int)$offset);
        $limit = max(1, (int)$limit);
        // 通用硬上限:防恶意 limit(如 ?limit=1000000)一次拉巨量行打爆内存/CPU。
        // 1000 远超任何正常分页,不影响合法使用;公开 API 另有更紧的每端点上限。
        $limit = min($limit, 1000);

        if (empty($orderby)) {
            $orderby = $this->primaryId . " DESC";
        } else {
            if (strpos($orderby, $this->primaryId) === false) {
                $orderby .= ", " . $this->primaryId . " DESC";
            }
        }

        $query_object = $this;
        if ($this->readFromMaster === true) {
            $query_object = $query_object->master();
        }
        $list = $query_object->where($cond)->field($fields)->order($orderby)->limit($offset, $limit)->select()->toArray();
        if (!$list) {
            return [];
        }
        $final = [];
        foreach ($list as $row) {
            // Collection::toArray() 已将模型转换为数组，非空列表不能再调用模型方法。
            $row_array = $row;
            if ($transform !== false) {
                $row_array = $this->transformRow($row_array, $transform);
            }
            $final[] = $row_array;
        }
        return $final;
    }

    /**
     * 剔除不属于目标表的键,再交给 update()/insert()。
     *
     * 后台表单直接把 Request::post() 整包丢给 saveData(),里面混着 __token__ 这种
     * 非字段键;TP 的写入构造器在严格模式(fields_strict,默认开)下遇到未知键会抛
     * "fields not exists:[__token__]" —— 后台【编辑采集/分类/管理员】保存全部 500。
     * 这里按真实表结构过滤,顺带让今后新增的表单隐藏域(_csrf、提交按钮 name 等)
     * 不会再打穿保存。
     *
     * 保留含 "." 或 "->" 的键,与 Builder::parseData() 的判断口径一致
     * (前者是带表名的字段,后者是 JSON 路径,两者都是合法写入键)。
     *
     * 取表结构走 PDOConnection::getSchemaInfo() 的连接内存缓存,而写入本身就要调
     * getFieldsBindType() 取同一份 schema —— 不产生额外查询。
     *
     * @param string $table 目标表(不含前缀);留空表示模型自身的表
     */
    protected function filterFields(array $data, string $table = ''): array
    {
        try {
            $fields = $table === ''
                ? $this->getTableFields()
                : Db::name($table)->getTableFields();
        } catch (\Throwable $e) {
            // 拿不到表结构时不擅自丢数据,原样放行,交回严格模式报错
            return $data;
        }
        if (empty($fields)) {
            return $data;
        }

        $out     = [];
        $dropped = [];
        foreach ($data as $k => $v) {
            $key = (string) $k;
            if (in_array($key, $fields, true) || str_contains($key, '.') || str_contains($key, '->')) {
                $out[$k] = $v;
            } else {
                $dropped[] = $key;
            }
        }

        // 严格模式原本能暴露代码里的字段名笔误,过滤后就没人报了。丢弃表单常见的
        // 无害键之后仍有剩余,才记一条 notice 方便排查。
        $dropped = array_diff($dropped, ['__token__', '__csrf__', 'submit', 'file', 'ids']);
        if ($dropped) {
            \think\facade\Log::notice('[model] ' . static::class . ' 丢弃非表字段: ' . implode(',', $dropped));
        }

        return $out;
    }

    public function transformRow($row, $extends = []) {
        return $row;
    }
}
