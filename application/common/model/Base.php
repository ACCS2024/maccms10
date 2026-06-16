<?php

namespace app\common\model;

use think\Config as ThinkConfig;
use think\Model;
use think\Db;
use think\Cache;

class Base extends Model
{
    protected $tablePrefix;
    protected $primaryId;
    protected $readFromMaster;

    //自定义初始化
    protected function initialize()
    {
        //需要调用`Model`的`initialize`方法
        parent::initialize();
        // 自定义的初始化
        $this->tablePrefix = isset($this->tablePrefix) ? $this->tablePrefix : ThinkConfig::get('database.prefix');
        $this->primaryId = isset($this->primaryId) ? $this->primaryId : $this->name . '_id';
        $this->readFromMaster = isset($this->readFromMaster) ? $this->readFromMaster : false;
        // 表创建或修改
        if (method_exists($this, 'createTableIfNotExists')) {
            $this->createTableIfNotExists();
        }
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
                $c = \think\Cache::get($key);
                if (is_int($c) || (is_string($c) && ctype_digit($c))) {
                    return (int)$c;
                }
                $n = (int)$query_object->where($cond)->count();
                \think\Cache::set($key, $n, $ttl);
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
        $list = $query_object->where($cond)->field($fields)->order($orderby)->limit($offset, $limit)->select();
        if (!$list) {
            return [];
        }
        $final = [];
        foreach ($list as $row) {
            $row_array = $row->getData();
            if ($transform !== false) {
                $row_array = $this->transformRow($row_array, $transform);
            }
            $final[] = $row_array;
        }
        return $final;
    }

    public function transformRow($row, $extends = []) {
        return $row;
    }
}