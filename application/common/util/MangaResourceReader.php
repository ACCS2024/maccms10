<?php
namespace app\common\util;

use think\facade\Db;

/** Fresh public resource reads never migrate a table or consult the core detail cache. */
final class MangaResourceReader
{
    public static function find(array $selection): array
    {
        if (count($selection) !== 1 || (!isset($selection['manga_id']) && !isset($selection['manga_en']))) {
            return ['code'=>1001, 'msg'=>lang('param_err')];
        }
        if (isset($selection['manga_id'])) {
            $id = ContentResource::positiveInt($selection['manga_id']);
            if ($id === null) {
                return ['code'=>1001, 'msg'=>lang('param_err')];
            }
            $selection = ['manga_id'=>$id];
        } elseif (!is_string($selection['manga_en']) || $selection['manga_en'] === '' || !mb_check_encoding($selection['manga_en'], 'UTF-8') || mb_strlen($selection['manga_en'], 'UTF-8') > 255) {
            return ['code'=>1001, 'msg'=>lang('param_err')];
        }
        $query = Db::name('Manga')->master();
        $columns = Db::query('SELECT COLUMN_NAME AS name FROM information_schema.COLUMNS '
            . 'WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=?', [$query->getTable()], true);
        $names = array_column($columns, 'name');
        if (!in_array('manga_id', $names, true) || !in_array('manga_status', $names, true)) {
            return ['code'=>1002, 'msg'=>lang('obtain_err')];
        }
        $query->where($selection)->where('manga_status', 1);
        if (in_array('manga_recycle_time', $names, true)) {
            $query->where('manga_recycle_time', 0);
        }
        $row = $query->find();
        if (!$row) {
            return ['code'=>1002, 'msg'=>lang('obtain_err')];
        }
        if (!ContentResource::mangaWithinBudget($row)) {
            return ['code'=>1002, 'msg'=>'漫画资源超过读取上限', 'purchase_supported'=>false];
        }
        $row['manga_page_list'] = ContentResource::mangaPages($row);
        $row['manga_page_total'] = count($row['manga_page_list']);
        if (!empty($row['type_id'])) {
            $types = (new \app\common\model\Type())->getCache('type_list');
            $row['type'] = $types[$row['type_id']] ?? [];
            $row['type_1'] = $types[$row['type']['type_pid'] ?? 0] ?? $row['type'];
        }
        if (!empty($row['group_id'])) {
            $groups = (new \app\common\model\Group())->getCache('group_list');
            $row['group'] = $groups[$row['group_id']] ?? [];
        }
        $row['type_is_vip_exclusive'] = in_array($row['type_id'] ?? 0, mac_get_vip_exclusive_type_ids()) ? 1 : 0;
        return ['code'=>1, 'msg'=>lang('obtain_ok'), 'info'=>$row];
    }
}
