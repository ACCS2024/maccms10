<?php
namespace app\common\model;
use think\facade\Db;

/**
 * 插件管理辅助类：只做插件目录扫描与配置读写，不落库。
 *
 * 【不要让它继承 Base/Model】
 * 本类没有对应的数据表（mac_addon 在官方原版与老库中同样不存在）。
 * TP8 的 think\Model::__construct() 会调用 initializeData() -> getFields()，
 * 即「实例化」本身就会去查自己那张表的字段结构；TP5 是懒加载从不触发，
 * 迁到 TP8 后 new Addon() 直接抛
 * SQLSTATE[42S02] Table '...mac_addon' doesn't exist。
 * 与 Extend / Cj 是同一类问题，处置一致：退回普通类。
 */
class Addon {

    public function onlineData($page=1)
    {
        $html = mac_curl_get( '预留功能'  /* 原base64已还原 */.'store/?page=' . $page);
        $json = json_decode($html, true);
        if (!$json) {
            return ['code' => 1001, 'msg' => lang('obtain_err')];
        }
        return $json;
    }

    public function localData()
    {
        $results = glob(ADDON_PATH.'*');

        $list = [];
        foreach ($results as $addonDir) {
            if ($addonDir === '.' or $addonDir === '..')
                continue;

            if (!is_dir($addonDir))
                continue;

            $info_file = $addonDir .DS. 'info.ini';
            if (!is_file($info_file))
                continue;
            $name = str_replace(ADDON_PATH,'',$addonDir);
            $info = parse_ini_file($info_file, true) ?: [];
            $info['url'] = mac_url($name);
            $info['install'] = 1;
            $list[$name] = $info;
        }
        return ['code'=>1,'list'=>$list];
    }



}