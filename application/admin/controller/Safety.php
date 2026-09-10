<?php
namespace app\admin\controller;
use think\facade\Db;

class Safety extends Base
{

    public function index()
    {
        return $this->file();
    }

    public function file()
    {
        // Integrity checks use the maintained local repository and local audit tools.
        // Do not trust a fingerprint manifest fetched from the former update service.
        return $this->fetch('admin@safety/file');
    }

    public function data()
    {
        $param = \think\facade\Request::param();
        if (!empty($param['ck'])) {
            $pre = config('database.connections.mysql.prefix');
            $schema = Db::query('select * from information_schema.columns where table_schema = ?', [Db::connect()->getConfig('database')]);
            $col_list = [];
            $sql = '';
            foreach ($schema as $k => $v) {
                $col_list[$v['TABLE_NAME']][$v['COLUMN_NAME']] = $v;
            }
            $tables = ['actor', 'art', 'gbook', 'link', 'topic', 'type', 'vod'];
            $param['tbi'] = max(0, intval($param['tbi'] ?? 0));
            if ($param['tbi'] >= count($tables)) {
                mac_echo(lang('admin/safety/data_clear_ok'));
                die;
            }

            $check_arr = ["<script","<iframe","{php}","{:"];
            $rel_val = [
                [
                    "/<script[\s\S]*?<\/(.*)>/is",
                    "/<script[\s\S]*?>/is",
                ],
                [
                    "/<iframe[\s\S]*?<\/(.*)>/is",
                    "/<iframe[\s\S]*?>/is",
                ],
                [
                    "/{php}[\s\S]*?{\/php}/is",
                ],
                [
                    "/{:[\s\S]*?}/is",
                ]
            ];
            mac_echo('<style type="text/css">body{font-size:12px;color: #333333;line-height:21px;}span{font-weight:bold;color:#FF0000}</style>');


            foreach ($col_list as $k1 => $v1) {
                $pre_tb = str_replace($pre, '', $k1);
                $si = array_search($pre_tb, $tables);
                if ($pre_tb !== $tables[$param['tbi']]) {
                    continue;
                }
                mac_echo(lang('admin/safety/data_check_tip1',[$k1]));
                $where = [];
                foreach ($v1 as $k2 => $v2) {
                    if (strpos($v2['DATA_TYPE'], 'int') === false) {
                        $where[] = [$k2, 'like', mac_like_arr(join(',', $check_arr))];
                    }
                }
                if (!empty($where)) {
                    $field = array_column($where, 0);
                    $field[] = $tables[$si] . '_id';
                    $list = Db::name($pre_tb)->field($field)->where(function ($query) use ($where) {
                        foreach ($where as [$column, $operator, $patterns]) {
                            foreach ($patterns as $pattern) {
                                $query->whereOr($column, $operator, $pattern);
                            }
                        }
                    })->select();

                    mac_echo(lang('admin/safety/data_check_tip2',[count($list)]));
                    foreach ($list as $k3 => $v3) {
                        $update = [];
                        $col_id = $tables[$si] . '_id';
                        $col_name = $tables[$si] . '_name';
                        $val_id = $v3[$col_id];;
                        $val_name = strip_tags($v3[$col_name]);
                        $ck = false;
                        $where2 = [];
                        $where2[$col_id] = $val_id;
                        foreach ($v3 as $k4 => $v4) {
                            if ($k4 != $col_id) {
                                $val = $v4;
                                foreach ($check_arr as $kk => $vv) {
                                    foreach($rel_val[$kk] as $k5=>$v5){
                                        $val = preg_replace($v5, "", $val);
                                    }
                                }
                                if ($val !== $v4) {
                                    $update[$k4] = $val;
                                    $ck = true;
                                }
                            }
                        }

                        if ($ck) {
                            $r = Db::name($pre_tb)->where($where2)->update($update);
                            mac_echo($val_id . '、' . $val_name . ' ok');
                        }
                    }
                }
            }

            $param['tbi']++;
            $url = url('safety/data') . '?' . http_build_query($param);
            mac_jump($url, 3);
            exit;
        }
        return $this->fetch('admin@safety/data');
    }
}
