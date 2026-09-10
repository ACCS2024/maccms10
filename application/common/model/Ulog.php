<?php
namespace app\common\model;
use think\facade\Db;

class Ulog extends Base {
    // 设置数据表（不含前缀）
    protected $name = 'ulog';

    // 定义时间戳字段名
    protected $createTime = '';
    protected $updateTime = '';

    // 自动完成
    protected $auto       = [];
    protected $insert     = [];
    protected $update     = [];


    public function listData($where,$order,$page=1,$limit=20,$start=0)
    {
        $page = $page > 0 ? (int)$page : 1;
        $limit = $limit ? (int)$limit : 20;
        $start = $start ? (int)$start : 0;
        if(!is_array($where)){
            $where = json_decode($where,true);
        }
        $offset = ($limit * ($page-1) + $start);
        $total = $this->where($where)->count();
        $list = Db::name('Ulog')->where($where)->order($order)->limit($offset, $limit)->select()->toArray();

        $user_ids=[];
        foreach($list as $k=>&$v){
            if($v['user_id'] >0){
                $user_ids[$v['user_id']] = $v['user_id'];
            }

            if($v['ulog_mid']==12){
                // 漫画收藏 / 历史
                $manga_info = (new \app\common\model\Manga())->infoData(['manga_id'=>$v['ulog_rid']],'*',1);
                if (!empty($manga_info['info'])) {
                    $manga_info['info']['link'] = mac_url_manga_detail($manga_info['info']);
                    $v['data'] = [
                        'id'   => $manga_info['info']['manga_id'],
                        'name' => $manga_info['info']['manga_name'],
                        'pic'  => mac_url_img($manga_info['info']['manga_pic']),
                        'link' => $manga_info['info']['link'],
                        'type' => [
                            'type_id'   => $manga_info['info']['type']['type_id'],
                            'type_name' => $manga_info['info']['type']['type_name'],
                            'link'      => mac_url_type($manga_info['info']['type']),
                        ],
                    ];
                }
            }

            if($v['ulog_mid']==1){
                $vod_info = (new \app\common\model\Vod())->infoData(['vod_id'=>$v['ulog_rid']],'*',1);

                if($v['ulog_sid']>0 && $v['ulog_nid']>0){
                    if($v['ulog_type']==5){
                        $vod_info['info']['link'] = mac_url_vod_down($vod_info['info'],['sid'=>$v['ulog_sid'],'nid'=>$v['ulog_nid']]);
                    }
                    else{
                        $vod_info['info']['link'] = mac_url_vod_play($vod_info['info'],['sid'=>$v['ulog_sid'],'nid'=>$v['ulog_nid']]);
                    }
                }
                else{
                    $vod_info['info']['link'] = mac_url_vod_detail($vod_info['info']);
                }
                $v['data'] = [
                    'id'=>$vod_info['info']['vod_id'],
                    'name'=>$vod_info['info']['vod_name'],
                    'pic'=>mac_url_img($vod_info['info']['vod_pic']),
                    'link'=>$vod_info['info']['link'],
                    'type'=>[
                        'type_id'=>$vod_info['info']['type']['type_id'],
                        'type_name'=>$vod_info['info']['type']['type_name'],
                        'link'=>mac_url_type($vod_info['info']['type']),
                    ],

                ];
            }
            elseif($v['ulog_mid']==2){
                $art_info = (new \app\common\model\Art())->infoData(['art_id'=>$v['ulog_rid']],'*',1);
                $art_info['info']['link'] = mac_url_art_detail($art_info['info']);
                $v['data'] = [
                    'id'=>$art_info['info']['art_id'],
                    'name'=>$art_info['info']['art_name'],
                    'pic'=>mac_url_img($art_info['info']['art_pic']),
                    'link'=>$art_info['info']['link'],
                    'type'=>[
                        'type_id'=>$art_info['info']['type']['type_id'],
                        'type_name'=>$art_info['info']['type']['type_name'],
                        'link'=>mac_url_type($art_info['info']['type']),
                    ],

                ];
            }
            elseif($v['ulog_mid']==3){
                $topic_info = (new \app\common\model\Topic())->infoData(['topic_id'=>$v['ulog_rid']],'*',1);
                $topic_info['info']['link'] = mac_url_topic_detail($topic_info['info']);
                $v['data'] = [
                    'id'=>$topic_info['info']['topic_id'],
                    'name'=>$topic_info['info']['topic_name'],
                    'pic'=>mac_url_img($topic_info['info']['topic_pic']),
                    'link'=>$topic_info['info']['link'],
                    'type'=>[],
                ];
            }
            elseif($v['ulog_mid']==8){
                $actor_info = (new \app\common\model\Actor())->infoData(['actor_id'=>$v['ulog_rid']],'*',1);
                $actor_info['info']['link'] = mac_url_actor_detail($actor_info['info']);
                $v['data'] = [
                    'id'=>$actor_info['info']['actor_id'],
                    'name'=>$actor_info['info']['actor_name'],
                    'pic'=>mac_url_img($actor_info['info']['actor_pic']),
                    'link'=>$actor_info['info']['link'],
                    'type'=>[],
                ];
            }
        }

        unset($v);

        if(!empty($user_ids)){
            // Only fetch names for accounts referenced by the current log page.
            $user_names = Db::name('User')->whereIn('user_id', array_values($user_ids))->column('user_name', 'user_id');
            foreach($list as $k=>$v){
                $list[$k]['user_name'] = $user_names[$v['user_id']] ?? '';
            }
        }

        return ['code'=>1,'msg'=>lang('data_list'),'page'=>$page,'pagecount'=>ceil($total/$limit),'limit'=>$limit,'total'=>$total,'list'=>$list];
    }

    public function infoData($where,$field='*')
    {
        if(empty($where) || !is_array($where)){
            return ['code'=>1001,'msg'=>lang('param_err')];
        }
        $info = $this->field($field)->where($where)->find();

        if(empty($info)){
            return ['code'=>1002,'msg'=>lang('obtain_err')];
        }
        $info = $info->toArray();

        return ['code'=>1,'msg'=>lang('obtain_ok'),'info'=>$info];
    }

    /** Append a record for the identity already verified by the caller; never read browser credentials here. */
    public function saveData($data)
    {
        if (!is_array($data) || array_key_exists('ulog_id', $data)) {
            return ['code'=>1001, 'msg'=>lang('param_err')];
        }
        $fields = [];
        foreach (['user_id', 'ulog_mid', 'ulog_type', 'ulog_rid', 'ulog_sid', 'ulog_nid', 'ulog_points'] as $field) {
            $optional = in_array($field, ['ulog_sid', 'ulog_nid', 'ulog_points'], true);
            $value = array_key_exists($field, $data) ? $data[$field] : ($optional ? 0 : null);
            $fields[$field] = \app\common\util\PointsBalance::amount($value, $optional);
            if ($fields[$field] === null) { return ['code'=>1001, 'msg'=>lang('param_err')]; }
        }
        $types = [1=>[2,3,4,5], 2=>[1,2,3], 3=>[2,3], 8=>[2,3], 12=>[1,2,3]];
        if (!isset($types[$fields['ulog_mid']]) || !in_array($fields['ulog_type'], $types[$fields['ulog_mid']], true)
            || $fields['ulog_sid'] > 255 || $fields['ulog_nid'] > 65535 || $fields['ulog_points'] > 65535) {
            return ['code'=>1002, 'msg'=>lang('param_err')];
        }
        $fields['ulog_time'] = \app\common\util\PointsBalance::amount(time());
        if ($fields['ulog_time'] === null) { return ['code'=>1002, 'msg'=>lang('param_err')]; }
        $started = false;
        try {
            $connection = Db::connect();
            $type = $connection->getConfig('type');
            if ($type === 'mysql') {
                $rows = Db::query('SELECT ENGINE AS engine FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=?', [$this->getTable()], true);
                if (count($rows) !== 1 || strtoupper((string)$rows[0]['engine']) !== 'INNODB') {
                    throw new \RuntimeException('Usage records require transactional storage');
                }
            } elseif ($type !== 'sqlite') { throw new \RuntimeException('Unsupported usage record storage'); }
            Db::startTrans(); $started = true;
            if (!Db::name('User')->master()->where('user_id', $fields['user_id'])->where('user_status', 1)->find()
                || $this->insert($fields) !== 1) { throw new \RuntimeException('Usage record insert failed'); }
            $id = \app\common\util\PointsBalance::amount($this->getLastInsID());
            $stored = $id === null ? null : Db::name('Ulog')->master()->where('ulog_id', $id)->find();
            foreach ($fields as $field=>$value) {
                if (!$stored || (string)$stored[$field] !== (string)$value) {
                    throw new \RuntimeException('Usage record was not stored exactly');
                }
            }
            Db::commit(); $started = false;
            return ['code'=>1, 'msg'=>lang('save_ok')];
        } catch (\Throwable $error) {
            if ($started) { Db::rollback(); }
            return ['code'=>1004, 'msg'=>lang('save_err')];
        }
    }

    public function delData($where)
    {
        $res = $this->where($where)->delete();
        if($res===false){
            return ['code'=>1001,'msg'=>lang('del_err').'：'.$this->getError() ];
        }
        return ['code'=>1,'msg'=>lang('del_ok')];
    }

    public function fieldData($where,$col,$val)
    {
        if(!isset($col) || !isset($val)){
            return ['code'=>1001,'msg'=>lang('param_err')];
        }

        $data = [];
        $data[$col] = $val;
        $res = $this->where($where)->update($data);
        if($res===false){
            return ['code'=>1001,'msg'=>lang('set_err').'：'.$this->getError() ];
        }
        return ['code'=>1,'msg'=>lang('set_ok')];
    }

}
