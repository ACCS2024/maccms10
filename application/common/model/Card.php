<?php
namespace app\common\model;
use think\facade\Db;

class Card extends Base {
    // 设置数据表（不含前缀）
    protected $name = 'card';

    // 定义时间戳字段名
    protected $createTime = '';
    protected $updateTime = '';

    // 自动完成
    protected $auto       = [];
    protected $insert     = [];
    protected $update     = [];

    public function getCardUseStatusTextAttr($val,$data)
    {
        $arr = [0=>lang('not_used'),1=>lang('used')];
        return $arr[$data['card_use_status']];
    }

    public function getCardSaleStatusTextAttr($val,$data)
    {
        $arr = [0=>lang('not_sale'),1=>lang('sold')];
        return $arr[$data['card_sale_status']];
    }

    public function listData($where,$order,$page,$limit=20)
    {
        $page = $page > 0 ? (int)$page : 1;
        $limit = $limit ? (int)$limit : 20;
        $total = $this->where($where)->count();
        $list = Db::name('Card')->where($where)->order($order)->page($page)->limit($limit)->select()->toArray();
        foreach($list as $k=>$v){
            if($v['user_id'] >0){
                $user = (new \app\common\model\User())->infoData(['user_id'=>$v['user_id']]);
                $list[$k]['user'] = $user['info'];
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

    public function saveData($data)
    {
        $validate = mac_validate('Card');
        if(!$validate->check($data)){
            return ['code'=>1001,'msg'=>lang('param_err').'：'.$validate->getError() ];
        }

        if(!empty($data['card_id'])){
            $where=[];
            $where['card_id'] = $data['card_id'];
            $data = $this->filterFields($data);
            $res = $this->where($where)->update($data);
        }
        else{
            $data['card_add_time'] = time();
            $data = $this->filterFields($data);
            $res = $this->insert($data);
        }
        if(false === $res){
            return ['code'=>1002,'msg'=>lang('save_err').'：'.$this->getError() ];
        }
        return ['code'=>1,'msg'=>lang('save_ok')];
    }

    public function saveAllData($num,$money,$point,$role_no,$role_pwd)
    {
        $data=[];
        $t = time();
        for($i=1;$i<=$num;$i++){
            $card_no = mac_get_rndstr(16,$role_no);
            $card_pwd = mac_get_rndstr(8,$role_pwd);

            $data[$card_no] = ['card_no'=>$card_no,'card_pwd'=>$card_pwd,'card_money'=>$money,'card_points'=>$point,'card_add_time'=>$t];
        }
        $data = array_values($data);
        $res = $this->insertAll($data);
        if(false === $res){
            return ['code'=>1002,'msg'=>lang('save_err').'：'.$this->getError() ];
        }
        return ['code'=>1,'msg'=>lang('save_ok')];
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

    public function useData($card_no,$card_pwd,$user_info)
    {
        $user_id = is_array($user_info) ? \app\common\util\PointsBalance::amount($user_info['user_id'] ?? null) : null;
        $credentials = \app\common\util\CardCredentials::parse($card_no, $card_pwd);
        if ($credentials === null || $user_id === null) { return ['code'=>1001, 'msg'=>lang('param_err')]; }
        $card_no = $credentials['card_no'];
        $card_pwd = $credentials['card_pwd'];

        $failure = ['code'=>1004, 'msg'=>lang('model/card/update_card_status_err')];
        $notFound = ['code'=>1002, 'msg'=>lang('model/card/not_found')];
        if (($blocked = \app\common\util\CardTransaction::blockedResult()) !== null) { return $blocked; }
        $scope = null;
        try {
            \app\common\util\FinancialTransaction::requireTables([$this->getTable(), Db::name('User')->getTable(), Db::name('Plog')->getTable()]);
            $scope = new \app\common\util\CardTransaction($user_id);
            $scope->begin();
            $matches = $this->master()->where(['card_no'=>$card_no, 'card_pwd'=>$card_pwd])->lock(true)->limit(2)->select();
            if (count($matches) !== 1 || !in_array($matches[0]['card_use_status'], [0, '0'], true)) {
                return $scope->rollback($notFound);
            }
            $info = $matches[0]->toArray();
            // SQL collations can ignore case, accents or trailing spaces; credentials remain exact bytes.
            if (!hash_equals((string)$info['card_no'], $card_no) || !hash_equals((string)$info['card_pwd'], $card_pwd)) {
                return $scope->rollback($notFound);
            }
            $cardId = \app\common\util\PointsBalance::amount($info['card_id']);
            $points = \app\common\util\PointsBalance::amount($info['card_points']);
            $user = Db::name('User')->master()->where('user_id', $user_id)->lock(true)->find();
            $balance = $user ? \app\common\util\PointsBalance::amount($user['user_points'] ?? null, true) : null;
            if ($cardId === null || $points === null || $balance === null
                || $balance > \app\common\util\PointsBalance::MAX - $points) { throw new \RuntimeException('Card credit rejected'); }
            $scope->record($cardId, $points);
            $success = ['code'=>1, 'msg'=>lang('model/card/used_card_ok', [$points])];
            $update = ['card_sale_status'=>1, 'card_use_status'=>1, 'card_use_time'=>time(), 'user_id'=>$user_id];
            if ($this->where('card_id', $cardId)->where('card_use_status', 0)->update($update) !== 1) {
                return $scope->rollback($notFound);
            }
            $scope->assertActive();
            if (!\app\common\util\PointsBalance::credit($user_id, $points)) { throw new \RuntimeException('Card credit rejected'); }
            $ledger = new \app\common\model\Plog();
            $expected = ['user_id'=>$user_id, 'plog_type'=>1, 'plog_points'=>$points, 'plog_remarks'=>''];
            if (($ledger->saveData($expected)['code'] ?? null) !== 1) { throw new \RuntimeException('Card ledger rejected'); }
            $scope->assertActive();
            $stored = Db::name('Plog')->master()->where('plog_id', $ledger->getLastInsID())->find();
            foreach ($expected as $field=>$value) {
                if (!$stored || (string)$stored[$field] !== (string)$value) { throw new \RuntimeException('Card ledger was not stored exactly'); }
            }
            $stored = $this->master()->where('card_id', $cardId)->find();
            foreach (array_merge(array_intersect_key($info, array_flip(['card_id','card_no','card_pwd','card_points','card_money'])), $update) as $field=>$value) {
                if (!$stored || (string)$stored[$field] !== (string)$value) { throw new \RuntimeException('Card claim was not stored exactly'); }
            }
            if ((string)Db::name('User')->master()->where('user_id', $user_id)->value('user_points') !== (string)($balance + $points)) {
                throw new \RuntimeException('Card balance was not stored exactly');
            }
            $scope->assertActive();
            return $scope->commit($success);
        } catch (\Throwable $error) {
            return $scope !== null ? $scope->rollback($failure) : $failure;
        }
    }
}
