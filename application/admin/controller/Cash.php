<?php
namespace app\admin\controller;
use think\facade\Db;

class Cash extends Base
{
    public function __construct()
    {
        parent::__construct();
    }

    public function index()
    {
        $param = \app\common\util\CashRead::admin(\think\facade\Request::param(), $this->_pagesize);
        if ($param === null) { return $this->error(lang('param_err')); }
        $where=[];
        if($param['status'] !== ''){
            $where['cash_status'] = $param['status'];
        }
        if($param['uid'] !== ''){
            $where['user_id'] = $param['uid'] ;
        }
        if($param['wd'] !== '' && $param['archive'] === 0){
            $where[] = ['cash_bank_no', 'like', '%'.$param['wd'].'%' ];
        }

        $order='cash_id desc';
        $res = $param['archive'] === 1
            ? \app\common\util\CashArchive::listData($where, $param['page'], $param['limit'], $param['wd'])
            : (new \app\common\model\Cash())->listData($where,$order,$param['page'],$param['limit']);
        if ($res['code'] !== 1) { return $this->error($res['msg']); }

        $this->assign('list',$res['list']);
        $this->assign('total',$res['total']);
        $this->assign('page',$res['page']);
        $this->assign('limit',$res['limit']);

        $param['page'] = '{page}';
        $param['limit'] = '{limit}';
        $this->assign('param',$param);

        $this->assign('title',lang('admin/cash/title'));
        return $this->fetch($param['archive'] === 1 ? 'admin@cash/history' : 'admin@cash/index');
    }

    public function del()
    {
        if (($failure = $this->authorizeCashWrite('del')) !== null) { return json($failure); }
        $ids = $this->cashSelection(true);
        if ($ids === null) { return json(['code'=>1001, 'msg'=>lang('param_err')]); }
        $where = $ids === [] ? [['cash_id', '>', 0]] : ['cash_id'=>$ids];
        return json((new \app\common\model\Cash())->delData($where, ['type'=>'admin', 'id'=>$this->_admin['admin_id']]));
    }

    public function audit()
    {
        if (($failure = $this->authorizeCashWrite('audit')) !== null) { return json($failure); }
        $ids = $this->cashSelection(false);
        if ($ids === null) { return json(['code'=>1001, 'msg'=>lang('param_err')]); }
        return json((new \app\common\model\Cash())->auditData(['cash_id'=>$ids]));
    }

    private function authorizeCashWrite(string $action): ?array
    {
        if (request()->method(true) !== 'POST' || request()->method() !== 'POST') {
            return ['code'=>1001, 'msg'=>lang('param_err')];
        }
        $auth = (new \app\common\model\Admin())->checkLogin();
        if (($auth['code'] ?? null) !== 1) { return ['code'=>1401, 'msg'=>lang('model/admin/not_login')]; }
        $this->_admin = $auth['info'];
        if (!$this->check_auth('cash', $action)) { return ['code'=>1403, 'msg'=>lang('permission_denied')]; }
        if (!\app\common\util\SessionCsrf::validate(request())) { return ['code'=>1403, 'msg'=>lang('token_err')]; }
        return null;
    }

    private function cashSelection(bool $allowAll): ?array
    {
        $param = \think\facade\Request::post();
        if (is_array($param['ids'] ?? null)) {
            $raw = $param['ids'];
            if (!array_is_list($raw) || count($raw) > 1000) { return null; }
            foreach ($raw as $id) {
                if ((!is_string($id) && !is_int($id)) || strlen((string)$id) > 10) { return null; }
                $one = \app\common\util\LogSelection::ids(['ids'=>$id]);
                if ($one === null || count($one) !== 1) { return null; }
            }
            $param['ids'] = implode(',', $raw);
        }
        $ids = \app\common\util\LogSelection::ids($param);
        return !$allowAll && $ids === [] ? null : $ids;
    }
}
