<?php

namespace app\api\validate;

use think\Validate;

class Cash extends Validate
{
    protected $rule = [
        'cash_id'         => 'require|cashIdentity',
        'cash_money'      => 'require|float|gt:0',
        'cash_bank_name'  => 'require|max:60',
        'cash_bank_no'    => 'require|max:30',
        'cash_payee_name' => 'require|max:30',
        'page'            => 'cashPage',
        'limit'           => 'cashLimit',
        'status'          => 'cashStatus',
        'ids'             => 'max:200',
    ];

    protected $message = [
        'cash_id.require'         => '提现记录ID不能为空',
        'cash_money.require'      => '提现金额不能为空',
        'cash_money.gt'           => '提现金额必须大于0',
        'cash_bank_name.require'  => '银行名称不能为空',
        'cash_bank_no.require'    => '银行账号不能为空',
        'cash_payee_name.require' => '收款人姓名不能为空',
    ];

    protected $scene = [
        'get_list' => [
            'page',
            'limit',
            'status',
        ],
        'get_detail' => [
            'cash_id',
        ],
        'create' => [
            'cash_money',
            'cash_bank_name',
            'cash_bank_no',
            'cash_payee_name',
        ],
        'del' => [
            'ids',
        ],
        'get_config' => [],
    ];

    protected function cashIdentity($value): bool
    {
        return \app\common\util\PointsBalance::amount($value) !== null;
    }

    protected function cashPage($value): bool
    {
        $page = \app\common\util\PointsBalance::amount($value);
        return $page !== null && $page <= \app\common\util\CashRead::MAX_OFFSET + 1;
    }

    protected function cashLimit($value): bool
    {
        $limit = \app\common\util\PointsBalance::amount($value);
        return $limit !== null && $limit <= \app\common\util\CashRead::MAX_LIMIT;
    }

    protected function cashStatus($value): bool
    {
        return in_array($value, [0,1,'0','1'], true);
    }
}
