<?php

namespace app\api\validate;

use think\Validate;

class Order extends Validate
{
    protected $rule = [
        // mac_order.order_price is DECIMAL(12,2); reject malformed values before float conversion.
        'price'      => 'require|regex:/^\d{1,10}(?:\.\d{1,2})?$/D|gt:0',
        'order_id'   => 'number|between:1,' . PHP_INT_MAX,
        'order_code' => 'max:30',
        'page'       => 'number|between:1,' . PHP_INT_MAX,
        'limit'      => 'number|between:1,100',
        'status'     => 'number|in:0,1',
    ];

    protected $message = [
        'order_code.max' => '订单号格式错误',
    ];

    protected $scene = [
        'create' => ['price'],
        'get_list' => [
            'page',
            'limit',
            'status',
        ],
        'get_detail' => [
            'order_id',
            'order_code',
        ],
        'check_status' => [
            'order_code',
        ],
    ];
}
