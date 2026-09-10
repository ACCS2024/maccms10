<?php

namespace app\api\validate;

use think\Validate;

class Type extends Validate
{
    protected $rule = [
        'type_id'      => 'number|between:1,' . PHP_INT_MAX,
        'ids'          => 'idList',
        'num'          => 'integer|egt:0',
        'mid'          => 'integer|egt:0',
        'parent'       => 'integer|in:0,1',
        'link_flag'    => 'string',
    ];

    protected $message = [
        
    ];

    protected $scene = [
        'get_list' => [
            'type_id',
        ],
        'get_nav_types' => ['ids', 'num', 'mid', 'parent', 'link_flag'],
        'get_type_with_children' => [
            'type_id',
            'num',
        ],
    ];

    protected function idList($value): bool
    {
        if (!is_string($value) && !is_int($value)) {
            return false;
        }
        $value = trim((string)$value);
        return $value === '' || preg_match('/^\d+(?:\s*,\s*\d+)*$/D', $value) === 1;
    }
}
