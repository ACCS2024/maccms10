<?php

namespace app\common\util;

/**
 * 默认安全的请求参数容器。
 *
 * 后台列表/表单模板大量用 {$param.xxx} 回显筛选条件;当某筛选项未提交时,
 * 该键不存在,PHP8 下「未定义数组键」会被 TP8 错误处理器升级为异常 → 整页 500。
 *
 * 将赋给模板的 param 包成本类后,{$param.xxx}(编译为 $param['xxx'])在键缺失时
 * 返回空串,行为与 PHP7/TP5 的宽松语义一致,且不影响 count/foreach/isset。
 * 仅用于「模板展示」,控制器内的 $where 构造仍使用原始数组。
 */
class SafeParam extends \ArrayObject
{
    public function offsetGet($key): mixed
    {
        return parent::offsetExists($key) ? parent::offsetGet($key) : '';
    }
}
