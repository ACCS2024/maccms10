<?php

namespace app\common\util;

/**
 * 安全的配置容器(用于后台设置页模板的 {$config.section.key} 多层访问)。
 *
 * 后台设置模板对 config 既有两层标量比较(如 {if $config.user.x eq 1}),也有
 * 大量三层访问(如 {$config.api.vod.auth}、{$config.seo.website.name})。当某段/
 * 某键在当前 config 缺失时,PHP8 的「未定义键」「字符串取偏移」「对象转 int」
 * 都会被升级为异常 → 整页 500。
 *
 * 缺键兜底采用「兄弟启发式」兼顾「可下标」与「标量可比较/可转 int」:
 *   - 若同级存在数组型兄弟(说明本段是 api/collect/seo 这类「段下有子段」),
 *     缺失键按「中间段」处理,返回空容器以支持继续下标;
 *   - 否则(本段子项均为标量,如 user/site 段),缺失键按「叶子」处理,返回空串,
 *     可安全参与 != / == / (int) 等标量运算。
 * 存在的数组值继续包装,存在的标量原样返回。配置不会被 volist 遍历,包装无副作用。
 * 与 SafeParam(扁平,用于 param/info 字段回显)各司其职。
 */
class SafeConfig extends \ArrayObject
{
    public function offsetGet($key): mixed
    {
        if (parent::offsetExists($key)) {
            $v = parent::offsetGet($key);
            return is_array($v) ? new self($v) : $v;
        }
        foreach ($this as $sibling) {
            if (is_array($sibling)) {
                return new self([]);
            }
        }
        return '';
    }

    public function __toString(): string
    {
        return '';
    }
}
