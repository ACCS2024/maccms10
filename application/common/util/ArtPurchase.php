<?php
declare(strict_types=1);
namespace app\common\util;

use think\facade\Db;

/** Resolves article chapter, current price and the established read policy inside one financial transaction. */
final class ArtPurchase
{
    /** Identity and policy are trusted controller inputs; only the chapter selection comes from the form. */
    public static function buy(array $identity, array $parameters, callable $access): array
    {
        $selection=ContentPurchase::parameters($parameters+['sid'=>1,'nid'=>0]);
        if ($selection===null || $selection['mid']!==2 || $selection['sid']<1 || $selection['nid']!==0) {
            return ['code'=>2001,'msg'=>lang('param_err')];
        }
        foreach (['art_points_type'=>0,'status'=>1] as $field=>$default) {
            if (!in_array(PointsBalance::amount($GLOBALS['config']['user'][$field]??$default,true),[0,1],true)) {
                return ['code'=>2001,'msg'=>lang('param_err')];
            }
        }
        return ContentPurchase::buyArt($identity['user_id']??null,static function(array $user) use($identity,$selection,$access): array {
            if (!is_string($identity['user_random']??null) || !is_string($user['user_random']??null)
                || !hash_equals($identity['user_random'],$user['user_random'])) {
                return ['code'=>1401,'msg'=>lang('api/please_login_first')];
            }
            $row=Db::name('Art')->master()->where('art_id',$selection['id'])->lock(true)->find();
            $whole=(string)($GLOBALS['config']['user']['art_points_type']??'0')==='1';
            $priceField=$whole?'art_points':'art_points_detail';
            if (!$row || PointsBalance::amount($row['art_status']??null,true)!==1
                || PointsBalance::amount($row['art_recycle_time']??null,true)!==0
                || PointsBalance::amount($row[$priceField]??null,true)===null
                || (!$whole && (int)$row[$priceField]===0 && PointsBalance::amount($row['art_points']??null,true)===null)) {
                return ['code'=>1002,'msg'=>lang('obtain_err')];
            }
            // Art intentionally clamps an oversized chapter to its actual final chapter before receipt lookup.
            $context=ContentResource::artContext($row,['page'=>$selection['sid']]);
            if ($context['code']!==1 || $context['points']>65535 || ($context['current']['content']??'')==='') {
                return ['code'=>1002,'msg'=>lang('obtain_err')];
            }
            $groupIds=explode(',',(string)$user['group_id']);
            foreach ($groupIds as $id) {
                if (ContentResource::positiveInt($id)===null || (int)$id>32767) {
                    return ['code'=>3001,'msg'=>lang('controller/no_popedom')];
                }
            }
            if (max($groupIds)>2 && (int)$user['user_end_time']<time()) { $groupIds=['2']; }
            $groups=Db::name('Group')->master()->whereIn('group_id',$groupIds)->where('group_status',1)->lock(true)->select()->toArray();
            if ($groups===[] || count($groups)!==count(array_unique(array_map('intval',$groupIds)))) {
                return ['code'=>3001,'msg'=>lang('controller/no_popedom')];
            }
            $cached=(new \app\common\model\Group())->getCache();$enabled=[];$currentPermission=false;
            foreach ($groups as $group) {
                $gid=$group['group_id'];$enabled[]=$gid;
                $current=self::groupPermission($group,(int)$row['type_id']);
                $policy=is_array($cached[$gid]??null)?self::groupPermission($cached[$gid],(int)$row['type_id']):null;
                if ($current===null || $current!==$policy) { return ['code'=>3001,'msg'=>'权限已更新，请刷新后重试']; }
                $currentPermission=$currentPermission || $current;
            }
            $record=['user_id'=>(int)$user['user_id'],'ulog_mid'=>2,'ulog_type'=>1,'ulog_rid'=>$context['id'],
                'ulog_sid'=>$context['ulog_sid'],'ulog_nid'=>0,'ulog_points'=>$context['points']];
            $receipt=$context['points']>0 ? Db::name('Ulog')->master()->where($record)->lock(true)->find() : null;
            $free=(int)($GLOBALS['config']['user']['status']??1)===0
                || ($currentPermission && (max($enabled)>2 || $context['points']===0));
            $user['group_id']=implode(',',$enabled);
            $hadUser=array_key_exists('user',$GLOBALS);$previous=$GLOBALS['user']??null;
            try {
                $GLOBALS['user']=$user;
                $permission=$access($row,['id'=>$context['id'],'page'=>$context['page']]);
            } finally {
                if ($hadUser) { $GLOBALS['user']=$previous; } else { unset($GLOBALS['user']); }
            }
            if (!empty($permission['password_required'])) { return ['code'=>6001,'msg'=>'需要验证内容密码']; }
            if (($permission['can_access']??false)===true) {
                // A Group-cache refresh during the policy callback cannot turn a locked paid resource into a free grant.
                return $free || $receipt ? ['code'=>1,'msg'=>lang('controller/popedom_ok')]
                    : ['code'=>3001,'msg'=>'权限已更新，请刷新后重试'];
            }
            if ($receipt && empty($permission['trysee'])) { return ['code'=>1,'msg'=>lang('controller/popedom_ok')]; }
            if ($free) { return ['code'=>3001,'msg'=>'权限已更新，请刷新后重试']; }
            // Unlike video, Art explicitly permits a member without category read permission to buy this chapter.
            if (($permission['code']??null)!==3003 || ($permission['confirm']??0)!==1 || !empty($permission['trysee'])
                || !$context['purchase_supported'] || empty($permission['purchase_supported']) || $context['points']===0) {
                return ['code'=>3001,'msg'=>lang('controller/no_popedom')];
            }
            unset($record['user_id']);
            return ['code'=>1,'record'=>$record];
        });
    }

    private static function groupPermission(array $group,int $type): ?bool
    {
        if (!is_string($group['group_type']??null)) { return null; }
        $permissions=$group['group_popedom']??null;
        if (is_string($permissions)) { $permissions=json_decode($permissions,true); }
        if (!is_array($permissions)) { return null; }
        return strpos(','.$group['group_type'],','.$type.',')!==false && !empty($permissions[$type][3]);
    }
}
