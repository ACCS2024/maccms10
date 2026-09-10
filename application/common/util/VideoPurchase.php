<?php
declare(strict_types=1);
namespace app\common\util;

use think\facade\Db;

/** Resolves the same current video resource and read policy inside the financial transaction. */
final class VideoPurchase
{
    /** $identity and $access are supplied by authenticated controllers, never by request data. */
    public static function buy(array $identity, array $parameters, callable $access): array
    {
        // Omitted coordinates match the resource reading API; explicit zero never aliases another episode.
        $selection=ContentPurchase::parameters($parameters+['sid'=>1,'nid'=>1]);
        if ($selection===null || $selection['mid']!==1 || $selection['sid']<1 || $selection['nid']<1) {
            return ['code'=>2001,'msg'=>lang('param_err')];
        }
        foreach (['vod_points_type'=>0,'status'=>1] as $field=>$default) {
            if (!in_array(PointsBalance::amount($GLOBALS['config']['user'][$field]??$default,true),[0,1],true)) {
                return ['code'=>2001,'msg'=>lang('param_err')];
            }
        }
        return ContentPurchase::buyVideo($identity['user_id']??null, static function(array $user) use($identity,$selection,$access): array {
            if (!is_string($identity['user_random']??null) || !is_string($user['user_random']??null)
                || !hash_equals($identity['user_random'],$user['user_random'])) {
                return ['code'=>1401,'msg'=>lang('api/please_login_first')];
            }
            $row=Db::name('Vod')->master()->where('vod_id',$selection['id'])->lock(true)->find();
            if (!$row) { return ['code'=>1002,'msg'=>lang('obtain_err')]; }
            $flag=$selection['type']===4?'play':'down';
            $priceField=(string)($GLOBALS['config']['user']['vod_points_type']??'0')==='1'?'vod_points':'vod_points_'.$flag;
            if (!array_key_exists('vod_recycle_time',$row) || PointsBalance::amount($row[$priceField]??null,true)===null) {
                return ['code'=>1002,'msg'=>lang('obtain_err')];
            }
            $row['vod_'.$flag.'_list']=mac_play_list($row['vod_'.$flag.'_from'],$row['vod_'.$flag.'_url'],
                $row['vod_'.$flag.'_server'],$row['vod_'.$flag.'_note'],$flag);
            $context=ContentResource::vodContext($row,$flag,$selection);
            if ($context['code']!==1 || $context['points']>65535) {
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
            if ($groups===[]) { return ['code'=>3001,'msg'=>lang('controller/no_popedom')]; }
            $cached=(new \app\common\model\Group())->getCache(); $enabled=[]; $currentPermission=false;
            foreach ($groups as $group) {
                $gid=$group['group_id']; $enabled[]=$gid;
                $current=self::groupPermission($group,(int)$row['type_id'],$flag==='play'?3:4);
                $policy=is_array($cached[$gid]??null)?self::groupPermission($cached[$gid],(int)$row['type_id'],$flag==='play'?3:4):null;
                // Never charge against a stale permission cache while a group edit awaits cache invalidation.
                if ($current===null || $current!==$policy) { return ['code'=>3001,'msg'=>'权限已更新，请刷新后重试']; }
                $currentPermission=$currentPermission || $current;
            }
            // A cache refresh between the comparison and the policy call cannot grant a denied DB permission.
            if (!$currentPermission && (int)($GLOBALS['config']['user']['status']??1)!==0) {
                return ['code'=>3001,'msg'=>lang('controller/no_popedom')];
            }
            $user['group_id']=implode(',',$enabled);
            $hadUser=array_key_exists('user',$GLOBALS); $previous=$GLOBALS['user']??null;
            try {
                $GLOBALS['user']=$user;
                $permission=$access($row,$flag,['id'=>$context['id'],'sid'=>$context['sid'],'nid'=>$context['nid']]);
            } finally {
                if ($hadUser) { $GLOBALS['user']=$previous; } else { unset($GLOBALS['user']); }
            }
            if (($permission['can_access']??false)===true) { return ['code'=>1,'msg'=>lang('controller/popedom_ok')]; }
            if (($permission['code']??null)!==($flag==='play'?3003:4003) || ($permission['confirm']??0)!==1
                || !empty($permission['trysee']) || !empty($permission['password_required']) || $context['points']===0) {
                return ['code'=>!empty($permission['password_required'])?6001:3001,
                    'msg'=>!empty($permission['password_required'])?'需要验证内容密码':lang('controller/no_popedom')];
            }
            return ['code'=>1,'record'=>['ulog_mid'=>1,'ulog_type'=>$context['ulog_type'],'ulog_rid'=>$context['id'],
                'ulog_sid'=>$context['ulog_sid'],'ulog_nid'=>$context['ulog_nid'],'ulog_points'=>$context['points']]];
        });
    }

    private static function groupPermission(array $group, int $type, int $operation): ?bool
    {
        if (!is_string($group['group_type']??null)) { return null; }
        $permissions=$group['group_popedom']??null;
        if (is_string($permissions)) { $permissions=json_decode($permissions,true); }
        if (!is_array($permissions)) { return null; }
        return strpos(','.$group['group_type'],','.$type.',')!==false && !empty($permissions[$type][$operation]);
    }
}
