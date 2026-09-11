<?php
declare(strict_types=1);
namespace app\common\util;

/** Bounded financial reads, before values reach ORM offsets or template output. */
final class CashRead
{
    public const MAX_LIMIT = 100;
    public const MAX_OFFSET = 1000000;

    public static function pagination($page = 1, $limit = 20, $start = 0): ?array
    {
        $page = PointsBalance::amount($page);
        $limit = PointsBalance::amount($limit);
        $start = PointsBalance::amount($start, true);
        if ($page === null || $limit === null || $start === null || $limit > self::MAX_LIMIT
            || $start > self::MAX_OFFSET || $page - 1 > intdiv(self::MAX_OFFSET - $start, $limit)) { return null; }
        return ['page'=>$page, 'limit'=>$limit, 'offset'=>($page - 1) * $limit + $start];
    }

    public static function admin(array $input, $defaultLimit = 20): ?array
    {
        $defaultLimit = PointsBalance::amount($defaultLimit);
        if ($defaultLimit === null || $defaultLimit > self::MAX_LIMIT) { $defaultLimit = 20; }
        $paging = self::pagination($input['page'] ?? 1, $input['limit'] ?? $defaultLimit);
        $archive = $input['archive'] ?? '0';
        $status = $input['status'] ?? '';
        $uid = $input['uid'] ?? '';
        $keyword = $input['wd'] ?? '';
        if ($paging === null || !in_array($archive, [0,1,'0','1'], true)
            || !in_array($status, (string)$archive === '1' ? ['',1,2,'1','2'] : ['',0,1,'0','1'], true)
            || ($uid !== '' && PointsBalance::amount($uid) === null)
            || !is_string($keyword) || strlen($keyword) > 200 || preg_match('//u', $keyword) !== 1
            || preg_match('/[\x00-\x1f\x7f]/', $keyword)) { return null; }
        return ['page'=>$paging['page'], 'limit'=>$paging['limit'], 'archive'=>(int)$archive,
            'status'=>$status === '' ? '' : (int)$status, 'uid'=>$uid === '' ? '' : (int)$uid, 'wd'=>$keyword];
    }

    public static function member(array $input): ?array
    {
        $input += ['page'=>1, 'limit'=>20, 'status'=>''];
        $paging = self::pagination($input['page'], $input['limit']);
        if ($paging === null || !in_array($input['status'], ['',0,1,'0','1'], true)) { return null; }
        return ['page'=>$paging['page'], 'limit'=>$paging['limit'], 'status'=>$input['status'] === '' ? '' : (int)$input['status']];
    }
}
