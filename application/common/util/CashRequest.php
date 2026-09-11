<?php
declare(strict_types=1);
namespace app\common\util;

/** Canonical request content and durable acknowledgement, independent of mutable exchange settings. */
final class CashRequest
{
    public static function key($value): ?string
    {
        return is_string($value) && preg_match('/^[a-f0-9]{64}$/D', $value) ? $value : null;
    }

    public static function fields(array $param): ?array
    {
        $minor = OrderAmount::minorUnits($param['cash_money'] ?? null);
        if ($minor === null) { return null; }
        $data = ['cash_money'=>OrderAmount::decimal($minor)];
        foreach (['cash_bank_name'=>60, 'cash_bank_no'=>30, 'cash_payee_name'=>30] as $field=>$limit) {
            $value = $param[$field] ?? null;
            if ((!is_string($value) && !is_int($value)) || strlen((string)$value) > $limit * 4
                || !mb_check_encoding((string)$value, 'UTF-8') || preg_match('/[\x00-\x1f\x7f]/', (string)$value)) { return null; }
            $data[$field] = htmlspecialchars(trim((string)$value), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
            if ($data[$field] === '' || mb_strlen($data[$field], 'UTF-8') > $limit) { return null; }
        }
        return $data;
    }

    public static function fingerprint(array $fields): string
    {
        return hash('sha256', json_encode($fields, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR));
    }

    public static function acknowledgement(int $cashId, string $key): array
    {
        return ['code'=>1, 'msg'=>lang('save_ok'), 'info'=>['cash_id'=>$cashId, 'request_id'=>$key]];
    }
}
