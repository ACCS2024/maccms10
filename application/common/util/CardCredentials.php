<?php
declare(strict_types=1);
namespace app\common\util;

/** Request parameters are already transport-decoded; credential identity is their literal UTF-8 value. */
final class CardCredentials
{
    public static function parse($number, $password): ?array
    {
        if ((!is_string($number) && !is_int($number)) || (!is_string($password) && !is_int($password))) { return null; }
        $number = (string)$number;
        $password = (string)$password;
        if ($number === '' || $password === '' || strlen($number) > 64 || strlen($password) > 32
            || !mb_check_encoding($number, 'UTF-8') || !mb_check_encoding($password, 'UTF-8')
            || mb_strlen($number, 'UTF-8') > 16 || mb_strlen($password, 'UTF-8') > 8) { return null; }
        return ['card_no'=>$number, 'card_pwd'=>$password];
    }
}
