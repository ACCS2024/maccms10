<?php
namespace app\common\util;

/** Content-password grants are separate from account identity and paid entitlements. */
final class ContentPassword
{
    private const VOD_SCOPES = ['detail' => 1, 'play' => 4, 'down' => 5];

    private static function vodField(string $operation): string
    {
        if (!isset(self::VOD_SCOPES[$operation])) {
            throw new \InvalidArgumentException('Unsupported video password operation');
        }
        return 'vod_pwd' . ($operation === 'detail' ? '' : '_' . $operation);
    }

    public static function vodState(array $row, string $operation): array
    {
        $field = self::vodField($operation);
        $password = is_string($row[$field] ?? null) ? $row[$field] : '';
        $scope = '1-' . self::VOD_SCOPES[$operation] . '-' . (int)($row['vod_id'] ?? 0);
        $grant = session($scope);
        $verified = $password === '' || (is_array($grant) && ($grant['version'] ?? null) === 1
            && is_string($grant['fingerprint'] ?? null)
            && hash_equals(hash('sha256', $scope . "\0" . $password), $grant['fingerprint']));
        $help = $row[$field . '_url'] ?? '';
        if (!is_string($help) || strlen($help) > 2048 || preg_match('/[\x00-\x20\x7f]/', $help)
            || (!preg_match('~^https?://[^/]+~i', $help) && (!str_starts_with($help, '/') || str_starts_with($help, '//')))) {
            $help = '';
        }
        return ['required' => $password !== '', 'verified' => $verified, 'scope' => $scope, 'help_url' => $help];
    }

    public static function verifyVod(array $row, string $operation, $submitted): array
    {
        $field = self::vodField($operation);
        if (!is_string($submitted) || $submitted === '' || strlen($submitted) > 1024) {
            return ['code' => 1001, 'msg' => lang('param_err')];
        }
        $state = self::vodState($row, $operation);
        if ($state['verified']) {
            return ['code' => 1002, 'msg' => lang('index/pwd_repeat')];
        }
        if (mac_get_time_span('last_pwd') < 5) {
            return ['code' => 1003, 'msg' => lang('index/pwd_frequently')];
        }
        if (!hash_equals($row[$field], $submitted)) {
            return ['code' => 1012, 'msg' => lang('pass_err')];
        }
        session($state['scope'], ['version' => 1, 'fingerprint' => hash('sha256', $state['scope'] . "\0" . $row[$field])]);
        return ['code' => 1, 'msg' => 'ok'];
    }

    /** One article access password covers its detail and chapters; it never substitutes for payment. */
    public static function artState(array $row): array
    {
        $password = is_string($row['art_pwd'] ?? null) ? $row['art_pwd'] : '';
        $scope = '2-1-' . (int)($row['art_id'] ?? 0);
        $grant = session($scope);
        $verified = $password === '' || (is_array($grant) && ($grant['version'] ?? null) === 1
            && is_string($grant['fingerprint'] ?? null)
            && hash_equals(hash('sha256', $scope . "\0" . $password), $grant['fingerprint']));
        $help = $row['art_pwd_url'] ?? '';
        if (!is_string($help) || strlen($help) > 2048 || preg_match('/[\x00-\x20\x7f]/', $help)
            || (!preg_match('~^https?://[^/]+~i', $help) && (!str_starts_with($help, '/') || str_starts_with($help, '//')))) {
            $help = '';
        }
        return ['required' => $password !== '', 'verified' => $verified, 'scope' => $scope, 'help_url' => $help];
    }

    public static function verifyArt(array $row, $submitted): array
    {
        if (!is_string($submitted) || $submitted === '' || strlen($submitted) > 1024) {
            return ['code' => 1001, 'msg' => lang('param_err')];
        }
        $state = self::artState($row);
        if ($state['verified']) {
            return ['code' => 1002, 'msg' => lang('index/pwd_repeat')];
        }
        if (mac_get_time_span('last_pwd') < 5) {
            return ['code' => 1003, 'msg' => lang('index/pwd_frequently')];
        }
        if (!hash_equals($row['art_pwd'], $submitted)) {
            return ['code' => 1022, 'msg' => lang('pass_err')];
        }
        session($state['scope'], ['version' => 1, 'fingerprint' => hash('sha256', $state['scope'] . "\0" . $row['art_pwd'])]);
        return ['code' => 1, 'msg' => 'ok'];
    }
    /** One manga access password covers its chapters; it never substitutes for payment. */
    public static function mangaState(array $row): array
    {
        $password = is_string($row['manga_pwd'] ?? null) ? $row['manga_pwd'] : '';
        $scope = '12-1-' . (int)($row['manga_id'] ?? 0);
        $grant = session($scope);
        $verified = $password === '' || (is_array($grant) && ($grant['version'] ?? null) === 1
            && is_string($grant['fingerprint'] ?? null)
            && hash_equals(hash('sha256', $scope . "\0" . $password), $grant['fingerprint']));
        $help = $row['manga_pwd_url'] ?? '';
        if (!is_string($help) || strlen($help) > 2048 || preg_match('/[\x00-\x20\x7f]/', $help)
            || (!preg_match('~^https?://[^/]+~i', $help) && (!str_starts_with($help, '/') || str_starts_with($help, '//')))) {
            $help = '';
        }
        return ['required' => $password !== '', 'verified' => $verified, 'scope' => $scope, 'help_url' => $help];
    }

    public static function verifyManga(array $row, $submitted): array
    {
        if (!is_string($submitted) || $submitted === '' || strlen($submitted) > 1024) {
            return ['code' => 1001, 'msg' => lang('param_err')];
        }
        $state = self::mangaState($row);
        if ($state['verified']) {
            return ['code' => 1002, 'msg' => lang('index/pwd_repeat')];
        }
        if (mac_get_time_span('last_pwd') < 5) {
            return ['code' => 1003, 'msg' => lang('index/pwd_frequently')];
        }
        if (!hash_equals($row['manga_pwd'], $submitted)) {
            return ['code' => 1032, 'msg' => lang('pass_err')];
        }
        session($state['scope'], ['version' => 1, 'fingerprint' => hash('sha256', $state['scope'] . "\0" . $row['manga_pwd'])]);
        return ['code' => 1, 'msg' => 'ok'];
    }
}
