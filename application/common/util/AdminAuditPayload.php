<?php
namespace app\common\util;

/** A bounded, redacted JSON snapshot for audit display; never serialize application objects. */
final class AdminAuditPayload
{
    private int $remaining = 8192;
    private int $nodes = 1024;
    private bool $truncated = false;
    private array $denyContains;

    public static function encode(array $data, array $app): string
    {
        try {
            $encoder = new self();
            $encoder->denyContains = self::denyWords($app);
            $safe = $encoder->walk($data, 0);
            $json = json_encode(['version'=>2, 'data'=>$safe, 'truncated'=>$encoder->truncated],
                JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
            // Escaped control characters can expand beyond the raw-text traversal budget.
            return strlen($json) <= 16384 ? $json : '{"redacted":"audit payload exceeds size limit","truncated":true}';
        } catch (\Throwable $error) {
            return '{"redacted":"audit payload unavailable"}';
        }
    }

    private static function denyWords(array $app): array
    {
        $words = ['secret','apikey','api_key','token','access_key','private_key',
            'password','passwd','pwd','authorization','cookie','session','credential'];
        $extra = array_key_exists('admin_audit_extra_redact', $app) ? $app['admin_audit_extra_redact'] : '';
        if (!is_string($extra) || strlen($extra) > 4096 || !mb_check_encoding($extra, 'UTF-8')) {
            throw new \InvalidArgumentException('Invalid audit redaction configuration');
        }
        $extraWords = preg_split('/[\s,|]+/u', trim($extra), -1, PREG_SPLIT_NO_EMPTY);
        if ($extraWords === false || count($extraWords) > 64) { throw new \InvalidArgumentException('Invalid audit redaction list'); }
        foreach ($extraWords as $word) {
            if (strlen($word) > 64) { throw new \InvalidArgumentException('Invalid audit redaction word'); }
            $words[] = mb_strtolower($word, 'UTF-8');
        }
        return array_values(array_unique($words));
    }

    private function walk(array $data, int $depth): array
    {
        $out = [];
        foreach ($data as $key => $value) {
            if ($this->nodes-- <= 0 || $this->remaining < 32) { $this->truncated = true; break; }
            if (strlen((string)$key) > 128 || !mb_check_encoding((string)$key, 'UTF-8')) {
                $this->truncated = true; continue;
            }
            $this->remaining -= strlen((string)$key) + 8;
            if ($this->remaining < 32) { $this->truncated = true; break; }
            $name = mb_strtolower((string)$key, 'UTF-8');
            $redacted = in_array($name, ['verify','user_check','admin_check','sql'], true);
            foreach ($this->denyContains as $word) {
                if (str_contains($name, $word)) { $redacted = true; break; }
            }
            if ($redacted) { $safe = '[redacted]'; }
            elseif (is_array($value)) {
                if ($depth >= 8) { $safe = '[truncated]'; $this->truncated = true; }
                else { $out[$key] = $this->walk($value, $depth + 1); continue; }
            } elseif (is_string($value)) {
                $limit = min(2000, $this->remaining - 16);
                // Cut by complete UTF-8 characters before appending a visible truncation marker.
                $safe = mb_strcut($value, 0, $limit, 'UTF-8');
                if (!mb_check_encoding($safe, 'UTF-8')) { $safe = '[invalid UTF-8]'; $this->truncated = true; }
                elseif (strlen($safe) < strlen($value)) { $safe .= '…'; $this->truncated = true; }
            } elseif (is_int($value) || is_bool($value) || $value === null || (is_float($value) && is_finite($value))) {
                $safe = $value;
            } else { $safe = '[unsupported]'; $this->truncated = true; }
            $this->remaining -= is_string($safe) ? strlen($safe) : 24;
            $out[$key] = $safe;
        }
        return $out;
    }
}
