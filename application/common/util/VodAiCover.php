<?php
namespace app\common\util;

use think\facade\Cache;
use think\facade\Db;
use think\facade\Log;

/**
 * AI-generated poster / cover for VOD (OpenAI Images API).
 * Defaults target GPT Image models (gpt-image-1, etc.); legacy dall-e-* may still work on some gateways.
 */
class VodAiCover
{
    /** @var int */
    const RATE_LIMIT_PER_MINUTE = 5;
    /** @var int */
    const RATE_LIMIT_PER_HOUR = 50;

    /**
     * Per-admin rate limit for expensive image generation (see AdminAssistantService::consumeRateLimit).
     *
     * @return bool true if request may proceed, false if limit exceeded
     */
    public static function consumeGenerateRateLimit($adminId)
    {
        $adminId = (int) $adminId;
        if ($adminId <= 0) {
            return false;
        }
        $minBucket = (int) floor(time() / 60);
        $keyMin = 'admin_vod_aicover_rl_min:' . $adminId . ':' . $minBucket;
        $nMin = (int) Cache::get($keyMin, 0);
        if ($nMin >= self::RATE_LIMIT_PER_MINUTE) {
            return false;
        }
        $hourBucket = (int) floor(time() / 3600);
        $keyHour = 'admin_vod_aicover_rl_hour:' . $adminId . ':' . $hourBucket;
        $nHour = (int) Cache::get($keyHour, 0);
        if ($nHour >= self::RATE_LIMIT_PER_HOUR) {
            return false;
        }
        Cache::set($keyMin, $nMin + 1, 70);
        Cache::set($keyHour, $nHour + 1, 3700);

        return true;
    }

    /**
     * @return array{code:int,msg:string,data?:array}
     */
    public static function generateByVodId($vodId, $extraPrompt = '')
    {
        $vodId = PointsBalance::amount($vodId);
        if ($vodId === null || !is_string($extraPrompt)) {
            return ['code'=>0, 'msg'=>lang('param_err')];
        }
        if (($blocked = VodCoverTransaction::blockedResult()) !== null) {
            $blocked['data'] = $blocked['info'];
            return $blocked;
        }
        $binding = VodCoverBinding::capture($vodId);
        $vod = $binding->snapshot();

        $config = config('maccms');
        $ai = isset($config['ai_cover']) && is_array($config['ai_cover']) ? $config['ai_cover'] : [];
        foreach (['enabled','api_key','provider','api_base','model','timeout','size','quality','prompt_suffix'] as $field) {
            if (isset($ai[$field]) && !is_string($ai[$field]) && !is_int($ai[$field])) {
                return ['code'=>0, 'msg'=>lang('param_err')];
            }
        }
        $enabled = isset($ai['enabled']) ? (string) $ai['enabled'] : '0';
        if ($enabled !== '1') {
            return ['code' => 0, 'msg' => lang('admin/ai_cover/msg_disabled')];
        }
        $apiKey = trim((string) (isset($ai['api_key']) ? $ai['api_key'] : ''));
        if ($apiKey === '') {
            return ['code' => 0, 'msg' => lang('admin/ai_cover/msg_no_key')];
        }
        $provider = strtolower(trim((string) (isset($ai['provider']) ? $ai['provider'] : 'openai')));
        if ($provider !== 'openai') {
            return ['code' => 0, 'msg' => lang('admin/ai_cover/msg_provider')];
        }

        $apiBase = !empty($ai['api_base']) ? rtrim((string)$ai['api_base'], '/') : 'https://api.openai.com/v1';
        $model = !empty($ai['model']) ? trim((string) $ai['model']) : 'gpt-image-1';
        $timeout = max(30, min(300, intval($ai['timeout'] ?? 120)));
        $size = self::sanitizeSize(isset($ai['size']) ? $ai['size'] : '1024x1536');
        $qRaw = isset($ai['quality']) ? strtolower(trim((string) $ai['quality'])) : 'medium';
        $quality = self::sanitizeQualityForModel($model, $qRaw);

        $prompt = self::buildPrompt(
            $vod,
            isset($ai['prompt_suffix']) ? (string) $ai['prompt_suffix'] : '',
            $extraPrompt
        );
        $url = $apiBase . '/images/generations';
        // Preserve the configured gateway's response format; validate either supported envelope below.
        $post = [
            'model' => $model,
            'prompt' => $prompt,
            'n' => 1,
            'size' => $size,
        ];
        if (self::modelUsesQualityParam($model)) {
            $post['quality'] = $quality;
        }

        $headers = [
            'Content-Type: application/json',
            'Authorization: Bearer ' . $apiKey,
        ];
        $respBody = self::curlPostJson($url, json_encode($post, JSON_UNESCAPED_UNICODE), $headers, $timeout);
        if ($respBody === false || $respBody === '') {
            return ['code' => 0, 'msg' => lang('admin/ai_cover/msg_empty_response')];
        }
        $json = json_decode((string) $respBody, true);
        if (!is_array($json)) {
            return ['code' => 0, 'msg' => lang('admin/ai_cover/msg_bad_json')];
        }
        if (isset($json['error'])) {
            return ['code'=>0, 'msg'=>lang('admin/ai_cover/msg_upstream_fail')];
        }
        $data = is_array($json['data'] ?? null) ? ($json['data'][0] ?? null) : null;
        if (!is_array($data)) {
            return ['code'=>0, 'msg'=>lang('admin/ai_cover/msg_bad_json')];
        }
        if (is_string($data['url'] ?? null) && $data['url'] !== '') {
            if (!self::isSafePublicHttpsImageUrl($data['url'])) {
                return ['code'=>0, 'msg'=>lang('admin/ai_cover/msg_bad_image_url')];
            }
            $bytes = self::curlGetBinary($data['url'], min(120, $timeout));
            if ($bytes === null || $bytes === '') {
                return ['code'=>0, 'msg'=>lang('admin/ai_cover/msg_download_fail')];
            }
        } elseif (is_string($data['b64_json'] ?? null) && strlen($data['b64_json']) <= 27962028) {
            $bytes = base64_decode($data['b64_json'], true);
            if ($bytes === false || $bytes === '' || strlen($bytes) > ImageProcessor::MAX_BYTES) {
                return ['code'=>0, 'msg'=>lang('admin/ai_cover/msg_decode_fail')];
            }
        } else {
            return ['code'=>0, 'msg'=>lang('admin/ai_cover/msg_no_image_url')];
        }
        // Decoding, optional processing, Annex, cover backups and transfer references form one operation.
        return self::finalizeAndUpdateVod($vod, $bytes);
    }

    public static function revertByVodId($vodId)
    {
        $vodId = PointsBalance::amount($vodId);
        if ($vodId === null) { return ['code'=>0, 'msg'=>lang('param_err')]; }
        if (($blocked = VodCoverTransaction::blockedResult()) !== null) {
            $blocked['data'] = $blocked['info'];
            return $blocked;
        }
        $binding = VodCoverBinding::capture($vodId);
        $row = $binding->snapshot();
        if ($row['vod_pic_thumb_original'] === null) {
            return ['code'=>0, 'msg'=>lang($row['vod_pic_original'] === ''
                ? 'admin/ai_cover/msg_no_backup' : 'admin/ai_cover/msg_incomplete_backup')];
        }
        $transaction = new VodCoverTransaction($vodId);
        try {
            $transaction->begin();
            $data = $binding->restore();
            $transaction->assertActive();
            $result = $transaction->commit(['code'=>1, 'msg'=>lang('save_ok'), 'data'=>$data]);
        } catch (\Throwable $error) {
            self::logFailure('restore', $vodId, $error);
            $result = $transaction->rollback(['code'=>0, 'msg'=>lang('save_err')]);
        }
        if ($result['code'] === 1) {
            self::afterCommit($vodId, $row['vod_en'], $result);
        } elseif (isset($result['info'])) {
            $result['data'] = $result['info'];
        }
        return $result;
    }

    private static function finalizeAndUpdateVod(array $vod, string $bytes): array
    {
        $binding = new VodCoverBinding($vod);
        try {
            $saved = LocalAttachment::storeVodCover($bytes, (array)config('maccms.upload'), $binding);
        } catch (VodCoverOutcomeUnknown $error) {
            return ['code'=>2005, 'msg'=>lang('admin/ai_cover/msg_outcome_unknown', [$error->reference]),
                'data'=>['outcome'=>'transaction_unknown','retryable'=>false,'reference'=>$error->reference]];
        }
        $result = ['code'=>1, 'msg'=>lang('save_ok'), 'data'=>$saved['_cover']];
        self::afterCommit($binding->owner(), (string)$vod['vod_en'], $result);
        return $result;
    }

    /** A confirmed write remains successful when derived caches/indexes need maintenance. */
    private static function afterCommit(int $id, string $name, array &$result): void
    {
        foreach (['index', 'cache'] as $operation) {
            try {
                if ($operation === 'index') { MeilisearchSync::afterVodSave($id); }
                else { self::bustVodDetailCache($id, $name); }
            } catch (\Throwable $error) {
                $result['data']['maintenance_pending'] = true;
                self::logFailure($operation, $id, $error);
            }
        }
    }

    public static function logFailure(string $operation, int $id, \Throwable $error): void
    {
        try { Log::error('VodAiCover ' . $operation . ' failed (vod_id=' . $id . ', type=' . get_class($error) . ')'); }
        catch (\Throwable $loggingError) { /* Diagnostics cannot change the operation outcome. */ }
    }

    private static function buildPrompt(array $vod, $suffix, $perVideoExtra = '')
    {
        $parts = [];
        $parts[] = 'Title: ' . self::clip((string) $vod['vod_name'], 200);
        if (!empty($vod['vod_sub'])) {
            $parts[] = 'Subtitle: ' . self::clip((string) $vod['vod_sub'], 120);
        }
        if (!empty($vod['vod_class'])) {
            $parts[] = 'Genre: ' . self::clip((string) $vod['vod_class'], 120);
        }
        if (!empty($vod['vod_area'])) {
            $parts[] = 'Region: ' . self::clip((string) $vod['vod_area'], 40);
        }
        if (!empty($vod['vod_year'])) {
            $parts[] = 'Year: ' . self::clip((string) $vod['vod_year'], 10);
        }
        if (!empty($vod['vod_blurb'])) {
            $parts[] = 'Summary: ' . self::clip(strip_tags((string) $vod['vod_blurb']), 400);
        } elseif (!empty($vod['vod_content'])) {
            $parts[] = 'Summary: ' . self::clip(strip_tags((string) $vod['vod_content']), 400);
        }
        $base = "Create a vertical cinematic poster illustration for the above video. No real-person photos, no text or watermarks on the image, strong composition, dramatic lighting, suitable for a streaming catalog thumbnail.\n\n"
            . implode("\n", $parts);
        $suffix = trim($suffix);
        if ($suffix !== '') {
            $base .= "\n\n" . self::clip($suffix, 500);
        }
        $perVideoExtra = trim(self::sanitizeExtraPrompt($perVideoExtra));
        if ($perVideoExtra !== '') {
            $base .= "\n\n" . self::clip($perVideoExtra, 700);
        }

        return self::clip($base, 3900);
    }

    private static function sanitizeExtraPrompt($s)
    {
        $s = mac_filter_xss((string) $s);

        return self::clip($s, 800);
    }

    private static function clip($s, $max)
    {
        $s = (string) $s;
        $cleaned = @preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/u', '', $s);
        if (!is_string($cleaned)) {
            $cleaned = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', '', $s);
        }
        $s = is_string($cleaned) ? $cleaned : $s;
        if (function_exists('mb_substr')) {
            return mb_substr($s, 0, $max, 'UTF-8');
        }

        return substr($s, 0, $max);
    }

    /**
     * GPT Image models use 1024x1536 / 1536x1024 (not DALL·E 1792). Map legacy saved sizes.
     */
    private static function sanitizeSize($size)
    {
        $size = strtolower(trim((string) $size));
        $legacy = [
            '1024x1792' => '1024x1536',
            '1792x1024' => '1536x1024',
        ];
        if (isset($legacy[$size])) {
            $size = $legacy[$size];
        }
        $allowed = ['1024x1024', '1024x1536', '1536x1024', '512x512', '256x256', 'auto'];

        return in_array($size, $allowed, true) ? $size : '1024x1536';
    }

    private static function modelUsesQualityParam($model)
    {
        $m = strtolower((string) $model);
        if (strpos($m, 'dall-e-3') !== false) {
            return true;
        }
        if (strpos($m, 'gpt-image') !== false) {
            return true;
        }

        return false;
    }

    /**
     * dall-e-3: standard | hd. GPT Image: low | medium | high | auto.
     */
    private static function sanitizeQualityForModel($model, $qRaw)
    {
        $m = strtolower((string) $model);
        $qRaw = strtolower(trim((string) $qRaw));
        if (strpos($m, 'dall-e-3') !== false) {
            return in_array($qRaw, ['hd', 'standard'], true) ? $qRaw : 'standard';
        }
        if (strpos($m, 'gpt-image') !== false) {
            $ok = ['low', 'medium', 'high', 'auto'];
            if (in_array($qRaw, $ok, true)) {
                return $qRaw;
            }
            if ($qRaw === 'hd') {
                return 'high';
            }
            if ($qRaw === 'standard') {
                return 'medium';
            }

            return 'medium';
        }

        return $qRaw !== '' ? $qRaw : 'medium';
    }

    /**
     * Prevent SSRF when downloading image URLs returned by the API (must be https + public IP).
     */
    private static function isSafePublicHttpsImageUrl($url)
    {
        $target = PublicHttpClient::resolve($url);
        return $target !== null && $target['scheme'] === 'https';
    }

    private static function bustVodDetailCache($vodId, $vodEn)
    {
        $vodId = intval($vodId);
        $vodEn = (string) $vodEn;
        Cache::delete('vod_detail_' . $vodId);
        if ($vodEn !== '') {
            Cache::delete('vod_detail_' . $vodEn);
            Cache::delete('vod_detail_' . $vodId . '_' . $vodEn);
        }
        $flag = isset($GLOBALS['config']['app']['cache_flag']) ? (string) $GLOBALS['config']['app']['cache_flag'] : '';
        if ($flag !== '' && $vodEn !== '') {
            Cache::delete($flag . '_vod_detail_' . $vodId . '_' . $vodEn);
        }
    }

    private static function curlPostJson($url, $body, array $headers, $timeout)
    {
        if (!is_string($url) || strncasecmp($url, 'https://', 8) !== 0 || !is_string($body)) { return false; }
        // Bounded decoded response, public pinned addresses, verified TLS, and controlled redirects.
        return PublicHttpClient::request($url, 'POST', $body, $headers, '', $timeout, 29360128);
    }

    /**
     * @return string|null
     */
    private static function curlGetBinary($url, $timeout)
    {
        if (!is_string($url) || strncasecmp($url, 'https://', 8) !== 0) {
            return null;
        }
        $out = PublicHttpClient::request($url, 'GET', null, [], '', $timeout);
        return $out === false ? null : $out;
    }
}
