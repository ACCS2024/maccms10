<?php
namespace app\common\util;

/** One-time OAuth state, bound to the initiating session, provider and local user. */
final class OAuthState
{
    private const PROVIDERS = ['qq', 'weixin'];
    private const TTL = 600;

    public static function supports($provider): bool
    {
        return is_string($provider) && in_array($provider, self::PROVIDERS, true);
    }

    public static function issue(string $provider, int $userId): string
    {
        if (!self::supports($provider)) {
            throw new \InvalidArgumentException('Unsupported OAuth provider');
        }
        $state = bin2hex(random_bytes(32));
        session('oauth_state_' . $provider, [
            'token' => $state, 'expires' => time() + self::TTL, 'user_id' => $userId,
        ]);
        return $state;
    }

    public static function consume($provider, $state, int $userId): bool
    {
        if (!self::supports($provider) || !is_string($state) || strlen($state) !== 64) {
            return false;
        }
        $key = 'oauth_state_' . $provider;
        $expected = session($key);
        if (!is_array($expected) || !is_string($expected['token'] ?? null)
            || !is_int($expected['expires'] ?? null) || $expected['expires'] <= time()
            || ($expected['user_id'] ?? null) !== $userId
            || !hash_equals($expected['token'], $state)) {
            return false;
        }
        session($key, null);
        return true;
    }
}
