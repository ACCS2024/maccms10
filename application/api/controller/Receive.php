<?php
namespace app\api\controller;

class Receive extends Base
{
    public array $_param = [];

    public function __construct()
    {
        parent::__construct();
        $this->_param = \think\facade\Request::param();
        $interface = $GLOBALS['config']['interface'] ?? [];
        if (!is_array($interface) || ($interface['status'] ?? 0) != 1) {
            $this->reject(3001, 'api/close_err');
        }
        $configuredPass = $interface['pass'] ?? null;
        $providedPass = $this->_param['pass'] ?? null;
        // Reject structured input before comparing; casting pass[] raises a PHP 8 warning.
        if (!is_string($configuredPass) || !is_string($providedPass) || !hash_equals($configuredPass, $providedPass)) {
            $this->reject(3002, 'api/pass_err');
        }
        if (strlen($configuredPass) < 16) {
            $this->reject(3003, 'api/pass_safe_err');
        }
    }

    public function index()
    {
    }

    private function reject(int $code, string $message): never
    {
        echo json_encode(['code'=>$code, 'msg'=>lang($message)], JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
        exit;
    }

    private function requireText(array $info, string $field, int $code, string $message): void
    {
        $value = $info[$field] ?? null;
        if ((!is_string($value) && !is_int($value) && !is_float($value)) || empty($value)) {
            $this->reject($code, $message);
        }
    }

    private function positiveId($value): ?int
    {
        if ((!is_string($value) && !is_int($value)) || !ctype_digit((string)$value)) {
            return null;
        }
        $digits = ltrim((string)$value, '0');
        $max = (string)PHP_INT_MAX;
        if ($digits === '' || strlen($digits) > strlen($max) || (strlen($digits) === strlen($max) && strcmp($digits, $max) > 0)) {
            return null;
        }
        return (int)$digits;
    }

    private function requireCategory(array &$info, string $kind, int $mid, int $code): void
    {
        foreach (['type_id','type_name'] as $field) {
            if (isset($info[$field]) && !is_string($info[$field]) && !is_int($info[$field])) {
                $this->reject($code, 'api/require_type');
            }
        }
        if (!empty($info['type_id'])) {
            $id = $this->positiveId($info['type_id']);
        } elseif (!empty($info['type_name'])) {
            // Explicit IDs do not depend on the optional name mapping configuration.
            $mapping = mac_interface_type();
            $id = $this->positiveId($mapping[$kind . 'type'][$info['type_name']] ?? null);
        } else {
            $id = null;
        }
        $types = (new \app\common\model\Type())->getCache('type_list');
        $type = $id === null ? null : ($types[$id] ?? null);
        if (!is_array($type) || (int)($type['type_mid'] ?? 0) !== $mid) {
            $this->reject($code, 'api/require_type');
        }
        $info['type_id'] = $id;
    }

    private function requireRelation(array $info, string $name, int $code, string $message): void
    {
        foreach ([$name,'douban_id'] as $field) {
            if (isset($info[$field]) && !is_string($info[$field]) && !is_int($info[$field])) {
                $this->reject($code, $message);
            }
        }
        if (empty($info[$name]) && empty($info['douban_id'])) {
            $this->reject($code, $message);
        }
    }

    private function collect(string $kind, array $info): void
    {
        // The receiving protocol contains flat form fields. Nested optional fields
        // otherwise reach strip_tags/trim or the SQL builder as arrays.
        unset($info['pass']);
        if ($kind !== 'vod') {
            // Only the video collector consumes the source category as class metadata.
            unset($info['type_name']);
        }
        foreach ($info as $field => $value) {
            if (!is_string($field) || (!is_scalar($value) && $value !== null)) {
                $this->reject(1001, 'param_err');
            }
            if ($value === null) {
                $info[$field] = '';
            }
        }
        $method = $kind . '_data';
        $result = (new \app\common\model\Collect())->$method([], ['data'=>[$info]], 0);
        echo json_encode($result, JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
    }

    public function vod()
    {
        $info = $this->_param;
        $this->requireText($info, 'vod_name', 2001, 'api/require_name');
        $this->requireCategory($info, 'vod', 1, 2002);
        $this->collect('vod', $info);
    }

    public function art()
    {
        $info = $this->_param;
        $this->requireText($info, 'art_name', 2001, 'api/require_name');
        $this->requireCategory($info, 'art', 2, 2002);
        $this->collect('art', $info);
    }

    public function actor()
    {
        $info = $this->_param;
        $this->requireText($info, 'actor_name', 2001, 'api/require_actor_name');
        $this->requireText($info, 'actor_sex', 2002, 'api/require_sex');
        $this->requireCategory($info, 'actor', 8, 2003);
        $this->collect('actor', $info);
    }

    public function role()
    {
        $info = $this->_param;
        $this->requireText($info, 'role_name', 2001, 'api/require_role_name');
        $this->requireText($info, 'role_actor', 2002, 'api/require_actor_name');
        $this->requireRelation($info, 'vod_name', 2003, 'api/require_rel_vod');
        $this->collect('role', $info);
    }

    public function website()
    {
        $info = $this->_param;
        $this->requireText($info, 'website_name', 2001, 'api/require_name');
        $this->requireCategory($info, 'website', 11, 2002);
        $this->collect('website', $info);
    }

    public function manga()
    {
        $info = $this->_param;
        $this->requireText($info, 'manga_name', 2001, 'api/require_name');
        $this->requireCategory($info, 'manga', 12, 2002);
        $this->collect('manga', $info);
    }

    public function comment()
    {
        $info = $this->_param;
        $this->requireText($info, 'comment_name', 2001, 'api/require_comment_name');
        $this->requireText($info, 'comment_content', 2002, 'api/require_comment_name');
        $mid = $this->positiveId($info['comment_mid'] ?? null);
        if ($mid === null) {
            $this->reject(2004, 'api/require_mid');
        }
        $info['comment_mid'] = $mid;
        $this->requireRelation($info, 'rel_name', 2003, 'api/require_rel_name');
        $this->collect('comment', $info);
    }
}
