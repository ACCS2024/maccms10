<?php
namespace think;

/**
 * TP5→TP8 compat shim: \think\Loader::validate($name)
 * Instantiates app\common\validate\{Name} (PSR-4 autoloaded).
 */
class Loader
{
    public static function validate(string $name): \think\Validate
    {
        $class = '\\app\\common\\validate\\' . $name;
        if (class_exists($class)) {
            return new $class();
        }
        return new \think\Validate();
    }
}
