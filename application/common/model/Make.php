<?php
namespace app\common\model;

/**
 * 静态页生成辅助类：调度生成逻辑，不落库。
 *
 * 【不要让它继承 Base/Model】
 * 本类没有对应的数据表（mac_make 在官方原版与老库中同样不存在）。
 * TP8 的 think\Model::__construct() 会调用 initializeData() -> getFields()，
 * 即「实例化」本身就会去查自己那张表的字段结构；TP5 是懒加载从不触发，
 * 迁到 TP8 后 new Make() 直接抛
 * SQLSTATE[42S02] Table '...mac_make' doesn't exist。
 * 与 Extend / Cj 是同一类问题，处置一致：退回普通类。
 */
class Make {


}