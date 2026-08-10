<?php
namespace app\common\model;
use think\facade\Db;
use app\common\util\Pinyin;

/**
 * 采集节点/内容的通用数据操作辅助类。
 *
 * 【不要让它继承 Base/Model】
 * 本类的每个方法都接收 $tab 参数、通过 Db::name($tab) 操作 cj_node / cj_content /
 * cj_history 等【别的】表，自身没有对应的 mac_cj 表（老库与官方原版同样没有）。
 * 而 TP8 的 think\Model::__construct() 会调用 initializeData() → getFields()，
 * 也就是「实例化」这个动作本身就去查自己那张表的字段结构 —— TP5 是懒加载从不触发，
 * 迁到 TP8 后每次 new Cj() 都去查 mac_cj，后台「采集」页直接 500
 * （SQLSTATE[42S02] Table '...mac_cj' doesn't exist）。
 * 与 app\common\model\Extend 是同一类问题，处置方式一致：退回普通类。
 *
 * 仅需保留 getError()（原从 Base 继承，用于拼错误提示）。
 */
class Cj {

    protected string $_error = '';

    public function getError(): string
    {
        return $this->_error;
    }

    protected function setError(string $msg): void
    {
        $this->_error = $msg;
    }

    public function listData($tab,$where,$order,$page,$limit=20)
    {
        $page = $page > 0 ? (int)$page : 1;
        $limit = $limit ? (int)$limit : 20;
        $total = Db::name($tab)->where($where)->count();
        $list = Db::name($tab)->where($where)->order($order)->page($page)->limit($limit)->select()->toArray();
        return ['code'=>1,'msg'=>lang('data_list'),'page'=>$page,'pagecount'=>ceil($total/$limit),'limit'=>$limit,'total'=>$total,'list'=>$list];
    }

    public function infoData($tab,$where=[],$field='*')
    {
        if(empty($tab) || empty($where) || !is_array($where)){
            return ['code'=>1001,'msg'=>lang('param_err')];
        }
        $info = Db::name($tab)->field($field)->where($where)->find();

        if(empty($info)){
            return ['code'=>1002,'msg'=>lang('obtain_err')];
        }

        return ['code'=>1,'msg'=>lang('obtain_ok'),'info'=>$info];
    }

    public function saveData($data)
    {
        $data['lastdate'] = time();
        if(!empty($data['nodeid'])){
            $where=[];
            $where['nodeid'] = $data['nodeid'];
            $res = Db::name('cj_node')->where($where)->update($data);
        }
        else{
            $data['urlpage'] = isset($data['urlpage']) ? (string)$data['urlpage'] : '';
            $data['page_base'] = isset($data['page_base']) ? (string)$data['page_base'] : '';
            $data['sourcecharset'] = isset($data['sourcecharset']) ? (string)$data['sourcecharset'] : 'utf-8';
            $data['customize_config'] = isset($data['customize_config']) ? (string)$data['customize_config'] : '';
            $data['program_config'] = isset($data['program_config']) ? (string)$data['program_config'] : '';
            $res = Db::name('cj_node')->insert($data);
        }
        if(false === $res){
            return ['code'=>1002,'msg'=>lang('save_err').'：'.$this->getError() ];
        }
        return ['code'=>1,'msg'=>lang('save_ok')];
    }

    public function delData($where)
    {
        //删除node
        $res = Db::name('cj_node')->where($where)->delete();
        //删除history
        $list = Db::name('cj_content')->field('url')->where($where)->select()->toArray();
        foreach ($list as $k => $v) {
            $md5 = md5($v['url']);
            Db::name('cj_history')->where('md5',$md5)->delete();
        }
        //删除content
        $res = Db::name('cj_content')->where($where)->delete();

        if($res===false){
            return ['code'=>1001,'msg'=>lang('del_err').'：'.$this->getError() ];
        }
        return ['code'=>1,'msg'=>lang('del_ok')];
    }


}