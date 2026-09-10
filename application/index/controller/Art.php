<?php
namespace app\index\controller;
use app\common\util\SearchService;

class Art extends Base
{
    public function __construct()
    {
        if (in_array(strtolower(request()->action()), ['detail', 'ajax_detail', 'rss', 'read'], true)
            && !\app\common\util\ContentResource::scalarParameters(array_merge(request()->param(), $_REQUEST))) {
            throw new \think\exception\HttpResponseException(\think\Response::create(lang('param_err'), 'html', 400));
        }
        parent::__construct();
    }

    public function index()
    {
        return $this->label_fetch('art/index');
    }

    public function type()
    {
        $info = $this->label_type();
        return $this->label_fetch( mac_tpl_fetch('art',$info['type_tpl'],'type') );
    }

    public function show()
    {
        $this->check_show();
        $info = $this->label_type();
        return $this->label_fetch( mac_tpl_fetch('art',$info['type_tpl_list'],'show') );
    }

    public function ajax_show()
    {
        $this->check_ajax();
        $this->check_show(1);
        $info = $this->label_type();
        return $this->label_fetch('art/ajax_show');
    }

    public function search()
    {
        $param = mac_param_url();
        $this->check_search($param);
        SearchService::logFromParam(2, $param);
        $this->label_search($param);
        return $this->label_fetch('art/search');
    }

    public function ajax_search()
    {
        $param = mac_param_url();
        $this->check_ajax();
        $this->check_search($param,1);
        SearchService::logFromParam(2, $param);
        $this->label_search($param);
        return $this->label_fetch('art/ajax_search');
    }

    public function detail()
    {
        $info = $this->label_art_detail([], 0, false, true);
        if (!\app\common\util\ContentPassword::artState($info)['verified']) {
            return $this->label_fetch($this->artTemplateOrFallback('art/detail_pwd'));
        }
        $tpl = mac_tpl_fetch('art',$info['art_tpl'],'detail');
        $tplFile = isset($GLOBALS['MAC_ROOT_TEMPLATE']) ? $GLOBALS['MAC_ROOT_TEMPLATE'] . $tpl . '.html' : '';
        if (empty($tplFile) || !is_file($tplFile)) {
            $tpl = 'art/detail';
        }
        return $this->label_fetch($tpl);
    }

    public function ajax_detail()
    {
        $this->check_ajax();
        $info = $this->label_art_detail();
        return $this->label_fetch($this->artTemplateOrFallback('art/ajax_detail'));
    }

    public function rss()
    {
        $info = $this->label_art_detail();
        return $this->label_fetch($this->artTemplateOrFallback('art/rss'));
    }

    /**
     * 小说阅读器视图：以文章分页为章节进行阅读
     */
    public function read()
    {
        $id = \app\common\util\ContentResource::positiveInt(request()->param('id'));
        if ($id === null) {
            $this->page_error(lang('param_err'));
        }
        // Existing reader links carry numeric IDs even when detail links use names or encoded IDs.
        $data = (new \app\common\model\Art())->infoData(['art_id'=>$id, 'art_status'=>1], '*', 0);
        if ($data['code'] !== 1) {
            $this->page_error($data['msg']);
        }
        $info = $this->label_art_detail($data['info'], 0, true);
        if (!\app\common\util\ContentPassword::artState($info)['verified']) {
            return $this->label_fetch($this->artTemplateOrFallback('art/detail_pwd'));
        }
        return $this->label_fetch($this->artTemplateOrFallback('art/read'));
    }

    private function artTemplateOrFallback(string $template): string
    {
        $root = $GLOBALS['MAC_ROOT_TEMPLATE'] ?? '';
        return is_string($root) && $root !== '' && is_file($root . $template . '.html')
            ? $template : APP_PATH . 'common/view/content/' . ($template === 'art/rss' ? 'art_rss' : 'art') . '.html';
    }
}
