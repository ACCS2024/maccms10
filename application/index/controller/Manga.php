<?php
namespace app\index\controller;

class Manga extends Base
{
    public function __construct()
    {
        if (in_array(strtolower(request()->action()), ['detail','play'], true)
            && !\app\common\util\ContentResource::scalarParameters(array_merge(request()->param(), $_REQUEST))) {
            throw new \think\exception\HttpResponseException(\think\Response::create(lang('param_err'), 'html', 400));
        }
        parent::__construct();
    }

    public function index()
    {
        return $this->label_fetch('manga/index');
    }

    public function type()
    {
        $info = $this->label_type();
        return $this->label_fetch(mac_tpl_fetch('manga', $info['type_tpl'], 'type'));
    }

    public function show()
    {
        $this->check_show();
        $info = $this->label_type();
        return $this->label_fetch(mac_tpl_fetch('manga', $info['type_tpl_list'], 'show'));
    }

    public function detail()
    {
        $info = $this->label_manga_detail();
        return $this->label_fetch($this->mangaTemplateOrFallback('manga/detail'));
    }

    public function play()
    {
        $id = \app\common\util\ContentResource::positiveInt(request()->param('id'));
        $info = [];
        if ($id !== null) {
            // New canonical links always carry a numeric ID, even with name/encoded detail settings.
            $data = \app\common\util\MangaResourceReader::find(['manga_id'=>$id]);
            if ($data['code'] !== 1) {
                $this->page_error($data['msg']);
            }
            $info = $data['info'];
        }
        $this->label_manga_detail($info, 0, true);
        return $this->label_fetch($this->mangaTemplateOrFallback('manga/play'));
    }

    private function mangaTemplateOrFallback(string $template): string
    {
        $root = $GLOBALS['MAC_ROOT_TEMPLATE'] ?? '';
        return is_string($root) && $root !== '' && is_file($root . $template . '.html')
            ? $template : APP_PATH . 'common/view/content/' . ($template === 'manga/detail' ? 'manga_detail' : 'manga') . '.html';
    }
}
