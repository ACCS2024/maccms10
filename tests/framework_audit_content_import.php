<?php
/** Three actual import actions, Token/Request, bounded parsers and installed content models. Admin constructors are an isolated boundary. */
declare(strict_types=1);
namespace app\admin\controller {
    function model(string $name):object {
        $real=\model($name);
        return new class($real,strtolower($name)) {
            public function __construct(private object $real,private string $module){}
            public function saveData($data){
                $GLOBALS['import_model_calls']++;
                $mode=$GLOBALS['import_model_fault']??null;
                if(($data[$this->module.'_name']??'')!=='Stop here'){return $this->real->saveData($data);}
                if($mode==='before'){throw new \RuntimeException('ordinary private service detail');}
                if($mode==='after'){$this->real->saveData($data);throw new \RuntimeException('ordinary private service detail');}
                if($mode==='bad-result'){return ['code'=>0,'msg'=>'ordinary private service detail'];}
                if($mode==='rejected'){return ['code'=>1001,'msg'=>'ordinary private service detail'];}
                if($mode==='failed'){return ['code'=>1002,'msg'=>'ordinary private service detail'];}
                return $this->real->saveData($data);
            }
        };
    }
}
namespace {
    $module=$argv[1]??'art';
    if(!in_array($module,['art','manga','vod'],true)){throw new \RuntimeException('Invalid import fixture module');}
    require __DIR__.'/framework_audit_'.$module.'_save.php';
    use think\facade\Db;
    use think\file\UploadedFile;
    use app\common\util\BulkTableIo;
    $initialChecks=$checks;
    function json($value){return \think\Response::create($value,'json');}
    class ContentImportRequest extends \app\Request {
        public function isCli():bool{return false;}
        public function file(string $name='') {
            $file=parent::file($name);
            // CLI private files are not HTTP uploads. Only this fixture grants UploadedFile's documented test mode.
            return $file instanceof UploadedFile?new UploadedFile($file->getPathname(),$file->getOriginalName(),null,0,true):$file;
        }
    }
    $app->config->set(['type'=>'file','path'=>$temp.'/sessions','name'=>'AUDITIMPORT'],'session');
    $app->config->set(['type'=>'Think','view_path'=>APP_PATH.'admin/view/','cache_path'=>$temp.'/views/'],'view');
    $GLOBALS['import_session']=new \think\Session($app);
    function importCall(string $module,array $files,array $post=['__token__'=>'ordinary-token'],string $method='POST',bool $ajax=true,$table=null):array {
        $GLOBALS['import_session']->set('__token__','ordinary-token');
        $request=ContentImportRequest::__make(\think\Container::getInstance())->withServer(['REQUEST_METHOD'=>$method,'HTTP_X_REQUESTED_WITH'=>$ajax?'XMLHttpRequest':''])
            ->withPost($post)->withFiles($files)->withSession($GLOBALS['import_session']);
        \think\Container::getInstance()->instance('request',$request);
        $class='app\\admin\\controller\\'.ucfirst($module);$reflection=new \ReflectionClass($class);
        $controller=$reflection->newInstanceWithoutConstructor();$property=new \ReflectionProperty(\app\common\controller\All::class,'request');$property->setValue($controller,$request);
        try{$result=$table===null?$controller->importData():$controller->base_import($table);}
        catch(\think\exception\HttpResponseException $error){return ['html'=>$error->getResponse()->getContent(),'jump_code'=>\app\common\controller\All::$lastJumpCode];}
        check($result instanceof \think\response\Json,'Actual import action returns its JSON response');return $result->getData();
    }
    function importFile(string $path,string $name='ordinary.csv',int $error=UPLOAD_ERR_OK):array {
        return ['file'=>['name'=>$name,'tmp_name'=>$path,'type'=>'application/octet-stream','error'=>$error,'size'=>is_file($path)?filesize($path):0]];
    }
    $directory=audit_temp_dir('content-import');
    try {
        $seed=$module.'SaveSeed';$path=$directory.'/source.csv';$name=$module.'_name';$id=$module.'_id';$body=$module.'_content';
        $GLOBALS['import_model_calls']=0;
        $ordinary="$id,$name,type_id,$body\n7,Imported,1,Ordinary body\n";
        file_put_contents($path,$ordinary);
        foreach(['GET','HEAD','OPTIONS','PUT','DELETE']as $method){
            $seed();$before=Db::name(ucfirst($module))->find();
            check(importCall($module,importFile($path),['__token__'=>'ordinary-token'],$method)['code']===0 && Db::name(ucfirst($module))->find()===$before,'Non-POST import never writes');
        }
        foreach([[],['__token__'=>'wrong'],['__token__'=>[]],['__token__'=>['ordinary-token']]]as $post){
            $seed();$before=Db::name(ucfirst($module))->find();
            check(importCall($module,importFile($path),$post)['code']===0 && Db::name(ucfirst($module))->find()===$before,'Actual Token rejects missing, wrong and malformed values');
        }
        foreach(['user','Art',[],false]as $table){
            check(importCall($module,importFile($path),['__token__'=>'ordinary-token'],'POST',true,$table)['code']===0,'Generic import accepts only the three server-owned module names');
        }
        foreach([[],importFile($path,'ordinary.csv',UPLOAD_ERR_PARTIAL),importFile($path,'ordinary.exe'),
            ['file'=>['name'=>['one.csv','two.csv'],'tmp_name'=>[$path,$path],'type'=>['text/csv','text/csv'],'error'=>[0,0],'size'=>[1,1]]]]as $files){
            check(importCall($module,$files)['code']===0 && is_file($path),'Missing/failed/multiple/unsupported upload returns a controlled error and preserves fixture files');
        }
        check($GLOBALS['import_model_calls']===0,'Ingress rejection never enters a content save');
        foreach([
            ["$id,$name,type_id,$body\n7,Must not save,1,new\n7,Short,1\n",3,4],
            ["$id,$name,type_id,$name\n7,First,1,Second\n",1,4],
            [ucfirst($id).",$name,type_id\n7,Must not insert,1\n",1,1],
            ["$id,$name,type_id,unknown_content\n7,Must not save,1,new\n",1,4],
            ["$id,$name,type_id,\n7,Must not save,1,\n0,Second,1,Ordinary note\n",3,4],
            ["$id,$name,type_id\n7,Must not save,1\n0,Second,1,Ordinary note\n",3,4],
            ["$id,$name\n7,Missing type header\n",1,3],
        ]as [$source,$sourceRow,$sourceColumn]){
            $seed();$before=Db::name(ucfirst($module))->order($id)->select()->toArray();$beforeCalls=$GLOBALS['import_model_calls'];file_put_contents($path,$source);
            $result=importCall($module,importFile($path));
            check($result['code']===0 && $result['data']===['status'=>'invalid_columns','row'=>$sourceRow,'column'=>$sourceColumn],'Whole-file mapping preflight reports the exact source coordinate');
            check($GLOBALS['import_model_calls']===$beforeCalls && Db::name(ucfirst($module))->order($id)->select()->toArray()===$before,'No valid prefix row is saved before a later mapping failure');
        }
        file_put_contents($path,$ordinary);
        foreach(['csv','txt','CSV']as $extension){
            $seed();$result=importCall($module,importFile($path,'ordinary.'.$extension));$row=Db::name(ucfirst($module))->where($id,7)->find();
            check($result['code']===1 && $result['data']['status']==='completed' && $result['data']['saved']===1,'Real CSV/TXT import propagates success and counts');
            check($row[$name]==='Imported' && $row[$body]==='Ordinary body','Actual installed model receives and stores ordinary content');
        }
        $seed();file_put_contents($path,"$id,$name,type_id,$body\n\n7ordinary,Invalid,1,wrong\n7,Imported,1,\n0,New row,1,new body\n");
        $result=importCall($module,importFile($path));
        check($result['code']===1 && $result['data']['status']==='partial' && $result['data']['saved']===2 && $result['data']['failed']===1 && $result['data']['errors']===[['row'=>3,'reason'=>'param_err']],'Known invalid row is reported at its source coordinate while valid rows continue');
        check(Db::name(ucfirst($module))->where($id,7)->value($body)==='' && Db::name(ucfirst($module))->count()===2,'Clear body and auto increment semantics survive the full action');
        $seed();file_put_contents($path,"$id,$name,type_id\n7,Invalid,1ordinary\n7,,1\n");$result=importCall($module,importFile($path));
        check($result['code']===0 && $result['data']['saved']===0 && $result['data']['failed']===2,'All-invalid import reports failure');
        foreach(['',"$id,$name,type_id\n",'"unclosed']as $source){file_put_contents($path,$source);check(importCall($module,importFile($path))['code']===0,'Empty/header-only/malformed file fails before save');}
        foreach(['before','after','bad-result','rejected','failed']as $fault){
            $seed();$GLOBALS['import_model_fault']=$fault;$GLOBALS['import_model_calls']=0;
            file_put_contents($path,"$id,$name,type_id\n7,First saved,1\n0,Stop here,1\n0,Must wait,1\n");
            $result=importCall($module,importFile($path));$summary=$result['data'];
            check(!str_contains($result['msg'],'ordinary private service detail'),'Raw model/service errors are never returned in the public response');
            if(in_array($fault,['rejected','failed'],true)){
                check($result['code']===1 && $summary['saved']===2 && $summary['failed']===1 && $summary['unknown']===0 && $GLOBALS['import_model_calls']===3,'Known model rejection is separate from uncertainty');
            }else{
                check($result['code']===0 && $summary['status']==='unknown' && $summary['saved']===1 && $summary['unknown']===1 && $summary['unknown_row']===3 && $summary['unprocessed']===1 && $GLOBALS['import_model_calls']===2,'Unconfirmed save stops the batch and reports the source row without retry');
                check(Db::name(ucfirst($module))->count()===($fault==='after'?2:1) && Db::name(ucfirst($module))->where($name,'Must wait')->count()===0,'Observer distinguishes a completed write from a pre-save failure; subsequent row is untouched');
            }
        }
        unset($GLOBALS['import_model_fault']);
        $seed();$source="$id,$name,type_id\n";for($i=0;$i<20;$i++){$source.="7ordinary,Invalid,1\n";}file_put_contents($path,$source);$result=importCall($module,importFile($path));
        check($result['data']['failed']===20 && count($result['data']['errors'])===15,'Row diagnostics are bounded independently of failure counts');
        $seed();file_put_contents($path,$ordinary);
        foreach([true,false]as $valid){
            $result=importCall($module,importFile($path),['__token__'=>$valid?'ordinary-token':'wrong'],'POST',false);
            check($result['jump_code']===($valid?1:0) && str_contains($result['html'],$valid?'class="success"':'class="error"'),'Non-Ajax action preserves actual HTML jump response and status');
        }
        // Sparse XLSX uses the same controller/model path and original row coordinates.
        $xlsx=$directory.'/source.xlsx';$xml='<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>';
        foreach([1=>[$id,$name,'type_id'],3=>['7ordinary','Invalid','1'],8=>['7','Sheet row','1']]as $row=>$values){
            $xml.='<row r="'.$row.'">';foreach($values as $column=>$value){$xml.='<c r="'.BulkTableIo::colName($column).$row.'" t="inlineStr"><is><t>'.BulkTableIo::xmlEsc($value).'</t></is></c>';}$xml.='</row>';
        }
        $xml.='</sheetData></worksheet>';$zip=new \ZipArchive();$zip->open($xlsx,\ZipArchive::CREATE);$zip->addFromString('xl/worksheets/sheet1.xml',$xml);$zip->close();
        $seed();$result=importCall($module,importFile($xlsx,'ordinary.xlsx'));
        check($result['data']['saved']===1 && $result['data']['failed']===1 && $result['data']['errors'][0]['row']===3 && Db::name(ucfirst($module))->where($id,7)->value($name)==='Sheet row','Actual XLSX action preserves sparse coordinates and stores the valid row');
        if($module==='vod'){
            $originalCache=$cache;
            $faultCache=new class($originalCache) implements \Psr\SimpleCache\CacheInterface {
                public function __construct(private \Psr\SimpleCache\CacheInterface $inner){}
                public function get(string $key,mixed $default=null):mixed{return $this->inner->get($key,$default);}
                public function set(string $key,mixed $value,null|int|\DateInterval $ttl=null):bool{return $this->inner->set($key,$value,$ttl);}
                public function delete(string $key):bool{if($key==='vod_repeat_table_created_time'){throw new \RuntimeException('ordinary cache outage');}return $this->inner->delete($key);}
                public function clear():bool{return $this->inner->clear();}
                public function has(string $key):bool{return $this->inner->has($key);}
                public function getMultiple(iterable $keys,mixed $default=null):iterable{return $this->inner->getMultiple($keys,$default);}
                public function setMultiple(iterable $values,null|int|\DateInterval $ttl=null):bool{return $this->inner->setMultiple($values,$ttl);}
                public function deleteMultiple(iterable $keys):bool{foreach($keys as $key){$this->delete($key);}return true;}
            };
            $app->instance('cache',$faultCache);file_put_contents($path,$ordinary);$result=importCall($module,importFile($path));$app->instance('cache',$originalCache);
            check($result['code']===1 && $result['data']['saved']===1 && $result['data']['repeat_index_pending']===1,'Final cache failure preserves acknowledged save and reports pending maintenance');
            Db::execute('DROP TABLE vod_save_audit_vod_repeat');
            file_put_contents($path,$ordinary);$result=importCall($module,importFile($path));
            check($result['code']===1 && $result['data']['saved']===1 && $result['data']['repeat_index_pending']===1 && str_contains($result['msg'],'admin/batch/io_pending'),'Saved video retains repeat catalog maintenance warning without a false failure');
        }
        // Missing actual table is a pre-write storage failure, even if an ORM field cache once existed.
        $tableName=Db::name(ucfirst($module))->getTable();Db::execute('DROP TABLE '.$tableName);file_put_contents($path,$ordinary);$beforeCalls=$GLOBALS['import_model_calls'];
        check(importCall($module,importFile($path))['code']===0 && $GLOBALS['import_model_calls']===$beforeCalls,'Current missing schema fails before entering saveData');
        printf("Content import actions: %d additional checks on PHP %s / %s / %s.\n",$checks-$initialChecks,PHP_VERSION,$mysql?'MySQL':'SQLite',$module);
    }finally{audit_remove_temp($directory);}
}
