<?php
/** Isolated failure-return, permission, editor-exit and uncertain-COMMIT cases. */
declare(strict_types=1);
$case=$argv[1]??'';
putenv('UPLOAD_AUDIT_MYSQL=0');putenv('UPLOAD_AUDIT_ENTRANCE=admin');
chdir(sys_get_temp_dir());
if ($case==='permissions' && posix_geteuid()===0) {
    if (!posix_setgid(65534) || !posix_setuid(65534)) { throw new RuntimeException('Unable to run permission fixture without root'); }
}
if (str_starts_with($case,'annex-error-')) {
    class AttachmentRejectedAnnex {
        public function saveData($data) {
            if ($GLOBALS['attachment_fault_case']==='annex-error-after') {
                \think\facade\Db::name('Annex')->insert($data+['annex_time'=>time()]);
            }
            return ['code'=>1001,'msg'=>'fixture rejected'];
        }
    }
    class_alias(AttachmentRejectedAnnex::class,'app\\common\\model\\Annex');
    $GLOBALS['attachment_fault_case']=$case;
}
if(str_starts_with($case,'commit-')) {
    require dirname(__DIR__,2).'/vendor/autoload.php';
    class AttachmentCommitSqlite extends \think\db\connector\Sqlite {
        public function __construct(array $config = []) { $config['type']='sqlite'; parent::__construct($config); }
        public function commit(): void {
            if ($GLOBALS['attachment_fault_case']==='commit-after') { parent::commit(); }
            throw new RuntimeException('Fixture lost COMMIT acknowledgement');
        }
    }
    define('UPLOAD_AUDIT_SQLITE_DRIVER','\\AttachmentCommitSqlite');
    $GLOBALS['attachment_fault_case']=$case;
}
require __DIR__.'/security_audit_upload_identity_db.php';
require __DIR__.'/security_audit_local_attachment_io.php';
use think\facade\Db;
use think\facade\Config;
Config::set(['site'=>['install_dir'=>'/'],'upload'=>['mode'=>'local','thumb'=>1,'thumb_size'=>'10x10,20x20','thumb_type'=>1,'watermark'=>0]],'maccms');
uploadIdentityAdmin();
$from='';
if(str_starts_with($case,'editor-')) {
    $parts=explode('-',$case);$from=$parts[2];
    if(!in_array($from,['ueditor','umeditor','ckeditor','kindeditor','tinymce'],true))throw new RuntimeException('Unknown editor');
    if($parts[1]==='failure'){$GLOBALS['attachment_io_fault']='second-publish';$GLOBALS['attachment_publish_count']=0;}
}
uploadIdentityRequest(['flag'=>'vod','thumb'=>'1','from'=>$from]);
$before=uploadIdentitySnapshot();$stages=glob(sys_get_temp_dir().'/maccms-attachment-*');
if($case==='permissions') {mkdir('upload/vod/'.date('Ymd').'-1',0755,true);chmod('upload/vod/'.date('Ymd').'-1',0555);$before=uploadIdentitySnapshot();}
$GLOBALS['upload_identity_before_cleanup']=static function () use($case,$before,$stages): void {
    try {
        if($case==='permissions')chmod('upload/vod/'.date('Ymd').'-1',0755);
        $after=uploadIdentitySnapshot();$newStages=array_values(array_diff(glob(sys_get_temp_dir().'/maccms-attachment-*'),$stages));
        if(str_starts_with($case,'editor-success-')) {
            check(Db::name('Annex')->count()===3,'Editor responded before all metadata committed');
            check($before[0]===$after[0],'Editor changed user metadata');
            foreach(Db::name('Annex')->select()->toArray() as $row)check((int)$row['annex_size']===filesize($row['annex_file']),'Editor returned a partial file set');
        } elseif(str_starts_with($case,'commit-')) {
            check(count($newStages)===1,'Unknown COMMIT lost its reconciliation manifest');
            $manifest=json_decode(file_get_contents($newStages[0].'/manifest.json'),true,512,JSON_THROW_ON_ERROR);
            check($manifest['state']==='commit_outcome_unknown','Unknown COMMIT incorrectly marked as completed');
            check(Db::name('Annex')->count()===($case==='commit-after'?3:0),'Fault fixture did not exercise intended commit outcome');
            foreach($manifest['files'] as $row)check(is_file($row['annex_file']) && filesize($row['annex_file'])===$row['annex_size'],'Unknown COMMIT deleted a possibly referenced file');
        } else {
            check($before===$after,'Rejected metadata/write operation changed existing files or DB');
        }
        if(!str_starts_with($case,'commit-'))check($newStages===[],'Editor exit or failure skipped staging cleanup');
        fwrite(STDERR,'attachment worker passed: '.$case."\n");
    } finally {
        // Only this fixture's explicitly recorded ambiguous manifests; production retains them for inspection.
        foreach(array_diff(glob(sys_get_temp_dir().'/maccms-attachment-*'),$stages) as $stage)audit_remove_temp($stage);
    }
};
$result=uploadIdentityController('admin');
check(($result['code']??null)===0,'Fault operation was acknowledged as successful');
echo json_encode($result,JSON_THROW_ON_ERROR);
