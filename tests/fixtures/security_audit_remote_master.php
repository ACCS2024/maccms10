<?php
/** Real Think ORM read/write routing to two explicit fixture databases on the same isolated MySQL server. */
use think\facade\Db;
$originalManager=think\Container::getInstance()->make('think\\DbManager');$masterConnection=Db::connect();
$masterConnection->execute('CREATE DATABASE IF NOT EXISTS maccms_audit_remote_upload_read CHARACTER SET utf8mb4');
foreach(['annex','user','storage_intent'] as $table) {
    $masterConnection->execute('DROP TABLE IF EXISTS maccms_audit_remote_upload_read.upload_audit_'.$table);
    $masterConnection->execute('CREATE TABLE maccms_audit_remote_upload_read.upload_audit_'.$table.' LIKE maccms_audit_remote_upload.upload_audit_'.$table);
}
$host=getenv('REMOTE_UPLOAD_AUDIT_HOST')?:'127.0.0.1';
$splitConfiguration=$configuration;
$splitConfiguration['connections']['upload']=array_replace($configuration['connections']['upload'],[
    'deploy'=>1,'rw_separate'=>true,'master_num'=>1,'slave_no'=>1,'hostname'=>$host.','.$host,
    'database'=>'maccms_audit_remote_upload,maccms_audit_remote_upload_read',
]);
$splitManager=new think\DbManager();$splitManager->setConfig($splitConfiguration);
think\Container::getInstance()->instance('think\\DbManager',$splitManager);
try {
    $connection=Db::connect();
    check($connection->query('SELECT DATABASE() AS db',[],true)[0]['db']==='maccms_audit_remote_upload'
        && $connection->query('SELECT DATABASE() AS db',[],false)[0]['db']==='maccms_audit_remote_upload_read','Fixture did not exercise actual master/reader routing');
    foreach(['annex','user'] as $table) {
        $masterConnection->execute('ALTER TABLE upload_audit_'.$table.' ENGINE=MyISAM');
        try {
            $query='SELECT ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=?';
            check($connection->query($query,['upload_audit_'.$table],true)[0]['ENGINE']==='MyISAM'
                && $connection->query($query,['upload_audit_'.$table],false)[0]['ENGINE']==='InnoDB','Fixture did not create different master/reader engines');
            $calls=$GLOBALS['storage_provider_calls'];$before=$masterConnection->name('Annex')->select()->toArray();
            try {
                app\common\util\LocalAttachment::storeAvatar(['flag'=>'user','thumb'=>'0','thumb_class'=>'','input'=>'file',
                    'imgdata'=>'data:image/png;base64,'.base64_encode(file_get_contents('source.png'))],['mode'=>'s3'],1,true);
                $rejected=false;
            } catch(Throwable $error){$rejected=true;}
            check($rejected && $GLOBALS['storage_provider_calls']===$calls && $masterConnection->name('Annex')->select()->toArray()===$before,
                'InnoDB reader masked a nontransactional '.$table.' master before an external write');
        } finally {$masterConnection->execute('ALTER TABLE upload_audit_'.$table.' ENGINE=InnoDB');}
    }
    $connection->query('SELECT 1',[],true);$masterPdo=$connection->getPdo();$masterPdo->beginTransaction();
    $connection->query('SELECT 1',[],false);$calls=$GLOBALS['storage_provider_calls'];
    try {
        try {
            app\common\util\LocalAttachment::storeAvatar(['flag'=>'user','thumb'=>'0','thumb_class'=>'','input'=>'file',
                'imgdata'=>'data:image/png;base64,'.base64_encode(file_get_contents('source.png'))],['mode'=>'s3'],1,true);
            $rejected=false;
        } catch(Throwable $error){$rejected=true;}
        check($rejected && $masterPdo->inTransaction() && $GLOBALS['storage_provider_calls']===$calls,
            'Switching to a reader hid an existing raw master transaction');
    } finally {$masterPdo->rollBack();}
} finally {think\Container::getInstance()->instance('think\\DbManager',$originalManager);}
