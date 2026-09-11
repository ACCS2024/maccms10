<?php
declare(strict_types=1);
namespace app\common\util;

/** Opt-in transfer contract. Existing Upload::api/adapter callers are deliberately unchanged. */
final class StorageTransfer
{
    public static function attempt(string $id): array
    {
        $row=StorageIntent::inspect($id);
        $policy=StoragePublicUrl::current($row['provider']);
        $row=StorageIntent::claim($id,$policy); // A failed/uncertain claim never reaches the provider.
        $remote=null;$reason='invalid_result';
        try {
            $class='app\\common\\extend\\upload\\'.ucfirst($policy->provider);
            // The legacy provider receives the immutable local object and cannot eagerly delete it on normal success.
            $reply=(new $class(['mode'=>$policy->provider,'keep_local'=>1]))->submit($row['local_path'], true);
            if ($reply===$row['local_path']) {$reason='local_fallback';}
            elseif (is_string($reply)) {
                if ($policy->accepts($reply,$row['local_path'])) {$remote=$reply;$reason='remote_confirmed';}
                else {$reason='invalid_url';}
            }
        } catch (\Throwable $error) {$reason='provider_exception';}
        $localAvailable=true;
        try {StorageIntent::sameSource($row);}catch(\Throwable $error){$localAvailable=false;}
        try {
            $saved=StorageIntent::finish($id,$policy,$remote,!$localAvailable?'source_changed':$reason);
        } catch (\Throwable $error) {
            // The independent pre-call record remains inspectable, even if the database is now unavailable.
            // A returned random object URL may be unknown after a crash/outage: never invent a remote rollback.
            error_log('Storage result not durably recorded; inspect intent '.$id);
            $result = ['intent_id'=>$id,'outcome'=>'unrecorded','file'=>$localAvailable?$row['local_path']:null,'remote_confirmed'=>false];
            if ($error instanceof StorageOutcomeUnknown) { $result['transaction'] = $error->details; }
            return $result;
        }
        return ['intent_id'=>$id,'outcome'=>!$localAvailable?'unavailable':($remote!==null?'remote':'local_fallback'),
            'file'=>!$localAvailable?null:($remote??$row['local_path']),'remote_confirmed'=>$localAvailable&&$saved['transfer_state']==='remote_confirmed'];
    }
}
