<?php
/** Provenance is granted only at authenticated creation and cannot be reassigned by ordinary edits. */
require __DIR__ . '/fixtures/security_audit_comment_submission_db.php';
use app\common\model\Comment;
use think\facade\Db;
if (!$mysql) {
    Db::execute('ALTER TABLE audit_comment ADD COLUMN comment_reward_verified INTEGER NOT NULL DEFAULT 0');
}
$body = ['comment_mid'=>1,'comment_rid'=>1,'comment_content'=>'Verified comment'];
function verifiedCommentCreate(string $entry = 'api'): array {
    commentSeed(); commentLogin();
    $GLOBALS['config']['comment']['audit'] = '1';
    $result = publicComment($entry, $GLOBALS['body'] + ['comment_reward_verified'=>0]);
    check($result['code'] === 1, 'Authenticated comment creation failed before provenance checks');
    return commentRows()[1];
}
foreach (['index','api'] as $entry) {
    $created = verifiedCommentCreate($entry);
    check((int)$created['comment_reward_verified'] === 1 && (int)$created['comment_status'] === 0,
        "$entry did not attest the authenticated creator while keeping moderation pending");
    check((int)commentRows()[0]['comment_reward_verified'] === 0, 'A legacy comment was automatically promoted');
    commentSeed();
    check(publicComment($entry, $body + ['user_id'=>1,'comment_reward_verified'=>1])['code'] === 1
        && (int)commentRows()[1]['comment_reward_verified'] === 0, "$entry guest forged a reward attestation");
}
$admin = ['comment_mid'=>1,'comment_rid'=>1,'comment_pid'=>0,'user_id'=>1,'comment_name'=>'admin supplied',
    'comment_content'=>'Ordinary administrative comment','comment_reward_verified'=>1];
commentSeed();
check((new Comment())->saveData($admin)['code'] === 1 && (int)commentRows()[1]['comment_reward_verified'] === 0,
    'Ordinary model creation accepted a client-controlled verified flag');
$legacy = commentRows()[0]; $legacy['comment_reward_verified'] = 1;
check((new Comment())->saveData($legacy)['code'] === 1 && (int)Db::name('Comment')->find(1)['comment_reward_verified'] === 0,
    'Administrative edit retroactively verified a historical comment');
$before = commentRows();
check((new Comment())->fieldData(['comment_id'=>1], 'comment_reward_verified', 1)['code'] !== 1 && commentRows() === $before,
    'Generic field update changed the server-owned verification flag');
check((new Comment())->saveData($legacy, true)['code'] !== 1 && commentRows() === $before,
    'Trusted create parameter allowed an existing row to be promoted');
foreach (['COMMENT_REWARD_VERIFIED','Comment_Reward_Verified','`comment_reward_verified`','comment.comment_reward_verified',
    ' comment_reward_verified', ['comment_reward_verified'], 1] as $column) {
    check((new Comment())->fieldData(['comment_id'=>1],$column,1)['code'] !== 1 && commentRows() === $before,
        'Case variants or malformed column names bypassed the protected provenance field');
}
$legacy = Db::name('Comment')->find(1);
unset($legacy['comment_reward_verified']);
check((new Comment())->saveData($legacy + ['COMMENT_REWARD_VERIFIED'=>1])['code'] === 1
    && (int)Db::name('Comment')->find(1)['comment_reward_verified'] === 0,
    'Uppercase marker in a full model update promoted a historical comment');
foreach (['audit_comment.comment_reward_verified','`comment_reward_verified`','comment_reward_verified->value'] as $key) {
    $before = commentRows();
    check((new Comment())->saveData($legacy + [$key=>1])['code'] !== 1 && commentRows() === $before,
        'Qualified/JSON column syntax bypassed the ordinary saveData provenance boundary');
}
$before = commentRows();
check((new Comment())->saveData($legacy + ['USER_ID'=>2])['code'] !== 1 && commentRows() === $before,
    'Duplicate case-insensitive field names were ambiguously accepted');

$created = verifiedCommentCreate(); $id = (int)$created['comment_id'];
check((new Comment())->fieldData(['comment_id'=>$id], 'comment_status', 1)['code'] === 1
    && (int)Db::name('Comment')->find($id)['comment_reward_verified'] === 1,
    'Approval discarded the authenticated creation provenance');
$unchanged = Db::name('Comment')->find($id); $unchanged['comment_reward_verified'] = 0;
check((new Comment())->saveData($unchanged)['code'] === 1 && (int)Db::name('Comment')->find($id)['comment_reward_verified'] === 1,
    'Submitting unchanged evidence revoked provenance or respected the client-supplied flag');
foreach (['user_id'=>2,'comment_time'=>1,'comment_content'=>'Altered content','comment_mid'=>2,'comment_rid'=>2,'comment_pid'=>1] as $field=>$value) {
    $created = verifiedCommentCreate();
    $created[$field] = $value; $created['comment_reward_verified'] = 1;
    check((new Comment())->saveData($created)['code'] === 1
        && (int)Db::name('Comment')->find($created['comment_id'])['comment_reward_verified'] === 0,
        "Editing $field retained or restored trusted reward evidence");
    $created = verifiedCommentCreate();
    check((new Comment())->fieldData(['comment_id'=>$created['comment_id']],$field,$value)['code'] === 1
        && (int)Db::name('Comment')->find($created['comment_id'])['comment_reward_verified'] === 0,
        "Bulk editing $field retained trusted reward evidence");
    $created = verifiedCommentCreate();
    check((new Comment())->fieldData(['comment_id'=>$created['comment_id']],strtoupper($field),$value)['code'] === 1
        && (int)Db::name('Comment')->find($created['comment_id'])['comment_reward_verified'] === 0,
        "Uppercase bulk editing $field retained trusted reward evidence");
    $created = verifiedCommentCreate();
    unset($created[$field]);
    $created[strtoupper($field)] = $value;
    check((new Comment())->saveData($created)['code'] === 1
        && (int)Db::name('Comment')->find($created['comment_id'])['comment_reward_verified'] === 0,
        "Uppercase full update of $field retained trusted reward evidence");
}
// An unmigrated database keeps accepting ordinary comments; it cannot manufacture the missing marker.
if ($mysql) { Db::execute('ALTER TABLE audit_comment DROP INDEX comment_reward_user'); }
Db::execute('ALTER TABLE audit_comment DROP COLUMN comment_reward_verified');
$manager->connect()->getSchemaInfo('audit_comment', true);
check(!(new Comment())->supportsRewardVerification(), 'Old-schema capability detection invented provenance support');
foreach (['index','api'] as $entry) {
    commentSeed(); commentLogin();
    check(publicComment($entry,$body + ['comment_reward_verified'=>1])['code'] === 1
        && !array_key_exists('comment_reward_verified',commentRows()[1]),
        "$entry stopped working on an unmigrated database or invented a provenance marker");
}
echo "comment provenance audit: $checks checks passed on PHP " . PHP_VERSION . ($mysql ? ' / MySQL' : ' / SQLite') . "\n";
