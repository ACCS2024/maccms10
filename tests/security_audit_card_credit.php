<?php
/** Card claim, balance and ledger must succeed or roll back together. */
require __DIR__ . '/fixtures/financial_before_begin.php';
define('MEMBERSHIP_AUDIT_CONNECTION_CLASS', getenv('MEMBERSHIP_AUDIT_MYSQL') === '1' ? FinancialBeforeBeginMysql::class : FinancialBeforeBeginSqlite::class);
require __DIR__ . '/fixtures/security_audit_card_db.php';
use think\facade\Db;
use app\common\model\Card;
use app\common\util\PointsBalance;
function redeemCard($user = null): array { return (new Card())->useData('fixture-card', 'fixture', $user ?? memberRow()); }
cardSeed();
check(redeemCard()['code'] === 1 && memberRow()['user_points'] === 120, 'Valid card redemption failed');
$card = Db::name('Card')->find(1);
check((int)$card['card_use_status'] === 1 && (int)$card['card_sale_status'] === 1 && (int)$card['user_id'] === 1
    && (int)Db::name('Plog')->value('plog_points') === 20 && Db::name('Plog')->count() === 1,
    'Successful card claim and ledger disagree');
$before = cardState();
check(redeemCard()['code'] !== 1 && cardState() === $before, 'A card replay credited a second time');

cardSeed(PointsBalance::MAX - 10);
$before = cardState();
check(redeemCard()['code'] !== 1 && cardState() === $before, 'Card overflow clipped the balance or consumed the card');
cardSeed(PointsBalance::MAX - 20);
check(redeemCard()['code'] === 1 && memberRow()['user_points'] === PointsBalance::MAX
    && (int)Db::name('Plog')->value('plog_points') === 20, 'Exact-capacity card redemption failed');
cardSeed();
$before = cardState();
check(redeemCard(['user_id'=>999])['code'] !== 1 && cardState() === $before, 'Missing recipient consumed a valid card');

foreach (['validation','throwable'] as $failure) {
    cardSeed();
    $GLOBALS[$failure === 'validation' ? 'member_fail_log_types' : 'member_throw_log_types'] = [1];
    $before = cardState();
    $result = redeemCard();
    check($result['code'] !== 1 && !str_contains($result['msg'], 'fixture') && cardState() === $before,
        'Ledger failure escaped, leaked internals, or committed a partially redeemed card');
    $GLOBALS['member_fail_log_types'] = $GLOBALS['member_throw_log_types'] = [];
    check(redeemCard()['code'] === 1 && memberRow()['user_points'] === 120, 'Rolled-back card could not be retried successfully');
}

// A concurrent winner can claim the card for another user, never once per caller.
cardSeed();
$GLOBALS['financial_before_begin'] = static function (): void {
    check(redeemCard(memberRow(2))['code'] === 1, 'Concurrent card winner failed');
    $GLOBALS['card_winner_state'] = cardState();
};
check(redeemCard()['code'] !== 1 && cardState() === $GLOBALS['card_winner_state'], 'Concurrent losing redemption left a second claim or ledger');
check(memberRow()['user_points'] === 100 && memberRow(2)['user_points'] === 20, 'Card was credited to both competing users');

// Legacy schemas allow duplicate credentials. Never consume multiple cards or choose one arbitrarily.
foreach ([0,1] as $otherStatus) {
    cardSeed();
    Db::name('Card')->insert(['card_id'=>2,'card_no'=>'fixture-card','card_pwd'=>'fixture','card_points'=>30,'card_use_status'=>$otherStatus]);
    $before = cardState();
    check(redeemCard()['code'] !== 1 && cardState() === $before, 'Ambiguous duplicate card credentials were redeemed');
}
cardSeed(100, 0);
$before = cardState();
check(redeemCard()['code'] !== 1 && cardState() === $before, 'Zero-point card was consumed as a successful recharge');

foreach ([[['fixture-card'],'fixture', ['user_id'=>1]], ['fixture-card',['fixture'], ['user_id'=>1]],
    ['fixture-card','fixture',[]], ['fixture-card','fixture',['user_id'=>[1]]], ['fixture-card','fixture',['user_id'=>true]],
    [str_repeat('x',17),'fixture',['user_id'=>1]], ['fixture-card',str_repeat('x',9),['user_id'=>1]],
    ['fixture-card','wrong',['user_id'=>1]], ['','fixture',['user_id'=>1]]] as [$code,$password,$recipientInput]) {
    cardSeed();
    $before = cardState();
    check((new Card())->useData($code,$password,$recipientInput)['code'] !== 1 && cardState() === $before,
        'Malformed credentials/recipient caused an exception, coercion or card mutation');
}
echo "card credit audit: $checks checks passed on PHP " . PHP_VERSION . ($mysql ? ' / MySQL non-strict' : ' / SQLite') . "\n";
