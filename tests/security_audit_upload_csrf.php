<?php
/** Real Cookie/JWT/admin models and UploadedFile writes behind the upload CSRF boundary. */
declare(strict_types=1);
require __DIR__.'/fixtures/security_audit_upload_identity_db.php';
use app\common\model\Upload;
use app\common\util\JwtService;

uploadIdentityMember();
foreach ([null, '', 'wrong', [], ['nested'=>'upload-identity-csrf'], str_repeat('x',129)] as $value) {
    uploadIdentityRequest([], 'POST', true, ['X-CSRF-Token'=>$value]);
    uploadIdentityDenied(fn() => (new Upload())->upload(), 'Missing/malformed header allowed cookie upload');
}
foreach ([null, '', 'wrong', [], ['nested'=>'upload-identity-csrf'], str_repeat('x',129)] as $value) {
    uploadIdentityRequest(['csrf_token'=>$value], 'POST', true, ['X-CSRF-Token'=>null]);
    uploadIdentityDenied(fn() => uploadIdentityController('member'), 'Missing/malformed form token allowed portrait upload');
}
foreach (['', 'wrong', ['upload-identity-csrf']] as $value) {
    uploadIdentityRequest(['csrf_token'=>'upload-identity-csrf'], 'POST', true, ['X-CSRF-Token'=>$value]);
    uploadIdentityDenied(fn() => (new Upload())->upload(), 'Invalid explicit header fell back to a valid form token');
}
uploadIdentityRequest([], 'POST', true, ['X-CSRF-Token'=>null, 'origin'=>'https://fixture.invalid', 'referer'=>'https://fixture.invalid/']);
request()->withGet(['csrf_token'=>'upload-identity-csrf']);
$GLOBALS['upload_cookies']['csrf_token'] = 'upload-identity-csrf';
uploadIdentityDenied(fn() => (new Upload())->upload(), 'Query/cookie/origin was accepted as a token');
foreach ([null, '', [], str_repeat('x',129)] as $expected) {
    uploadIdentityRequest();
    $GLOBALS['upload_session']['__csrf_token__'] = $expected;
    uploadIdentityDenied(fn() => (new Upload())->upload(), 'Missing/malformed server session token accepted');
}
foreach ([['X-CSRF-Token'=>'upload-identity-csrf'], ['X-CSRF-Token'=>null]] as $headers) {
    uploadIdentityRequest(['csrf_token'=>'upload-identity-csrf'], 'POST', true, $headers);
    check(uploadIdentityController('member')['code'] === 1, 'Valid token failed ordinary portrait upload');
}
$base64 = 'data:image/png;base64,'.base64_encode(file_get_contents('source.png'));
uploadIdentityRequest(['imgdata'=>$base64], 'POST', false, ['X-CSRF-Token'=>null]);
uploadIdentityDenied(fn() => (new Upload())->upload(), 'Base64 bypassed cookie CSRF');
uploadIdentityRequest(['imgdata'=>$base64, 'csrf_token'=>'upload-identity-csrf'], 'POST', false, ['X-CSRF-Token'=>null]);
check((new Upload())->upload()['code'] === 1, 'Valid form-token base64 portrait failed');

$jwt = JwtService::encode(1, md5('upload-random-1'));
$GLOBALS['upload_cookies'] = [];
uploadIdentityRequest([], 'POST', true, ['authorization'=>'Bearer '.$jwt, 'X-CSRF-Token'=>null]);
$GLOBALS['upload_session'] = [];
check((new Upload())->upload()['code'] === 1, 'Verified enabled Bearer incorrectly required cookie CSRF');
uploadIdentityMember();
uploadIdentityRequest([], 'POST', true, ['authorization'=>'Bearer '.$jwt.'x']);
uploadIdentityDenied(fn() => (new Upload())->upload(), 'Invalid Bearer fell back to valid cookie and CSRF');
$GLOBALS['config']['app']['api_jwt_enabled']='0';
uploadIdentityRequest([], 'POST', true, ['authorization'=>'Bearer '.$jwt, 'X-CSRF-Token'=>null]);
uploadIdentityDenied(fn() => (new Upload())->upload(), 'Disabled Bearer bypassed cookie CSRF');
$GLOBALS['config']['app']['api_jwt_enabled']='1';

uploadIdentityAdmin();
foreach ([['X-CSRF-Token'=>null], ['X-CSRF-Token'=>'wrong'], ['X-CSRF-Token'=>null, 'authorization'=>'Bearer '.$jwt]] as $headers) {
    uploadIdentityRequest(['flag'=>'vod'], 'POST', true, $headers);
    uploadIdentityDenied(fn() => uploadIdentityController('admin'), 'Admin cookie upload bypassed CSRF (including member Bearer)');
}
uploadIdentityRequest(['flag'=>'vod', 'csrf_token'=>'upload-identity-csrf'], 'POST', true, ['X-CSRF-Token'=>null]);
check(uploadIdentityController('admin')['code'] === 1, 'Native admin form token failed');
printf("Upload CSRF: %d checks passed (%s, %s)\n", $checks, PHP_VERSION, $mysql ? 'MySQL' : 'SQLite');
