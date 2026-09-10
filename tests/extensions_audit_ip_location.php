<?php
/** Preserve the embedded IPv4 lookup while rejecting malformed values before PHP string operations. */
declare(strict_types=1);
require dirname(__DIR__).'/vendor/autoload.php';
require __DIR__.'/fixtures/security_audit_test_helpers.php';
$query=new \ip_limit\IpLocationQuery();
foreach ([null,[],['1.0.1.0'],true,false,1,1.5,new stdClass(),'','1.0.1.junk','1.0.1.1x',
    '1.0.1.1e2','1.0.1.+1','1.0.1.01','1.0.1. 1','1.0.1.-1','1.0.1.256','1.0.1',
    '1.0.1.1.1',"1.0.1.1\n",'::1','2001:db8::1','::ffff:1.0.1.0','0x01000100'] as $invalid) {
    check($query->queryProvince($invalid)==='','Malformed input cannot acquire a province by integer coercion or trigger a PHP 8 type error');
}
foreach (['1.0.1.0','1.0.2.17','1.0.3.255'] as $ip) {
    check($query->queryProvince($ip)==='福建','Valid embedded range endpoints and interior retain their existing lookup');
}
foreach (['0.0.0.0','1.0.0.255','1.0.4.0','255.255.255.255'] as $ip) {
    check($query->queryProvince($ip)==='','Addresses outside these embedded ranges remain unknown');
}
$rows=(new ReflectionProperty($query,'ipData'))->getValue($query);$map=$query->getProvinceMap();
$end=-1;$valid=true;$unknownSafe=true;$unknownCount=0;
foreach ($rows as $row) {
    if (count($row)!==3 || !is_int($row[0]) || !is_int($row[1]) || $row[0]<0 || $row[0]<=$end
        || $row[0]>$row[1] || $row[1]>4294967295 || (!isset($map[$row[2]]) && $row[2] !== 'UNK')) { $valid=false;break; }
    if ($row[2] === 'UNK') { ++$unknownCount; $unknownSafe = $unknownSafe && $query->queryProvince(long2ip($row[0])) === ''; }
    $end=$row[1];
}
check($rows!==[] && $valid && $query->getIpDataCount()===count($rows),'All embedded ranges satisfy the binary-search ordering, bounds and province-key requirements');
check($unknownCount===18 && $unknownSafe,'Explicit UNK ranges keep their existing unknown province instead of an invented geographic assignment');
echo "IPv4 location audit: $checks checks passed on PHP ".PHP_VERSION.'; '.count($rows)." embedded ranges inspected\n";
