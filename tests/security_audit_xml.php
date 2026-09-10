<?php
// Isolated regression: no application boot, persistent storage or external network.
function config($key) { return $key === 'database.connections.mysql.prefix' ? 'mac_' : null; }
require dirname(__DIR__) . '/application/common.php';
set_error_handler(static function ($severity, $message, $file, $line) {
        if (!(error_reporting() & $severity)) { return false; }
        throw new ErrorException($message, 0, $severity, $file, $line);
    });
    $checks = 0;
    function check($expected, $actual, $label) {
        global $checks;
        if ($expected !== $actual) { throw new RuntimeException('FAIL: ' . $label); }
        ++$checks;
    }
    check(['title' => 'a & b'], mac_xml2array('<xml><title><![CDATA[a & b]]></title></xml>'), 'CDATA parsing preserved');
    foreach (['', [], '<xml>', '<!DOCTYPE xml [<!ENTITY x SYSTEM "file:///etc/passwd">]><xml>&x;</xml>',
        "<xml>\0</xml>"] as $xml) {
        check(null, mac_xml2array($xml), 'malformed XML and entity declarations rejected');
    }
    check(false, libxml_use_internal_errors(), 'XML parser restores previous diagnostic setting');


    echo "XML parsing contracts: {$checks} checks passed on PHP " . PHP_VERSION . "\n";
