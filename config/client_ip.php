<?php
return [
    // Exact proxy IPs/CIDRs only; an empty list trusts no forwarded request headers.
    'trusted_proxies' => env('CLIENT_IP_TRUSTED_PROXIES', ''),
    // Choose the single header that the configured proxy overwrites or safely appends.
    'forwarded_header' => env('CLIENT_IP_FORWARDED_HEADER', 'x-forwarded-for'),
];
