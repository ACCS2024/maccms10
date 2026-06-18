<?php
return [
    'commands' => [
        'admin:reset-password' => \app\command\AdminResetPassword::class,
        'cache:flush'          => \app\command\CacheFlush::class,
        'db:export'            => \app\command\DbExport::class,
        'db:import'            => \app\command\DbImport::class,
        'db:search-replace'    => \app\command\DbSearchReplace::class,
        'info'                 => \app\command\Info::class,
        'seo:ai-generate'      => \app\command\SeoAiGenerate::class,
        'site:destroy'         => \app\command\SiteDestroy::class,
        'site:install'         => \app\command\SiteInstall::class,
        'tune'                 => \app\command\Tune::class,
    ],
];
