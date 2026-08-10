<?php

use think\facade\Route;

// ── PPVOD 入库接口的历史入口兼容 ────────────────────────────────────────
// 控制器已由 Yzm 更名为 Ppvod，但转码机侧长期配置的是
//   POST /api.php/yzm/yzmauto?ac=yzm&pass=...
// 保留该别名，避免改名当天入库静默中断。
// 待转码机改指到 /api.php/ppvod/ingest 之后，本文件可整体删除。
//
// 注意：多应用模式下路由文件必须放在 application/<应用>/route/ 下，
// 根目录的 route/api.php 不会被 api 应用加载（前台同理用
// application/index/route/web.php）。
Route::any('yzm/yzmauto', 'ppvod/yzmauto');
Route::any('yzm/ingest', 'ppvod/ingest');
