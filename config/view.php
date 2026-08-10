<?php
return [
    'type'               => 'Think',
    'view_path'          => '',
    'view_suffix'        => 'html',
    'view_depr'          => DIRECTORY_SEPARATOR,
    'tpl_begin'          => '{',
    'tpl_end'            => '}',
    'taglib_begin'       => '{',
    'taglib_end'         => '}',
    'taglib_pre_load'    => 'app\\common\\taglib\\Maccms',
    'tpl_cache'          => true,
    'cache_path'         => '',
    'cache_suffix'       => 'php',
    'cache_prefix'       => '',
    'display_cache'      => false,
    'cache_id'           => '',
    'tpl_deny_func_list' => 'echo,exit,die',
    'tpl_deny_php'       => false,

    // 普通标签 {$var} 的默认输出过滤器。必须显式置空。
    //
    // think-template 自身的默认值是 'htmlentities'(Template.php 的 $config)，
    // 而 TP5 时代 maccms 是在 application/config.php 里设成 '' 的 —— 那个文件在 TP8
    // 下不再被加载，于是默认值回到 htmlentities，编译产物变成：
    //     echo htmlentities((string) $extends['ext_html']);
    // 后果是全站每一个 {$var} 都被转义。凡是变量里装着 HTML 的地方，源码直接打到页面上
    // (附件配置的第三方存储表单 {$extends['ext_html']}、URL 配置的百度推送 tab 等)；
    // 装文本的地方则会冒出 &quot; &amp; &#039;，在 <script> 里的字符串还会直接坏掉
    // (PHP 8.1 起 htmlentities 默认带 ENT_QUOTES，单引号也转)。
    //
    // 置空即恢复 TP5/上游 maccms 的语义，也是整套模板编写时的前提。
    // 代价是没有自动转义兜底 —— 但这与老站/上游行为一致，不是本次迁移引入的新风险；
    // 需要转义的地方模板里本来就用 mac_replace_text 等显式处理。
    'default_filter'     => '',
];
