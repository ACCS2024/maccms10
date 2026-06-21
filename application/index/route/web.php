<?php

use think\facade\Route;

Route::any('sitehome', 'index/home');
Route::any('publish-<id>', 'index/publish_group');

Route::any('map', 'map/index');
Route::any('rss', 'rss/index');

Route::any('index-<page?>', 'index/index');

Route::any('gbook-<page?>', 'gbook/index');
Route::any('gbook$', 'gbook/index');

Route::any('topic-<page?>', 'topic/index');
Route::any('topic$', 'topic/index');
Route::any('topicdetail-<id>', 'topic/detail');

Route::any('actor-<page?>', 'actor/index');
Route::any('actor$', 'actor/index');
Route::any('actordetail-<id>', 'actor/detail');
Route::any('actorshow/<area?>-<blood?>-<by?>-<letter?>-<level?>-<order?>-<page?>-<sex?>-<starsign?>', 'actor/show');

Route::any('role-<page?>', 'role/index');
Route::any('role$', 'role/index');
Route::any('roledetail-<id>', 'role/detail');
Route::any('roleshow/<by?>-<letter?>-<level?>-<order?>-<page?>-<rid?>', 'role/show');

Route::any('vodtype/<id>-<page?>', 'vod/type');
Route::any('vodtype/<id>', 'vod/type');
Route::any('voddetail/<id>', 'vod/detail');
Route::any('vodrss-<id>', 'vod/rss');
Route::any('vodplay/<id>-<sid>-<nid>', 'vod/play');
Route::any('voddown/<id>-<sid>-<nid>', 'vod/down');
Route::any('vodshow/<id>', 'vod/show')->pattern(['id' => '[^-]+']);
Route::any('vodshow/<id>-<area?>-<by?>-<class?>-<lang?>-<letter?>-<level?>-<order?>-<page?>-<state?>-<tag?>-<year?>', 'vod/show');
Route::any('vodsearch/<wd>', 'vod/search')->pattern(['wd' => '[^-]+']);
Route::any('vodsearch/<wd?>-<actor?>-<area?>-<by?>-<class?>-<director?>-<lang?>-<letter?>-<level?>-<order?>-<page?>-<state?>-<tag?>-<year?>', 'vod/search');
Route::any('vodplot/<id>-<page?>', 'vod/plot');
Route::any('vodplot/<id>', 'vod/plot');

Route::any('arttype/<id>-<page?>', 'art/type');
Route::any('arttype/<id>', 'art/type');
Route::any('artshow-<id>', 'art/show');
Route::any('artdetail-<id>-<page?>', 'art/detail');
Route::any('artdetail-<id>', 'art/detail');
Route::any('artrss-<id>-<page>', 'art/rss');
Route::any('artshow/<id>-<by?>-<class?>-<level?>-<letter?>-<order?>-<page?>-<tag?>', 'art/show');
Route::any('artsearch/<wd?>-<by?>-<class?>-<level?>-<letter?>-<order?>-<page?>-<tag?>', 'art/search');
Route::any('artread/<id>-<page?>', 'art/read');

Route::any('manga-<page?>', 'manga/index');
Route::any('manga$', 'manga/index');
Route::any('mangatype/<id>-<page?>', 'manga/type');
Route::any('mangatype/<id>', 'manga/type');
Route::any('mangadetail-<id>', 'manga/detail');
Route::any('mangaplay/<id>-<sid>-<nid>', 'manga/play');
Route::any('mangadown/<id>-<sid>-<nid>', 'manga/down');
Route::any('mangashow/<id>-<area?>-<by?>-<class?>-<lang?>-<letter?>-<level?>-<order?>-<page?>-<state?>-<tag?>-<year?>', 'manga/show');
Route::any('mangasearch/<wd?>-<actor?>-<area?>-<by?>-<class?>-<director?>-<lang?>-<letter?>-<level?>-<order?>-<page?>-<state?>-<tag?>-<year?>', 'manga/search');

Route::any('label-<file>', 'label/index');

Route::any('liveshow', 'live/show');
Route::any('liveplay/<id>', 'live/play');
