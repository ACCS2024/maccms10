-- Dedicated disposable HTTP fixture, loaded after install.sql and initdata.sql.
SET SESSION sql_mode='';
INSERT INTO mac_vod (vod_id,type_id,vod_name,vod_status,vod_time,vod_letter,vod_play_from,vod_play_url,vod_content)
VALUES (1,6,'CI Smoke Vod',1,UNIX_TIMESTAMP(),'C','mac_test','01$https://media.invalid/1.m3u8','测试内容');
INSERT INTO mac_art (art_id,type_id,art_name,art_status,art_time,art_letter,art_content)
VALUES (1,2,'CI Smoke Art',1,UNIX_TIMESTAMP(),'C','测试文章');
INSERT INTO mac_actor (actor_id,type_id,actor_name,actor_status,actor_time,actor_letter,actor_content)
VALUES (1,8,'CI Actor',1,UNIX_TIMESTAMP(),'C','测试人物');
INSERT INTO mac_topic (topic_id,topic_name,topic_status,topic_time,topic_en,topic_content)
VALUES (1,'CI Topic',1,UNIX_TIMESTAMP(),'ci','测试专题');
INSERT INTO mac_admin (admin_id,admin_name,admin_pwd,admin_status,admin_auth)
VALUES (1,'admin',MD5('admin888'),1,'');

INSERT INTO mac_user (user_id,user_name,user_pwd,user_status,group_id,user_random)
VALUES (1,'CI Smoke User',MD5('fixture-password'),1,2,'fixture-user-random');
