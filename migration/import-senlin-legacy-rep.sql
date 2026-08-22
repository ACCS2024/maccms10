-- Import the two replacement notices formerly hard-coded in the legacy site.
-- The target values were verified as active before marking the records applied.

START TRANSACTION;

INSERT INTO mac_rep (
    rep_type,
    rep_original,
    rep_replacement,
    rep_note,
    rep_status,
    rep_applied,
    rep_applied_time,
    rep_create_time
)
SELECT
    '视频播放地址',
    'https://vip4.bbffsl.com/',
    'https://v5.slv525627.com/',
    '从旧站 replace.html 迁移',
    1,
    1,
    1760976000,
    1760976000
WHERE NOT EXISTS (
    SELECT 1
    FROM mac_rep
    WHERE rep_type = '视频播放地址'
      AND rep_original = 'https://vip4.bbffsl.com/'
      AND rep_replacement = 'https://v5.slv525627.com/'
);

INSERT INTO mac_rep (
    rep_type,
    rep_original,
    rep_replacement,
    rep_note,
    rep_status,
    rep_applied,
    rep_applied_time,
    rep_create_time
)
SELECT
    '播放器替换',
    'https://sljxsl.com/?url=',
    'https://slslplay.com/?url=',
    '从旧站 replace.html 迁移',
    1,
    1,
    1760976000,
    1760976000
WHERE NOT EXISTS (
    SELECT 1
    FROM mac_rep
    WHERE rep_type = '播放器替换'
      AND rep_original = 'https://sljxsl.com/?url='
      AND rep_replacement = 'https://slslplay.com/?url='
);

COMMIT;
