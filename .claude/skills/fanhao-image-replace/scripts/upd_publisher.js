/**
 * 改 ffcore 发布程序里番号任务(fhm3u8)的域名配置。
 *
 *   node upd_publisher.js <旧域名> <新域名> [--field=picDomain|playDomain|all] [--apply]
 *
 * 默认 --field=all:配置里任何字段含旧域名都替换(picDomain / playDomain / targetProvideApi …)。
 * 在发布机 216.180.225.138 上跑,cwd 需为 /home/dev/ffcore。
 *
 * 为什么必须做这一步:改库只管存量,今后每一批新内容的封面/播放域名由这份配置决定 ——
 * 不改的话下一轮跑批(北京时间 14:20)又全带回旧域名。
 *
 * 注意:配置存在 SQLite(server/data/ffcore.db 的 tasks 表),不是 seed/legacy-config.json,
 * 改那个 JSON 没有任何效果。服务每轮 SELECT * FROM tasks WHERE id=? 读,改库即生效,无需重启。
 */
const fs = require('fs');
const Database = require('/home/dev/ffcore/node_modules/better-sqlite3');

const DB_PATH = '/home/dev/ffcore/server/data/ffcore.db';
const TASK_NAME = 'fhm3u8';

const args = process.argv.slice(2);
const OLD = args[0];
const NEW = args[1];
const APPLY = args.includes('--apply');
const fieldArg = (args.find(a => a.startsWith('--field=')) || '--field=all').split('=')[1];

if (!OLD || !NEW) {
  console.error('用法: node upd_publisher.js <旧域名> <新域名> [--field=picDomain|playDomain|all] [--apply]');
  process.exit(1);
}
if (OLD === NEW) { console.error('新旧相同'); process.exit(1); }

const db = new Database(DB_PATH, { readonly: !APPLY });
const row = db.prepare('SELECT id, name, config FROM tasks WHERE name = ?').get(TASK_NAME);
if (!row) { console.error('找不到任务 ' + TASK_NAME); process.exit(1); }

const cfg = JSON.parse(row.config);
console.log('  任务 id=' + row.id + ' name=' + row.name + '   目标字段: ' + fieldArg);
for (const k of ['picDomain', 'playDomain']) {
  if (k in cfg) console.log('    当前 ' + k + ' = ' + cfg[k]);
}

// 挑出含旧域名、且在目标字段范围内的键
const hits = Object.entries(cfg).filter(([k, v]) =>
  typeof v === 'string' && v.includes(OLD) && (fieldArg === 'all' || k === fieldArg));

if (hits.length === 0) {
  console.log('  配置里(范围 ' + fieldArg + ')没有 ' + OLD + ',无需修改');
  process.exit(0);
}
console.log('  将修改的字段:');
hits.forEach(([k, v]) => console.log('    ' + k + ' : ' + v + '  ->  ' + v.split(OLD).join(NEW)));

if (!APPLY) { console.log('  [预演] 未写入,加 --apply 执行'); process.exit(0); }

const next = { ...cfg };
for (const [k, v] of hits) next[k] = v.split(OLD).join(NEW);

const stamp = new Date().toISOString().replace(/[:.]/g, '').slice(0, 15);
const bk = '/home/dev/ffcore/server/data/task-' + row.id + '-config-backup-' + stamp + '.json';
fs.writeFileSync(bk, row.config);

db.prepare('UPDATE tasks SET config = ?, updated_at = ? WHERE id = ?')
  .run(JSON.stringify(next), Math.floor(Date.now() / 1000), row.id);

const after = JSON.parse(db.prepare('SELECT config FROM tasks WHERE id = ?').get(row.id).config);
hits.forEach(([k]) => console.log('  已写入,复核 ' + k + ' = ' + after[k]));
console.log('  原配置备份 -> ' + bk);
console.log('  下一轮跑批自动生效(每 2 小时一次,真正发布的是北京时间 14:20 那轮)');
