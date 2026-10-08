import { DatabaseSync, backup } from 'node:sqlite';
import { chmodSync, readdirSync, renameSync, rmSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { join } from 'node:path';

process.umask(0o077);
process.env.SQLITE_TMPDIR = '/backups';
const pattern = /^participation-\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}-\d{3}Z-[a-f0-9-]{36}\.sqlite$/;
for (const name of readdirSync('/backups')) {
  if (name.endsWith('.partial') && pattern.test(name.slice(0, -8))) rmSync(join('/backups', name));
}
const name = `participation-${new Date().toISOString().replaceAll(':', '-').replace('.', '-')}-${randomUUID()}.sqlite`;
const partial = join('/backups', `${name}.partial`);
const source = new DatabaseSync('/data/participation.sqlite', { readOnly: true });
try {
  source.exec('PRAGMA busy_timeout=5000');
  await backup(source, partial);
  const snapshot = new DatabaseSync(partial);
  try {
    snapshot.exec('PRAGMA journal_mode=DELETE');
    const rows = snapshot.prepare('PRAGMA integrity_check').all();
    if (rows.length !== 1 || rows[0].integrity_check !== 'ok') throw new Error('Snapshot integrity_check failed');
  } finally { snapshot.close(); }
  chmodSync(partial, 0o600);
  renameSync(partial, join('/backups', name));
  const snapshots = readdirSync('/backups').filter(entry => pattern.test(entry)).sort().reverse();
  for (const expired of snapshots.slice(28)) rmSync(join('/backups', expired));
  console.log(`Verified snapshot ${name}; retained ${Math.min(snapshots.length, 28)}`);
} finally {
  source.close();
  rmSync(partial, { force: true });
}
