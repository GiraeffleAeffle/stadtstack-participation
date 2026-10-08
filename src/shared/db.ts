import { DatabaseSync } from "node:sqlite";

/**
 * Open the module database. Both the issuer and the participation lane add
 * their tables to the same file through their own idempotent `migrate(db)`.
 */
export function openDatabase(path: string): DatabaseSync {
  const db = new DatabaseSync(path);
  db.exec("PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;");
  if (path !== ":memory:") db.exec("PRAGMA journal_mode = WAL;");
  return db;
}

export type { DatabaseSync };
