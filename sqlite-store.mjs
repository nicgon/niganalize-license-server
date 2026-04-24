import fs from "node:fs/promises";
import fsSync from "node:fs";
import path from "node:path";
import Database from "better-sqlite3";

const DATA_DIR = process.env.DATA_DIR || path.resolve("./data");
fsSync.mkdirSync(DATA_DIR, { recursive: true });

const SQLITE_FILE = path.join(DATA_DIR, "license-server.sqlite");
const LEGACY_JSON_FILE = path.join(DATA_DIR, "data.json");
const MIGRATED_JSON_FILE = path.join(DATA_DIR, "data.migrated.json");

const db = new Database(SQLITE_FILE);
db.pragma("journal_mode = WAL");
db.pragma("synchronous = NORMAL");

db.exec(`
CREATE TABLE IF NOT EXISTS kv_store (
  key TEXT PRIMARY KEY,
  payload TEXT NOT NULL,
  updated_at_utc TEXT NOT NULL
);
`);

function nowIso() {
  return new Date().toISOString();
}

function normalizeDbShape(raw) {
  return {
    devices: Array.isArray(raw?.devices) ? raw.devices : [],
    trials: Array.isArray(raw?.trials) ? raw.trials : [],
    licenses: Array.isArray(raw?.licenses) ? raw.licenses : [],
    activations: Array.isArray(raw?.activations) ? raw.activations : [],
    refresh_tokens: Array.isArray(raw?.refresh_tokens) ? raw.refresh_tokens : [],
    settings:
      raw?.settings && typeof raw.settings === "object" && !Array.isArray(raw.settings)
        ? raw.settings
        : {}
  };
}

function getBucket(key) {
  const row = db.prepare("SELECT payload FROM kv_store WHERE key = ?").get(key);
  if (!row) return [];
  try {
    const parsed = JSON.parse(row.payload);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function setBucket(key, arr) {
  db.prepare(`
    INSERT INTO kv_store (key, payload, updated_at_utc)
    VALUES (?, ?, ?)
    ON CONFLICT(key) DO UPDATE SET
      payload = excluded.payload,
      updated_at_utc = excluded.updated_at_utc
  `).run(key, JSON.stringify(arr ?? []), nowIso());
}

function getObject(key) {
  const row = db.prepare("SELECT payload FROM kv_store WHERE key = ?").get(key);
  if (!row) return {};
  try {
    const parsed = JSON.parse(row.payload);
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
  } catch {
    return {};
  }
}

function setObject(key, value) {
  db.prepare(`
    INSERT INTO kv_store (key, payload, updated_at_utc)
    VALUES (?, ?, ?)
    ON CONFLICT(key) DO UPDATE SET
      payload = excluded.payload,
      updated_at_utc = excluded.updated_at_utc
  `).run(key, JSON.stringify(value ?? {}), nowIso());
}

function hasAnyData() {
  const row = db.prepare("SELECT COUNT(*) AS c FROM kv_store").get();
  return Number(row?.c || 0) > 0;
}

const saveAllTx = db.transaction((state) => {
  const safe = normalizeDbShape(state);
  setBucket("devices", safe.devices);
  setBucket("trials", safe.trials);
  setBucket("licenses", safe.licenses);
  setBucket("activations", safe.activations);
  setBucket("refresh_tokens", safe.refresh_tokens);
  setObject("settings", safe.settings);
});

async function migrateLegacyJsonIfNeeded() {
  if (hasAnyData()) return;

  if (!fsSync.existsSync(LEGACY_JSON_FILE)) return;

  try {
    const raw = await fs.readFile(LEGACY_JSON_FILE, "utf8");
    const parsed = JSON.parse(raw);
    saveAllTx(parsed);

    await fs.copyFile(LEGACY_JSON_FILE, MIGRATED_JSON_FILE);
  } catch (err) {
    console.error("No pude migrar data.json a SQLite:", err);
    throw err;
  }
}

export async function loadDb() {
  await migrateLegacyJsonIfNeeded();

  return normalizeDbShape({
    devices: getBucket("devices"),
    trials: getBucket("trials"),
    licenses: getBucket("licenses"),
    activations: getBucket("activations"),
    refresh_tokens: getBucket("refresh_tokens"),
    settings: getObject("settings")
  });
}

export async function saveDb(state) {
  saveAllTx(state);
}
