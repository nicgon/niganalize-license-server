import Fastify from "fastify";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import nacl from "tweetnacl";
import { Buffer } from "node:buffer";
import { loadDb, saveDb } from "./sqlite-store.mjs";

const DATA_DIR = process.env.DATA_DIR || path.resolve("./data");
fs.mkdirSync(DATA_DIR, { recursive: true });

const SIGNING_KEY_PATH = path.join(DATA_DIR, "signing-key.json");

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = Number(process.env.PORT || 8787);
const ADMIN_SECRET = process.env.ADMIN_SECRET || "cambiar-esto";

const SIGNING_KEY_FILE = SIGNING_KEY_PATH;

const TRIAL_DAYS = 30;
const LICENSE_DAYS_DEFAULT = 365;
const REFRESH_TOKEN_DAYS = 30;

const app = Fastify({ logger: true });
const ADMIN_UI_HTML = `<!doctype html>
<style>
  :root{
    --bg:#0b0d10;
    --panel:#12161b;
    --panel2:#161b22;
    --ink:#e8eef6;
    --muted:#9fb0c3;
    --stroke:#1e2631;
    --accent:#00d2ff;
    --ok:#21c58b;
    --warn:#f3c94d;
    --bad:#ff6b6b;
  }

  *{box-sizing:border-box}

  body{
    margin:0;
    background:linear-gradient(180deg,#081018,#0b0d10);
    color:var(--ink);
    font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;
  }

  .wrap{
    max-width:1400px;
    margin:0 auto;
    padding:24px;
  }

  .brand{
    display:flex;
    align-items:center;
    gap:12px;
    margin:0 0 18px 0;
  }

  .brandLogo{
    width:34px;
    height:34px;
    object-fit:contain;
    border-radius:8px;
    display:block;
    flex:0 0 auto;
  }

  .brandTitle{
    margin:0;
    font-size:28px;
    line-height:1.1;
  }

  h1{
    margin:0 0 18px 0;
    font-size:28px;
  }

  .grid{
    display:grid;
    grid-template-columns:1fr 1fr;
    gap:16px;
  }

  .card{
    background:rgba(18,22,27,.9);
    border:1px solid var(--stroke);
    border-radius:18px;
    padding:16px;
  }

  .card h2{
    margin:0 0 12px 0;
    font-size:18px;
  }

  .row{
    display:grid;
    grid-template-columns:1fr 1fr;
    gap:10px;
    margin-bottom:10px;
  }

  .row3{
    display:grid;
    grid-template-columns:1fr 1fr 1fr;
    gap:10px;
    margin-bottom:10px;
  }

  .row4{
    display:grid;
    grid-template-columns:1fr 1fr 1fr 1fr;
    gap:10px;
    margin-bottom:10px;
  }

  input,button,textarea,select{
    width:100%;
    border-radius:12px;
    border:1px solid rgba(52,72,99,.45);
    background:#0f141a;
    color:var(--ink);
    padding:12px 14px;
    font-size:14px;
  }

  button{
  cursor:pointer;
  background:rgba(0,210,255,.08);
  font-weight:700;
  transition:
    transform .08s ease,
    filter .14s ease,
    background-color .14s ease,
    border-color .14s ease,
    box-shadow .14s ease,
    opacity .14s ease;
  will-change:transform,filter;
}

button:hover{
  filter:brightness(1.10);
  border-color:rgba(86,170,255,.32);
}

button:active{
  transform:translateY(1px) scale(.975);
  filter:brightness(1.22);
  background:rgba(0,210,255,.16);
}

button.btnFlash{
  background:rgba(86,170,255,.22) !important;
  border-color:rgba(86,170,255,.65) !important;
  box-shadow:
    0 0 0 1px rgba(86,170,255,.28) inset,
    0 0 18px rgba(86,170,255,.24);
  filter:brightness(1.24);
  animation:btnFlashFx .28s ease;
}

@keyframes btnFlashFx{
  0%{ transform:scale(1); }
  35%{ transform:scale(.97); }
  100%{ transform:scale(1); }
}

  .muted{
    color:var(--muted);
    font-size:13px;
  }

  .ok{color:var(--ok)}
  .warn{color:var(--warn)}
  .bad{color:var(--bad)}

  pre{
    margin:0;
    white-space:pre-wrap;
    word-break:break-word;
    background:#0a0f14;
    border:1px solid var(--stroke);
    border-radius:14px;
    padding:14px;
    min-height:260px;
    max-height:520px;
    overflow:auto;
  }

  pre#result{
    min-height:260px;
    max-height:520px;
    overflow:auto;
  }

  .tableShell{
    overflow:auto;
    border:1px solid rgba(255,255,255,.08);
    border-radius:14px;
    background:#0a0f14;
  }

  table{
  width:100%;
  min-width:760px;
  table-layout:fixed;
  border-collapse:separate;
  border-spacing:0;
  font-size:10px;
}

th,td{
  padding:5px 5px;
  border-bottom:1px solid rgba(255,255,255,.07);
  text-align:left;
  vertical-align:top;
}

th:nth-child(1), td:nth-child(1){ width:92px; }   /* key */
th:nth-child(2), td:nth-child(2){ width:60px; }   /* status */
th:nth-child(3), td:nth-child(3){ width:92px; }   /* cliente */
th:nth-child(4), td:nth-child(4){ width:110px; }  /* expira */
th:nth-child(5), td:nth-child(5){ width:115px; }  /* device */
th:nth-child(6), td:nth-child(6){ width:130px; }  /* fingerprint */
th:nth-child(7), td:nth-child(7){ width:38px; }   /* refresh */
th:nth-child(8), td:nth-child(8){ width:36px; }   /* dias */
th:nth-child(9), td:nth-child(9){ width:76px; }   /* acciones */

  th{
    color:var(--muted);
    font-weight:600;
  }

  thead th{
    position:sticky;
    top:0;
    background:#0f141a;
    z-index:1;
  }

  .cellMono{
    font-family:ui-monospace, SFMono-Regular, Menlo, monospace;
  }

 .clip{
  display:block;
  max-width:120px;
  overflow:hidden;
  text-overflow:ellipsis;
  white-space:nowrap;
}

.clipSm{
  display:block;
  max-width:82px;
  overflow:hidden;
  text-overflow:ellipsis;
  white-space:nowrap;
}

 .actionsGrid{
  display:grid;
  grid-template-columns:1fr;
  gap:6px;
  min-width:72px;
}

.btnTiny{
  width:100%;
  padding:7px 6px;
  font-size:10px;
  line-height:1.1;
  border-radius:9px;
}

  .btnDanger{
    background:rgba(255,107,107,.10);
    border-color:rgba(255,107,107,.28);
  }

  .btnWarn{
    background:rgba(243,201,77,.10);
    border-color:rgba(243,201,77,.28);
  }

  .btnOk{
    background:rgba(33,197,139,.10);
    border-color:rgba(33,197,139,.28);
  }

  .pill{
    display:inline-block;
    padding:4px 10px;
    border-radius:999px;
    border:1px solid rgba(52,72,99,.45);
  }

  .toolbar{
    display:flex;
    gap:10px;
    flex-wrap:wrap;
    margin-bottom:12px;
  }

    .topGrid{
  display:grid;
  grid-template-columns:1fr 1fr;
  gap:16px;
  align-items:start;
}

.leftStack{
  display:grid;
  gap:16px;
}

.resultCard{
  height:100%;
}

.resultCard pre{
  min-height:560px;
  max-height:560px;
  height:560px;
}

@media (max-width: 980px){
  .topGrid{grid-template-columns:1fr}
}

  @media (max-width: 980px){
    .grid{grid-template-columns:1fr}
    .row,.row3,.row4{grid-template-columns:1fr}
  }
</style>
</head>
<body>
  <div class="wrap">

    <div class="brand">
  <img class="brandLogo" src="/NiG.png" alt="NiG" />
  <h1 class="brandTitle">NiGanalysis · License Admin</h1>
</div>

<section class="card" style="margin-bottom:14px">
  <h2>Conexión admin</h2>
  <div class="row">
    <input id="backendBase" placeholder="https://niganalize-license-server-production.up.railway.app" />
    <input id="adminSecret" type="password" placeholder="ADMIN_SECRET" />
  </div>
  <div class="row3">
    <button onclick="saveAdminConfig()">Guardar conexión</button>
    <button onclick="clearAdminConfig()">Limpiar</button>
    <button onclick="testAdminConfig()">Probar conexión</button>
  </div>
  <div class="muted">
    Escribí acá la URL pública de Railway y tu ADMIN_SECRET real. No lo hardcodees en el archivo.
  </div>
</section>

<div class="topGrid">

  <div class="leftStack">
    <section class="card">
      <h2>Crear licencia</h2>
      <div class="row">
        <input id="createCustomer" placeholder="Cliente sin nombre" />
        <input id="createDays" type="number" value="365" />
      </div>
      <div class="row">
        <button onclick="createLicense()">Crear licencia</button>
      </div>
    </section>

    <section class="card">
      <h2>Operaciones por License Key</h2>
      <div class="row">
        <input id="licenseKey" placeholder="NIG-2026-XXXX-XXXX-XXXX" />
        <input id="reason" placeholder="reason / motivo" value="admin_action" />
      </div>

      <div class="row3">
        <button onclick="getByKey()">Ver licencia</button>
        <button onclick="revokeLicense()">Revocar</button>
        <button onclick="releaseLicense()">Liberar</button>
      </div>

      <div class="row3">
        <button onclick="restoreLicense()">Restaurar</button>
        <input id="extendDays" type="number" value="365" placeholder="Días (+/-)" />
        <button onclick="extendLicense()">Ajustar días</button>
      </div>

      <div class="row4">
        <button onclick="quickAdjust(-30)">-30d</button>
        <button onclick="quickAdjust(-365)">-365d</button>
        <button onclick="quickAdjust(30)">+30d</button>
        <button onclick="quickAdjust(365)">+365d</button>
      </div>

      <div class="muted">Usá días positivos para sumar y negativos para restar.</div>
    </section>
  </div>

  <section class="card resultCard">
    <h2>Resultado</h2>
    <pre id="result">{}</pre>
  </section>

</div>

<section class="card">
  <div class="toolbar">
    <input id="filterQ" placeholder="Buscar por key, cliente, device o fingerprint" style="max-width:420px" />
    <select id="filterStatus" style="max-width:180px">
      <option value="">Todos los estados</option>
      <option value="issued">issued</option>
      <option value="revoked">revoked</option>
    </select>
    <input id="filterLimit" type="number" value="200" style="max-width:120px" />
  </div>

  <button onclick="listLicenses()">Refrescar listado</button>
  <button onclick="downloadBackup()" style="margin-top:10px">Exportar backup</button>

  <div id="tableWrap" class="muted" style="margin-top:12px">Sin datos todavía.</div>
</section>
  </div>

<script>

function getInputValue(id, fallback = "") {
  const el = document.getElementById(id);
  if (!el) return fallback;
  return String(el.value ?? "").trim() || fallback;
}

function baseUrl() {
  return getInputValue("backendBase", "") || window.location.origin;
}

const ADMIN_CFG_KEY = "nig_license_admin_cfg_v1";

function readAdminConfig() {
  try {
    return JSON.parse(localStorage.getItem(ADMIN_CFG_KEY) || "{}");
  } catch {
    return {};
  }
}

function loadAdminConfig() {
  const cfg = readAdminConfig();

  const baseEl = document.getElementById("backendBase");
  const secretEl = document.getElementById("adminSecret");

  if (baseEl) baseEl.value = String(cfg.backendBase || window.location.origin);
  if (secretEl) secretEl.value = String(cfg.adminSecret || "");
}

function saveAdminConfig() {
  const cfg = {
    backendBase: getInputValue("backendBase", window.location.origin),
    adminSecret: getInputValue("adminSecret", "")
  };

  localStorage.setItem(ADMIN_CFG_KEY, JSON.stringify(cfg));

  show({
    ok: true,
    message: "Configuración admin guardada en este navegador.",
    backendBase: cfg.backendBase
  });
}

function clearAdminConfig() {
  localStorage.removeItem(ADMIN_CFG_KEY);

  const baseEl = document.getElementById("backendBase");
  const secretEl = document.getElementById("adminSecret");

  if (baseEl) baseEl.value = window.location.origin;
  if (secretEl) secretEl.value = "";

  show({
    ok: true,
    message: "Configuración admin limpiada."
  });
}

async function testAdminConfig() {
  try {
    const payload = await api("GET", "/admin/licenses?limit=1");
    show({
      ok: true,
      message: "Conexión admin correcta.",
      backendBase: baseUrl(),
      summary: payload?.summary || null
    });
  } catch (e) {
    show(e);
  }
}

function initAdminUi() {
  loadAdminConfig();
  listLicenses();
}

async function downloadBackup() {
  const res = await fetch(baseUrl() + "/admin/export", {
    method: "GET",
    headers: {
      "x-admin-secret": getInputValue("adminSecret", "cambiar-esto")
    }
  });

  if (!res.ok) {
    const txt = await res.text();
    show(txt);
    return;
  }

  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "niganalize-license-backup.json";
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function adminHeaders() {
  return {
    "x-admin-secret": getInputValue("adminSecret", "cambiar-esto"),
    "Content-Type": "application/json"
  };
}

function show(obj) {
  const el = document.getElementById("result");
  if (!el) return;

  const prevTop = el.scrollTop;
  const prevLeft = el.scrollLeft;
  const prevHeight = el.scrollHeight;
  const wasNearBottom = (prevTop + el.clientHeight) >= (prevHeight - 8);

  el.textContent = typeof obj === "string" ? obj : JSON.stringify(obj, null, 2);

  requestAnimationFrame(() => {
    el.scrollLeft = prevLeft;

    if (wasNearBottom) {
      el.scrollTop = el.scrollHeight;
    } else {
      el.scrollTop = Math.min(
        prevTop,
        Math.max(0, el.scrollHeight - el.clientHeight)
      );
    }
  });
}

function flashButton(btn) {
  if (!btn) return;
  btn.classList.remove("btnFlash");
  void btn.offsetWidth;
  btn.classList.add("btnFlash");
  setTimeout(() => btn.classList.remove("btnFlash"), 240);
}

document.addEventListener("pointerdown", (ev) => {
  const btn = ev.target.closest("button");
  if (!btn) return;
  flashButton(btn);
}, true);

function key() {
  return document.getElementById("licenseKey").value.trim().toUpperCase();
}
function reason() {
  return document.getElementById("reason").value.trim() || "admin_action";
}
async function api(method, path, body) {
  const res = await fetch(baseUrl() + path, {
    method,
    headers: adminHeaders(),
    body: body ? JSON.stringify(body) : undefined
  });
  const txt = await res.text();
  let payload;
  try { payload = JSON.parse(txt); } catch { payload = txt; }
  if (!res.ok) throw payload;
  return payload;
}
async function createLicense() {
  try {
    const customer_name = document.getElementById("createCustomer").value.trim();
    const days = Number(document.getElementById("createDays").value || 365);
    const payload = await api("POST", "/admin/license/create", { customer_name, days });
    show(payload);
    if (payload?.license?.license_key) {
      document.getElementById("licenseKey").value = payload.license.license_key;
    }
    await listLicenses();
  } catch (e) { show(e); }
}
async function getByKey() {
  try {
    const payload = await api("GET", "/admin/license/by-key/" + encodeURIComponent(key()));
    show(payload);
  } catch (e) { show(e); }
}
async function revokeLicense() {
  try {
    const payload = await api("POST", "/admin/license/revoke", {
      license_key: key(),
      reason: reason()
    });
    show(payload);
    await listLicenses();
  } catch (e) { show(e); }
}
async function releaseLicense() {
  try {
    const payload = await api("POST", "/admin/license/release", {
      license_key: key(),
      reason: reason()
    });
    show(payload);
    await listLicenses();
  } catch (e) { show(e); }
}
async function restoreLicense() {
  try {
    const payload = await api("POST", "/admin/license/restore", {
      license_key: key(),
      reason: reason()
    });
    show(payload);
    await listLicenses();
  } catch (e) { show(e); }
}
async function extendLicense() {
  try {
    const days = Number(document.getElementById("extendDays").value || 0);

    if (!Number.isFinite(days) || days === 0) {
      show({ error: "invalid_days", detail: "Ingresá un número distinto de 0." });
      return;
    }

    const payload = await api("POST", "/admin/license/extend", {
      license_key: key(),
      days,
      reason: reason()
    });

    show(payload);
    await listLicenses();
  } catch (e) { show(e); }
}

async function quickAdjust(days) {
  document.getElementById("extendDays").value = String(days);
  await extendLicense();
}

async function listLicenses() {
  try {
    const q = encodeURIComponent(document.getElementById("filterQ").value.trim());
    const status = encodeURIComponent(document.getElementById("filterStatus").value.trim());
    const limit = encodeURIComponent(document.getElementById("filterLimit").value.trim() || "200");

    const qs = new URLSearchParams();
    if (q) qs.set("q", decodeURIComponent(q));
    if (status) qs.set("status", decodeURIComponent(status));
    if (limit) qs.set("limit", decodeURIComponent(limit));

    const suffix = qs.toString() ? "/admin/licenses?" + qs.toString() : "/admin/licenses";
    const payload = await api("GET", suffix);

    show(payload);
    renderTable(payload);
  } catch (e) { show(e); }
}
function escHtml(v) {
  return String(v ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function escAttr(v) {
  return escHtml(v);
}

function useKeyInForm(k) {
  document.getElementById("licenseKey").value = String(k || "");
}

async function quickAction(kind, keyValue) {
  try {
    useKeyInForm(keyValue);

    if (kind === "view") {
      await getByKey();
      return;
    }

    if (kind === "revoke") {
      await revokeLicense();
      return;
    }

    if (kind === "release") {
      await releaseLicense();
      return;
    }

    if (kind === "restore") {
      await restoreLicense();
      return;
    }

    if (kind === "reduce30") {
      document.getElementById("extendDays").value = "-30";
      await extendLicense();
      return;
    }

    if (kind === "reduce365") {
      document.getElementById("extendDays").value = "-365";
      await extendLicense();
      return;
    }

    if (kind === "extend365") {
      document.getElementById("extendDays").value = "365";
      await extendLicense();
      return;
    }
  } catch (e) {
    show(e);
  }
}

function renderTable(payload) {
  const el = document.getElementById("tableWrap");
  const items = Array.isArray(payload?.licenses) ? payload.licenses : [];
  const summary = payload?.summary || {};

  const summaryHtml = \`
    <div style="display:grid;grid-template-columns:repeat(6,minmax(120px,1fr));gap:10px;margin-bottom:14px">
      <div class="card" style="padding:10px 12px;border-radius:14px">
        <div class="muted">Mostradas</div>
        <div style="font-size:20px;font-weight:800">\${Number(summary.total || 0)}</div>
      </div>
      <div class="card" style="padding:10px 12px;border-radius:14px">
        <div class="muted">Issued</div>
        <div style="font-size:20px;font-weight:800">\${Number(summary.issued || 0)}</div>
      </div>
      <div class="card" style="padding:10px 12px;border-radius:14px">
        <div class="muted">Revoked</div>
        <div style="font-size:20px;font-weight:800">\${Number(summary.revoked || 0)}</div>
      </div>
      <div class="card" style="padding:10px 12px;border-radius:14px">
        <div class="muted">Vencidas</div>
        <div style="font-size:20px;font-weight:800">\${Number(summary.expired_now || 0)}</div>
      </div>
      <div class="card" style="padding:10px 12px;border-radius:14px">
        <div class="muted">Pronto a vencer</div>
        <div style="font-size:20px;font-weight:800">\${Number(summary.expiring_soon || 0)}</div>
      </div>
      <div class="card" style="padding:10px 12px;border-radius:14px">
        <div class="muted">Atadas a device</div>
        <div style="font-size:20px;font-weight:800">\${Number(summary.active_bound || 0)}</div>
      </div>
    </div>
  \`;

  if (!items.length) {
    el.innerHTML = summaryHtml + '<div class="muted">No hay licencias para ese filtro.</div>';
    return;
  }

  const rows = items.map(x => {
    const k = escAttr(x.license_key || "");
    const statusTone =
      x.status === "revoked"
        ? "background:rgba(255,107,107,.12);border-color:rgba(255,107,107,.28);color:#ffb3b3"
        : (x.expired_now
            ? "background:rgba(255,107,107,.12);border-color:rgba(255,107,107,.28);color:#ffb3b3"
            : (x.expiring_soon
                ? "background:rgba(243,201,77,.12);border-color:rgba(243,201,77,.28);color:#ffe08a"
                : "background:rgba(33,197,139,.10);border-color:rgba(33,197,139,.25);color:#9df0cb"));

    return \`
      <tr>
        <td>
          <span class="cellMono clipSm" title="\${k}">
            \${escHtml(x.license_key || "")}
          </span>
        </td>

        <td>
          <span class="pill" style="\${statusTone}">
            \${escHtml(x.status || "")}
          </span>
        </td>

        <td>
          <span class="clipSm" title="\${escAttr(x.customer_name || "")}">
            \${escHtml(x.customer_name || "")}
          </span>
        </td>

        <td>
          <span class="cellMono clipSm" title="\${escAttr(x.expires_at_utc || "")}">
            \${escHtml(x.expires_at_utc || "")}
          </span>
        </td>

        <td>
          <span class="cellMono clip" title="\${escAttr(x.active_device_id || "")}">
            \${escHtml(x.active_device_id || "—")}
          </span>
        </td>

        <td>
          <span class="cellMono clip" title="\${escAttr(x.active_fingerprint_hash || "")}">
            \${escHtml(x.active_fingerprint_hash || "—")}
          </span>
        </td>

        <td>\${Number(x.active_refresh_tokens ?? 0)}</td>
        <td>\${x.days_to_expiry == null ? "" : Number(x.days_to_expiry)}</td>

       <td>
  <div class="actionsGrid">
    <button class="btnTiny" onclick="useKeyInForm('\${k}')">Usar key</button>
    <button class="btnTiny" onclick="quickAction('view','\${k}')">Ver</button>
    <button class="btnTiny btnDanger" onclick="quickAction('revoke','\${k}')">Revocar</button>
    <button class="btnTiny btnWarn" onclick="quickAction('release','\${k}')">Liberar</button>
    <button class="btnTiny btnOk" onclick="quickAction('restore','\${k}')">Restaurar</button>
  </div>
</td>
      </tr>
    \`;
  }).join("");

  el.innerHTML = \`
    \${summaryHtml}
    <div class="tableShell">
      <table>
        <thead>
          <tr>
            <th>License Key</th>
            <th>Status</th>
            <th>Cliente</th>
            <th>Expira</th>
            <th>Device activo</th>
            <th>Fingerprint activo</th>
            <th>Refresh activos</th>
            <th>Días</th>
            <th>Acciones</th>
          </tr>
        </thead>
        <tbody>\${rows}</tbody>
      </table>
    </div>
  \`;
}
initAdminUi();
</script>
</body>
</html>`;

function nowIso() {
  return new Date().toISOString();
}

function addDaysIso(days) {
  const d = new Date();
  d.setUTCDate(d.getUTCDate() + days);
  return d.toISOString();
}

function isExpired(iso) {
  return new Date(iso).getTime() < Date.now();
}

function daysUntilIso(iso) {
  if (!iso) return null;
  const ms = new Date(iso).getTime() - Date.now();
  if (!Number.isFinite(ms)) return null;
  return Math.ceil(ms / 86400000);
}

function randomToken() {
  return crypto.randomBytes(32).toString("hex");
}

function makeId(prefix) {
  return `${prefix}_${crypto.randomUUID()}`;
}

function normalizeKey(k) {
  return String(k || "").trim().toUpperCase();
}

function b64urlEncode(buf) {
  return Buffer.from(buf).toString("base64url");
}

function b64urlDecode(s) {
  return Buffer.from(s, "base64url");
}

function loadOrCreateSigningKeys() {
  let seed;

  if (fs.existsSync(SIGNING_KEY_FILE)) {
    const raw = fs.readFileSync(SIGNING_KEY_FILE, "utf8");
    const json = JSON.parse(raw);
    seed = b64urlDecode(json.seed_b64);
  } else {
    seed = crypto.randomBytes(32);
    fs.writeFileSync(
      SIGNING_KEY_FILE,
      JSON.stringify(
        {
          seed_b64: b64urlEncode(seed)
        },
        null,
        2
      ),
      "utf8"
    );
  }

  if (seed.length !== 32) {
    throw new Error("signing-key.json debe contener un seed de 32 bytes");
  }

  const kp = nacl.sign.keyPair.fromSeed(Uint8Array.from(seed));

  return {
    publicKey: kp.publicKey,
    secretKey: kp.secretKey,
    publicKeyB64: b64urlEncode(kp.publicKey)
  };
}

const SIGNING = loadOrCreateSigningKeys();

function issueLicenseToken({ license, device_id, fingerprint_hash }) {
  const claims = {
    v: 1,
    typ: "license",
    license_id: license.id,
    license_kind: license.license_kind,
    device_id,
    fingerprint_hash,
    iat: nowIso(),
    exp: license.expires_at_utc,
    jti: crypto.randomUUID()
  };

  const payloadB64 = b64urlEncode(Buffer.from(JSON.stringify(claims), "utf8"));
  const sig = nacl.sign.detached(Buffer.from(payloadB64, "utf8"), SIGNING.secretKey);
  const sigB64 = b64urlEncode(sig);

  return `nlg1.${payloadB64}.${sigB64}`;
}

function makeLicenseKey() {
  const year = new Date().getUTCFullYear();
  const a = crypto.randomBytes(2).toString("hex").toUpperCase();
  const b = crypto.randomBytes(2).toString("hex").toUpperCase();
  const c = crypto.randomBytes(2).toString("hex").toUpperCase();
  return `NIG-${year}-${a}-${b}-${c}`;
}

function buildResponseBase(status, message) {
  return {
    status,
    message,
    server_time_utc: nowIso(),
    trial_expires_at_utc: null,
    license_id: null,
    license_kind: null,
    issued_at_utc: null,
    expires_at_utc: null,
    license_token: null,
    refresh_token: null
  };
}

function rotateRefreshToken(db, payload) {
  const {
    device_id,
    fingerprint_hash,
    license_id = null,
    license_key = null,
    days = REFRESH_TOKEN_DAYS
  } = payload;

  for (const t of db.refresh_tokens) {
    if (
      !t.revoked_at_utc &&
      t.device_id === device_id &&
      t.fingerprint_hash === fingerprint_hash &&
      t.license_id === license_id
    ) {
      t.revoked_at_utc = nowIso();
    }
  }

  const token = {
    id: makeId("rt"),
    token: randomToken(),
    device_id,
    fingerprint_hash,
    license_id,
    license_key,
    issued_at_utc: nowIso(),
    expires_at_utc: addDaysIso(days),
    revoked_at_utc: null
  };

  db.refresh_tokens.push(token);
  return token;
}

app.get("/NiG.png", async (_req, reply) => {
  const filePath = path.join(__dirname, "..", "public", "NiG.png");

  if (!fs.existsSync(filePath)) {
    return reply.code(404).send({ error: "asset_not_found", file: "NiG.png" });
  }

  reply.type("image/png");
  return reply.send(fs.createReadStream(filePath));
});

app.get("/v1/meta/signing-public-key", async () => {
  return {
    ok: true,
    algorithm: "ed25519",
    public_key_b64: SIGNING.publicKeyB64
  };
});

app.get("/health", async () => {
  return {
    ok: true,
    service: "niganalize-license-server",
    time_utc: nowIso()
  };
});

app.get("/", async (req, reply) => {
  return reply.redirect("/admin/ui");
});

app.get("/admin/ui", async (_req, reply) => {
  reply.type("text/html; charset=utf-8").send(ADMIN_UI_HTML);
});

app.post("/admin/license/create", async (req, reply) => {
  const secret = req.headers["x-admin-secret"];
  if (secret !== ADMIN_SECRET) {
    return reply.code(401).send({ error: "unauthorized" });
  }

  const body = req.body || {};
  const customer_name = String(body.customer_name || "Cliente sin nombre");
  const days = Number(body.days || LICENSE_DAYS_DEFAULT);

  const db = await loadDb();

  const license = {
    id: makeId("lic"),
    license_key: makeLicenseKey(),
    customer_name,
    status: "issued",
    license_kind: "annual",
    issued_at_utc: nowIso(),
    expires_at_utc: addDaysIso(days),
    max_seats: 1
  };

  db.licenses.push(license);
  await saveDb(db);

  return {
    ok: true,
    license
  };
});

app.post("/admin/license/revoke", async (req, reply) => {
  const secret = req.headers["x-admin-secret"];
  if (secret !== ADMIN_SECRET) {
    return reply.code(401).send({ error: "unauthorized" });
  }

  const body = req.body || {};
  const key = normalizeKey(body.license_key);
  const reason = String(body.reason || "revoked_by_admin");

  if (!key) {
    return reply.code(400).send({ error: "missing_license_key" });
  }

  const db = await loadDb();

  const license = db.licenses.find((l) => normalizeKey(l.license_key) === key);
  if (!license) {
    return reply.code(404).send({ error: "license_not_found" });
  }

  license.status = "revoked";
  license.revoked_at_utc = nowIso();
  license.revoked_reason = reason;

  for (const a of db.activations) {
    if (a.license_id === license.id && !a.revoked_at_utc) {
      a.revoked_at_utc = nowIso();
      a.revoked_reason = reason;
    }
  }

  for (const t of db.refresh_tokens) {
    if (t.license_id === license.id && !t.revoked_at_utc) {
      t.revoked_at_utc = nowIso();
      t.revoked_reason = reason;
    }
  }

  await saveDb(db);

  return {
    ok: true,
    license_id: license.id,
    license_key: license.license_key,
    status: license.status,
    revoked_at_utc: license.revoked_at_utc,
    revoked_reason: license.revoked_reason
  };
});

app.post("/admin/license/release", async (req, reply) => {
  const secret = req.headers["x-admin-secret"];
  if (secret !== ADMIN_SECRET) {
    return reply.code(401).send({ error: "unauthorized" });
  }

  const body = req.body || {};
  const key = normalizeKey(body.license_key);
  const reason = String(body.reason || "released_by_admin");

  if (!key) {
    return reply.code(400).send({ error: "missing_license_key" });
  }

  const db = await loadDb();

  const license = db.licenses.find((l) => normalizeKey(l.license_key) === key);
  if (!license) {
    return reply.code(404).send({ error: "license_not_found" });
  }

  // La licencia vuelve a quedar disponible para ser activada en otra PC
  if (!isExpired(license.expires_at_utc)) {
    license.status = "issued";
  }
  license.released_at_utc = nowIso();
  license.released_reason = reason;

  for (const a of db.activations) {
    if (a.license_id === license.id && !a.revoked_at_utc) {
      a.revoked_at_utc = nowIso();
      a.revoked_reason = reason;
    }
  }

  for (const t of db.refresh_tokens) {
    if (t.license_id === license.id && !t.revoked_at_utc) {
      t.revoked_at_utc = nowIso();
      t.revoked_reason = reason;
    }
  }

  await saveDb(db);

  return {
    ok: true,
    license_id: license.id,
    license_key: license.license_key,
    status: license.status,
    released_at_utc: license.released_at_utc,
    released_reason: license.released_reason
  };
});

app.post("/admin/license/extend", async (req, reply) => {
  const secret = req.headers["x-admin-secret"];
  if (secret !== ADMIN_SECRET) {
    return reply.code(401).send({ error: "unauthorized" });
  }

  const body = req.body || {};
  const key = normalizeKey(body.license_key);
  const deltaDays = Number(body.days ?? 365);
  const reason = String(
    body.reason || (deltaDays >= 0 ? "extended_by_admin" : "reduced_by_admin")
  );

  if (!key) {
    return reply.code(400).send({ error: "missing_license_key" });
  }

  if (!Number.isFinite(deltaDays) || deltaDays === 0) {
    return reply.code(400).send({ error: "invalid_days" });
  }

  const db = await loadDb();

  const license = db.licenses.find((l) => normalizeKey(l.license_key) === key);
  if (!license) {
    return reply.code(404).send({ error: "license_not_found" });
  }

  const currentExpiry = new Date(license.expires_at_utc);
  const hasValidExpiry = Number.isFinite(currentExpiry.getTime());

  const baseDate =
    deltaDays > 0
      ? (isExpired(license.expires_at_utc)
          ? new Date()
          : (hasValidExpiry ? currentExpiry : new Date()))
      : (hasValidExpiry ? currentExpiry : new Date());

  baseDate.setUTCDate(baseDate.getUTCDate() + deltaDays);

  license.expires_at_utc = baseDate.toISOString();
  license.status = "issued";
  license.extended_at_utc = nowIso();
  license.extended_reason = reason;
  license.extended_days = deltaDays;

  await saveDb(db);

  return {
    ok: true,
    license_id: license.id,
    license_key: license.license_key,
    status: license.status,
    expires_at_utc: license.expires_at_utc,
    extended_at_utc: license.extended_at_utc,
    extended_reason: license.extended_reason,
    extended_days: license.extended_days,
    days_to_expiry: daysUntilIso(license.expires_at_utc)
  };
});

app.get("/admin/license/by-key/:licenseKey", async (req, reply) => {
  const secret = req.headers["x-admin-secret"];
  if (secret !== ADMIN_SECRET) {
    return reply.code(401).send({ error: "unauthorized" });
  }

  const key = normalizeKey(req.params.licenseKey);
  const db = await loadDb();

  const license = db.licenses.find((l) => normalizeKey(l.license_key) === key);
  if (!license) {
    return reply.code(404).send({ error: "license_not_found" });
  }

  const activations = db.activations.filter((a) => a.license_id === license.id);
  const refreshTokens = db.refresh_tokens.filter((t) => t.license_id === license.id);

  return {
    ok: true,
    license,
    activations,
    refresh_tokens: refreshTokens
  };
});

app.post("/v1/trial/start", async (req, reply) => {
  const body = req.body || {};
  const {
    device_id,
    fingerprint_hash,
    device_public_key_b64,
    machine_name,
    app_version
  } = body;

  if (!device_id || !fingerprint_hash || !device_public_key_b64) {
    return reply.code(400).send({ error: "missing required fields" });
  }

  const db = await loadDb();

  let device = db.devices.find(
    (d) => d.device_id === device_id || d.fingerprint_hash === fingerprint_hash
  );

  if (!device) {
    device = {
      id: makeId("dev"),
      device_id,
      fingerprint_hash,
      device_public_key_b64,
      machine_name: machine_name || "",
      app_version: app_version || "",
      first_seen_utc: nowIso(),
      last_seen_utc: nowIso()
    };
    db.devices.push(device);
  } else {
    device.last_seen_utc = nowIso();
    device.device_public_key_b64 = device_public_key_b64;
    device.machine_name = machine_name || device.machine_name;
    device.app_version = app_version || device.app_version;
  }

  let trial = db.trials.find(
    (t) => t.fingerprint_hash === fingerprint_hash
  );

  if (!trial) {
    trial = {
      id: makeId("trial"),
      device_id,
      fingerprint_hash,
      started_at_utc: nowIso(),
      expires_at_utc: addDaysIso(TRIAL_DAYS)
    };
    db.trials.push(trial);
  }

  await saveDb(db);

  const status = isExpired(trial.expires_at_utc) ? "trial_expired" : "trial_active";

  return {
    ...buildResponseBase(
      status,
      status === "trial_active" ? "Trial online activo." : "Trial online expirado."
    ),
    trial_expires_at_utc: trial.expires_at_utc,
    license_token: randomToken(),
    refresh_token: randomToken()
  };
});

app.post("/v1/license/activate", async (req, reply) => {
  const body = req.body || {};
  const {
    license_key,
    device_id,
    fingerprint_hash,
    device_public_key_b64,
    machine_name,
    app_version
  } = body;

  if (!license_key || !device_id || !fingerprint_hash || !device_public_key_b64) {
    return reply.code(400).send({ error: "missing required fields" });
  }

  const db = await loadDb();
  const key = normalizeKey(license_key);

  const license = db.licenses.find((l) => normalizeKey(l.license_key) === key);
  if (!license) {
    return reply.code(404).send({ error: "license_not_found" });
  }

  if (license.status === "revoked") {
    return reply.code(403).send({ error: "license_revoked" });
  }

  if (isExpired(license.expires_at_utc)) {
    return {
      ...buildResponseBase("licensed_expired", "La licencia está vencida."),
      license_id: license.id,
      license_kind: license.license_kind,
      issued_at_utc: license.issued_at_utc,
      expires_at_utc: license.expires_at_utc
    };
  }

  let device = db.devices.find(
    (d) => d.device_id === device_id || d.fingerprint_hash === fingerprint_hash
  );

  if (!device) {
    device = {
      id: makeId("dev"),
      device_id,
      fingerprint_hash,
      device_public_key_b64,
      machine_name: machine_name || "",
      app_version: app_version || "",
      first_seen_utc: nowIso(),
      last_seen_utc: nowIso()
    };
    db.devices.push(device);
  } else {
    device.last_seen_utc = nowIso();
    device.device_public_key_b64 = device_public_key_b64;
    device.machine_name = machine_name || device.machine_name;
    device.app_version = app_version || device.app_version;
  }

  const existing = db.activations.find(
    (a) => a.license_id === license.id && !a.revoked_at_utc
  );

  if (existing) {
    const sameDevice =
      existing.device_id === device_id &&
      existing.fingerprint_hash === fingerprint_hash;

    if (!sameDevice) {
      return reply.code(409).send({
        error: "license_already_used_on_other_device"
      });
    }
  } else {
    db.activations.push({
      id: makeId("act"),
      license_id: license.id,
      license_key: license.license_key,
      device_id,
      fingerprint_hash,
      activated_at_utc: nowIso(),
      revoked_at_utc: null
    });
  }

  const refresh = rotateRefreshToken(db, {
    device_id,
    fingerprint_hash,
    license_id: license.id,
    license_key: license.license_key
  });

  await saveDb(db);

  return {
    ...buildResponseBase("licensed_active", "Licencia activada correctamente."),
    license_id: license.id,
    license_kind: license.license_kind,
    issued_at_utc: license.issued_at_utc,
    expires_at_utc: license.expires_at_utc,
    license_token: issueLicenseToken({
  license,
  device_id,
  fingerprint_hash
}),
    refresh_token: refresh.token
  };
});

app.get("/admin/licenses", async (req, reply) => {
  const secret = req.headers["x-admin-secret"];
  if (secret !== ADMIN_SECRET) {
    return reply.code(401).send({ error: "unauthorized" });
  }

  const db = await loadDb();

  const q = String(req.query?.q || "").trim().toLowerCase();
  const statusFilter = String(req.query?.status || "").trim().toLowerCase();
  const limit = Math.max(1, Math.min(1000, Number(req.query?.limit || 200)));
  const expiringDays = Math.max(0, Math.min(3650, Number(req.query?.expiring_days || 0)));

  let licenses = [...db.licenses]
    .sort((a, b) => {
      const da = new Date(a.issued_at_utc || 0).getTime();
      const dbb = new Date(b.issued_at_utc || 0).getTime();
      return dbb - da;
    })
    .map((lic) => {
      const activations = db.activations.filter((a) => a.license_id === lic.id);
      const activeActivation = activations.find((a) => !a.revoked_at_utc) || null;
      const refreshTokens = db.refresh_tokens.filter((t) => t.license_id === lic.id);
      const activeRefreshTokens = refreshTokens.filter((t) => !t.revoked_at_utc).length;

      const days_to_expiry = daysUntilIso(lic.expires_at_utc);
      const expired_now = days_to_expiry !== null && days_to_expiry <= 0;
      const expiring_soon =
        lic.status !== "revoked" &&
        days_to_expiry !== null &&
        days_to_expiry > 0 &&
        days_to_expiry <= 30;

      return {
        id: lic.id,
        license_key: lic.license_key,
        customer_name: lic.customer_name || "",
        status: lic.status,
        license_kind: lic.license_kind,
        issued_at_utc: lic.issued_at_utc,
        expires_at_utc: lic.expires_at_utc,
        revoked_at_utc: lic.revoked_at_utc || null,
        revoked_reason: lic.revoked_reason || null,
        released_at_utc: lic.released_at_utc || null,
        released_reason: lic.released_reason || null,
        restored_at_utc: lic.restored_at_utc || null,
        restored_reason: lic.restored_reason || null,
        extended_at_utc: lic.extended_at_utc || null,
        extended_days: lic.extended_days || null,
        activation_count: activations.length,
        active_device_id: activeActivation?.device_id || null,
        active_fingerprint_hash: activeActivation?.fingerprint_hash || null,
        active_refresh_tokens: activeRefreshTokens,
        days_to_expiry,
        expired_now,
        expiring_soon
      };
    });

  if (statusFilter) {
    licenses = licenses.filter((x) => String(x.status || "").toLowerCase() === statusFilter);
  }

  if (q) {
    licenses = licenses.filter((x) => {
      const hay = [
        x.license_key,
        x.customer_name,
        x.status,
        x.active_device_id,
        x.active_fingerprint_hash,
        x.id
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();

      return hay.includes(q);
    });
  }

  if (expiringDays > 0) {
    licenses = licenses.filter(
      (x) => x.days_to_expiry !== null && x.days_to_expiry > 0 && x.days_to_expiry <= expiringDays
    );
  }

  licenses = licenses.slice(0, limit);

  const summary = {
    total: licenses.length,
    issued: licenses.filter((x) => x.status === "issued").length,
    revoked: licenses.filter((x) => x.status === "revoked").length,
    expired_now: licenses.filter((x) => x.expired_now).length,
    expiring_soon: licenses.filter((x) => x.expiring_soon).length,
    active_bound: licenses.filter((x) => !!x.active_device_id).length
  };

  return {
    ok: true,
    count: licenses.length,
    filters: {
      q,
      status: statusFilter,
      limit,
      expiring_days: expiringDays
    },
    summary,
    licenses
  };
});

app.get("/admin/export", async (req, reply) => {
  const secret = req.headers["x-admin-secret"];
  if (secret !== ADMIN_SECRET) {
    return reply.code(401).send({ error: "unauthorized" });
  }

  const db = await loadDb();
  const ts = nowIso().replaceAll(":", "-");
  const filename = `niganalize-license-backup-${ts}.json`;

  reply
    .header("Content-Type", "application/json; charset=utf-8")
    .header("Content-Disposition", `attachment; filename="${filename}"`)
    .send(JSON.stringify(db, null, 2));
});

app.post("/admin/license/restore", async (req, reply) => {
  const secret = req.headers["x-admin-secret"];
  if (secret !== ADMIN_SECRET) {
    return reply.code(401).send({ error: "unauthorized" });
  }

  const body = req.body || {};
  const key = normalizeKey(body.license_key);
  const reason = String(body.reason || "restored_by_admin");

  if (!key) {
    return reply.code(400).send({ error: "missing_license_key" });
  }

  const db = await loadDb();

  const license = db.licenses.find((l) => normalizeKey(l.license_key) === key);
  if (!license) {
    return reply.code(404).send({ error: "license_not_found" });
  }

  if (isExpired(license.expires_at_utc)) {
    return reply.code(400).send({ error: "license_expired_cannot_restore" });
  }

  license.status = "issued";
  license.restored_at_utc = nowIso();
  license.restored_reason = reason;

  await saveDb(db);

  return {
    ok: true,
    license_id: license.id,
    license_key: license.license_key,
    status: license.status,
    restored_at_utc: license.restored_at_utc,
    restored_reason: license.restored_reason
  };
});

app.post("/v1/license/refresh", async (req, reply) => {
  const body = req.body || {};
  const { refresh_token, device_id, fingerprint_hash } = body;

  if (!refresh_token || !device_id || !fingerprint_hash) {
    return reply.code(400).send({ error: "missing required fields" });
  }

  const db = await loadDb();

  const tokenRow = db.refresh_tokens.find(
    (t) => t.token === refresh_token && !t.revoked_at_utc
  );

  if (!tokenRow) {
    return reply.code(401).send({ error: "refresh_token_invalid" });
  }

  if (isExpired(tokenRow.expires_at_utc)) {
    return reply.code(401).send({ error: "refresh_token_expired" });
  }

  if (
    tokenRow.device_id !== device_id ||
    tokenRow.fingerprint_hash !== fingerprint_hash
  ) {
    return reply.code(403).send({ error: "device_mismatch" });
  }

  const license = db.licenses.find((l) => l.id === tokenRow.license_id);
  if (!license) {
    return reply.code(404).send({ error: "license_not_found" });
  }

  if (license.status === "revoked") {
    return reply.code(403).send({ error: "license_revoked" });
  }

  tokenRow.revoked_at_utc = nowIso();

  const refresh = rotateRefreshToken(db, {
    device_id,
    fingerprint_hash,
    license_id: license.id,
    license_key: license.license_key
  });

  await saveDb(db);

  if (isExpired(license.expires_at_utc)) {
    return {
      ...buildResponseBase("licensed_expired", "La licencia está vencida."),
      license_id: license.id,
      license_kind: license.license_kind,
      issued_at_utc: license.issued_at_utc,
      expires_at_utc: license.expires_at_utc,
      refresh_token: refresh.token
    };
  }

  return {
    ...buildResponseBase("licensed_active", "Licencia revalidada correctamente."),
    license_id: license.id,
    license_kind: license.license_kind,
    issued_at_utc: license.issued_at_utc,
    expires_at_utc: license.expires_at_utc,
    license_token: issueLicenseToken({
  license,
  device_id,
  fingerprint_hash
}),
    refresh_token: refresh.token
  };
});

const HOST = process.env.HOST || "0.0.0.0";

app.listen({ port: PORT, host: HOST })
  .then(() => {
    console.log(`License server running on http://${HOST}:${PORT}`);
    console.log(`License signing public key: ${SIGNING.publicKeyB64}`);
  })
  .catch((err) => {
    app.log.error(err);
    process.exit(1);
  });