// Seaways Order Desk API: logins + data, stored in Netlify Blobs. No setup needed.
import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

export const config = { path: "/api/*" };

const COLS = ["catalog", "customers", "orders", "journeys", "settings"];
const st = () => getStore({ name: "orderdesk", consistency: "strong" });
const json = (d, status = 200) =>
  new Response(JSON.stringify(d), { status, headers: { "content-type": "application/json", "cache-control": "no-store" } });
const fail = (status, error, code) => json({ error, code: code || (status === 403 ? "permission-denied" : "error") }, status);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/* ---------- storage helpers ---------- */
async function readCol(s, col) {
  const r = await s.getWithMetadata("col/" + col, { type: "json" });
  return r ? { data: r.data || {}, etag: r.etag || null, exists: true } : { data: {}, etag: null, exists: false };
}
// Read-modify-write with conditional writes so two phones saving at once never overwrite each other.
async function mutate(s, col, fn) {
  for (let i = 0; i < 8; i++) {
    const { data, etag, exists } = await readCol(s, col);
    const res = await fn(data);
    if (res === false) return data;
    const w = await s.setJSON("col/" + col, data, etag ? { onlyIfMatch: etag } : exists ? {} : { onlyIfNew: true });
    if (!w || w.modified !== false) return data;
    await sleep(40 + Math.random() * 160);
  }
  throw Object.assign(new Error("Busy, try again"), { status: 503 });
}
async function secret(s) {
  let v = await s.get("secret");
  if (!v) {
    await s.set("secret", crypto.randomBytes(32).toString("hex"), { onlyIfNew: true });
    v = await s.get("secret");
  }
  return v;
}
const hashPw = (pw, salt) => crypto.pbkdf2Sync(String(pw), salt, 120000, 32, "sha256").toString("hex");
const makeCred = (pw) => { const salt = crypto.randomBytes(16).toString("hex"); return { salt, hash: hashPw(pw, salt) }; };
const clean = (a) => { if (!a) return a; const { salt, hash, ...rest } = a; return rest; };
const newId = () => Date.now().toString(36) + crypto.randomBytes(5).toString("hex");

async function sign(s, uid) {
  const exp = Date.now() + 90 * 864e5;
  const body = uid + "." + exp;
  return body + "." + crypto.createHmac("sha256", await secret(s)).update(body).digest("hex");
}
async function auth(s, req) {
  const t = (req.headers.get("authorization") || "").replace(/^Bearer\s+/i, "");
  const [uid, exp, sig] = t.split(".");
  if (!uid || !exp || !sig || Number(exp) < Date.now()) return null;
  const good = crypto.createHmac("sha256", await secret(s)).update(uid + "." + exp).digest("hex");
  if (good.length !== sig.length || !crypto.timingSafeEqual(Buffer.from(good), Buffer.from(sig))) return null;
  const { data: accounts } = await readCol(s, "accounts");
  const me = accounts[uid];
  if (!me || me.active === false) return null;
  return { ...clean(me), id: uid, accounts };
}

/* ---------- what each person can see ---------- */
function visible(col, data, me) {
  if (me.role === "admin") return data;
  const out = {};
  for (const [id, d] of Object.entries(data)) {
    if (col === "customers" && !((d.assignedTo || []).includes(me.id) || d.createdBy === me.id)) continue;
    if (col === "orders" && d.createdBy !== me.id) continue;
    if (col === "journeys" && d.memberId !== me.id) continue;
    out[id] = d;
  }
  return out;
}

/* ---------- what each person can change ---------- */
function applyOp(col, data, op, me) {
  const admin = me.role === "admin";
  const id = String(op.id || "");
  if (!id || id.length > 200) throw Object.assign(new Error("Bad id"), { status: 400 });
  const ex = data[id];
  const deny = () => { throw Object.assign(new Error("Not allowed"), { status: 403 }); };
  if (col === "catalog" || col === "settings") { if (!admin) deny(); }
  else if (col === "customers") {
    if (!admin) {
      if (op.op === "delete") deny();
      if (!ex) { if (op.op !== "set" || op.data.createdBy !== me.id) deny(); op.data.assignedTo = [me.id]; }
      else { if (ex.createdBy !== me.id) deny(); if (op.data) op.data.assignedTo = ex.assignedTo || [me.id]; }
    }
  } else if (col === "orders") {
    if (!admin && (ex || op.op !== "set" || op.data.createdBy !== me.id)) deny();
  } else if (col === "journeys") {
    if (!admin) {
      if (op.op === "delete") deny();
      if (!ex) { if (op.op !== "set" || op.data.memberId !== me.id || op.data.status !== "active") deny(); }
      else { if (ex.memberId !== me.id || ex.status !== "active") deny(); op.data.memberId = me.id; }
    }
  } else deny();

  if (op.op === "delete") delete data[id];
  else if (op.op === "set") data[id] = op.data || {};
  else if (op.op === "update") { if (!ex) return; data[id] = { ...ex, ...(op.data || {}) }; }
  else throw Object.assign(new Error("Bad op"), { status: 400 });
}

/* ---------- handler ---------- */
export default async (req) => {
  const s = st();
  const url = new URL(req.url);
  const route = url.pathname.replace(/^\/api\//, "").replace(/\/$/, "");
  const body = req.method === "POST" ? await req.json().catch(() => ({})) : {};
  try {
    if (route === "status") {
      const { data } = await readCol(s, "accounts");
      return json({ setup: Object.keys(data).length > 0 });
    }

    if (route === "setup") {
      const username = String(body.username || "").trim().toLowerCase();
      if (!/^[a-z0-9._-]{3,}$/.test(username) || !body.name || String(body.password || "").length < 6) return fail(400, "Check the name, username and password.");
      const uid = newId();
      let done = false;
      await mutate(s, "accounts", (a) => {
        if (Object.keys(a).length) return false;
        a[uid] = { name: String(body.name).toUpperCase(), username, role: "admin", active: true, createdAt: Date.now(), ...makeCred(body.password) };
        done = true;
      });
      if (!done) return fail(409, "Setup was already done. Sign in instead.");
      return json({ token: await sign(s, uid) });
    }

    if (route === "login") {
      const username = String(body.username || "").trim().toLowerCase();
      const { data: a } = await readCol(s, "accounts");
      const entry = Object.entries(a).find(([, x]) => x.username === username);
      await sleep(250);
      if (!entry || entry[1].active === false || hashPw(body.password || "", entry[1].salt) !== entry[1].hash) return fail(401, "Wrong username or password.", "bad-login");
      return json({ token: await sign(s, entry[0]) });
    }

    const me = await auth(s, req);
    if (!me) return fail(401, "Sign in again.", "unauthenticated");
    const accounts = me.accounts; delete me.accounts;

    if (route === "sync") {
      const known = JSON.parse(url.searchParams.get("revs") || "{}");
      const out = { me, cols: {} };
      const accRev = "a" + crypto.createHash("md5").update(JSON.stringify(accounts)).digest("hex");
      if (known.accounts !== accRev) {
        const vis = {};
        for (const [id, a] of Object.entries(accounts)) if (me.role === "admin" || id === me.id) vis[id] = clean(a);
        out.cols.accounts = { rev: accRev, docs: vis };
      }
      await Promise.all(COLS.map(async (col) => {
        const m = await s.getMetadata("col/" + col);
        let rev = m ? m.etag : "empty", data = null;
        if (m && !rev) { data = (await readCol(s, col)).data; rev = "h" + crypto.createHash("md5").update(JSON.stringify(data)).digest("hex"); }
        if (known[col] === rev) return;
        if (!data) data = (await readCol(s, col)).data;
        out.cols[col] = { rev, docs: visible(col, data, me) };
      }));
      return json(out);
    }

    if (route === "write") {
      const ops = Array.isArray(body.ops) ? body.ops.slice(0, 2000) : [];
      const byCol = {};
      for (const op of ops) (byCol[op.col] = byCol[op.col] || []).push(op);
      for (const [col, list] of Object.entries(byCol)) {
        if (!COLS.includes(col)) return fail(400, "Unknown collection");
        await mutate(s, col, (data) => { for (const op of list) applyOp(col, data, JSON.parse(JSON.stringify(op)), me); });
      }
      return json({ ok: true });
    }

    if (route === "img") {
      const kind = (req.method === "POST" ? body.kind : url.searchParams.get("kind")) === "journey" ? "journey" : "product";
      const id = String((req.method === "POST" ? body.id : url.searchParams.get("id")) || "").replace(/[^a-zA-Z0-9_-]/g, "");
      if (!id) return fail(400, "Bad id");
      const key = `img/${kind}/${id}`;
      if (req.method === "POST") {
        if (kind === "product" && me.role !== "admin") return fail(403, "Not allowed");
        if (kind === "journey" && body.memberId !== me.id) return fail(403, "Not allowed");
        if (!/^data:image\/(jpeg|png|webp);base64,/.test(body.data || "") || body.data.length > 1500000) return fail(400, "Bad image");
        await s.setJSON(key, { data: body.data, memberId: body.memberId || null, at: Date.now() });
        return json({ ok: true });
      }
      const v = await s.get(key, { type: "json" });
      if (!v) return json({});
      if (kind === "journey" && me.role !== "admin" && v.memberId !== me.id) return fail(403, "Not allowed");
      return new Response(JSON.stringify(v), { headers: { "content-type": "application/json", "cache-control": "private, max-age=86400" } });
    }

    if (route === "password") {
      const next = String(body.next || "");
      if (next.length < 6) return fail(400, "New password must be at least 6 characters.");
      const cur = accounts[me.id];
      if (hashPw(body.current || "", cur.salt) !== cur.hash) return fail(400, "Current password is wrong.", "bad-current");
      await mutate(s, "accounts", (a) => { Object.assign(a[me.id], makeCred(next), { updatedAt: Date.now() }); });
      return json({ ok: true });
    }

    if (route === "account") {
      if (me.role !== "admin") return fail(403, "Only an admin can manage logins.");
      const username = String(body.username || "").trim().toLowerCase();
      const pw = String(body.password || "");
      if (!body.name || !/^[a-z0-9._-]{3,}$/.test(username)) return fail(400, "Enter a name and a username (3+ letters or numbers, no spaces).");
      if (pw && pw.length < 6) return fail(400, "Password must be at least 6 characters.");
      let err = null;
      await mutate(s, "accounts", (a) => {
        const id = body.id || null;
        if (Object.entries(a).some(([k, x]) => x.username === username && k !== id)) { err = "That username is taken."; return false; }
        if (id && !a[id]) { err = "Login not found."; return false; }
        if (!id && !pw) { err = "Password must be at least 6 characters."; return false; }
        const role = body.role === "admin" ? "admin" : "sales";
        const active = body.active !== false;
        if (id && a[id].role === "admin" && (role !== "admin" || !active)) {
          const admins = Object.entries(a).filter(([k, x]) => x.role === "admin" && x.active !== false && k !== id).length;
          if (!admins) { err = "Keep at least one active admin."; return false; }
        }
        const base = id ? a[id] : { createdAt: Date.now(), createdBy: me.id };
        a[id || newId()] = { ...base, name: String(body.name).toUpperCase(), username, role, active, updatedAt: Date.now(), ...(pw ? makeCred(pw) : {}) };
      });
      return err ? fail(400, err) : json({ ok: true });
    }

    if (route === "account-delete") {
      if (me.role !== "admin") return fail(403, "Only an admin can manage logins.");
      let err = null;
      await mutate(s, "accounts", (a) => {
        const x = a[body.id]; if (!x) return false;
        if (body.id === me.id) { err = "You can't delete your own login."; return false; }
        if (x.role === "admin" && !Object.entries(a).some(([k, y]) => k !== body.id && y.role === "admin" && y.active !== false)) { err = "Keep at least one active admin."; return false; }
        delete a[body.id];
      });
      return err ? fail(400, err) : json({ ok: true });
    }

    return fail(404, "Not found");
  } catch (e) {
    return fail(e.status || 500, e.message || "Server error");
  }
};
