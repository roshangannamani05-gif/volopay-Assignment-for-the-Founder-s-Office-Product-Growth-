import express from "express";
import Database from "better-sqlite3";
import crypto from "node:crypto";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";

const PORT = process.env.PORT || 3000;
const BASE_URL = (process.env.BASE_URL || `http://localhost:${PORT}`).replace(/\/$/, "");
const db = new Database(process.env.DB_PATH || "data.db");
db.exec(`
create table if not exists users(id integer primary key, username text unique, salt text, hash text, token text unique, business text default '');
create table if not exists invoices(
  id text primary key, user_id integer, client_name text, client_email text default '',
  items text, currency text default 'INR', due_date text, notes text default '',
  status text default 'unpaid', created_at text, viewed_at text, paid_at text, last_reminder_at text);
`);

// ---------- helpers ----------
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const hash = (pw, salt) => crypto.scryptSync(pw, salt, 32).toString("hex");
const now = () => new Date().toISOString();
const money = (n, cur) => new Intl.NumberFormat("en-IN", { style: "currency", currency: cur || "INR" }).format(n);
const total = (inv) => JSON.parse(inv.items).reduce((s, i) => s + i.quantity * i.unit_price, 0);
const isOverdue = (inv) => inv.status !== "paid" && inv.due_date && inv.due_date < now().slice(0, 10);
const label = (inv) => (inv.status === "paid" ? "paid" : isOverdue(inv) ? "overdue" : inv.viewed_at ? "viewed" : "sent");

function createUser(username, password, business = "", token = crypto.randomBytes(20).toString("hex")) {
  const salt = crypto.randomBytes(8).toString("hex");
  db.prepare("insert into users(username,salt,hash,token,business) values(?,?,?,?,?)").run(username, salt, hash(password, salt), token, business);
}
// DEMO_TOKEN keeps the demo account's MCP link stable even if the database resets (free hosting)
if (!db.prepare("select 1 from users where username='demo'").get()) createUser("demo", "demo1234", "Demo Studio", process.env.DEMO_TOKEN || undefined);

const sessions = new Map();
const parseCookies = (req) => Object.fromEntries((req.headers.cookie || "").split(";").filter(Boolean).map((c) => c.trim().split("=")));
const getUser = (req) => {
  const sid = parseCookies(req).sid;
  const uid = sid && sessions.get(sid);
  return uid ? db.prepare("select * from users where id=?").get(uid) : null;
};
const requireUser = (req, res, next) => {
  const u = getUser(req);
  if (!u) return res.redirect("/");
  req.user = u;
  next();
};

const css = `<style>
*{box-sizing:border-box}body{font:15px/1.5 system-ui,sans-serif;margin:0;background:#f6f7fb;color:#15171f}
.w{max-width:860px;margin:0 auto;padding:24px 16px}.card{background:#fff;border:1px solid #e4e6ee;border-radius:12px;padding:20px;margin-bottom:16px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:16px;margin:0 0 10px}table{width:100%;border-collapse:collapse}
td,th{text-align:left;padding:8px 6px;border-bottom:1px solid #eef0f5;font-size:14px}input,textarea,select{width:100%;padding:9px;border:1px solid #cfd3de;border-radius:8px;font:inherit;margin:4px 0 12px}
button,.btn{background:#4b4bff;color:#fff;border:0;border-radius:8px;padding:9px 14px;font:inherit;cursor:pointer;text-decoration:none;display:inline-block}
.btn2{background:#eef0f7;color:#15171f}.tag{padding:2px 8px;border-radius:99px;font-size:12px;background:#eef0f7}
.paid{background:#d9f7e4;color:#12703a}.overdue{background:#ffe0e0;color:#a11}.viewed{background:#fff2cc;color:#8a6100}
code{background:#eef0f7;padding:2px 6px;border-radius:6px;word-break:break-all}.row{display:flex;gap:12px}.row>*{flex:1}.right{text-align:right}
</style><meta name="viewport" content="width=device-width,initial-scale=1">`;
const page = (title, body) => `<!doctype html><html><head><title>${esc(title)}</title>${css}</head><body><div class="w">${body}</div></body></html>`;

// ---------- web app ----------
const app = express();
app.use("/mcp", express.json());
app.use(express.urlencoded({ extended: false }));

app.get("/", (req, res) => {
  if (getUser(req)) return res.redirect("/dashboard");
  res.send(page("InvoiceClaw", `<div class="card"><h1>InvoiceClaw</h1><p>Tell Claude who to invoice. A live, trackable invoice appears here. Edit it, send the link, get paid.</p>
  <div class="row"><form method="post" action="/login"><h2>Log in</h2><input name="username" placeholder="username"><input name="password" type="password" placeholder="password"><button>Log in</button></form>
  <form method="post" action="/signup"><h2>Sign up</h2><input name="username" placeholder="username"><input name="password" type="password" placeholder="password"><input name="business" placeholder="Your business name"><button class="btn2" style="color:#15171f">Create account</button></form></div>
  <p style="color:#666">Reviewer test login: <code>demo</code> / <code>demo1234</code></p></div>`));
});
const startSession = (res, uid) => {
  const sid = crypto.randomBytes(16).toString("hex");
  sessions.set(sid, uid);
  res.setHeader("Set-Cookie", `sid=${sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000`);
};
app.post("/login", (req, res) => {
  const u = db.prepare("select * from users where username=?").get(req.body.username || "");
  if (!u || hash(req.body.password || "", u.salt) !== u.hash) return res.status(401).send(page("Login", `<div class="card">Wrong username or password. <a href="/">Back</a></div>`));
  startSession(res, u.id);
  res.redirect("/dashboard");
});
app.post("/signup", (req, res) => {
  const { username, password, business } = req.body;
  if (!username || !password || password.length < 6) return res.status(400).send(page("Signup", `<div class="card">Username and a 6+ character password required. <a href="/">Back</a></div>`));
  try { createUser(username.trim(), password, business || ""); } catch { return res.status(400).send(page("Signup", `<div class="card">Username taken. <a href="/">Back</a></div>`)); }
  const u = db.prepare("select id from users where username=?").get(username.trim());
  startSession(res, u.id);
  res.redirect("/dashboard");
});
app.post("/logout", (req, res) => { sessions.delete(parseCookies(req).sid); res.setHeader("Set-Cookie", "sid=; Path=/; Max-Age=0"); res.redirect("/"); });

app.get("/dashboard", requireUser, (req, res) => {
  const rows = db.prepare("select * from invoices where user_id=? order by created_at desc").all(req.user.id);
  const sum = (f) => rows.filter(f).reduce((s, i) => s + total(i), 0);
  res.send(page("Dashboard", `<div class="card"><div class="row"><div><h1>${esc(req.user.business || req.user.username)}</h1><span style="color:#666">Invoices created by Claude appear here</span></div>
  <form method="post" action="/logout" class="right"><button class="btn2" style="color:#15171f">Log out</button></form></div></div>
  <div class="card"><h2>Connect Claude</h2><p>Claude → Settings → Connectors → Add custom connector → paste:</p><code>${BASE_URL}/mcp/${req.user.token}</code>
  <p style="color:#666">Then ask: "Invoice Acme Corp ₹50,000 for May design work, due in 15 days."</p></div>
  <div class="card"><div class="row"><div><b>Outstanding</b><br>${money(sum((i) => i.status !== "paid"))}</div><div><b>Paid</b><br>${money(sum((i) => i.status === "paid"))}</div><div><b>Invoices</b><br>${rows.length}</div></div></div>
  <div class="card"><h2>Invoices</h2><table><tr><th>Client</th><th>Amount</th><th>Due</th><th>Status</th><th></th></tr>
  ${rows.map((i) => `<tr><td>${esc(i.client_name)}</td><td>${money(total(i), i.currency)}</td><td>${esc(i.due_date)}</td><td><span class="tag ${label(i)}">${label(i)}</span></td><td class="right"><a href="/invoices/${i.id}/edit">Edit</a> · <a href="/i/${i.id}" target="_blank">View</a></td></tr>`).join("") || `<tr><td colspan=5>No invoices yet. Ask Claude to create one.</td></tr>`}</table></div>`));
});

const ownInvoice = (req, res) => {
  const inv = db.prepare("select * from invoices where id=? and user_id=?").get(req.params.id, req.user.id);
  if (!inv) res.status(404).send(page("Not found", `<div class="card">Invoice not found.</div>`));
  return inv;
};
app.get("/invoices/:id/edit", requireUser, (req, res) => {
  const inv = ownInvoice(req, res); if (!inv) return;
  const lines = JSON.parse(inv.items).map((i) => `${i.description} | ${i.quantity} | ${i.unit_price}`).join("\n");
  res.send(page("Edit invoice", `<div class="card"><h1>Edit invoice</h1><p>Public link: <a href="/i/${inv.id}" target="_blank">${BASE_URL}/i/${inv.id}</a></p>
  <form method="post" action="/invoices/${inv.id}"><label>Client name</label><input name="client_name" value="${esc(inv.client_name)}">
  <label>Client email</label><input name="client_email" value="${esc(inv.client_email)}">
  <div class="row"><div><label>Currency</label><input name="currency" value="${esc(inv.currency)}"></div><div><label>Due date</label><input type="date" name="due_date" value="${esc(inv.due_date)}"></div></div>
  <label>Line items (one per line: description | quantity | unit price)</label><textarea name="items" rows="5">${esc(lines)}</textarea>
  <label>Notes</label><textarea name="notes" rows="3">${esc(inv.notes)}</textarea>
  <button>Save</button> <a class="btn btn2" href="/dashboard">Back</a></form></div>
  <form method="post" action="/invoices/${inv.id}/${inv.status === "paid" ? "unpaid" : "paid"}"><button class="btn2" style="color:#15171f">${inv.status === "paid" ? "Mark unpaid" : "Mark as paid"}</button></form>`));
});
app.post("/invoices/:id", requireUser, (req, res) => {
  const inv = ownInvoice(req, res); if (!inv) return;
  const items = String(req.body.items || "").split("\n").map((l) => l.split("|").map((s) => s.trim())).filter((p) => p[0])
    .map((p) => ({ description: p[0], quantity: Number(p[1]) || 1, unit_price: Number(p[2]) || 0 }));
  db.prepare("update invoices set client_name=?,client_email=?,currency=?,due_date=?,items=?,notes=? where id=?")
    .run(req.body.client_name, req.body.client_email, req.body.currency || "INR", req.body.due_date, JSON.stringify(items), req.body.notes, inv.id);
  res.redirect("/dashboard");
});
app.post("/invoices/:id/:action(paid|unpaid)", requireUser, (req, res) => {
  const inv = ownInvoice(req, res); if (!inv) return;
  db.prepare("update invoices set status=?, paid_at=? where id=?").run(req.params.action, req.params.action === "paid" ? now() : null, inv.id);
  res.redirect(`/invoices/${inv.id}/edit`);
});

// public client-facing invoice (tracks first view)
app.get("/i/:id", (req, res) => {
  const inv = db.prepare("select * from invoices where id=?").get(req.params.id);
  if (!inv) return res.status(404).send(page("Not found", `<div class="card">Invoice not found.</div>`));
  if (!inv.viewed_at) db.prepare("update invoices set viewed_at=? where id=?").run(now(), inv.id);
  const from = db.prepare("select business,username from users where id=?").get(inv.user_id);
  const items = JSON.parse(inv.items);
  res.send(page(`Invoice ${inv.id}`, `<div class="card"><div class="row"><div><h1>Invoice</h1><span style="color:#666">#${inv.id}</span></div><div class="right"><span class="tag ${label(inv)}">${label(inv).toUpperCase()}</span></div></div>
  <p><b>From:</b> ${esc(from.business || from.username)}<br><b>To:</b> ${esc(inv.client_name)}<br><b>Due:</b> ${esc(inv.due_date)}</p>
  <table><tr><th>Description</th><th>Qty</th><th>Price</th><th class="right">Amount</th></tr>
  ${items.map((i) => `<tr><td>${esc(i.description)}</td><td>${i.quantity}</td><td>${money(i.unit_price, inv.currency)}</td><td class="right">${money(i.quantity * i.unit_price, inv.currency)}</td></tr>`).join("")}
  <tr><td colspan=3 class="right"><b>Total</b></td><td class="right"><b>${money(total(inv), inv.currency)}</b></td></tr></table>
  ${inv.notes ? `<p style="color:#555">${esc(inv.notes)}</p>` : ""}</div>`));
});

// ---------- MCP server (no AI inside; Claude is the client) ----------
const itemSchema = z.object({ description: z.string(), quantity: z.number().default(1), unit_price: z.number() });
const summary = (inv) => ({ id: inv.id, client: inv.client_name, total: total(inv), currency: inv.currency, due_date: inv.due_date, status: label(inv), public_link: `${BASE_URL}/i/${inv.id}`, edit_link: `${BASE_URL}/invoices/${inv.id}/edit` });
const text = (o) => ({ content: [{ type: "text", text: typeof o === "string" ? o : JSON.stringify(o, null, 2) }] });

function buildServer(user) {
  const s = new McpServer({ name: "invoiceclaw", version: "1.0.0" });
  s.tool("create_invoice", "Create a live, shareable invoice. Returns a public link to send to the client and an edit link for the user.",
    { client_name: z.string(), client_email: z.string().optional(), items: z.array(itemSchema).min(1), currency: z.string().default("INR").describe("ISO code, e.g. INR, USD"), due_date: z.string().describe("YYYY-MM-DD"), notes: z.string().optional() },
    async (a) => {
      const id = crypto.randomBytes(5).toString("hex");
      db.prepare("insert into invoices(id,user_id,client_name,client_email,items,currency,due_date,notes,created_at) values(?,?,?,?,?,?,?,?,?)")
        .run(id, user.id, a.client_name, a.client_email || "", JSON.stringify(a.items), a.currency, a.due_date, a.notes || "", now());
      return text(summary(db.prepare("select * from invoices where id=?").get(id)));
    });
  s.tool("list_invoices", "List the user's invoices with status (sent, viewed, overdue, paid).", { status: z.enum(["sent", "viewed", "overdue", "paid"]).optional() },
    async ({ status }) => text(db.prepare("select * from invoices where user_id=? order by created_at desc").all(user.id).map(summary).filter((i) => !status || i.status === status)));
  s.tool("update_invoice", "Edit an invoice or mark it paid.",
    { id: z.string(), client_name: z.string().optional(), client_email: z.string().optional(), items: z.array(itemSchema).optional(), due_date: z.string().optional(), notes: z.string().optional(), mark_paid: z.boolean().optional() },
    async (a) => {
      const inv = db.prepare("select * from invoices where id=? and user_id=?").get(a.id, user.id);
      if (!inv) return { ...text("Invoice not found"), isError: true };
      db.prepare("update invoices set client_name=?,client_email=?,items=?,due_date=?,notes=?,status=?,paid_at=? where id=?")
        .run(a.client_name ?? inv.client_name, a.client_email ?? inv.client_email, a.items ? JSON.stringify(a.items) : inv.items, a.due_date ?? inv.due_date, a.notes ?? inv.notes,
          a.mark_paid ? "paid" : inv.status, a.mark_paid ? now() : inv.paid_at, inv.id);
      return text(summary(db.prepare("select * from invoices where id=?").get(inv.id)));
    });
  return s;
}

app.post("/mcp/:token", async (req, res) => {
  const user = db.prepare("select * from users where token=?").get(req.params.token);
  if (!user) return res.status(401).json({ jsonrpc: "2.0", error: { code: -32001, message: "Invalid token" }, id: null });
  const server = buildServer(user);
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  res.on("close", () => { transport.close(); server.close(); });
  await server.connect(transport);
  await transport.handleRequest(req, res, req.body);
});
app.all("/mcp/:token", (_req, res) => res.status(405).json({ jsonrpc: "2.0", error: { code: -32000, message: "Use POST" }, id: null }));

// ---------- reminders (the "keeps working after the chat ends" part) ----------
async function sendEmail(to, subject, html) {
  if (!process.env.RESEND_API_KEY || !to) return console.log(`[reminder] would email ${to}: ${subject}`);
  await fetch("https://api.resend.com/emails", { method: "POST", headers: { Authorization: `Bearer ${process.env.RESEND_API_KEY}`, "Content-Type": "application/json" },
    body: JSON.stringify({ from: process.env.MAIL_FROM || "invoices@example.com", to, subject, html }) }).catch(console.error);
}
async function runReminders() {
  const cutoff = new Date(Date.now() - 3 * 864e5).toISOString();
  const due = db.prepare("select * from invoices where status!='paid' and due_date < ? and (last_reminder_at is null or last_reminder_at < ?)").all(now().slice(0, 10), cutoff);
  for (const inv of due) {
    await sendEmail(inv.client_email, `Reminder: invoice ${inv.id} is overdue`, `<p>Hi ${esc(inv.client_name)}, your invoice is overdue: <a href="${BASE_URL}/i/${inv.id}">view it here</a>.</p>`);
    db.prepare("update invoices set last_reminder_at=? where id=?").run(now(), inv.id);
  }
}
setInterval(runReminders, 60 * 60 * 1000);
setTimeout(runReminders, 5000);

app.get("/health", (_req, res) => res.send("ok"));
app.listen(PORT, () => console.log(`InvoiceClaw on ${BASE_URL}`));
