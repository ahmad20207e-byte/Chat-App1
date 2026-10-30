const express = require("express");
const http = require("http");
const path = require("path");
const crypto = require("crypto");
const fs = require("fs");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { WebSocketServer } = require("ws");

const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || __dirname;
const SECRET = process.env.JWT_SECRET || (() => {
  const f = path.join(DATA_DIR, ".secret");
  if (!fs.existsSync(f)) fs.writeFileSync(f, crypto.randomBytes(32).toString("hex"));
  return fs.readFileSync(f, "utf8");
})();

const db = new Database(path.join(DATA_DIR, "chat.db"));
db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL COLLATE NOCASE,
  password_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sender_id INTEGER NOT NULL,
  receiver_id INTEGER,            -- NULL = general room
  text TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pair ON messages(sender_id, receiver_id);
`);

const app = express();
app.use(express.json({ limit: "10kb" }));
app.use(express.static(path.join(__dirname, "public")));

// very small rate limiter for auth endpoints
const hits = new Map();
function limit(req, res, next) {
  const k = req.ip, now = Date.now();
  const arr = (hits.get(k) || []).filter(t => now - t < 60000);
  if (arr.length >= 20) return res.status(429).json({ error: "محاولات كثيرة، انتظر دقيقة" });
  arr.push(now); hits.set(k, arr); next();
}

function sign(u) { return jwt.sign({ id: u.id, username: u.username }, SECRET, { expiresIn: "30d" }); }
function auth(req, res, next) {
  try {
    const t = (req.headers.authorization || "").replace("Bearer ", "");
    req.user = jwt.verify(t, SECRET); next();
  } catch { res.status(401).json({ error: "غير مصرح" }); }
}

app.post("/api/register", limit, (req, res) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");
  if (!/^[\w\u0600-\u06FF.-]{3,20}$/.test(username)) return res.status(400).json({ error: "اسم المستخدم 3-20 حرفاً (حروف وأرقام و _ . -)" });
  if (password.length < 6) return res.status(400).json({ error: "كلمة المرور 6 أحرف على الأقل" });
  try {
    const hash = bcrypt.hashSync(password, 10);
    const r = db.prepare("INSERT INTO users (username, password_hash, created_at) VALUES (?,?,?)").run(username, hash, Date.now());
    const u = { id: r.lastInsertRowid, username };
    res.json({ token: sign(u), user: u });
  } catch { res.status(409).json({ error: "اسم المستخدم مستخدم مسبقاً" }); }
});

app.post("/api/login", limit, (req, res) => {
  const u = db.prepare("SELECT * FROM users WHERE username = ?").get(String(req.body.username || "").trim());
  if (!u || !bcrypt.compareSync(String(req.body.password || ""), u.password_hash))
    return res.status(401).json({ error: "بيانات الدخول غير صحيحة" });
  res.json({ token: sign(u), user: { id: u.id, username: u.username } });
});

app.get("/api/users", auth, (req, res) => {
  res.json(db.prepare("SELECT id, username FROM users ORDER BY username").all());
});

// history: ?with=0 -> general room, ?with=<id> -> private chat
app.get("/api/messages", auth, (req, res) => {
  const w = parseInt(req.query.with, 10) || 0, me = req.user.id;
  const rows = w === 0
    ? db.prepare("SELECT id, sender_id, receiver_id, text, created_at FROM messages WHERE receiver_id IS NULL ORDER BY id DESC LIMIT 200").all()
    : db.prepare(`SELECT id, sender_id, receiver_id, text, created_at FROM messages
        WHERE (sender_id=? AND receiver_id=?) OR (sender_id=? AND receiver_id=?) ORDER BY id DESC LIMIT 200`).all(me, w, w, me);
  res.json(rows.reverse());
});

const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: "/ws" });
const sockets = new Map(); // userId -> Set<ws>

wss.on("connection", (ws, req) => {
  let user;
  try { user = jwt.verify(new URL(req.url, "http://x").searchParams.get("token"), SECRET); }
  catch { return ws.close(4001); }
  if (!sockets.has(user.id)) sockets.set(user.id, new Set());
  sockets.get(user.id).add(ws);
  ws.on("close", () => sockets.get(user.id)?.delete(ws));
  ws.on("message", raw => {
    let d; try { d = JSON.parse(raw); } catch { return; }
    const text = String(d.text || "").trim().slice(0, 1000);
    if (!text) return;
    const to = d.to ? parseInt(d.to, 10) : null;
    if (to && !db.prepare("SELECT 1 FROM users WHERE id=?").get(to)) return;
    const now = Date.now();
    const r = db.prepare("INSERT INTO messages (sender_id, receiver_id, text, created_at) VALUES (?,?,?,?)").run(user.id, to, text, now);
    const msg = JSON.stringify({ type: "message", message: { id: r.lastInsertRowid, sender_id: user.id, receiver_id: to, text, created_at: now } });
    const targets = to === null ? [...sockets.values()].flatMap(s => [...s]) : [...(sockets.get(user.id) || []), ...(sockets.get(to) || [])];
    targets.forEach(c => c.readyState === 1 && c.send(msg));
  });
});

server.listen(PORT, () => console.log("Chat running on http://localhost:" + PORT));
