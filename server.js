const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const SECRET = process.env.JWT_SECRET || 'change-me-in-production';
const PORT = process.env.PORT || 3000;

const db = new Database(path.join(__dirname, 'blog.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS posts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  content TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS comments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  content TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);`);

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const sign = (u) => jwt.sign({ id: u.id, username: u.username }, SECRET, { expiresIn: '7d' });

function auth(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  try { req.user = jwt.verify(token, SECRET); next(); }
  catch { res.status(401).json({ error: 'Please log in to continue.' }); }
}

const clean = (v) => (typeof v === 'string' ? v.trim() : '');

// ---------- Auth ----------
app.post('/api/auth/register', (req, res) => {
  const username = clean(req.body.username), email = clean(req.body.email).toLowerCase(), password = req.body.password || '';
  if (username.length < 3) return res.status(400).json({ error: 'Username must be at least 3 characters.' });
  if (!/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: 'Enter a valid email address.' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  try {
    const info = db.prepare('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)')
      .run(username, email, bcrypt.hashSync(password, 10));
    const user = { id: info.lastInsertRowid, username };
    res.status(201).json({ token: sign(user), user });
  } catch {
    res.status(409).json({ error: 'That username or email is already registered.' });
  }
});

app.post('/api/auth/login', (req, res) => {
  const email = clean(req.body.email).toLowerCase();
  const row = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!row || !bcrypt.compareSync(req.body.password || '', row.password_hash))
    return res.status(401).json({ error: 'Email or password is incorrect.' });
  const user = { id: row.id, username: row.username };
  res.json({ token: sign(user), user });
});

app.get('/api/auth/me', auth, (req, res) => res.json({ user: req.user }));

// ---------- Posts ----------
const POST_SELECT = `SELECT p.*, u.username AS author,
  (SELECT COUNT(*) FROM comments c WHERE c.post_id = p.id) AS comment_count
  FROM posts p JOIN users u ON u.id = p.user_id`;

app.get('/api/posts', (req, res) => {
  res.json(db.prepare(`${POST_SELECT} ORDER BY p.created_at DESC, p.id DESC`).all());
});

app.get('/api/posts/:id', (req, res) => {
  const post = db.prepare(`${POST_SELECT} WHERE p.id = ?`).get(req.params.id);
  if (!post) return res.status(404).json({ error: 'Post not found.' });
  post.comments = db.prepare(`SELECT c.*, u.username AS author FROM comments c
    JOIN users u ON u.id = c.user_id WHERE c.post_id = ? ORDER BY c.created_at ASC, c.id ASC`).all(req.params.id);
  res.json(post);
});

app.post('/api/posts', auth, (req, res) => {
  const title = clean(req.body.title), content = clean(req.body.content);
  if (!title || !content) return res.status(400).json({ error: 'Title and content are required.' });
  const info = db.prepare('INSERT INTO posts (user_id, title, content) VALUES (?, ?, ?)').run(req.user.id, title, content);
  res.status(201).json(db.prepare(`${POST_SELECT} WHERE p.id = ?`).get(info.lastInsertRowid));
});

app.put('/api/posts/:id', auth, (req, res) => {
  const post = db.prepare('SELECT * FROM posts WHERE id = ?').get(req.params.id);
  if (!post) return res.status(404).json({ error: 'Post not found.' });
  if (post.user_id !== req.user.id) return res.status(403).json({ error: 'You can only edit your own posts.' });
  const title = clean(req.body.title), content = clean(req.body.content);
  if (!title || !content) return res.status(400).json({ error: 'Title and content are required.' });
  db.prepare('UPDATE posts SET title = ?, content = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(title, content, post.id);
  res.json(db.prepare(`${POST_SELECT} WHERE p.id = ?`).get(post.id));
});

app.delete('/api/posts/:id', auth, (req, res) => {
  const post = db.prepare('SELECT * FROM posts WHERE id = ?').get(req.params.id);
  if (!post) return res.status(404).json({ error: 'Post not found.' });
  if (post.user_id !== req.user.id) return res.status(403).json({ error: 'You can only delete your own posts.' });
  db.prepare('DELETE FROM posts WHERE id = ?').run(post.id);
  res.status(204).end();
});

// ---------- Comments ----------
app.post('/api/posts/:id/comments', auth, (req, res) => {
  const post = db.prepare('SELECT id FROM posts WHERE id = ?').get(req.params.id);
  if (!post) return res.status(404).json({ error: 'Post not found.' });
  const content = clean(req.body.content);
  if (!content) return res.status(400).json({ error: 'Write something before posting a comment.' });
  const info = db.prepare('INSERT INTO comments (post_id, user_id, content) VALUES (?, ?, ?)').run(post.id, req.user.id, content);
  res.status(201).json(db.prepare(`SELECT c.*, u.username AS author FROM comments c
    JOIN users u ON u.id = c.user_id WHERE c.id = ?`).get(info.lastInsertRowid));
});

app.delete('/api/comments/:id', auth, (req, res) => {
  const c = db.prepare(`SELECT c.*, p.user_id AS post_owner FROM comments c
    JOIN posts p ON p.id = c.post_id WHERE c.id = ?`).get(req.params.id);
  if (!c) return res.status(404).json({ error: 'Comment not found.' });
  if (c.user_id !== req.user.id && c.post_owner !== req.user.id)
    return res.status(403).json({ error: 'You can only delete your own comments.' });
  db.prepare('DELETE FROM comments WHERE id = ?').run(c.id);
  res.status(204).end();
});

app.listen(PORT, () => console.log(`Blog running at http://localhost:${PORT}`));
