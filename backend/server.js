const express = require('express');
const { MongoClient, ObjectId } = require('mongodb');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET;
const MONGODB_URI = process.env.MONGODB_URI;
if (!MONGODB_URI || !SECRET) {
  console.error('Lipsesc variabilele de mediu MONGODB_URI și/sau JWT_SECRET');
  process.exit(1);
}

const client = new MongoClient(MONGODB_URI);
let users, weightsC, videosC, kvC;

const KV_KEYS = ['goal', 'habits', 'done', 'plan', 'tt'];
const DEFAULT_HABITS = ['💧 Apă suficientă', '🚶 Plimbare / pași', '🥗 Masă echilibrată', '😴 Somn bun'];

const app = express();
app.use(express.json({ limit: '100kb' }));

// CORS: front end-ul static are alt domeniu, deci trebuie permis explicit
const ORIGINS = (process.env.CORS_ORIGIN || '').split(',').map((x) => x.trim().replace(/\/$/, '')).filter(Boolean);
app.use((req, res, next) => {
  const o = req.headers.origin;
  if (o && (ORIGINS.includes('*') || ORIGINS.includes(o))) {
    res.setHeader('Access-Control-Allow-Origin', o);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  }
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

const h = (fn) => (req, res) =>
  fn(req, res).catch((e) => {
    console.error(e);
    res.status(500).json({ error: 'Eroare de server' });
  });
const sign = (id) => jwt.sign({ id: String(id) }, SECRET, { expiresIn: '30d' });
const validEmail = (e) => typeof e === 'string' && /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e) && e.length < 200;

app.get('/health', (req, res) => res.send('ok'));

app.post('/api/register', h(async (req, res) => {
  const { email, password } = req.body || {};
  if (!validEmail(email)) return res.status(400).json({ error: 'Email invalid' });
  if (typeof password !== 'string' || password.length < 6)
    return res.status(400).json({ error: 'Parola trebuie să aibă minim 6 caractere' });
  try {
    const r = await users.insertOne({
      email: email.toLowerCase(),
      pass: bcrypt.hashSync(password, 10),
      createdAt: new Date(),
    });
    res.json({ token: sign(r.insertedId) });
  } catch (e) {
    if (e.code === 11000) return res.status(409).json({ error: 'Există deja un cont cu acest email' });
    throw e;
  }
}));

app.post('/api/login', h(async (req, res) => {
  const { email, password } = req.body || {};
  const u = validEmail(email) && (await users.findOne({ email: email.toLowerCase() }));
  if (!u || typeof password !== 'string' || !bcrypt.compareSync(password, u.pass))
    return res.status(401).json({ error: 'Email sau parolă greșită' });
  res.json({ token: sign(u._id) });
}));

// Rutele de mai jos cer autentificare
app.use('/api', (req, res, next) => {
  try {
    const token = (req.headers.authorization || '').replace('Bearer ', '');
    req.uid = new ObjectId(jwt.verify(token, SECRET).id);
    next();
  } catch (e) {
    res.status(401).json({ error: 'Neautentificat' });
  }
});

const getWeights = (uid) =>
  weightsC.find({ userId: uid }).sort({ d: 1 }).project({ _id: 0, d: 1, v: 1 }).toArray();
const getVideos = async (uid) =>
  (await videosC.find({ userId: uid }).sort({ _id: -1 }).toArray()).map((x) => ({
    id: x._id.toString(), u: x.url, n: x.note,
  }));

app.get('/api/data', h(async (req, res) => {
  const kv = {};
  (await kvC.find({ userId: req.uid }).toArray()).forEach((r) => (kv[r.k] = JSON.parse(r.v)));
  res.json({
    goal: kv.goal || {},
    habits: kv.habits || DEFAULT_HABITS,
    done: kv.done || {},
    plan: kv.plan || {},
    tt: kv.tt || '',
    ws: await getWeights(req.uid),
    vids: await getVideos(req.uid),
  });
}));

app.put('/api/kv/:key', h(async (req, res) => {
  if (!KV_KEYS.includes(req.params.key)) return res.status(400).json({ error: 'Cheie invalidă' });
  const val = JSON.stringify(req.body.value ?? null);
  if (val.length > 50000) return res.status(413).json({ error: 'Prea mare' });
  await kvC.updateOne({ userId: req.uid, k: req.params.key }, { $set: { v: val } }, { upsert: true });
  res.json({ ok: true });
}));

app.post('/api/weights', h(async (req, res) => {
  const { d, v } = req.body || {};
  if (!/^\d{4}-\d{2}-\d{2}$/.test(d) || !(v > 20 && v < 500)) return res.status(400).json({ error: 'Date invalide' });
  await weightsC.updateOne({ userId: req.uid, d }, { $set: { v } }, { upsert: true });
  res.json(await getWeights(req.uid));
}));

app.delete('/api/weights/:d', h(async (req, res) => {
  await weightsC.deleteOne({ userId: req.uid, d: req.params.d });
  res.json(await getWeights(req.uid));
}));

app.post('/api/videos', h(async (req, res) => {
  const { u, n } = req.body || {};
  if (typeof u !== 'string' || !/^https?:\/\//.test(u) || u.length > 500)
    return res.status(400).json({ error: 'Link invalid' });
  await videosC.insertOne({ userId: req.uid, url: u, note: String(n || '').slice(0, 100) });
  res.json(await getVideos(req.uid));
}));

app.delete('/api/videos/:id', h(async (req, res) => {
  if (!ObjectId.isValid(req.params.id)) return res.status(400).json({ error: 'Id invalid' });
  await videosC.deleteOne({ userId: req.uid, _id: new ObjectId(req.params.id) });
  res.json(await getVideos(req.uid));
}));

(async () => {
  await client.connect();
  const db = client.db(process.env.DB_NAME || 'planul-meu');
  users = db.collection('users');
  weightsC = db.collection('weights');
  videosC = db.collection('videos');
  kvC = db.collection('kv');
  await users.createIndex({ email: 1 }, { unique: true });
  await weightsC.createIndex({ userId: 1, d: 1 }, { unique: true });
  await videosC.createIndex({ userId: 1 });
  await kvC.createIndex({ userId: 1, k: 1 }, { unique: true });
  app.listen(PORT, () => console.log('Server pornit pe portul ' + PORT));
})().catch((e) => {
  console.error('Nu m-am putut conecta la MongoDB:', e.message);
  process.exit(1);
});
