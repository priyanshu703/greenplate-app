const path = require('path');
const express = require('express');
const helmet = require('helmet');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const { MongoClient, ObjectId } = require('mongodb');
require('dotenv').config({ path: path.join(__dirname, '.env') });

const app = express();
const PORT = Number(process.env.PORT || 3000);
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017';
const DB_NAME = process.env.MONGODB_DB || 'greenplate';
const IS_PRODUCTION = process.env.NODE_ENV === 'production';
const SESSION_SECRET = process.env.SESSION_SECRET || (IS_PRODUCTION ? '' : 'local-development-only-change-this-secret');
if (IS_PRODUCTION && SESSION_SECRET.length < 32) {
  throw new Error('SESSION_SECRET must be set to a random value of at least 32 characters in production.');
}

const client = new MongoClient(MONGODB_URI, { serverSelectionTimeoutMS: 10000 });
const mongoClientPromise = client.connect();
let usersCollection = null;
let stateCollection = null;
let mongoError = null;

if (IS_PRODUCTION) app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false })); // Existing app uses inline CSS/JS; retain other Helmet headers.
app.use(express.json({ limit: '200kb', strict: true }));
app.use(session({
  name: 'greenplate.sid',
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  rolling: true,
  store: MongoStore.create({
    clientPromise: mongoClientPromise,
    dbName: DB_NAME,
    collectionName: 'sessions',
    ttl: 7 * 24 * 60 * 60,
    autoRemove: 'native'
  }),
  cookie: {
    httpOnly: true,
    secure: IS_PRODUCTION,
    sameSite: 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000
  }
}));

// Reject cross-origin browser writes. SameSite cookies are an additional CSRF layer.
app.use((req, res, next) => {
  if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) return next();
  const origin = req.get('origin');
  if (!origin) return next(); // Non-browser clients may omit Origin; cookie auth is still required.
  try {
    if (new URL(origin).host !== req.get('host')) return res.status(403).json({ error: 'Cross-origin request blocked.' });
  } catch (_) {
    return res.status(403).json({ error: 'Invalid request origin.' });
  }
  next();
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Too many sign-in attempts. Please wait 15 minutes and try again.' }
});
const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 5,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Too many accounts created from this connection. Please try again later.' }
});

function authRequired(req, res, next) {
  if (!req.session || !req.session.userId) return res.status(401).json({ error: 'Please sign in to continue.' });
  if (!ObjectId.isValid(req.session.userId)) {
    req.session.destroy(() => {});
    return res.status(401).json({ error: 'Session expired. Please sign in again.' });
  }
  next();
}
function safeUser(user) {
  return { id: String(user._id), name: user.name || '', email: user.email };
}
function setSessionUser(req, user) {
  return new Promise((resolve, reject) => {
    req.session.regenerate(err => {
      if (err) return reject(err);
      req.session.userId = String(user._id);
      req.session.save(saveErr => saveErr ? reject(saveErr) : resolve());
    });
  });
}
function validEmail(email) {
  return typeof email === 'string' && email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

app.get('/api/health', (_req, res) => {
  res.status(stateCollection ? 200 : 503).json({
    ok: Boolean(stateCollection),
    database: stateCollection ? 'connected' : 'disconnected',
    authentication: 'session-cookie',
    ...(mongoError ? { databaseMessage: mongoError } : {})
  });
});

app.post('/api/auth/register', registerLimiter, async (req, res) => {
  if (!usersCollection) return res.status(503).json({ error: 'Database is not ready. Please try again shortly.' });
  const name = typeof req.body?.name === 'string' ? req.body.name.trim() : '';
  const email = typeof req.body?.email === 'string' ? req.body.email.trim().toLowerCase() : '';
  const password = req.body?.password;
  if (name.length > 60) return res.status(400).json({ error: 'Name must be 60 characters or fewer.' });
  if (!validEmail(email)) return res.status(400).json({ error: 'Enter a valid email address.' });
  if (typeof password !== 'string' || password.length < 8 || password.length > 128) {
    return res.status(400).json({ error: 'Password must be 8–128 characters long.' });
  }
  try {
    const existing = await usersCollection.findOne({ email }, { projection: { _id: 1 } });
    if (existing) return res.status(409).json({ error: 'An account with this email already exists. Sign in instead.' });
    const passwordHash = await bcrypt.hash(password, 12);
    const user = { name, email, passwordHash, createdAt: new Date(), updatedAt: new Date() };
    const result = await usersCollection.insertOne(user);
    user._id = result.insertedId;
    await setSessionUser(req, user);
    return res.status(201).json({ ok: true, user: safeUser(user) });
  } catch (error) {
    if (error && error.code === 11000) return res.status(409).json({ error: 'An account with this email already exists. Sign in instead.' });
    console.error('Registration failed:', error.message);
    return res.status(500).json({ error: 'Could not create your account. Please try again.' });
  }
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  if (!usersCollection) return res.status(503).json({ error: 'Database is not ready. Please try again shortly.' });
  const email = typeof req.body?.email === 'string' ? req.body.email.trim().toLowerCase() : '';
  const password = req.body?.password;
  if (!validEmail(email) || typeof password !== 'string' || password.length > 128) {
    return res.status(400).json({ error: 'Enter your email and password.' });
  }
  try {
    const user = await usersCollection.findOne({ email });
    const passwordMatches = user && await bcrypt.compare(password, user.passwordHash);
    if (!passwordMatches) return res.status(401).json({ error: 'Email or password is incorrect.' });
    await setSessionUser(req, user);
    return res.json({ ok: true, user: safeUser(user) });
  } catch (error) {
    console.error('Login failed:', error.message);
    return res.status(500).json({ error: 'Could not sign in. Please try again.' });
  }
});

app.get('/api/auth/me', authRequired, async (req, res) => {
  try {
    const user = await usersCollection.findOne({ _id: new ObjectId(req.session.userId) }, { projection: { name: 1, email: 1 } });
    if (!user) {
      req.session.destroy(() => {});
      return res.status(401).json({ error: 'Account not found. Please sign in again.' });
    }
    res.json({ user: safeUser(user) });
  } catch (error) {
    res.status(500).json({ error: 'Could not verify your session.' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  if (!req.session) return res.json({ ok: true });
  req.session.destroy(error => {
    if (error) return res.status(500).json({ error: 'Could not sign out completely.' });
    res.clearCookie('greenplate.sid', { httpOnly: true, secure: IS_PRODUCTION, sameSite: 'lax' });
    res.json({ ok: true });
  });
});

// State endpoints are private and scoped to the signed-in user's MongoDB ObjectId.
app.get('/api/state', authRequired, async (req, res) => {
  if (!stateCollection) return res.status(503).json({ error: 'MongoDB is not connected.' });
  try {
    const userId = new ObjectId(req.session.userId);
    const record = await stateCollection.findOne({ userId }, { projection: { state: 1, updatedAt: 1 } });
    res.json({ state: record?.state || null, updatedAt: record?.updatedAt || null });
  } catch (error) {
    console.error('State read failed:', error.message);
    res.status(500).json({ error: 'Could not read your Greenplate data.' });
  }
});

app.put('/api/state', authRequired, async (req, res) => {
  if (!stateCollection) return res.status(503).json({ error: 'MongoDB is not connected.' });
  const nextState = req.body;
  if (!nextState || typeof nextState !== 'object' || Array.isArray(nextState)) {
    return res.status(400).json({ error: 'Expected Greenplate state as a JSON object.' });
  }
  if (Buffer.byteLength(JSON.stringify(nextState), 'utf8') > 150 * 1024) {
    return res.status(413).json({ error: 'Your saved data is too large.' });
  }
  try {
    const userId = new ObjectId(req.session.userId);
    const savedAt = new Date();
    await stateCollection.updateOne(
      { userId },
      { $set: { userId, state: nextState, updatedAt: savedAt } },
      { upsert: true }
    );
    res.json({ ok: true, savedAt: savedAt.toISOString() });
  } catch (error) {
    console.error('State save failed:', error.message);
    res.status(500).json({ error: 'Could not save your Greenplate data.' });
  }
});

app.use(express.static(__dirname, { index: 'index.html', dotfiles: 'deny' }));
app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api/')) return res.status(404).json({ error: 'API endpoint not found.' });
  res.sendFile(path.join(__dirname, 'index.html'), err => err && next(err));
});

async function start() {
  try {
    await mongoClientPromise;
    const db = client.db(DB_NAME);
    usersCollection = db.collection('users');
    stateCollection = db.collection('user_states');
    await usersCollection.createIndex({ email: 1 }, { unique: true });
    await stateCollection.createIndex({ userId: 1 }, { unique: true });
    mongoError = null;
    console.log(`MongoDB connected: ${DB_NAME}; user authentication and per-user state are ready.`);
  } catch (error) {
    mongoError = 'Connection failed. Check MONGODB_URI and database access rules.';
    console.error('MongoDB connection failed:', error.message);
  }
  app.listen(PORT, '0.0.0.0', () => console.log(`Greenplate running on port ${PORT}`));
}
start();
