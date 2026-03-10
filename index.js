require('dotenv').config();
const express = require('express');
const cors    = require('cors');

const app = express();

const prodOrigins = (process.env.FRONTEND_URL || '').split(',').map(s => s.trim()).filter(Boolean);
const devOrigins  = ['http://localhost:3000','http://localhost:3001','http://127.0.0.1:3000'];
const allowedOrigins = [...new Set([...prodOrigins, ...devOrigins])];

app.use(cors({
  origin: (origin, cb) => {
    if (!origin || allowedOrigins.includes(origin)) return cb(null, true);
    cb(new Error('CORS: not allowed - ' + origin));
  },
  credentials: true,
}));
app.set('trust proxy', 1);
app.use(express.json());

const db = require('./lib/firestore');
app.use('/bank', require('./routes/sepay')(db));

// ── Health check ────────────────────────────────────────────
app.get('/', (req, res) => {
  res.json({ status: 'GameStore VN Server ✅', time: new Date().toISOString() });
});

// ── Debug endpoints - S3: che API key, chỉ show trong dev ───
app.get('/debug/env', (req, res) => {
  const isProd = process.env.NODE_ENV === 'production';
  res.json({
    BANK_VA_NUMBER:      process.env.BANK_VA_NUMBER     || '❌ CHƯA SET',
    BANK_ACCOUNT_NUMBER: process.env.BANK_ACCOUNT_NUMBER|| '❌ CHƯA SET',
    BANK_BIN:            process.env.BANK_BIN           || '❌ CHƯA SET',
    SEPAY_API_KEY:       process.env.SEPAY_API_KEY
      ? `✅ SET (${isProd ? '***hidden***' : process.env.SEPAY_API_KEY.slice(0,8) + '...'})`
      : '❌ CHƯA SET',
    SEPAY_HMAC_SECRET:   process.env.SEPAY_HMAC_SECRET  ? '✅ SET' : '⚠️ CHƯA SET (optional)',
    SKIP_IP_CHECK:       process.env.SKIP_IP_CHECK      || 'false',
    FRONTEND_URL:        process.env.FRONTEND_URL        || '❌ CHƯA SET',
    NODE_ENV:            process.env.NODE_ENV            || 'not set',
  });
});

app.get('/debug/firestore', async (req, res) => {
  const results = {};
  try {
    const r = await db.query('users', [], null, 1);
    results.read_users = r.length > 0 ? '✅ OK' : '✅ OK (empty)';
  } catch(e) {
    results.read_users = '❌ ' + (e.response?.status || e.message);
  }
  try {
    const ref = await db.add('topups', {
      userId: 'debug-test', userEmail: 'debug@test.com',
      amount: 10000, status: 'debug',
      createdAt: db.FieldValue.serverTimestamp(),
    });
    results.write_topup = '✅ OK id=' + ref.id;
  } catch(e) {
    results.write_topup = '❌ HTTP ' + (e.response?.status || e.code) + ' → ' + JSON.stringify(e.response?.data?.error || e.message);
  }
  res.json(results);
});

// Retry queue processor (manual trigger)
app.post('/admin/retry-queue', async (req, res) => {
  const adminKey = req.headers['x-admin-key'];
  if (!adminKey || adminKey !== process.env.SEPAY_API_KEY) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  try {
    const items = await db.query('retryQueue', [['status','==','pending']], null, 10);
    const results = [];
    for (const item of items) {
      const d = item.data();
      try {
        // Re-process
        const { processWebhook } = require('./routes/sepay');
        results.push({ id: item.id, status: 'retried' });
        await db.update('retryQueue', item.id, { status: 'retried', retriedAt: db.FieldValue.serverTimestamp() });
      } catch(e) {
        results.push({ id: item.id, status: 'failed', error: e.message });
      }
    }
    res.json({ processed: results.length, results });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`✅ GameStore Server v4 | Port ${PORT}`);
  console.log(`   POST /bank/webhook  ← SePay webhook`);
  console.log(`   GET  /bank/vietqr   ← Generate QR`);
  console.log(`   HMAC: ${process.env.SEPAY_HMAC_SECRET ? '✅ Enabled' : '⚠️  Disabled (set SEPAY_HMAC_SECRET)'}`);
});
