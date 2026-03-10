require('dotenv').config();
const express = require('express');
const cors = require('cors');

const app = express();
// ✅ FIX: Restrict CORS to frontend domain only
// ✅ FIX BUG 19: Always include localhost for dev, production domains from env
const prodOrigins = (process.env.FRONTEND_URL || '').split(',').map(s => s.trim()).filter(Boolean);
const devOrigins = ['http://localhost:3000', 'http://localhost:3001', 'http://127.0.0.1:3000'];
const allowedOrigins = [...new Set([...prodOrigins, ...devOrigins])];
app.use(cors({
  origin: (origin, callback) => {
    // Allow no-origin (Postman, curl, server-to-server) and allowed origins
    if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
    callback(new Error('CORS: origin not allowed - ' + origin));
  },
  credentials: true,
}));

// ✅ FIX: Trust proxy correctly for Render.com (1 hop)
app.set('trust proxy', 1);
app.use(express.json());

// Dùng Firestore REST API thay vì firebase-admin
// Không cần Service Account key!
const db = require('./lib/firestore');

app.use('/bank', require('./routes/sepay')(db));

app.get('/', (req, res) => {
  res.json({ status: 'GameStore VN Server ✅', time: new Date().toISOString() });
});

// ── Debug endpoints (tạm thời) ───────────────────────────────────────────
app.get('/debug/env', (req, res) => {
  res.json({
    BANK_VA_NUMBER:        process.env.BANK_VA_NUMBER     || '❌ CHƯA SET',
    BANK_ACCOUNT_NUMBER:   process.env.BANK_ACCOUNT_NUMBER|| '❌ CHƯA SET',
    BANK_BIN:              process.env.BANK_BIN           || '❌ CHƯA SET',
    SEPAY_API_KEY:         process.env.SEPAY_API_KEY ? '✅ SET (hidden)' : '❌ CHƯA SET',
    SKIP_IP_CHECK:         process.env.SKIP_IP_CHECK      || 'false',
    FRONTEND_URL:          process.env.FRONTEND_URL        || '❌ CHƯA SET',
    NODE_ENV:              process.env.NODE_ENV            || 'not set',
  });
});

// Test Firestore write trực tiếp
app.get('/debug/firestore', async (req, res) => {
  const db = require('./lib/firestore');
  const results = {};

  // Test 1: đọc collection users (bất kỳ doc nào)
  try {
    const r = await db.query('users', [], null, 1);
    results.read_users = r.length > 0 ? '✅ OK' : '✅ OK (empty)';
  } catch(e) {
    results.read_users = '❌ ' + (e.response?.status || e.message) + ' ' + JSON.stringify(e.response?.data);
  }

  // Test 2: tạo topup doc
  try {
    const ref = await db.add('topups', {
      userId: 'debug-test',
      userEmail: 'debug@test.com',
      amount: 10000,
      status: 'pending',
      createdAt: db.FieldValue.serverTimestamp(),
    });
    results.write_topup = '✅ OK id=' + ref.id;
    // Xóa luôn
    try { await db.update('topups', ref.id, { status: 'debug-delete' }); } catch(_){}
  } catch(e) {
    results.write_topup = '❌ HTTP ' + (e.response?.status || e.code) + ' → ' + JSON.stringify(e.response?.data?.error || e.message);
  }

  // Test 3: đọc topups
  try {
    const r = await db.query('topups', [], null, 1);
    results.read_topups = '✅ OK';
  } catch(e) {
    results.read_topups = '❌ ' + (e.response?.status || e.message);
  }

  res.json(results);
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`✅ Server chạy port ${PORT}`);
  console.log(`   SePay Webhook: POST /bank/webhook`);
  console.log(`   VietQR:        GET  /bank/vietqr`);
});
