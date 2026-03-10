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

// ── Debug endpoint (tạm thời) ─────────────────────────────────────────────
// Gọi: GET /debug/env để kiểm tra env vars đã load chưa
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

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`✅ Server chạy port ${PORT}`);
  console.log(`   SePay Webhook: POST /bank/webhook`);
  console.log(`   VietQR:        GET  /bank/vietqr`);
});
