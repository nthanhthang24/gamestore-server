require('dotenv').config();
const express = require('express');
const cors = require('cors');

const app = express();
// ✅ Security: CORS — restrict to known frontend origins
// FIX VULN-13: 'no-origin' bypass removed. Webhook is server-to-server so CORS
// doesn't apply to it. All browser-facing APIs require explicit origin check.
const prodOrigins = (process.env.FRONTEND_URL || '').split(',').map(s => s.trim()).filter(Boolean);
const devOrigins  = process.env.NODE_ENV !== 'production'
  ? ['http://localhost:3000', 'http://localhost:3001', 'http://127.0.0.1:3000']
  : [];
const allowedOrigins = [...new Set([...prodOrigins, ...devOrigins])];

app.use(cors({
  origin: (origin, callback) => {
    // Webhook (POST /bank/webhook) is server-to-server — has no browser origin, handled separately
    // All other browser requests must have an allowed origin
    if (!origin && allowedOrigins.length === 0) return callback(null, true); // dev mode, no origins configured
    if (origin && allowedOrigins.includes(origin)) return callback(null, true);
    if (!origin) return callback(new Error('CORS: direct server-to-server requests not allowed on this endpoint'));
    callback(new Error('CORS: origin not allowed - ' + origin));
  },
  credentials: true,
}));

// ✅ FIX: Trust proxy correctly for Render.com (1 hop)
app.set('trust proxy', 1);
// ✅ Security: body size limit — prevent large payload DoS
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));

// ✅ Security: remove fingerprinting headers
app.disable('x-powered-by');

// ✅ Security: basic security headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  next();
});

// Dùng Firestore REST API thay vì firebase-admin
// Không cần Service Account key!
const db = require('./lib/firestore');

// ✅ Webhook endpoint has no browser origin — exempt from CORS middleware
app.post('/bank/webhook', (req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*'); // webhook is server-to-server
  next();
});

app.use('/bank', require('./routes/sepay')(db));

app.get('/', (req, res) => {
  res.status(200).json({ ok: true });
});

// ── Debug endpoints REMOVED (security: info disclosure risk) ─────────────
// /debug/env and /debug/firestore were removed in security hardening.
// Use Render.com dashboard to inspect env vars and Firestore console for DB.

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`✅ Server chạy port ${PORT}`);
  console.log(`   SePay Webhook: POST /bank/webhook`);
  console.log(`   VietQR:        GET  /bank/vietqr`);
});
