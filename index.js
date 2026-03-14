require('dotenv').config();
const express = require('express');
const cors    = require('cors');
const helmet  = require('helmet');

const app = express();

// ── FIX V18: Helmet — bổ sung HSTS, Referrer-Policy, CSP và các security headers ──
app.use(helmet({
  // HSTS: bắt buộc HTTPS trong 1 năm, bao gồm subdomain
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
  // CSP: chỉ cho phép same-origin (API server không serve HTML nên rất hạn chế)
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'none'"],
      frameSrc:   ["'none'"],
      objectSrc:  ["'none'"],
    }
  },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  noSniff: true,
  xssFilter: true,
  hidePoweredBy: true,
  frameguard: { action: 'deny' },
}));

// ── CORS — restrict to known frontend origins ──────────────────────────────
const prodOrigins = (process.env.FRONTEND_URL || '')
  .split(',').map(s => s.trim()).filter(Boolean);
const devOrigins = process.env.NODE_ENV !== 'production'
  ? ['http://localhost:3000', 'http://localhost:3001', 'http://127.0.0.1:3000']
  : [];
const allowedOrigins = [...new Set([...prodOrigins, ...devOrigins])];

// Vercel preview URLs pattern (e.g. gamestore-client-abc123-user.vercel.app)
const VERCEL_PROJECT_NAMES = (process.env.VERCEL_PROJECT_NAMES || 'gamestore-client,playtogethermarket')
  .split(',').map(s => s.trim().toLowerCase()).filter(Boolean);

function isAllowedOrigin(origin) {
  // SECURITY: null origin (file://, sandboxed iframe) phải bị chặn
  // Chỉ server-to-server (webhook từ SePay) mới không có origin → nhưng webhook
  // đi qua /bank/webhook có verifyWebhook middleware riêng (API key) → không cần CORS bypass
  if (!origin) return false;
  if (allowedOrigins.includes(origin)) return true;
  if (allowedOrigins.length === 0 && process.env.NODE_ENV !== 'production') return true;
  // Allow all Vercel deployments for configured project names
  try {
    const host = new URL(origin).hostname.toLowerCase();
    if (host.endsWith('.vercel.app')) {
      return VERCEL_PROJECT_NAMES.some(name => host.startsWith(name + '-') || host === name + '.vercel.app');
    }
  } catch (_) {}
  return false;
}

app.use(cors({
  origin: (origin, callback) => {
    if (isAllowedOrigin(origin)) return callback(null, true);
    callback(new Error('CORS: origin not allowed - ' + origin));
  },
  credentials: true,
}));

// ── Trust proxy (Render.com: 1 hop) ─────────────────────────────────────
app.set('trust proxy', 1);

// ── Body limits — prevent large payload DoS ──────────────────────────────
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));

// ── Remove fingerprinting ─────────────────────────────────────────────────
app.disable('x-powered-by');

// ── Health check — TRƯỚC CORS (Render monitor không gửi Origin header) ──
app.get('/', (_req, res) => res.status(200).json({ ok: true }));
app.get('/health', (_req, res) => res.status(200).json({ ok: true }));

// ── Routes ────────────────────────────────────────────────────────────────
const db = require('./lib/firestore');
app.use('/bank', require('./routes/sepay')(db));

// ── 404 handler ───────────────────────────────────────────────────────────
app.use((_req, res) => res.status(404).json({ error: 'Not found' }));

// ── Error handler ─────────────────────────────────────────────────────────
app.use((err, _req, res, _next) => {
  console.error('Unhandled error:', err.message);
  res.status(500).json({ error: 'Internal server error' });
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`✅ Server port ${PORT}`);
  console.log(`   SePay Webhook: POST /bank/webhook`);
  console.log(`   VietQR:        GET  /bank/vietqr`);
  console.log(`   Checkout:      POST /bank/checkout/confirm`);
});
