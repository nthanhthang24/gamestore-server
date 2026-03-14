require('dotenv').config();
const express = require('express');
const cors    = require('cors');
const helmet  = require('helmet');

const app = express();

// ── Health / ping — TRƯỚC mọi middleware (không cần Origin) ──────────────
app.get('/', (_req, res) => res.status(200).json({ ok: true }));
app.get('/health', (_req, res) => res.status(200).json({ ok: true }));


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


// ── Routes ────────────────────────────────────────────────────────────────
const db = require('./lib/firestore');
app.use('/bank', require('./routes/sepay')(db));

// ── Debug bot — logs to Render console, returns plain text ──────────────
app.get('/debug/bot', (req, res) => {
  if (req.query.key !== process.env.SEPAY_API_KEY) return res.status(403).end('forbidden');
  const email = process.env.SERVER_BOT_EMAIL || '(not set)';
  const pass4 = (process.env.SERVER_BOT_PASSWORD || '').slice(-4);
  console.log('[DEBUG/BOT] starting, email=' + email + ' pass4=' + pass4);
  db.getServerBotToken()
    .then(function(token) {
      if (!token) {
        console.log('[DEBUG/BOT] token=null, sign-in failed');
        return res.end('token=null email=' + email + ' pass4=' + pass4);
      }
      var uid = '?';
      try { uid = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString()).user_id; } catch(_) {}
      console.log('[DEBUG/BOT] token OK uid=' + uid);
      db.set('topups', '_dbg_', { t: 1 }, token)
        .then(function() {
          console.log('[DEBUG/BOT] write OK');
          res.end('OK uid=' + uid + ' write=OK');
        })
        .catch(function(we) {
          console.log('[DEBUG/BOT] write FAIL: ' + we.message);
          res.end('OK uid=' + uid + ' write=FAIL: ' + we.message);
        });
    })
    .catch(function(e) {
      console.log('[DEBUG/BOT] getServerBotToken threw: ' + e.message);
      res.end('ERROR: ' + e.message);
    });
});

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
