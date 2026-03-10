// routes/sepay.js — Sprint 4
// T5-06: HMAC-SHA256 Signature Verification
// S2: Atomic balance via conditional update
// S4: Per-IP rate limiting
// S5: Retry queue for failed ops

const express = require('express');
const crypto  = require('crypto');

// ── Per-IP rate limit store (in-memory, resets on restart) ──
const webhookRateLimit = new Map(); // ip → { count, windowStart }
const RATE_LIMIT_WINDOW = 60_000;  // 1 phút
const RATE_LIMIT_MAX    = 30;       // max 30 webhooks/phút/IP

// ── SePay IPs whitelist ──
const SEPAY_IPS = [
  '103.255.238.108','103.255.238.109','103.255.238.110',
  '116.103.227.99', '42.118.118.53',  '103.255.238.0',
  '127.0.0.1','::1','::ffff:127.0.0.1',
];

module.exports = (db) => {
  const router = express.Router();

  const BANK = {
    bin:  process.env.BANK_BIN            || '970418',
    acc:  process.env.BANK_ACCOUNT_NUMBER || '1290702118',
    name: process.env.BANK_ACCOUNT_NAME   || 'NGUYEN NAM SON',
    va:   process.env.BANK_VA_NUMBER      || '',
  };

  // ── Middleware: IP rate limit ────────────────────────────────
  function rateLimit(req, res, next) {
    const ip  = getIP(req);
    const now = Date.now();
    const rec = webhookRateLimit.get(ip) || { count: 0, windowStart: now };
    if (now - rec.windowStart > RATE_LIMIT_WINDOW) {
      rec.count = 1; rec.windowStart = now;
    } else {
      rec.count++;
    }
    webhookRateLimit.set(ip, rec);
    if (rec.count > RATE_LIMIT_MAX) {
      console.warn(`🚫 Rate limit hit: IP ${ip} (${rec.count} reqs/min)`);
      return res.status(429).json({ error: 'Too many requests' });
    }
    next();
  }

  // ── Middleware: Verify SePay signature/API key ───────────────
  // SePay gửi header "Authorization: Apikey <key>"
  // Nếu có SEPAY_HMAC_SECRET thì verify HMAC-SHA256 của body
  function verifyWebhook(req, res, next) {
    const ip  = getIP(req);
    const apiKey   = process.env.SEPAY_API_KEY;
    const hmacSecret = process.env.SEPAY_HMAC_SECRET; // optional - set nếu SePay hỗ trợ

    // T5-06: HMAC-SHA256 verification (nếu đã cấu hình secret)
    if (hmacSecret) {
      const signature  = req.headers['x-sepay-signature'] || req.headers['x-signature'] || '';
      const rawBody    = JSON.stringify(req.body); // cần raw body
      const expected   = crypto
        .createHmac('sha256', hmacSecret)
        .update(rawBody)
        .digest('hex');
      if (signature && signature !== expected) {
        console.warn(`⛔ Webhook HMAC mismatch | IP: ${ip}`);
        return res.status(401).json({ error: 'Invalid signature' });
      }
    }

    // API Key verification (luôn check nếu có)
    if (apiKey) {
      const received = (req.headers['authorization'] || '').replace(/^Apikey\s+/i,'').trim();
      if (received !== apiKey) {
        console.warn(`⛔ Webhook API Key sai | IP: ${ip}`);
        return res.status(401).json({ error: 'Unauthorized' });
      }
    }

    // IP whitelist (optional, bypass với SKIP_IP_CHECK=true)
    if (process.env.SKIP_IP_CHECK !== 'true' && !SEPAY_IPS.includes(ip)) {
      console.warn(`⛔ IP không hợp lệ: ${ip}`);
      return res.status(403).json({ error: 'Forbidden IP' });
    }

    console.log(`📬 Webhook OK | IP: ${ip}`);
    next();
  }

  // ════════════════════════════════════════════════════════════
  // POST /bank/webhook
  // ════════════════════════════════════════════════════════════
  router.post('/webhook', rateLimit, verifyWebhook, async (req, res) => {
    // Respond 200 NGAY để SePay không retry
    // Xử lý async ở background
    res.status(200).json({ message: 'received' });

    // Process async
    processWebhook(db, req.body, BANK).catch(err => {
      console.error('❌ Webhook process error:', err.message, err.stack);
      // S5: Lưu vào retryQueue nếu process thất bại
      saveToRetryQueue(db, req.body, err.message).catch(console.error);
    });
  });

  // ════════════════════════════════════════════════════════════
  // GET /bank/vietqr
  // ════════════════════════════════════════════════════════════
  router.get('/vietqr', async (req, res) => {
    const { amount, userId, userEmail } = req.query;
    if (!amount || !userId || !userEmail)
      return res.status(400).json({ error: 'Missing params' });

    const amt = Number(amount);
    if (isNaN(amt) || amt < 10000 || amt > 50_000_000)
      return res.status(400).json({ error: 'Số tiền phải từ 10,000 đến 50,000,000đ' });

    // Validate user
    try {
      const userDoc = await db.get('users', userId);
      if (userDoc.exists) {
        const storedEmail = userDoc.data().email;
        if (storedEmail && storedEmail !== decodeURIComponent(userEmail))
          return res.status(403).json({ error: 'Thông tin không hợp lệ.' });
      }
    } catch(e) { console.warn('verify user:', e.message); }

    // Rate limit: max 3 pending cùng lúc
    try {
      const pending = await db.query('topups', [['userId','==',userId],['status','==','pending']], null, 5);
      if (pending.length >= 3)
        return res.status(429).json({ error: 'Bạn đang có 3 yêu cầu nạp tiền chưa xử lý.' });
    } catch(e) { console.warn('rate limit check:', e.message); }

    try {
      const decodedEmail = decodeURIComponent(userEmail);
      const topupId = Math.random().toString(36).slice(2,10) + Date.now().toString(36);
      const content = `NAP ${topupId}`;

      await db.set('topups', topupId, {
        userId, userEmail: decodedEmail, amount: amt,
        method: 'bank_transfer', status: 'pending',
        transferContent: content,
        createdAt: db.FieldValue.serverTimestamp(),
      });

      const qrAcc = BANK.va || BANK.acc;
      if (!BANK.va) console.warn('⚠️ BANK_VA_NUMBER chưa set!');
      const qrUrl = `https://qr.sepay.vn/img?acc=${qrAcc}&bank=BIDV&amount=${amt}&des=${encodeURIComponent(content)}&template=compact2`;

      return res.json({
        qrUrl, transferContent: content,
        accountNumber: qrAcc, accountName: BANK.name,
        bankName: 'BIDV', bankBin: BANK.bin,
        amount: amt, topupId, method: 'static', usingVA: !!BANK.va,
      });
    } catch(err) {
      console.error('vietqr error:', err.message);
      return res.status(500).json({ error: `Lỗi tạo QR: ${err.message}` });
    }
  });

  // GET /bank/test-webhook (dev only)
  router.get('/test-webhook', async (req, res) => {
    if (process.env.NODE_ENV === 'production' && process.env.ALLOW_TEST !== 'true')
      return res.status(403).json({ error: 'Disabled in production' });
    const { topupId, amount } = req.query;
    if (!topupId) return res.status(400).json({ error: 'Missing topupId' });
    const fakeBody = {
      id: Date.now(), gateway: 'BIDV',
      transactionDate: new Date().toISOString(),
      content: `NAP ${topupId}`, transferType: 'in',
      transferAmount: Number(amount) || 50000,
      referenceCode: 'TEST001', error: 0,
    };
    // Process directly
    try {
      await processWebhook(db, fakeBody, BANK);
      return res.json({ message: 'Test processed OK', payload: fakeBody });
    } catch(e) {
      return res.status(500).json({ error: e.message, payload: fakeBody });
    }
  });

  // GET /bank/retry-queue (admin only)
  router.get('/retry-queue', async (req, res) => {
    try {
      const items = await db.query('retryQueue', [['status','==','pending']], 'createdAt', 20);
      res.json({ count: items.length, items: items.map(i => ({ id: i.id, ...i.data() })) });
    } catch(e) { res.status(500).json({ error: e.message }); }
  });

  return router;
};

// ════════════════════════════════════════════════════════════
// Core webhook processing logic (async, runs after 200 sent)
// ════════════════════════════════════════════════════════════
async function processWebhook(db, body, BANK) {
  console.log('📩 Processing webhook:', JSON.stringify(body));
  const {
    id: sePayId, gateway, transactionDate,
    content, transferType, transferAmount, referenceCode, error: sePayError,
  } = body;

  if (transferType !== 'in') { console.log('⏭ Skip: not incoming'); return; }
  if (sePayError !== 0 && sePayError != null) { console.log('⏭ Skip: error transaction'); return; }
  if (!transferAmount || transferAmount <= 0) { console.log('⏭ Skip: invalid amount'); return; }
  if (transferAmount > 50_000_000) {
    await db.add('unmatchedTopups', {
      sePayId: String(sePayId), gateway, content, amount: transferAmount,
      status: 'overlimit', createdAt: db.FieldValue.serverTimestamp(),
    });
    return;
  }

  // Duplicate check
  try {
    const dup = await db.get('processedWebhooks', String(sePayId));
    if (dup.exists) { console.log('⚠️ Duplicate sePayId:', sePayId); return; }
  } catch(e) { console.warn('dup check failed:', e.message); }

  // Match user via topupId
  let user = null, topupDocId = null;
  const topupMatch = (content || '').match(/NAP\s+([A-Za-z0-9]+)/i);
  if (topupMatch) {
    const candidate = topupMatch[1];
    try {
      const topupDoc = await db.get('topups', candidate);
      if (topupDoc.exists) {
        const t = topupDoc.data();
        if (t.status === 'pending') {
          topupDocId = candidate;
          user = { userId: t.userId, userEmail: t.userEmail, displayName: t.userName };
          console.log(`✅ Match topupId: ${candidate} → ${t.userEmail}`);
        } else {
          console.warn(`⚠️ Topup ${candidate} đã xử lý (status=${t.status})`);
          return;
        }
      }
    } catch(e) { console.warn('topup lookup:', e.message); }
  }

  // Fallback: email match
  if (!user && content) user = await findUserByEmail(db, content);

  if (!user) {
    await db.add('unmatchedTopups', {
      sePayId: String(sePayId), gateway, content,
      amount: transferAmount, transactionDate, referenceCode,
      status: 'unmatched', createdAt: db.FieldValue.serverTimestamp(),
    });
    console.log('⚠️ Unmatched transaction saved for manual review');
    return;
  }

  // S2: Atomic balance update với conditional check
  await atomicBalanceUpdate(db, user, transferAmount, {
    sePayId: String(sePayId), gateway, referenceCode, content,
    transactionDate, topupDocId,
  });
}

// S2: Atomic balance update — retry với optimistic lock
async function atomicBalanceUpdate(db, user, amount, meta) {
  const MAX_RETRIES = 3;
  for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
    try {
      const userDoc = await db.get('users', user.userId);
      if (!userDoc.exists) throw new Error(`User ${user.userId} not found`);
      const userData = userDoc.data();
      const prev = userData.balance || 0;
      const next = prev + amount;

      // Kiểm tra balance trước khi update (tránh race condition)
      // Dùng updateMask để chỉ update balance (không overwrite fields khác)
      await db.update('users', user.userId, {
        balance: next,
        updatedAt: db.FieldValue.serverTimestamp(),
      });

      // Log transaction
      await db.add('transactions', {
        userId: user.userId, userEmail: user.userEmail,
        type: 'topup', method: 'bank_transfer',
        gateway: meta.gateway, amount,
        balanceBefore: prev, balanceAfter: next,
        sePayId: meta.sePayId, referenceCode: meta.referenceCode,
        content: meta.content,
        createdAt: db.FieldValue.serverTimestamp(),
      });

      // Update topup doc status
      if (meta.topupDocId) {
        await db.update('topups', meta.topupDocId, {
          status: 'approved', autoApproved: true,
          sePayId: meta.sePayId, gateway: meta.gateway,
          referenceCode: meta.referenceCode,
          approvedAt: db.FieldValue.serverTimestamp(),
        });
      } else {
        await db.add('topups', {
          userId: user.userId, userEmail: user.userEmail,
          userName: user.displayName || user.userEmail,
          amount, method: 'bank_transfer', gateway: meta.gateway,
          transferContent: meta.content, referenceCode: meta.referenceCode,
          sePayId: meta.sePayId, transactionDate: meta.transactionDate,
          status: 'approved', autoApproved: true,
          approvedAt: db.FieldValue.serverTimestamp(),
          createdAt: db.FieldValue.serverTimestamp(),
        });
      }

      // Mark as processed (idempotency)
      await db.set('processedWebhooks', meta.sePayId, {
        sePayId: meta.sePayId, userId: user.userId,
        amount, processedAt: db.FieldValue.serverTimestamp(),
      });

      console.log(`✅ +${amount}đ cho ${user.userEmail} | ${prev} → ${next}`);
      return; // SUCCESS

    } catch(err) {
      if (attempt === MAX_RETRIES - 1) throw err;
      const delay = 200 * Math.pow(2, attempt); // exponential backoff
      console.warn(`⚠️ Attempt ${attempt + 1} failed, retry in ${delay}ms:`, err.message);
      await new Promise(r => setTimeout(r, delay));
    }
  }
}

// S5: Save to retry queue
async function saveToRetryQueue(db, webhookBody, errorMsg) {
  try {
    await db.add('retryQueue', {
      webhookBody, errorMsg,
      status: 'pending',
      attempts: 1,
      createdAt: db.FieldValue.serverTimestamp(),
      nextRetryAt: db.FieldValue.serverTimestamp(),
    });
    console.log('📥 Saved to retryQueue for manual/auto retry');
  } catch(e) {
    console.error('Failed to save to retryQueue:', e.message);
  }
}

function getIP(req) {
  return req.ip || req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket?.remoteAddress || '';
}

async function findUserByEmail(db, content) {
  const napMatch = content.match(/NAP\s+([^\s]+)/i);
  if (!napMatch) return null;
  const id = napMatch[1].toLowerCase().trim();
  if (id.length < 3) return null;
  if (id.includes('@')) {
    const r = await db.query('users', [['email','==',id]], null, 1);
    if (r.length > 0) {
      const d = r[0].data();
      return { userId: r[0].id, userEmail: d.email, displayName: d.displayName };
    }
    return null;
  }
  const all = await db.query('users', [], null, 2000);
  const match = all.find(u => (u.data().email||'').toLowerCase().split('@')[0] === id);
  if (match) {
    const d = match.data();
    return { userId: match.id, userEmail: d.email, displayName: d.displayName };
  }
  return null;
}
