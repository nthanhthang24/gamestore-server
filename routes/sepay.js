// routes/sepay.js
// ── Tích hợp SePay (BIDV cá nhân - API Banking) ─────────────────────────────

const express = require('express');
const crypto  = require('crypto');

// ── IP Whitelist ──────────────────────────────────────────────────────────
const SEPAY_IPS_EXTRA = (process.env.SEPAY_IPS || '')
  .split(',').map(s => s.trim()).filter(Boolean);

const SEPAY_IPS = [
  '103.255.238.108', '103.255.238.109', '103.255.238.110',
  '116.103.227.99',  '42.118.118.53',
  '127.0.0.1', '::1', '::ffff:127.0.0.1',
  ...SEPAY_IPS_EXTRA,
];

function getCallerIP(req) {
  const xff    = req.headers['x-forwarded-for'] || '';
  const cfIP   = req.headers['cf-connecting-ip'] || '';
  const socket = (req.socket?.remoteAddress || '').replace(/^::ffff:/, '');
  const xffFirst = xff.split(',')[0]?.trim().replace(/^::ffff:/, '') || '';
  return { socket, xff: xffFirst, cf: cfIP, best: cfIP || xffFirst || socket };
}

function isKnownSepayIP(ip) {
  if (!ip) return false;
  if (SEPAY_IPS.includes(ip)) return true;
  if (ip.startsWith('103.255.238.')) return true;
  return false;
}

// ── In-memory rate limiter (simple, non-distributed) ──────────────────────
// Đủ cho single-instance Render deployment
const rateLimitStore = new Map(); // key → { count, resetAt }

function rateLimit(key, maxRequests, windowMs) {
  const now = Date.now();
  const entry = rateLimitStore.get(key);
  if (!entry || now > entry.resetAt) {
    rateLimitStore.set(key, { count: 1, resetAt: now + windowMs });
    return false; // not limited
  }
  if (entry.count >= maxRequests) return true; // limited
  entry.count++;
  return false;
}

// Cleanup stale entries every 5 min
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of rateLimitStore) {
    if (now > v.resetAt) rateLimitStore.delete(k);
  }
}, 5 * 60 * 1000);

module.exports = (db) => {
  const router = express.Router();

  const BANK = {
    bin:  process.env.BANK_BIN            || '970418',
    acc:  process.env.BANK_ACCOUNT_NUMBER || '1290702118',
    name: process.env.BANK_ACCOUNT_NAME   || 'NGUYEN NAM SON',
    va:   process.env.BANK_VA_NUMBER      || '',
  };

  // ── Middleware: verify SePay webhook ─────────────────────────────────────
  function verifyWebhook(req, res, next) {
    const apiKey   = process.env.SEPAY_API_KEY;
    const received = (req.headers['authorization'] || '').replace(/^Apikey\s+/i, '').trim();
    const ips      = getCallerIP(req);

    console.log(`📬 Webhook | socket:${ips.socket} xff:${ips.xff} cf:${ips.cf} | auth:${received ? received.slice(0,8)+'...' : 'NONE'}`);

    if (!apiKey) {
      console.error('⛔ SEPAY_API_KEY chưa cấu hình');
      return res.status(503).json({ error: 'Service not configured' });
    }
    // FIX: constant-time compare để tránh timing attack
    if (!received || !timingSafeEqual(received, apiKey)) {
      console.warn(`⛔ API Key sai | ip:${ips.best}`);
      return res.status(401).json({ error: 'Unauthorized' });
    }
    if (!isKnownSepayIP(ips.best)) {
      console.warn(`⚠️ IP lạ nhưng API key đúng: ${ips.best} — thêm vào SEPAY_IPS env nếu là IP mới của SePay`);
    }
    next();
  }

  function timingSafeEqual(a, b) {
    try {
      return crypto.timingSafeEqual(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));
    } catch {
      return false; // different lengths
    }
  }

  // ════════════════════════════════════════════════════════════════════
  // POST /bank/webhook  ← SePay gọi vào đây
  // ════════════════════════════════════════════════════════════════════
  router.post('/webhook', verifyWebhook, async (req, res) => {
    try {
      console.log('📩 SePay webhook raw:', JSON.stringify(req.body));

      const {
        id: sePayId,
        gateway,
        transactionDate,
        content,
        transferType,
        transferAmount,
        referenceCode,
        error: sePayError,
        code,
        subAccount,
      } = req.body;

      if (transferType !== 'in') {
        return res.status(200).json({ message: 'Skipped - not incoming' });
      }
      if (sePayError !== 0 && sePayError != null) {
        return res.status(200).json({ message: 'Skipped - error transaction' });
      }
      // FIX A1: Cast and validate transferAmount as a proper number
      const safeAmount = Number(transferAmount);
      if (!transferAmount || isNaN(safeAmount) || safeAmount <= 0 || !isFinite(safeAmount)) {
        return res.status(200).json({ message: 'Invalid amount' });
      }
      // Re-assign as validated number for all downstream use
      // (reassign via const in outer scope is not possible; use safeAmount below)
      if (safeAmount > 50_000_000) {
        console.warn(`⚠️ Amount vượt giới hạn: ${transferAmount}`);
        // FIX: dùng Admin SDK — không cần Firestore rules
        await db.add('unmatchedTopups', {
          sePayId: String(sePayId), gateway, content,
          amount: safeAmount, transactionDate,
          status: 'overlimit', createdAt: db.FieldValue.serverTimestamp(),
        });
        return res.status(200).json({ message: 'Amount over limit' });
      }

      // ── Atomic duplicate check ─────────────────────────────────────
      // FIX V3: Admin SDK createIfNotExists — attacker không thể pre-create doc
      // vì processedWebhooks rules là allow create: if isAdmin() (không có anonymous create)
      // và Admin SDK bypass rules hoàn toàn.
      try {
        await db.createIfNotExists('processedWebhooks', String(sePayId), {
          sePayId: String(sePayId),
          status: 'processing',
          startedAt: db.FieldValue.serverTimestamp(),
        });
      } catch(e) {
        if (e.response?.status === 409 || (e.message || '').includes('ALREADY_EXISTS')) {
          console.log('⚠️ Duplicate sePayId:', sePayId);
          return res.status(200).json({ message: 'Already processed' });
        }
        console.error('⛔ Atomic dedup check failed:', e.message);
        return res.status(500).json({ error: 'Dedup check failed, will retry' });
      }

      // ── Match user ────────────────────────────────────────────────
      let user       = null;
      let topupDocId = null;

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
              return res.status(200).json({ message: 'Topup already processed' });
            }
          }
        } catch (e) {
          console.warn('⚠️ Lỗi tìm topup:', e.message);
        }
      }

      if (!user && content) {
        user = await findUserByEmail(db, content);
      }

      if (!user) {
        await db.add('unmatchedTopups', {
          sePayId: String(sePayId), gateway, content, code: code || null,
          amount: safeAmount, transactionDate, referenceCode,
          status: 'unmatched', createdAt: db.FieldValue.serverTimestamp(),
        });
        console.log('⚠️ Unmatched transaction:', { content, transferAmount, sePayId });
        return res.status(200).json({ message: 'Unmatched - saved for manual review' });
      }

      // ── Credit balance (FIX V1: dùng Admin SDK — không dựa vào Firestore rules) ──
      // Admin SDK bypass rules → không có lỗ hổng anonymous REST credit.
      // FieldValue.increment() là atomic server-side — không có race condition.
      const userDoc = await db.get('users', user.userId);
      if (!userDoc.exists) {
        console.error('❌ User không tìm thấy:', user.userId);
        return res.status(404).json({ error: 'User not found' });
      }
      const prev = userDoc.data().balance || 0;
      const next = prev + safeAmount;

      // Tất cả writes dùng Admin SDK — bypass Firestore rules
      const writePromises = [
        // FIX V1: Admin SDK update — không phụ thuộc rule !isAuthenticated()
        db.update('users', user.userId, {
          balance:   db.FieldValue.increment(safeAmount), // FIX A1: use validated safeAmount
          updatedAt: db.FieldValue.serverTimestamp(),
        }),
        db.add('transactions', {
          userId:        user.userId,
          userEmail:     user.userEmail,
          type:          'topup',
          method:        'bank_transfer',
          gateway,
          amount:        safeAmount,
          balanceBefore: prev,
          balanceAfter:  next,
          sePayId:       String(sePayId),
          referenceCode,
          content,
          createdAt:     db.FieldValue.serverTimestamp(),
        }),
      ];

      if (topupDocId) {
        writePromises.push(db.update('topups', topupDocId, {
          status:       'approved',
          autoApproved: true,
          sePayId:      String(sePayId),
          gateway,
          referenceCode,
          approvedAt:   db.FieldValue.serverTimestamp(),
        }));
      } else {
        writePromises.push(db.add('topups', {
          userId:          user.userId,
          userEmail:       user.userEmail,
          userName:        user.displayName || user.userEmail,
          amount:          safeAmount,
          method:          'bank_transfer',
          gateway,
          transferContent: content,
          referenceCode,
          sePayId:         String(sePayId),
          transactionDate,
          status:          'approved',
          autoApproved:    true,
          approvedAt:      db.FieldValue.serverTimestamp(),
          createdAt:       db.FieldValue.serverTimestamp(),
        }));
      }

      writePromises.push(db.update('processedWebhooks', String(sePayId), {
        status:      'done',
        userId:      user.userId,
        amount:      safeAmount,   // FIX A1: use validated safeAmount
        processedAt: db.FieldValue.serverTimestamp(),
      }));

      await Promise.all(writePromises);
      console.log(`✅ Nạp +${safeAmount}đ cho ${user.userEmail} | ${prev} → ${next}`);

      try {
        await processReferralCommission(db, user.userId, safeAmount);
      } catch (refErr) {
        console.warn('⚠️ Referral commission error (non-critical):', refErr.message);
      }

      return res.status(200).json({ message: 'success' });

    } catch (err) {
      console.error('❌ Webhook error:', err.message, err.stack);
      return res.status(500).json({ error: 'Internal server error' });
    }
  });

  // ── Referral Commission ───────────────────────────────────────────────
  async function processReferralCommission(db, userId, topupAmount) {
    let commissionPct  = 2;
    let minTopup       = 50000;
    let newUserBonus   = 10000;
    try {
      const settingsDoc = await db.get('settings', 'global');
      if (settingsDoc.exists) {
        const s = settingsDoc.data();
        if (s.referralCommissionPct != null) commissionPct  = Math.min(Number(s.referralCommissionPct), 50); // FIX BUG#5: cap at 50%
        if (s.referralMinTopup      != null) minTopup       = Number(s.referralMinTopup);
        if (s.referralNewUserBonus  != null) newUserBonus   = Number(s.referralNewUserBonus);
      }
    } catch(e) { console.warn('Referral config read failed:', e.message); }

    if (topupAmount < minTopup) return;

    // FIX BUG#4 RACE CONDITION: Use createIfNotExists as a distributed lock.
    // Two concurrent webhooks for the same user will both try to create this lock doc.
    // Only ONE will succeed (precondition: exists=false).
    // The other gets ALREADY_EXISTS → returns early → no double commission.
    const lockKey = `referral_lock_${userId}`;
    try {
      await db.createIfNotExists('processedWebhooks', lockKey, {
        type:      'referral_lock',
        userId,
        lockedAt:  db.FieldValue.serverTimestamp(),
      });
    } catch (lockErr) {
      if (lockErr.message === 'ALREADY_EXISTS' || lockErr.response?.status === 409) {
        console.log(`⚠️ Referral commission already being processed for userId=${userId}`);
        return;
      }
      throw lockErr; // Re-throw unexpected errors
    }

    try {
      const existingCredited = await db.query('referrals', [
        ['newUserId', '==', userId],
        ['credited',  '==', true ],
      ], null, 1);
      if (existingCredited && existingCredited.length > 0) return;

      const pendingReferrals = await db.query('referrals', [
        ['newUserId', '==', userId],
        ['credited',  '==', false],
      ], null, 1);
      if (!pendingReferrals || pendingReferrals.length === 0) return;

      const prevTopups = await db.query('topups', [
        ['userId', '==', userId],
        ['status', '==', 'approved'],
      ], null, 5);
      if (prevTopups && prevTopups.length > 1) return;

      const referral   = pendingReferrals[0];
      const referrerId = referral.data().referrerId;
      if (!referrerId) return;

      const commissionAmount = Math.round(topupAmount * commissionPct / 100);
      const referrerDoc = await db.get('users', referrerId);
      if (!referrerDoc.exists) return;

      const referrerBalance = referrerDoc.data().balance || 0;

      await Promise.all([
        db.update('users', referrerId, {
          balance:   db.FieldValue.increment(commissionAmount),
          updatedAt: db.FieldValue.serverTimestamp(),
        }),
        db.update('referrals', referral.id, {
          credited:         true,
          commissionAmount,
          commissionPct,
          topupAmount,
          creditedAt:       db.FieldValue.serverTimestamp(),
        }),
        db.add('transactions', {
          userId:        referrerId,
          type:          'referral_commission',
          amount:        commissionAmount,
          fromUserId:    userId,
          commissionPct,
          topupAmount,
          balanceBefore: referrerBalance,
          balanceAfter:  referrerBalance + commissionAmount,
          createdAt:     db.FieldValue.serverTimestamp(),
        }),
        db.add('notifications', {
          title:        '💰 Nhận hoa hồng giới thiệu!',
          body:         `Bạn bè nạp ${topupAmount.toLocaleString('vi-VN')}đ → bạn nhận ${commissionAmount.toLocaleString('vi-VN')}đ (${commissionPct}% hoa hồng).`,
          type:         'referral',
          targetAll:    false,
          targetUserId: referrerId,
          active:       true,
          read:         [],
          createdAt:    db.FieldValue.serverTimestamp(),
          createdBy:    'system',
        }),
      ]);
      console.log(`✅ Referral commission: ${commissionAmount}đ → ${referrerId}`);
    } finally {
      // Always release the lock after processing (whether success or error)
      // This allows future webhooks to process if this one errored out
      // (The lock prevents concurrent same-second double-credit, not future retries)
      try {
        // Update lock status to 'done' so it still acts as dedup evidence
        await db.update('processedWebhooks', lockKey, {
          status: 'done',
          doneAt: db.FieldValue.serverTimestamp(),
        });
      } catch (_) { /* non-critical */ }
    }
  }

  // ── Middleware: verify Firebase ID token ────────────────────────────────
  // FIX C1: Decode JWT manually để check expiry + uid TRƯỚC KHI gọi accounts:lookup.
  // accounts:lookup không enforce expiry — attacker có thể dùng token đã hết hạn.
  // Giải pháp: decode JWT payload (base64), check exp claim, sau đó verify với Firebase.
  const _fetchModule = (...a) => import('node-fetch').then(({ default: f }) => f(...a));

  function decodeJwtPayload(token) {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) return null;
      const payload = Buffer.from(parts[1], 'base64url').toString('utf8');
      return JSON.parse(payload);
    } catch { return null; }
  }

  async function verifyFirebaseToken(req, res, next) {
    const authHeader = req.headers['authorization'] || '';
    const idToken = authHeader.replace(/^Bearer\s+/i, '').trim();
    if (!idToken) {
      return res.status(401).json({ error: 'Missing Authorization token' });
    }
    try {
      // FIX C1: Check expiry locally first (fast, no network)
      const payload = decodeJwtPayload(idToken);
      if (!payload || !payload.exp || !payload.sub) {
        return res.status(401).json({ error: 'Invalid token format' });
      }
      const nowSec = Math.floor(Date.now() / 1000);
      if (payload.exp < nowSec) {
        return res.status(401).json({ error: 'Token expired' });
      }
      // Also check iat — token should not be issued in future (clock skew >5min)
      if (payload.iat && payload.iat > nowSec + 300) {
        return res.status(401).json({ error: 'Token issued in future' });
      }

      // Verify with Firebase (confirms signature + not revoked)
      const apiKey = process.env.FIREBASE_API_KEY;
      const verifyRes = await _fetchModule(
        `https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${apiKey}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ idToken }),
        }
      );
      const data = await verifyRes.json();
      if (!verifyRes.ok || !data.users || data.users.length === 0) {
        return res.status(401).json({ error: 'Invalid or expired token' });
      }
      const user = data.users[0];
      // Cross-check uid from JWT payload vs Firebase response
      if (user.localId !== payload.sub) {
        return res.status(401).json({ error: 'Token uid mismatch' });
      }
      req.firebaseUid   = user.localId;
      req.firebaseEmail = user.email;
      next();
    } catch (e) {
      console.warn('Token verify failed:', e.message);
      return res.status(401).json({ error: 'Invalid or expired token' });
    }
  }

  // ════════════════════════════════════════════════════════════════════
  // GET /bank/vietqr  ← Frontend gọi để lấy QR
  // ════════════════════════════════════════════════════════════════════
  router.get('/vietqr', verifyFirebaseToken, async (req, res) => {
    const { amount, userId, userEmail } = req.query;
    if (!amount || !userId || !userEmail)
      return res.status(400).json({ error: 'Missing params' });

    if (userId !== req.firebaseUid) {
      return res.status(403).json({ error: 'userId không khớp với token' });
    }

    const amt = Number(amount);
    if (isNaN(amt) || amt < 10000 || amt > 50_000_000)
      return res.status(400).json({ error: 'Số tiền phải từ 10,000 đến 50,000,000đ' });

    // Rate limit: max 10 requests per user per minute
    if (rateLimit(`vietqr:${req.firebaseUid}`, 10, 60_000)) {
      return res.status(429).json({ error: 'Quá nhiều yêu cầu. Vui lòng thử lại sau.' });
    }

    // Validate user
    try {
      const userDoc = await db.get('users', userId);
      if (userDoc.exists) {
        const storedEmail = userDoc.data().email;
        if (storedEmail && storedEmail !== decodeURIComponent(userEmail)) {
          return res.status(403).json({ error: 'Thông tin không hợp lệ.' });
        }
      }
    } catch (e) {
      console.warn('⚠️ Không thể verify user:', e.message);
    }

    // Rate limit: max 3 pending topups
    try {
      const pending = await db.query('topups', [
        ['userId', '==', userId],
        ['status',  '==', 'pending'],
      ], null, 5);
      if (pending.length >= 3) {
        return res.status(429).json({ error: 'Bạn đang có 3 yêu cầu nạp tiền chưa xử lý.' });
      }
    } catch (e) {
      console.warn('Rate limit check failed:', e.message);
    }

    try {
      const decodedEmail = decodeURIComponent(userEmail);
      const topupId = crypto.randomBytes(12).toString('hex');
      const content = `NAP ${topupId}`;

      // FIX V4: Tạo topup doc với Admin SDK — không phụ thuộc Firestore rules cho server write
      // Rule topups/create hiện tại: isAuthenticated() && userId == own uid
      // Nhưng server write qua Admin SDK bypass rules hoàn toàn → an toàn hơn
      await db.set('topups', topupId, {
        userId,
        userEmail:       decodedEmail,
        amount:          amt,
        method:          'bank_transfer',
        status:          'pending',
        transferContent: content,
        createdAt:       db.FieldValue.serverTimestamp(),
      });

      const qrAcc = BANK.va || BANK.acc;
      if (!BANK.va) console.warn('⚠️ BANK_VA_NUMBER chưa set!');
      const qrUrl = `https://qr.sepay.vn/img?acc=${qrAcc}&bank=BIDV&amount=${amt}&des=${encodeURIComponent(content)}&template=compact2`;

      return res.json({
        qrUrl, transferContent: content,
        accountNumber: qrAcc, accountName: BANK.name,
        bankName: 'BIDV', bankBin: BANK.bin,
        amount: amt, topupId,
        method: BANK.va ? 'va' : 'static',
        usingVA: !!BANK.va,
      });

    } catch (err) {
      console.error('❌ /vietqr error:', err.message);
      return res.status(500).json({ error: `Lỗi tạo QR: ${err.message}` });
    }
  });

  // ════════════════════════════════════════════════════════════════════
  // POST /bank/checkout/confirm
  // Logic đúng: 1 item = 1 combo (có thể chứa nhiều accounts trong slots[])
  // Khi user mua → server inject TẤT CẢ slots của combo vào order
  // Sau khi bán → account status = 'sold' (không dùng soldCount nữa)
  // ════════════════════════════════════════════════════════════════════
  router.post('/checkout/confirm', verifyFirebaseToken, async (req, res) => {
    const { orderId } = req.body;
    if (!orderId || typeof orderId !== 'string' || orderId.length > 64) {
      return res.status(400).json({ error: 'Missing or invalid orderId' });
    }

    // Rate limit: 1 req/30s per orderId, 10 req/min per user
    if (rateLimit(`checkout:order:${orderId}`, 1, 30_000)) {
      return res.status(429).json({ error: 'Yêu cầu đang được xử lý. Thử lại sau 30 giây.' });
    }
    if (rateLimit(`checkout:user:${req.firebaseUid}`, 10, 60_000)) {
      return res.status(429).json({ error: 'Quá nhiều yêu cầu. Thử lại sau 1 phút.' });
    }

    try {
      const orderDoc = await db.get('orders', orderId);
      if (!orderDoc.exists) return res.status(404).json({ error: 'Order not found' });

      const order = orderDoc.data();
      if (order.userId !== req.firebaseUid) {
        console.warn(`⛔ checkout/confirm: userId mismatch. token=${req.firebaseUid} order=${order.userId}`);
        return res.status(403).json({ error: 'Order does not belong to this user' });
      }
      if (order.status !== 'completed') {
        return res.status(409).json({ error: 'Order is not completed' });
      }

      // Idempotency: đã inject đủ credentials rồi thì skip
      if (order._credentialsInjected) {
        return res.status(200).json({ message: 'already_updated' });
      }

      // Verify idempotencyKey bắt đầu bằng uid của user (chống forge)
      const iKey = order.idempotencyKey || '';
      if (!iKey.startsWith(req.firebaseUid + '_')) {
        console.error(`⛔ checkout/confirm: invalid idempotencyKey. orderId=${orderId} uid=${req.firebaseUid}`);
        return res.status(403).json({ error: 'Invalid order — please re-checkout.', code: 'INVALID_IKEY' });
      }

      const items = order.items || [];
      if (items.length === 0) {
        return res.status(400).json({ error: 'Order has no items' });
      }

      // ── Verify giá từ DB (chống price manipulation) ───────────────────
      const uniqueAccountIds = [...new Set(items.map(i => i.id).filter(Boolean))];
      const accountDocsById = {};
      await Promise.all(uniqueAccountIds.map(async (accountId) => {
        try {
          const accDoc = await db.get('accounts', accountId);
          accountDocsById[accountId] = accDoc.exists ? accDoc.data() : null;
        } catch (e) {
          console.warn(`⚠️ Fetch account ${accountId}:`, e.message);
          accountDocsById[accountId] = null;
        }
      }));

      let dbPriceSum = 0;
      for (const item of items) {
        const accData = accountDocsById[item.id];
        if (!accData) {
          return res.status(400).json({ error: `Account ${item.id} không tồn tại` });
        }
        dbPriceSum += accData.price || 0;
      }

      const orderTotal = order.total || 0;
      const effectiveMin = Math.floor(dbPriceSum * 0.25); // cho phép discount tối đa 75%
      if (orderTotal < effectiveMin || orderTotal <= 0) {
        console.error(`⛔ Price manipulation! orderId=${orderId} total=${orderTotal} dbSum=${dbPriceSum}`);
        return res.status(403).json({ error: 'Tổng đơn hàng không hợp lệ. Vui lòng đặt hàng lại.', code: 'PRICE_MISMATCH' });
      }

      // ── Fetch credentials từ subcollection ──────────────────────────────
      // slots[] có stock × quantity entries.
      // Combo thứ N (0-indexed) = slots[ N*quantity .. (N+1)*quantity - 1 ]
      // N = soldCount TRƯỚC khi bán (đọc trong transaction bên dưới)
      const credsByAccountId = {};
      await Promise.all(uniqueAccountIds.map(async (accountId) => {
        try {
          const credDoc = await db.get(`accounts/${accountId}/credentials`, 'slots');
          credsByAccountId[accountId] = credDoc.exists ? (credDoc.data().slots || []) : [];
        } catch (e) {
          console.warn(`⚠️ Fetch credentials ${accountId}:`, e.message);
          credsByAccountId[accountId] = [];
        }
      }));

      // ── Atomic: increment soldCount per combo purchased ─────────────
      // 1 order có thể có N combos của cùng 1 item (user mua qty > 1)
      // Mỗi combo = 1 lần increment soldCount + 1 slot assignment
      const soldCountAlreadyDone = !!order._soldCountUpdated;
      const firestore = db.getFirestore();

      // Đếm số combo per accountId trong order
      const comboCountByAccountId = {}; // accountId → số combo trong order này
      for (const item of items) {
        if (!item.id) continue;
        comboCountByAccountId[item.id] = (comboCountByAccountId[item.id] || 0) + 1;
      }

      // assignedCombosByAccountId: accountId → [[slot,...], [slot,...], ...]
      // Mỗi phần tử là 1 combo (mảng các accounts trong combo đó)
      const assignedCombosByAccountId = {};

      if (soldCountAlreadyDone) {
        // Re-inject: soldCount đã tăng N lần, đọc lại soldCount hiện tại
        console.log('ℹ️ soldCount already done, re-injecting credentials only');
        for (const accountId of uniqueAccountIds) {
          const nCombos = comboCountByAccountId[accountId] || 1;
          try {
            const accDoc = await db.get('accounts', accountId);
            const accData   = accDoc.exists ? accDoc.data() : {};
            const quantity  = accData.quantity  || 1;
            const soldCount = accData.soldCount  || 0;
            const creds     = credsByAccountId[accountId] || [];
            // Combos đã assign: indices [soldCount-nCombos .. soldCount-1]
            assignedCombosByAccountId[accountId] = Array.from({ length: nCombos }, (_, ci) => {
              const comboIndex = (soldCount - nCombos) + ci;
              const slotStart  = Math.max(0, comboIndex) * quantity;
              return Array.from({ length: quantity }, (__, i) =>
                creds[slotStart + i] || { loginUsername:'', loginPassword:'', loginEmail:'', loginNote:'', attachmentContent:null, attachmentUrl:null, attachmentName:null }
              );
            });
          } catch (e) {
            console.warn(`⚠️ Re-fetch ${accountId}:`, e.message);
            assignedCombosByAccountId[accountId] = Array(comboCountByAccountId[accountId] || 1).fill([]);
          }
        }
      } else {
        // Normal path: N sequential transactions per accountId (N = nCombos)
        for (const accountId of uniqueAccountIds) {
          const nCombos = comboCountByAccountId[accountId] || 1;
          const creds   = credsByAccountId[accountId] || [];
          const combos  = [];
          try {
            const accRef = firestore.collection('accounts').doc(accountId);
            for (let ci = 0; ci < nCombos; ci++) {
              let assignedSlots = [];
              await db.runTransactionWithRetry(async (tx) => {
                const accSnap = await tx.get(accRef);
                if (!accSnap.exists) throw new Error('not_found');
                const accData   = accSnap.data();
                const quantity  = accData.quantity  || 1;
                const stock     = accData.stock     || 1;
                const soldCount = accData.soldCount || 0;
                if (soldCount >= stock) throw new Error('sold_out');
                const slotStart = soldCount * quantity;
                assignedSlots = Array.from({ length: quantity }, (_, i) =>
                  creds[slotStart + i] || { loginUsername:'', loginPassword:'', loginEmail:'', loginNote:'', attachmentContent:null, attachmentUrl:null, attachmentName:null }
                );
                const updateData = { soldCount: db.FieldValue.increment(1) };
                if (soldCount + 1 >= stock) updateData.status = 'sold';
                tx.update(accRef, updateData);
              });
              combos.push(assignedSlots);
              console.log(`✅ soldCount +1 (combo ${ci+1}/${nCombos}): ${accountId}`);
            }
            assignedCombosByAccountId[accountId] = combos;
          } catch (e) {
            console.error(`❌ Transaction failed ${accountId}: ${e.message}`);
            // Fill remaining combos with empty slots
            while (combos.length < nCombos) combos.push([]);
            assignedCombosByAccountId[accountId] = combos;
          }
        }
      }

      // ── Build updatedItems: assign combo sequentially per accountId ──
      const comboOffsetByAccountId = {}; // accountId → next combo index
      const updatedItems = items.map(item => {
        if (!item.id) return item;
        const offset = comboOffsetByAccountId[item.id] || 0;
        comboOffsetByAccountId[item.id] = offset + 1;
        const slots = (assignedCombosByAccountId[item.id] || [])[offset] || [];
        return {
          ...item,
          loginUsername:     slots[0]?.loginUsername     || '',
          loginPassword:     slots[0]?.loginPassword     || '',
          loginEmail:        slots[0]?.loginEmail        || '',
          loginNote:         slots[0]?.loginNote         || '',
          attachmentContent: slots[0]?.attachmentContent || null,
          attachmentUrl:     slots[0]?.attachmentUrl     || null,
          attachmentName:    slots[0]?.attachmentName    || null,
          credentials: slots.map(s => ({
            loginUsername:     s.loginUsername     || '',
            loginPassword:     s.loginPassword     || '',
            loginEmail:        s.loginEmail        || '',
            loginNote:         s.loginNote         || '',
            attachmentContent: s.attachmentContent || null,
            attachmentUrl:     s.attachmentUrl     || null,
            attachmentName:    s.attachmentName    || null,
          })),
        };
      });

      // ── Ghi order ────────────────────────────────────────────────────
      await db.update('orders', orderId, {
        items:                updatedItems,
        _soldCountUpdated:    true,
        _credentialsInjected: true,
      });

      return res.status(200).json({ message: 'success' });

    } catch (err) {
      console.error('❌ /checkout/confirm error:', err.message, err.stack?.split('\n')[1] || '');
      const msg = process.env.NODE_ENV === 'production'
        ? 'Internal server error'
        : (err.message || 'Internal server error');
      return res.status(500).json({ error: msg });
    }
  });

  return router;
};

// ── Fallback: tìm user theo email ─────────────────────────────────────────
async function findUserByEmail(db, content) {
  const napMatch = content.match(/NAP\s+([^\s]+)/i);
  if (!napMatch) return null;
  const id = napMatch[1].toLowerCase().trim();
  if (id.length < 3) return null;
  if (id.includes('@')) {
    const r = await db.query('users', [['email', '==', id]], null, 1);
    if (r.length > 0) {
      const d = r[0].data();
      return { userId: r[0].id, userEmail: d.email, displayName: d.displayName };
    }
  }
  return null;
}
