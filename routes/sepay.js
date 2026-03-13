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

      // Lấy server bot token cho tất cả operations trong webhook
      const serverToken = await db.getServerBotToken();
      if (!serverToken) {
        console.error('⛔ Server bot token không khả dụng — kiểm tra SERVER_BOT_EMAIL/PASSWORD env');
        return res.status(503).json({ error: 'Server not configured' });
      }

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
        await db.add('unmatchedTopups', {
          sePayId: String(sePayId), gateway, content,
          amount: safeAmount, transactionDate,
          status: 'overlimit', createdAt: db.FieldValue.serverTimestamp(),
        }, serverToken);
        return res.status(200).json({ message: 'Amount over limit' });
      }

      // ── Atomic duplicate check ─────────────────────────────────────
      try {
        await db.createIfNotExists('processedWebhooks', String(sePayId), {
          sePayId: String(sePayId),
          status: 'processing',
          startedAt: db.FieldValue.serverTimestamp(),
        }, serverToken);
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
          const topupDoc = await db.get('topups', candidate, serverToken);
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
        user = await findUserByEmail(db, content, serverToken);
      }

      if (!user) {
        await db.add('unmatchedTopups', {
          sePayId: String(sePayId), gateway, content, code: code || null,
          amount: safeAmount, transactionDate, referenceCode,
          status: 'unmatched', createdAt: db.FieldValue.serverTimestamp(),
        }, serverToken);
        console.log('⚠️ Unmatched transaction:', { content, transferAmount, sePayId });
        return res.status(200).json({ message: 'Unmatched - saved for manual review' });
      }

      // ── Credit balance ────────────────────────────────────────────────────
      const userDoc = await db.get('users', user.userId, serverToken);
      if (!userDoc.exists) {
        console.error('❌ User không tìm thấy:', user.userId);
        return res.status(404).json({ error: 'User not found' });
      }

      // FIX: Không đọc balance trước khi increment để tránh race condition trong log.
      // balanceBefore/After = -1 nghĩa là "not tracked" (tránh 2 webhook song song ghi sai log).
      // Balance thực tế luôn đúng vì dùng atomic increment().
      const writePromises = [
        db.update('users', user.userId, {
          balance:   db.FieldValue.increment(safeAmount),
          updatedAt: db.FieldValue.serverTimestamp(),
        }, serverToken),
        db.add('transactions', {
          userId:        user.userId,
          userEmail:     user.userEmail,
          type:          'topup',
          method:        'bank_transfer',
          gateway,
          amount:        safeAmount,
          balanceBefore: -1, // not tracked — use increment() to avoid race condition in log
          balanceAfter:  -1,
          sePayId:       String(sePayId),
          referenceCode,
          content,
          createdAt:     db.FieldValue.serverTimestamp(),
        }, serverToken),
      ];

      if (topupDocId) {
        writePromises.push(db.update('topups', topupDocId, {
          status:       'approved',
          autoApproved: true,
          sePayId:      String(sePayId),
          gateway,
          referenceCode,
          approvedAt:   db.FieldValue.serverTimestamp(),
        }, serverToken));
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
        }, serverToken));
      }

      writePromises.push(db.update('processedWebhooks', String(sePayId), {
        status:      'done',
        userId:      user.userId,
        amount:      safeAmount,
        processedAt: db.FieldValue.serverTimestamp(),
      }, serverToken));

      await Promise.all(writePromises);
      console.log(`✅ Nạp +${safeAmount}đ cho ${user.userEmail}`);

      try {
        await processReferralCommission(db, user.userId, safeAmount, serverToken);
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
  async function processReferralCommission(db, userId, topupAmount, serverToken) {
    let commissionPct  = 2;
    let minTopup       = 50000;
    let newUserBonus   = 10000;
    try {
      const settingsDoc = await db.get('settings', 'global', serverToken);
      if (settingsDoc.exists) {
        const s = settingsDoc.data();
        if (s.referralCommissionPct != null) commissionPct  = Math.min(Number(s.referralCommissionPct), 50);
        if (s.referralMinTopup      != null) minTopup       = Number(s.referralMinTopup);
        if (s.referralNewUserBonus  != null) newUserBonus   = Number(s.referralNewUserBonus);
      }
    } catch(e) { console.warn('Referral config read failed:', e.message); }

    if (topupAmount < minTopup) return;

    const lockKey = `referral_lock_${userId}`;
    try {
      // FIX: Kiểm tra lock có quá 5 phút không (stuck lock sau crash) trước khi tạo mới
      try {
        const existingLock = await db.get('processedWebhooks', lockKey, serverToken);
        if (existingLock.exists) {
          const lockData = existingLock.data();
          if (lockData.status === 'done') {
            // Lock đã done → referral đã xử lý xong → skip
            console.log(`⚠️ Referral commission lock already done for userId=${userId}`);
            return;
          }
          // Lock đang processing: check xem có stuck không (> 5 phút)
          const lockedAt = lockData.lockedAt ? new Date(lockData.lockedAt) : null;
          const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
          if (lockedAt && lockedAt > fiveMinutesAgo) {
            console.log(`⚠️ Referral commission in-progress for userId=${userId}, skipping`);
            return;
          }
          // Lock cũ hơn 5 phút → có thể stuck, ghi đè để retry
          console.log(`🔄 Overwriting stale referral lock for userId=${userId}`);
          await db.update('processedWebhooks', lockKey, {
            type: 'referral_lock', userId,
            lockedAt: db.FieldValue.serverTimestamp(),
            status: 'processing',
          }, serverToken);
        } else {
          // Lock chưa tồn tại → tạo mới
          await db.createIfNotExists('processedWebhooks', lockKey, {
            type: 'referral_lock', userId,
            lockedAt: db.FieldValue.serverTimestamp(),
            status: 'processing',
          }, serverToken);
        }
      } catch (lockErr) {
        if (lockErr.message === 'ALREADY_EXISTS' || lockErr.response?.status === 409) {
          console.log(`⚠️ Referral commission race — concurrent request for userId=${userId}`);
          return;
        }
        throw lockErr;
      }
    } catch (lockErr) {
      if (lockErr.message === 'ALREADY_EXISTS' || lockErr.response?.status === 409) {
        console.log(`⚠️ Referral commission already being processed for userId=${userId}`);
        return;
      }
      throw lockErr;
    }

    try {
      const existingCredited = await db.query('referrals', [
        ['newUserId', '==', userId],
        ['credited',  '==', true ],
      ], null, 1, serverToken);
      if (existingCredited && existingCredited.length > 0) return;

      const pendingReferrals = await db.query('referrals', [
        ['newUserId', '==', userId],
        ['credited',  '==', false],
      ], null, 1, serverToken);
      if (!pendingReferrals || pendingReferrals.length === 0) return;

      const prevTopups = await db.query('topups', [
        ['userId', '==', userId],
        ['status', '==', 'approved'],
      ], null, 5, serverToken);
      if (prevTopups && prevTopups.length > 1) return;

      const referral   = pendingReferrals[0];
      const referrerId = referral.data().referrerId;
      if (!referrerId) return;

      const commissionAmount = Math.round(topupAmount * commissionPct / 100);
      const referrerDoc = await db.get('users', referrerId, serverToken);
      if (!referrerDoc.exists) return;

      const referrerBalance = referrerDoc.data().balance || 0;

      await Promise.all([
        db.update('users', referrerId, {
          balance:   db.FieldValue.increment(commissionAmount),
          updatedAt: db.FieldValue.serverTimestamp(),
        }, serverToken),
        db.update('referrals', referral.id, {
          credited:         true,
          commissionAmount,
          commissionPct,
          topupAmount,
          creditedAt:       db.FieldValue.serverTimestamp(),
        }, serverToken),
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
        }, serverToken),
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
        }, serverToken),
      ]);
      console.log(`✅ Referral commission: ${commissionAmount}đ → ${referrerId}`);
    } finally {
      try {
        await db.update('processedWebhooks', lockKey, {
          status: 'done',
          doneAt: db.FieldValue.serverTimestamp(),
        }, serverToken);
      } catch (_) { /* non-critical */ }
    }
  }

  // ── Middleware: verify Firebase ID token ────────────────────────────────
  // FIX C1: Decode JWT manually để check expiry + uid TRƯỚC KHI gọi accounts:lookup.
  // accounts:lookup không enforce expiry — attacker có thể dùng token đã hết hạn.
  // Giải pháp: decode JWT payload (base64), check exp claim, sau đó verify với Firebase.
  const _fetchModule = (...a) => import('node-fetch').then(({ default: f }) => f(...a));

  async function verifyFirebaseToken(req, res, next) {
    const authHeader = req.headers['authorization'] || '';
    const idToken = authHeader.replace(/^Bearer\s+/i, '').trim();
    if (!idToken) {
      return res.status(401).json({ error: 'Missing Authorization token' });
    }
    try {
      const decoded = await db.verifyIdToken(idToken);
      req.firebaseUid   = decoded.uid;
      req.firebaseEmail = decoded.email || '';
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
      ], null, 5, serverToken);
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
  // FIX V2: soldCount dùng FieldValue.increment() — atomic, không có race condition
  // FIX V7: Rate limit 5 requests per orderId per minute
  // ════════════════════════════════════════════════════════════════════
  router.post('/checkout/confirm', verifyFirebaseToken, async (req, res) => {
    const { orderId } = req.body;
    if (!orderId || typeof orderId !== 'string' || orderId.length > 64) {
      return res.status(400).json({ error: 'Missing or invalid orderId' });
    }

    // FIX V7 + H4: Rate limit theo CẢ userId VÀ orderId
    // - Per orderId: ngăn race condition double-inject (1 req/30s per order)
    // - Per userId: ngăn DoS với nhiều orderId khác nhau (10 req/min per user)
    if (rateLimit(`checkout:order:${orderId}`, 2, 30_000)) { // 2 req/30s: allow 1 retry after Render cold start
      return res.status(429).json({ error: 'Yêu cầu đang được xử lý. Thử lại sau 30 giây.' });
    }
    if (rateLimit(`checkout:user:${req.firebaseUid}`, 10, 60_000)) {
      return res.status(429).json({ error: 'Quá nhiều yêu cầu. Thử lại sau 1 phút.' });
    }

    // Lấy userToken từ request để dùng cho Firestore REST calls
    const userToken = (req.headers['authorization'] || '').replace(/^Bearer\s+/i, '').trim();
    // Lấy server bot token để dùng cho transaction (beginTransaction yêu cầu server role)
    const serverToken = await db.getServerBotToken();
    if (!serverToken) {
      console.error('⛔ Server bot token không khả dụng — kiểm tra SERVER_BOT_EMAIL/PASSWORD env');
      return res.status(503).json({ error: 'Server not configured properly' });
    }

    try {
      // Đọc order bằng userToken (user đọc order của họ — rules cho phép)
      const orderDoc = await db.getWithToken('orders', orderId, userToken);
      if (!orderDoc.exists) return res.status(404).json({ error: 'Order not found' });

      const order = orderDoc.data();
      if (order.userId !== req.firebaseUid) {
        console.warn(`⛔ checkout/confirm: userId mismatch. token=${req.firebaseUid} order=${order.userId}`);
        return res.status(403).json({ error: 'Order does not belong to this user' });
      }
      if (order.status !== 'completed') {
        return res.status(409).json({ error: 'Order is not completed' });
      }
      const soldCountAlreadyDone = !!order._soldCountUpdated;
      const hasAllCreds = (order.items || []).some(i =>
        i.allCredentials?.length > 0 || i.loginUsername
      );
      if (soldCountAlreadyDone && order._credentialsInjected && hasAllCreds) {
        return res.status(200).json({ message: 'already_updated' });
      }
      const iKey = order.idempotencyKey || '';
      if (!iKey.startsWith(req.firebaseUid + '_')) {
        console.error(`⛔ checkout/confirm: invalid idempotencyKey format. orderId=${orderId} uid=${req.firebaseUid} key=${iKey.slice(0,30)}`);
        return res.status(403).json({ error: 'Invalid order — please re-checkout.', code: 'INVALID_IKEY' });
      }

      const items = order.items || [];
      if (items.length === 0) {
        return res.status(400).json({ error: 'Order has no items' });
      }

      // ── Verify order total: server recalculates from DB (authoritative) ──────
      // SECURITY: Server tự tính expectedTotal từ DB thay vì dùng threshold %.
      // Bao gồm flash sale (server fetch), bulk discount, voucher → so sánh ±1đ.
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

      for (const item of items) {
        if (!accountDocsById[item.id]) {
          console.warn(`⚠️ Account ${item.id} not in DB — aborting`);
          return res.status(400).json({ error: `Account ${item.id} không tồn tại` });
        }
      }

      // Fetch active flash sale from DB (không tin client)
      let activeFlashSale = null;
      try {
        const fsSnap = await db.query('flashSales', [['active', '==', true]], null, 5, null);
        const now = new Date();
        activeFlashSale = fsSnap.find(doc => {
          const d = doc.data();
          const start = d.startAt ? new Date(d.startAt) : null;
          const end   = d.endAt   ? new Date(d.endAt)   : null;
          if (start && now < start) return false;
          if (end   && now > end)   return false;
          return true;
        })?.data() || null;
      } catch (e) {
        console.warn('⚠️ Could not fetch flash sales, using base prices:', e.message);
      }

      // Tính expectedSubtotal (kể cả flash sale per-gameType)
      let expectedSubtotal = 0;
      for (const item of items) {
        const accData = accountDocsById[item.id];
        const dbPrice = accData.price || 0;
        let effectivePrice = dbPrice;
        if (activeFlashSale) {
          const gameType = accData.gameType || item.gameType || '';
          const appliesTo = activeFlashSale.targetAll ||
            !activeFlashSale.targetGameTypes?.length ||
            (gameType && (activeFlashSale.targetGameTypes || []).includes(gameType));
          if (appliesTo) {
            const discount = Math.min(Math.max(0, activeFlashSale.discount || 0), 99);
            effectivePrice = Math.round(dbPrice * (1 - discount / 100));
          }
        }
        expectedSubtotal += effectivePrice;
      }

      // Fetch bulk discount rules từ DB
      let expectedBulkDiscount = 0;
      try {
        const bdSnap = await db.query('bulkDiscountRules', [['active', '==', true]], null, 20, serverToken);
        const applicable = bdSnap.filter(d => items.length >= (d.data().minQty || 0));
        if (applicable.length > 0) {
          const best = applicable.reduce((a, b) =>
            (a.data().minQty || 0) > (b.data().minQty || 0) ? a : b);
          const pct = best.data().discountPct || 0;
          expectedBulkDiscount = Math.round(expectedSubtotal * pct / 100);
        }
      } catch (e) {
        console.warn('⚠️ Could not fetch bulk discount rules:', e.message);
      }

      // Fetch và verify voucher từ DB nếu order có voucherCode
      let expectedVoucherDiscount = 0;
      const voucherCode = order.voucherCode;
      if (voucherCode) {
        try {
          const vSnap = await db.query('vouchers', [
            ['code',   '==', String(voucherCode).toUpperCase()],
            ['active', '==', true],
          ], null, 1, serverToken);
          if (vSnap.length > 0) {
            const vData = vSnap[0].data();
            const afterBulk = expectedSubtotal - expectedBulkDiscount;
            if (vData.type === 'fixed') {
              expectedVoucherDiscount = Math.min(vData.value || 0, afterBulk);
            } else {
              const raw = (afterBulk * (vData.value || 0)) / 100;
              expectedVoucherDiscount = vData.maxDiscount > 0
                ? Math.min(raw, vData.maxDiscount) : raw;
            }
          }
        } catch (e) {
          console.warn('⚠️ Could not verify voucher:', e.message);
        }
      }

      // So sánh server-expected vs client-submitted (tolerance ±1đ làm tròn float)
      const expectedTotal = Math.round(Math.max(0,
        expectedSubtotal - expectedBulkDiscount - expectedVoucherDiscount));
      const orderTotal = order.total || 0;
      if (Math.abs(orderTotal - expectedTotal) > 1 || orderTotal <= 0) {
        console.error(`⛔ Price mismatch! orderId=${orderId} clientTotal=${orderTotal} serverExpected=${expectedTotal} (sub=${expectedSubtotal} bulk=${expectedBulkDiscount} voucher=${Math.round(expectedVoucherDiscount)})`);
        return res.status(403).json({
          error: 'Tổng đơn hàng không hợp lệ. Vui lòng đặt hàng lại.',
          code:  'PRICE_MISMATCH',
        });
      }
      console.log(`✅ Price verified: clientTotal=${orderTotal} === serverExpected=${expectedTotal}`);

      // ── Fetch credentials dùng serverToken (server role có quyền đọc credentials) ─
      const deltaByAccountId = {};
      for (const item of items) {
        if (!item.id) continue;
        deltaByAccountId[item.id] = (deltaByAccountId[item.id] || 0) + 1;
      }

      const accountDataById = {};
      await Promise.all(uniqueAccountIds.map(async (accountId) => {
        try {
          const credDoc = await db.getWithToken(`accounts/${accountId}/credentials`, 'slots', serverToken);
          accountDataById[accountId] = {
            acc:   accountDocsById[accountId],
            creds: credDoc.exists ? (credDoc.data().slots || []) : [],
          };
        } catch (e) {
          console.warn(`⚠️ Fetch credentials ${accountId} error:`, e.message);
          accountDataById[accountId] = { acc: accountDocsById[accountId], creds: [] };
        }
      }));

      // ── Atomic soldCount + credential slot assignment dùng serverToken ────
      const firestore = db.getFirestore();
      const slotsByAccountId = {};

      if (soldCountAlreadyDone) {
        console.log(`ℹ️ soldCount already done, re-injecting all combo slots`);
        for (const accountId of Object.keys(deltaByAccountId)) {
          const creds = (accountDataById[accountId] && accountDataById[accountId].creds) || [];
          try {
            const accDoc = await db.get('accounts', accountId);
            const accData  = accDoc.exists ? accDoc.data() : {};
            const quantity = accData.quantity || 1;
            const soldCount  = accData.soldCount || 1;
            const slotStart  = (soldCount - 1) * quantity;
            const assignedSlots = [];
            for (let i = 0; i < quantity; i++) {
              assignedSlots.push(creds[slotStart + i] || {
                loginUsername: '', loginPassword: '', loginEmail: '', loginNote: '',
                attachmentContent: null, attachmentName: null,
              });
            }
            slotsByAccountId[accountId] = assignedSlots;
            // Đảm bảo status = 'sold' nếu chưa được set (lần trước bị crash giữa chừng)
            // SECURITY FIX: dùng serverToken thay vì userToken — userToken có thể expire
            // khi user navigate đến OrderDetailPage sau thời gian dài
            if (accData.status !== 'sold') {
              try {
                await db.update('accounts', accountId, { status: 'sold' }, serverToken);
                console.log(`✅ Re-set status=sold for ${accountId} (via serverToken)`);
              } catch (se) {
                console.warn(`⚠️ Re-set status failed for ${accountId}:`, se.message);
              }
            }
          } catch (e) {
            console.warn(`⚠️ Re-fetch account ${accountId}:`, e.message);
            slotsByAccountId[accountId] = [];
          }
        }
      } else {
        // Dùng Firestore transaction với serverToken.
        // Firestore rules cho phép isAdminOrServer() update soldCount/status → beginTransaction OK.
        // Transaction đảm bảo atomicity: 2 người mua cùng lúc → chỉ 1 người thành công.
        for (const accountId of Object.keys(deltaByAccountId)) {
          const creds = (accountDataById[accountId] && accountDataById[accountId].creds) || [];
          let assignedSlots = [];

          try {
            const accRef = firestore.collection('accounts').doc(accountId);

            await db.runTransactionWithRetry(async (tx) => {
              const accSnap = await tx.get(accRef);
              if (!accSnap.exists) throw new Error('not_found');

              const accData          = accSnap.data();
              const quantity         = accData.quantity || 1;
              const currentSoldCount = accData.soldCount || 0;

              if (currentSoldCount >= 1) {
                throw new Error('sold_out');
              }

              // Assign credential slots trong transaction — đảm bảo chỉ 1 người nhận
              const slotStart = currentSoldCount * quantity;
              assignedSlots = [];
              for (let i = 0; i < quantity; i++) {
                assignedSlots.push(creds[slotStart + i] || {
                  loginUsername: '', loginPassword: '',
                  loginEmail: '', loginNote: '',
                  attachmentContent: null, attachmentName: null,
                });
              }

              tx.update(accRef, {
                soldCount: db.FieldValue.increment(1),
                status: 'sold',
              });
            }, 3, serverToken);

            slotsByAccountId[accountId] = assignedSlots;
            console.log(`✅ soldCount +1, status=sold (atomic tx), injecting ${assignedSlots.length} slots: ${accountId}`);
          } catch (e) {
            console.error(`❌ Transaction failed for ${accountId}: ${e.message}`);
            throw new Error(`Không thể cập nhật trạng thái sản phẩm ${accountId}: ${e.message}`);
          }
        }
      }

      const updatedItems = items.map(item => {
        if (!item.id || !slotsByAccountId[item.id]) return item;
        const slots = slotsByAccountId[item.id];
        const first = slots[0] || {
          loginUsername: '', loginPassword: '', loginEmail: '', loginNote: '',
          attachmentContent: null, attachmentUrl: null, attachmentName: null,
        };
        return {
          ...item,
          loginUsername:     first.loginUsername     || '',
          loginPassword:     first.loginPassword     || '',
          loginEmail:        first.loginEmail        || '',
          loginNote:         first.loginNote         || '',
          attachmentContent: first.attachmentContent || null,
          attachmentUrl:     first.attachmentUrl     || null,
          attachmentName:    first.attachmentName    || null,
          allCredentials: slots.map(s => ({
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

      // Update order dùng userToken (rules cho phép user update order của họ)
      await db.update('orders', orderId, {
        items:               updatedItems,
        _soldCountUpdated:   true,
        _credentialsInjected: true,
      }, userToken);

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
async function findUserByEmail(db, content, serverToken) {
  const napMatch = content.match(/NAP\s+([^\s]+)/i);
  if (!napMatch) return null;
  const id = napMatch[1].toLowerCase().trim();
  if (id.length < 3) return null;
  if (id.includes('@')) {
    const r = await db.query('users', [['email', '==', id]], null, 1, serverToken);
    if (r.length > 0) {
      const d = r[0].data();
      return { userId: r[0].id, userEmail: d.email, displayName: d.displayName };
    }
  }
  return null;
}