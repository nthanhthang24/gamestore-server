// routes/sepay.js
// ── Tích hợp SePay (Tài khoản BIDV cá nhân - API Banking) ────────────────
//
// Flow hoạt động với tài khoản CÁ NHÂN:
//   1. User bấm "Tạo QR" → server tạo nội dung CK duy nhất (NAP + topupId ngắn)
//   2. Frontend hiển thị QR với STK BIDV + nội dung đã điền sẵn
//   3. User quét QR → chuyển khoản (nội dung tự động điền)
//   4. SePay phát hiện biến động số dư → POST /bank/webhook
//   5. Server đọc field "content" trong webhook → tìm topupId → cộng balance
//
// QUAN TRỌNG: Nội dung CK phải chứa topupId (ngắn) thay vì email prefix
// → Đảm bảo match chính xác 100%, không phụ thuộc vào email format

const express = require('express');
const crypto  = require('crypto');

// ── IP Whitelist — đọc từ env var để cập nhật KHÔNG CẦN redeploy ────
// Render dashboard → Environment → SEPAY_IPS = "103.255.238.108,116.103.227.99"
// Lấy IP mới nhất tại: my.sepay.vn → Tài khoản → Cài đặt webhook → IP cho phép
const SEPAY_IPS_EXTRA = (process.env.SEPAY_IPS || '')
  .split(',').map(s => s.trim()).filter(Boolean);

const SEPAY_IPS = [
  // Fallback hardcode — IPs đã biết tại thời điểm deploy
  '103.255.238.108', '103.255.238.109', '103.255.238.110',
  '116.103.227.99',  '42.118.118.53',
  // Local/test only
  '127.0.0.1', '::1', '::ffff:127.0.0.1',
  // IPs từ env var (cập nhật không cần redeploy)
  ...SEPAY_IPS_EXTRA,
];

console.log(`🔒 IP whitelist: ${SEPAY_IPS.filter(ip => !ip.startsWith('127') && !ip.startsWith('::')).join(', ')}${SEPAY_IPS_EXTRA.length ? ` (+${SEPAY_IPS_EXTRA.length} từ env)` : ''}`);

// ── IP Verification — Best-Effort Secondary Layer ─────────────────────
// QUAN TRỌNG: trên Render.com (có Cloudflare edge + internal LB), không có
// cách 100% reliable để lấy IP gốc của caller:
//
//   Request chain: SePay → [Cloudflare] → [Render LB] → App
//   req.socket.remoteAddress = IP Render internal LB (10.x.x.x), KHÔNG phải SePay
//   X-Forwarded-For = có thể bị forge bởi attacker
//   CF-Connecting-IP = Cloudflare thêm, nhưng bypass được nếu gọi origin IP trực tiếp
//
// → PRIMARY security = SEPAY_API_KEY (secret, không thể forge)
// → IP check = secondary best-effort layer (chặn unsophisticated attacks)
//
// Chiến lược: đọc X-Forwarded-For NHƯNG chỉ lấy hop ĐẦU TIÊN (leftmost = closest to real origin)
// và log tất cả để monitoring. Không hard-fail nếu IP không match — chỉ LOG WARN.
function getCallerIP(req) {
  const xff    = req.headers['x-forwarded-for'] || '';
  const cfIP   = req.headers['cf-connecting-ip'] || '';      // Cloudflare edge header
  const socket = (req.socket?.remoteAddress || '').replace(/^::ffff:/, '');

  // Leftmost XFF entry = IP gần origin nhất (nhưng vẫn có thể forge)
  const xffFirst = xff.split(',')[0]?.trim().replace(/^::ffff:/, '') || '';

  return {
    socket,
    xff:    xffFirst,
    cf:     cfIP,
    // Best guess: CF-Connecting-IP nếu có (Cloudflare đảm bảo), fallback XFF leftmost
    best:   cfIP || xffFirst || socket,
  };
}

function isKnownSepayIP(ip) {
  if (!ip) return false;
  if (SEPAY_IPS.includes(ip)) return true;
  if (ip.startsWith('103.255.238.')) return true; // SePay subnet
  return false;
}

module.exports = (db) => {
  const router = express.Router();

  const BANK = {
    bin:  process.env.BANK_BIN            || '970418',
    acc:  process.env.BANK_ACCOUNT_NUMBER || '1290702118',
    name: process.env.BANK_ACCOUNT_NAME   || 'NGUYEN NAM SON',
    // ⚡ VA number từ SePay dashboard (Tài khoản ảo tab)
    // SePay chỉ track giao dịch đến VA number, KHÔNG track STK BIDV gốc
    // Lấy từ: my.sepay.vn → Ngân hàng → Tài khoản ảo (VA) → cột "Số VA"
    va:   process.env.BANK_VA_NUMBER      || '',
  };

  // ── Middleware bảo mật webhook ────────────────────────────────────────
  // PRIMARY guard  = SEPAY_API_KEY (secret — hard fail nếu sai)
  // SECONDARY guard = IP check (best-effort — log warn nếu không match,
  //                   không hard-fail vì Render proxy layers không reliable)
  function verifyWebhook(req, res, next) {
    const apiKey   = process.env.SEPAY_API_KEY;
    const received = (req.headers['authorization'] || '').replace(/^Apikey\s+/i, '').trim();
    const ips      = getCallerIP(req);

    // Log tất cả IP sources để monitoring thực tế trên Render
    console.log(`📬 Webhook | socket:${ips.socket} xff:${ips.xff} cf:${ips.cf} best:${ips.best} | auth:${received ? received.slice(0,8)+'...' : 'NONE'}`);

    // PRIMARY: API key check — hard fail
    if (!apiKey) {
      console.error('⛔ SEPAY_API_KEY chưa cấu hình — từ chối (fail-closed)');
      return res.status(503).json({ error: 'Service not configured' });
    }
    if (received !== apiKey) {
      console.warn(`⛔ API Key sai | best_ip:${ips.best}`);
      return res.status(401).json({ error: 'Unauthorized' });
    }

    // SECONDARY: IP check — log warn nhưng không block
    // (vì trên Render, IP qua nhiều proxy layer → không reliable để hard-fail)
    if (!isKnownSepayIP(ips.best)) {
      console.warn(`⚠️  IP lạ nhưng API key đúng: best=${ips.best} socket=${ips.socket} xff=${ips.xff}`);
      console.warn(`⚠️  Nếu đây là SePay IP mới → thêm vào Render env: SEPAY_IPS=...,${ips.best}`);
    } else {
      console.log(`✅ IP match: ${ips.best}`);
    }

    next();
  }

  // ════════════════════════════════════════════════════════════════════
  // POST /bank/webhook  ← SePay gọi vào đây
  // ════════════════════════════════════════════════════════════════════
  router.post('/webhook', verifyWebhook, async (req, res) => {
    try {
      // Log TOÀN BỘ body để debug
      console.log('📩 SePay webhook raw:', JSON.stringify(req.body));

      const {
        id: sePayId,
        gateway,
        transactionDate,
        content,          // ← nội dung chuyển khoản, VD: "NAP abc123 GAMESTORE"
        transferType,
        transferAmount,
        referenceCode,
        error: sePayError,
        code,             // ← chỉ có khi dùng VA API (tài khoản doanh nghiệp)
        subAccount,       // ← VA number nếu có
      } = req.body;

      // Chỉ xử lý giao dịch VÀO, không có lỗi
      if (transferType !== 'in') {
        console.log('⏭ Bỏ qua: transferType =', transferType);
        return res.status(200).json({ message: 'Skipped - not incoming' });
      }
      if (sePayError !== 0 && sePayError != null) {
        console.log('⏭ Bỏ qua: sePayError =', sePayError);
        return res.status(200).json({ message: 'Skipped - error transaction' });
      }
      if (!transferAmount || transferAmount <= 0) {
        return res.status(200).json({ message: 'Invalid amount' });
      }
      if (transferAmount > 50_000_000) {
        console.warn(`⚠️ Amount vượt giới hạn: ${transferAmount}`);
        await db.add('unmatchedTopups', {
          sePayId: String(sePayId), gateway, content,
          amount: transferAmount, transactionDate,
          status: 'overlimit', createdAt: db.FieldValue.serverTimestamp(),
        });
        return res.status(200).json({ message: 'Amount over limit' });
      }

      // ── Atomic duplicate check (FIX VULN-16: race condition) ───────
      // Attempt to CREATE processedWebhooks/{sePayId} with precondition "must not exist"
      // Firestore REST PATCH with currentDocument.exists=false is atomic — if two requests
      // race, only one wins; the other gets HTTP 409 Conflict.
      try {
        await db.createIfNotExists('processedWebhooks', String(sePayId), {
          sePayId: String(sePayId),
          status: 'processing',
          startedAt: db.FieldValue.serverTimestamp(),
        });
      } catch(e) {
        if (e.response?.status === 409 || (e.message || '').includes('ALREADY_EXISTS')) {
          console.log('⚠️ Duplicate sePayId (atomic check):', sePayId);
          return res.status(200).json({ message: 'Already processed' });
        }
        // Other errors: continue (idempotency via topup status as backup)
        console.warn('⚠️ Atomic duplicate check failed, continuing:', e.message);
      }

      // ── Match user ──────────────────────────────────────────────────
      let user      = null;
      let topupDocId = null;

      // Cách 1: tìm topupId trong nội dung CK (format: "NAP <topupId>")
      // topupId là Firestore auto-ID ngắn gọn được nhúng vào nội dung QR
      const topupMatch = (content || '').match(/NAP\s+([A-Za-z0-9]+)/i);
      if (topupMatch) {
        const candidate = topupMatch[1];
        console.log('🔍 Tìm topupId từ nội dung:', candidate);
        try {
          const topupDoc = await db.get('topups', candidate);
          if (topupDoc.exists) {
            const t = topupDoc.data();
            console.log('📄 Topup doc found:', JSON.stringify(t));
            if (t.status === 'pending') {
              topupDocId = candidate;
              user = { userId: t.userId, userEmail: t.userEmail, displayName: t.userName };
              console.log(`✅ Match theo topupId: ${candidate} → ${t.userEmail}`);
            } else {
              console.warn(`⚠️ Topup ${candidate} đã xử lý rồi (status=${t.status})`);
              return res.status(200).json({ message: 'Topup already processed' });
            }
          } else {
            console.log('📄 Không tìm thấy topupId:', candidate, '- thử match email');
          }
        } catch (e) {
          console.warn('⚠️ Lỗi tìm topup doc:', e.message);
        }
      }

      // Cách 2: fallback tìm theo email prefix (nội dung format cũ "NAP EMAIL")
      if (!user && content) {
        user = await findUserByEmail(db, content);
      }

      // Không match được
      if (!user) {
        await db.add('unmatchedTopups', {
          sePayId: String(sePayId), gateway, content, code: code || null,
          amount: transferAmount, transactionDate, referenceCode,
          status: 'unmatched', createdAt: db.FieldValue.serverTimestamp(),
        });
        console.log('⚠️ Unmatched transaction:', { content, transferAmount, sePayId });
        return res.status(200).json({ message: 'Unmatched - saved for manual review' });
      }

      // ── Cộng balance ────────────────────────────────────────────────
      const userDoc = await db.get('users', user.userId);
      if (!userDoc.exists) {
        console.error('❌ User doc không tìm thấy:', user.userId);
        return res.status(404).json({ error: 'User not found' });
      }
      const prev = userDoc.data().balance || 0;
      const next = prev + transferAmount;

      const ops = [
        db.update('users', user.userId, {
          balance: next,
          updatedAt: db.FieldValue.serverTimestamp(),
        }),
        db.add('transactions', {
          userId:        user.userId,
          userEmail:     user.userEmail,
          type:          'topup',
          method:        'bank_transfer',
          gateway,
          amount:        transferAmount,
          balanceBefore: prev,
          balanceAfter:  next,
          sePayId:       String(sePayId),
          referenceCode,
          content,
          createdAt:     db.FieldValue.serverTimestamp(),
        }),
      ];

      if (topupDocId) {
        // Update doc pending → approved
        ops.push(db.update('topups', topupDocId, {
          status:        'approved',
          autoApproved:  true,
          sePayId:       String(sePayId),
          gateway,
          referenceCode,
          approvedAt:    db.FieldValue.serverTimestamp(),
        }));
      } else {
        // Tạo mới (fallback email match)
        ops.push(db.add('topups', {
          userId:          user.userId,
          userEmail:       user.userEmail,
          userName:        user.displayName || user.userEmail,
          amount:          transferAmount,
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

      // Mark processedWebhooks as fully committed (update from 'processing' → 'done')
      ops.push(db.update('processedWebhooks', String(sePayId), {
        status: 'done',
        userId: user.userId,
        amount: transferAmount,
        processedAt: db.FieldValue.serverTimestamp(),
      }));

      await Promise.all(ops);
      console.log(`✅ Nạp +${transferAmount}đ cho ${user.userEmail} | ${prev} → ${next}`);

      // ── Referral commission (2% of first topup, configurable) ───────
      // Only triggers on first-ever topup ≥ minTopup threshold
      try {
        await processReferralCommission(db, user.userId, transferAmount);
      } catch (refErr) {
        // Non-critical — log and continue, don't fail the webhook
        console.warn('⚠️ Referral commission error (non-critical):', refErr.message);
      }

      return res.status(200).json({ message: 'success' });

    } catch (err) {
      console.error('❌ Webhook error:', err.message, err.stack);
      return res.status(500).json({ error: 'Internal server error' });
    }
  });

  // ── Referral Commission Processor ───────────────────────────────────
  // Reads config from settings/global, triggers only on first qualifying topup
  async function processReferralCommission(db, userId, topupAmount) {
    // 1. Read referral config from Firestore settings/global
    let commissionPct  = 2;     // default 2%
    let minTopup       = 50000; // default 50,000đ
    let newUserBonus   = 10000; // default 10,000đ
    try {
      const settingsDoc = await db.get('settings', 'global');
      if (settingsDoc.exists) {
        const s = settingsDoc.data();
        if (s.referralCommissionPct != null) commissionPct  = Number(s.referralCommissionPct);
        if (s.referralMinTopup      != null) minTopup       = Number(s.referralMinTopup);
        if (s.referralNewUserBonus  != null) newUserBonus   = Number(s.referralNewUserBonus);
      }
    } catch(e) { console.warn('Could not read referral config, using defaults:', e.message); }

    // 2. Only process if topup meets minimum threshold
    if (topupAmount < minTopup) {
      console.log(`ℹ️ Referral skip: topup ${topupAmount}đ < minTopup ${minTopup}đ`);
      return;
    }

    // 3. Check if this user already has a credited referral (prevent double-credit)
    const existingCredited = await db.query('referrals', [
      ['newUserId', '==', userId],
      ['credited',  '==', true ],
    ], null, 1);
    if (existingCredited && existingCredited.length > 0) {
      console.log(`ℹ️ Referral already credited for user ${userId}`);
      return;
    }

    // 4. Find uncredited referral for this user
    const pendingReferrals = await db.query('referrals', [
      ['newUserId', '==', userId],
      ['credited',  '==', false],
    ], null, 1);
    if (!pendingReferrals || pendingReferrals.length === 0) {
      console.log(`ℹ️ No pending referral for user ${userId}`);
      return;
    }

    // 5. Check this is first topup (no previous approved topups)
    const prevTopups = await db.query('topups', [
      ['userId', '==', userId],
      ['status', '==', 'approved'],
    ], null, 5);
    // prevTopups includes the current one already committed — so if count > 1, not first topup
    if (prevTopups && prevTopups.length > 1) {
      console.log(`ℹ️ Not first topup for user ${userId} (count: ${prevTopups.length})`);
      return;
    }

    const referral = pendingReferrals[0];
    const referrerId = referral.referrerId;
    if (!referrerId) return;

    // 6. Calculate commission
    const commissionAmount = Math.round(topupAmount * commissionPct / 100);
    console.log(`💰 Referral commission: ${commissionAmount}đ (${commissionPct}% of ${topupAmount}đ) → ${referrerId}`);

    // 7. Credit referrer + mark referral credited (atomic-ish via sequential writes)
    const referrerDoc = await db.get('users', referrerId);
    if (!referrerDoc.exists) {
      console.warn('⚠️ Referrer user not found:', referrerId);
      return;
    }
    const referrerBalance = referrerDoc.data().balance || 0;

    await Promise.all([
      // Credit referrer
      db.update('users', referrerId, {
        balance: referrerBalance + commissionAmount,
        updatedAt: db.FieldValue.serverTimestamp(),
      }),
      // Mark referral as credited, store topup info
      db.update('referrals', referral.id, {
        credited: true,
        commissionAmount,
        commissionPct,
        topupAmount,
        creditedAt: db.FieldValue.serverTimestamp(),
      }),
      // Transaction record for referrer
      db.add('transactions', {
        userId:   referrerId,
        type:     'referral_commission',
        amount:   commissionAmount,
        fromUserId: userId,
        commissionPct,
        topupAmount,
        balanceBefore: referrerBalance,
        balanceAfter:  referrerBalance + commissionAmount,
        createdAt: db.FieldValue.serverTimestamp(),
      }),
      // In-app notification for referrer
      db.add('notifications', {
        title:        '💰 Nhận hoa hồng giới thiệu!',
        body:         `Bạn bè của bạn vừa nạp ${topupAmount.toLocaleString ? topupAmount.toLocaleString('vi-VN') : topupAmount.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',')}đ. Bạn nhận được ${commissionAmount.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',')}đ (${commissionPct}% hoa hồng).`,
        type:         'referral',
        targetAll:    false,
        targetUserId: referrerId,
        active:       true,
        read:         [],
        createdAt:    db.FieldValue.serverTimestamp(),
        createdBy:    'system',
      }),
    ]);
    console.log(`✅ Referral commission credited: ${commissionAmount}đ to ${referrerId}`);
  }

  // ── Middleware: verify Firebase ID token ─────────────────────────────
  // FIX VULN-14: /bank/vietqr phải có auth — không ai gọi thay người khác được
  async function verifyFirebaseToken(req, res, next) {
    const authHeader = req.headers['authorization'] || '';
    const idToken = authHeader.replace(/^Bearer\s+/i, '').trim();
    if (!idToken) {
      return res.status(401).json({ error: 'Missing Authorization token' });
    }
    try {
      // Verify via Firebase REST (no Admin SDK needed)
      const FIREBASE_API_KEY = process.env.FIREBASE_API_KEY;
      if (!FIREBASE_API_KEY) return res.status(503).json({ error: 'Server not configured' });
      const resp = await require('axios').post(
        `https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${FIREBASE_API_KEY}`,
        { idToken }
      );
      const users = resp.data?.users;
      if (!users || users.length === 0) {
        return res.status(401).json({ error: 'Invalid token' });
      }
      req.firebaseUid = users[0].localId;
      req.firebaseEmail = users[0].email;
      next();
    } catch (e) {
      console.warn('Token verify failed:', e.response?.data || e.message);
      return res.status(401).json({ error: 'Invalid or expired token' });
    }
  }

  // ════════════════════════════════════════════════════════════════════
  // GET /bank/vietqr  ← Frontend gọi để lấy QR (requires auth token)
  // ════════════════════════════════════════════════════════════════════
  router.get('/vietqr', verifyFirebaseToken, async (req, res) => {
    const { amount, userId, userEmail } = req.query;
    if (!amount || !userId || !userEmail)
      return res.status(400).json({ error: 'Missing params' });

    // FIX VULN-14: userId phải khớp với token đã verify — không cho đặt userId người khác
    if (userId !== req.firebaseUid) {
      return res.status(403).json({ error: 'userId không khớp với token. Vui lòng đăng nhập lại.' });
    }

    const amt = Number(amount);
    if (isNaN(amt) || amt < 10000 || amt > 50_000_000)
      return res.status(400).json({ error: 'Số tiền phải từ 10,000 đến 50,000,000đ' });

    // Validate user (soft check)
    try {
      const userDoc = await db.get('users', userId);
      if (userDoc.exists) {
        const storedEmail = userDoc.data().email;
        if (storedEmail && storedEmail !== decodeURIComponent(userEmail)) {
          return res.status(403).json({ error: 'Thông tin không hợp lệ. Vui lòng đăng nhập lại.' });
        }
      }
    } catch (e) {
      console.warn('⚠️ Không thể verify user:', e.message);
    }

    // Rate limit: max 3 pending cùng lúc
    try {
      const pending = await db.query('topups', [
        ['userId', '==', userId],
        ['status',  '==', 'pending'],
      ], null, 5);
      if (pending.length >= 3) {
        return res.status(429).json({
          error: 'Bạn đang có 3 yêu cầu nạp tiền chưa xử lý. Vui lòng thử lại sau.',
        });
      }
    } catch (e) {
      console.warn('Rate limit check failed:', e.message);
    }

    try {
      const decodedEmail = decodeURIComponent(userEmail);

      // Bước 1: Tạo topup doc trước → lấy Firestore ID làm mã đối chiếu
      // Note: Firestore rules phải cho phép server tạo topups
      // rules: match /topups/{id} { allow create: if true; } (server dùng API key)
      // Bước 1b: Tạo ID trước bằng cách dùng set() với ID tự sinh
      // Tạo topupId ngẫu nhiên để dùng làm nội dung CK TRƯỚC khi tạo doc
      // FIX VULN-17: CSPRNG topupId — không dùng Math.random() (predictable)
      const topupId = crypto.randomBytes(12).toString('hex'); // 24-char hex, 96-bit entropy

      // Bước 2: Nội dung CK = "NAP <topupId>"
      const content = `NAP ${topupId}`;

      // Tạo topup doc với transferContent ngay từ đầu (1 lần write, không cần update)
      // → tránh lỗi 403 khi server update (rules chỉ cho admin update)
      await db.set('topups', topupId, {
        userId,
        userEmail:  decodedEmail,
        amount:     amt,
        method:     'bank_transfer',
        status:     'pending',
        transferContent: content,
        createdAt:  db.FieldValue.serverTimestamp(),
      });

      // Bước 3: Tạo QR URL
      // ⚡ ROOT CAUSE FIX: Phải dùng SỐ VA thay vì STK BIDV gốc!
      // SePay chỉ theo dõi giao dịch đến VA number (98247NNS10032026)
      // Giao dịch đến STK gốc (1290702118) SePay KHÔNG track → webhook không bao giờ được gọi
      // Cài BANK_VA_NUMBER trên Render = số VA lấy từ my.sepay.vn → Ngân hàng → cột "Số VA"
      const qrAcc = BANK.va || BANK.acc;
      if (!BANK.va) {
        console.warn('⚠️ BANK_VA_NUMBER chưa set! QR đang dùng STK gốc - SePay KHÔNG track được!');
      }
      const qrUrl = `https://qr.sepay.vn/img?acc=${qrAcc}&bank=BIDV&amount=${amt}&des=${encodeURIComponent(content)}&template=compact2`;

      console.log(`✅ Tạo QR: topupId=${topupId} amount=${amt} content="${content}" qrAcc=${qrAcc}`);

      return res.json({
        qrUrl,
        transferContent: content,
        accountNumber:   qrAcc,
        accountName:     BANK.name,
        bankName:        'BIDV',
        bankBin:         BANK.bin,
        amount:          amt,
        topupId,
        method:          BANK.va ? 'va' : 'static', // FIX S-07: 'va' khi dùng VA — không cần nhập nội dung CK
        usingVA:         !!BANK.va,
      });

    } catch (err) {
      console.error('❌ /vietqr error:', err.message);
      return res.status(500).json({ error: `Lỗi tạo QR: ${err.message}` });
    }
  });

  // ── /bank/test-webhook REMOVED (S-02: security risk) ────────────────
  // Endpoint này đã bị xóa vĩnh viễn — ALLOW_TEST env bypass nguy hiểm.
  // Để test webhook, dùng: curl trực tiếp với SEPAY_API_KEY từ máy local.

  return router;
};

// ── Fallback: tìm user theo email prefix ──────────────────────────────────
// FIX S-03: Removed O(n) full-scan. Only match full email now.
// topupId match (primary path) handles 99%+ of cases.
// Email prefix match was legacy from before topupId existed.
async function findUserByEmail(db, content) {
  const napMatch = content.match(/NAP\s+([^\s]+)/i);
  if (!napMatch) return null;

  const id = napMatch[1].toLowerCase().trim();
  if (id.length < 3) return null;

  // Full email match only — no O(n) prefix scan
  if (id.includes('@')) {
    const r = await db.query('users', [['email', '==', id]], null, 1);
    if (r.length > 0) {
      const d = r[0].data();
      return { userId: r[0].id, userEmail: d.email, displayName: d.displayName };
    }
  }
  // FIX S-03: prefix scan removed — unmatch goes to manual review instead
  return null;
}
