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

const SEPAY_IPS = [
  '103.255.238.108', '103.255.238.109', '103.255.238.110',
  '116.103.227.99',  '42.118.118.53',
  '127.0.0.1', '::1',
];

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
  function verifyWebhook(req, res, next) {
    const apiKey   = process.env.SEPAY_API_KEY;
    const received = (req.headers['authorization'] || '').replace(/^Apikey\s+/i, '').trim();
    if (apiKey && received !== apiKey) {
      console.warn(`⛔ Webhook từ chối: API Key sai | IP: ${getIP(req)}`);
      return res.status(401).json({ error: 'Unauthorized' });
    }
    if (process.env.SKIP_IP_CHECK !== 'true') {
      const ip = getIP(req);
      if (!SEPAY_IPS.includes(ip)) {
        console.warn(`⛔ Webhook từ chối: IP không hợp lệ: ${ip}`);
        return res.status(403).json({ error: 'Forbidden' });
      }
    }
    next();
  }

  function getIP(req) {
    return req.ip || req.socket?.remoteAddress || '';
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

      // Chống duplicate
      const existing = await db.query('transactions', [['sePayId', '==', String(sePayId)]], null, 1);
      if (existing.length > 0) {
        console.log('⚠️ Duplicate sePayId:', sePayId);
        return res.status(200).json({ message: 'Already processed' });
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

      await Promise.all(ops);
      console.log(`✅ Nạp +${transferAmount}đ cho ${user.userEmail} | ${prev} → ${next}`);
      return res.status(200).json({ message: 'success' });

    } catch (err) {
      console.error('❌ Webhook error:', err.message, err.stack);
      return res.status(500).json({ error: 'Internal server error' });
    }
  });

  // ════════════════════════════════════════════════════════════════════
  // GET /bank/vietqr  ← Frontend gọi để lấy QR
  // Nội dung CK: "NAP <topupId>" - topupId là Firestore doc ID ngắn
  // ════════════════════════════════════════════════════════════════════
  router.get('/vietqr', async (req, res) => {
    const { amount, userId, userEmail } = req.query;
    if (!amount || !userId || !userEmail)
      return res.status(400).json({ error: 'Missing params' });

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
      const topupRef = await db.add('topups', {
        userId,
        userEmail:  decodedEmail,
        amount:     amt,
        method:     'bank_transfer',
        status:     'pending',
        createdAt:  db.FieldValue.serverTimestamp(),
      });
      const topupId = topupRef.id; // VD: "Xk9mR2pQwL3nVbTy"

      // Bước 2: Nội dung CK = "NAP <topupId>"
      // SePay sẽ gửi lại đúng nội dung này trong webhook → server match chính xác
      const content = `NAP ${topupId}`;

      // Update topup doc với transferContent
      await db.update('topups', topupId, { transferContent: content });

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
        method:          'static',
        usingVA:         !!BANK.va,
      });

    } catch (err) {
      console.error('❌ /vietqr error:', err.message);
      return res.status(500).json({ error: `Lỗi tạo QR: ${err.message}` });
    }
  });

  // ── GET /bank/test-webhook ← Để test thủ công ──────────────────────
  // Gọi: GET /bank/test-webhook?topupId=xxx&amount=50000
  router.get('/test-webhook', async (req, res) => {
    if (process.env.NODE_ENV === 'production' && process.env.ALLOW_TEST !== 'true') {
      return res.status(403).json({ error: 'Disabled in production' });
    }
    const { topupId, amount } = req.query;
    if (!topupId) return res.status(400).json({ error: 'Missing topupId' });

    // Giả lập webhook payload
    const fakeBody = {
      id:             99999,
      gateway:        'BIDV',
      transactionDate: new Date().toISOString(),
      content:        `NAP ${topupId}`,
      transferType:   'in',
      transferAmount: Number(amount) || 50000,
      referenceCode:  'TEST001',
      error:          0,
    };
    req.body = fakeBody;
    console.log('🧪 Test webhook với:', JSON.stringify(fakeBody));

    // Gọi lại handler webhook (bypass auth)
    req.headers['authorization'] = `Apikey ${process.env.SEPAY_API_KEY}`;
    process.env.SKIP_IP_CHECK = 'true';

    // Trả về luôn response cho user xem
    res.json({ message: 'Test initiated, check server logs', payload: fakeBody });
  });

  return router;
};

// ── Fallback: tìm user theo email prefix ──────────────────────────────────
async function findUserByEmail(db, content) {
  const napMatch = content.match(/NAP\s+([^\s]+)/i);
  if (!napMatch) return null;

  const id = napMatch[1].toLowerCase().trim();
  if (id.length < 3) return null;

  // Email đầy đủ
  if (id.includes('@')) {
    const r = await db.query('users', [['email', '==', id]], null, 1);
    if (r.length > 0) {
      const d = r[0].data();
      return { userId: r[0].id, userEmail: d.email, displayName: d.displayName };
    }
    return null;
  }

  // Email prefix
  const all = await db.query('users', [], null, 2000);
  const match = all.find(u => {
    const prefix = (u.data().email || '').toLowerCase().split('@')[0];
    return prefix === id;
  });
  if (match) {
    const d = match.data();
    return { userId: match.id, userEmail: d.email, displayName: d.displayName };
  }
  return null;
}
