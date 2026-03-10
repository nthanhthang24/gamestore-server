// routes/sepay.js
const express = require('express');

// IP hợp lệ của SePay (cập nhật từ docs.sepay.vn)
const SEPAY_IPS = [
  '103.255.238.108',
  '103.255.238.109', 
  '103.255.238.110',
  '116.103.227.99',
  '42.118.118.53',
  '127.0.0.1',   // localhost để test
  '::1',         // localhost IPv6
];

module.exports = (db) => {
  const router = express.Router();

  const BANK = {
    bin:  process.env.BANK_BIN            || '970418',
    acc:  process.env.BANK_ACCOUNT_NUMBER || '1290702118',
    name: process.env.BANK_ACCOUNT_NAME   || 'NGUYEN NAM SON',
  };

  // ── Middleware bảo mật webhook ─────────────────
  function verifyWebhook(req, res, next) {
    // Lớp 1: Kiểm tra API Key
    const apiKey = process.env.SEPAY_API_KEY;
    if (apiKey) {
      const received = (req.headers['authorization'] || '').replace('Apikey ', '').trim();
      if (received !== apiKey) {
        console.warn(`⛔ Webhook từ chối: API Key sai | IP: ${getIP(req)}`);
        return res.status(401).json({ error: 'Unauthorized' });
      }
    }

    // Lớp 2: Whitelist IP SePay (bỏ qua nếu SKIP_IP_CHECK=true để test)
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
    // ✅ FIX: Dùng req.ip (đã processed bởi trust proxy=1) thay vì đọc raw header
    // trust proxy=1 → Express lấy đúng IP từ x-forwarded-for, không bị spoof
    return req.ip || req.socket?.remoteAddress || '';
  }

  // ── POST /bank/webhook ─────────────────────────
  router.post('/webhook', verifyWebhook, async (req, res) => {
    try {
      console.log('✅ SePay webhook hợp lệ:', JSON.stringify(req.body));

      const {
        id: sePayId, gateway, transactionDate, content,
        transferType, transferAmount, referenceCode, error: sePayError,
      } = req.body;

      if (transferType !== 'in' || sePayError !== 0)
        return res.status(200).json({ message: 'Skipped' });
      if (!transferAmount || transferAmount <= 0)
        return res.status(200).json({ message: 'Invalid amount' });
      // ✅ FIX: Giới hạn amount tối đa 50 triệu/giao dịch (chống abuse)
      const MAX_TOPUP = 50_000_000;
      if (transferAmount > MAX_TOPUP) {
        console.warn(`⚠️ Amount vượt giới hạn: ${transferAmount}`);
        await db.add('unmatchedTopups', {
          sePayId: String(sePayId), gateway, content,
          amount: transferAmount, transactionDate, referenceCode,
          status: 'overlimit', createdAt: db.FieldValue.serverTimestamp(),
        });
        return res.status(200).json({ message: 'Amount over limit, manual review required' });
      }

      // Chống duplicate
      const existing = await db.query('transactions', [['sePayId', '==', String(sePayId)]], null, 1);
      if (existing.length > 0) {
        // ✅ FIX BUG 20: log duplicate để debug
        console.log('⚠️ Duplicate sePayId:', sePayId, '- đã xử lý trước đó');
        return res.status(200).json({ message: 'Already processed' });
      }

      // Tìm user
      const user = await findUser(db, content, transferAmount);
      if (!user) {
        await db.add('unmatchedTopups', {
          sePayId: String(sePayId), gateway, content,
          amount: transferAmount, transactionDate, referenceCode,
          status: 'unmatched', createdAt: db.FieldValue.serverTimestamp(),
        });
        console.log('⚠️ Unmatched:', content, transferAmount);
        return res.status(200).json({ message: 'Unmatched' });
      }

      // Cộng balance
      const userDoc = await db.get('users', user.userId);
      if (!userDoc.exists) return res.status(404).json({ error: 'User not found' });
      const prev = userDoc.data().balance || 0;
      const next = prev + transferAmount;

      await Promise.all([
        db.update('users', user.userId, { balance: next, updatedAt: db.FieldValue.serverTimestamp() }),
        db.add('topups', {
          userId: user.userId, userEmail: user.userEmail,
          userName: user.displayName || user.userEmail,
          amount: transferAmount, method: 'bank_transfer', gateway,
          content, referenceCode, sePayId: String(sePayId),
          transactionDate, status: 'approved', autoApproved: true,
          approvedAt: db.FieldValue.serverTimestamp(),
          createdAt: db.FieldValue.serverTimestamp(),
        }),
        db.add('transactions', {
          userId: user.userId, userEmail: user.userEmail,
          type: 'topup', method: 'bank_transfer', gateway,
          amount: transferAmount, balanceBefore: prev, balanceAfter: next,
          sePayId: String(sePayId), referenceCode, content,
          createdAt: db.FieldValue.serverTimestamp(),
        }),
      ]);

      console.log(`✅ +${transferAmount} cho ${user.userEmail} | ${prev} → ${next}`);
      return res.status(200).json({ message: 'success' });

    } catch (err) {
      console.error('SePay error:', err.message);
      return res.status(500).json({ error: 'Internal server error' });
    }
  });

  // ── GET /bank/vietqr ───────────────────────────
  router.get('/vietqr', async (req, res) => {
    const { amount, userId, userEmail } = req.query;
    if (!amount || !userId || !userEmail) return res.status(400).json({ error: 'Missing params' });

    // ✅ FIX: Validate amount range
    const amt = Number(amount);
    if (isNaN(amt) || amt < 10000 || amt > 50_000_000) {
      return res.status(400).json({ error: 'Amount must be between 10,000 and 50,000,000' });
    }

    // ✅ FIX: Validate user exists in Firestore (chống spam tạo topup với userId giả)
    const userDoc = await db.get('users', userId);
    if (!userDoc.exists) return res.status(404).json({ error: 'User not found' });

    // ✅ FIX: Verify userEmail matches the user document
    if (userDoc.data().email !== userEmail) {
      return res.status(403).json({ error: 'User email mismatch' });
    }

    const content = `NAP ${(userEmail.split('@')[0] || userId.slice(0, 8)).toUpperCase()}`;
    const qrUrl = `https://qr.sepay.vn/img?acc=${BANK.acc}&bank=BIDV&amount=${amt}&des=${encodeURIComponent(content)}&template=compact2`;

    const ref = await db.add('topups', {
      userId, userEmail, amount: amt,
      method: 'bank_transfer', transferContent: content,
      status: 'pending', createdAt: db.FieldValue.serverTimestamp(),
    });

    return res.json({
      qrUrl, transferContent: content,
      bankBin: BANK.bin, accountNumber: BANK.acc, accountName: BANK.name,
      amount: amt, topupId: ref.id,
    });
  });

  return router;
};

// ── Tìm user từ nội dung CK ────────────────────
// ✅ FIX: Xóa fallback by-amount — ngăn attacker nhận tiền người khác
// Nội dung CK bắt buộc phải chứa "NAP <email_prefix>" đúng format
async function findUser(db, content, amount) {
  if (!content) return null;

  const napMatch = content.match(/NAP\s+([^\s]+)/i);
  if (!napMatch) {
    console.log('⚠️ Nội dung CK không có từ khóa NAP:', content);
    return null; // Không match → unmatchedTopups, admin xử lý thủ công
  }

  const id = napMatch[1].toLowerCase().trim();

  // Nếu là email đầy đủ
  if (id.includes('@')) {
    const r = await db.query('users', [['email', '==', id]], null, 1);
    if (r.length > 0) {
      const d = r[0].data();
      return { userId: r[0].id, userEmail: d.email, displayName: d.displayName };
    }
    console.log('⚠️ Không tìm thấy email:', id);
    return null;
  }

  // Tìm theo email prefix (tối đa 200 users để tránh scan cả DB)
  // ✅ SAFER: prefix phải >= 3 ký tự để tránh false match
  if (id.length < 3) {
    console.log('⚠️ Email prefix quá ngắn, từ chối:', id);
    return null;
  }
  // ✅ FIX: Tăng limit lên 2000, warn nếu sắp đầy
  const all = await db.query('users', [], null, 2000);
  if (all.length >= 1990) {
    console.warn('⚠️ User count approaching scan limit (2000). Consider indexing email field.');
  }
  const match = all.find(u => {
    const email = (u.data().email || '').toLowerCase();
    const prefix = email.split('@')[0];
    return prefix === id; // ✅ Exact prefix match (không dùng startsWith)
  });
  if (match) {
    const d = match.data();
    return { userId: match.id, userEmail: d.email, displayName: d.displayName };
  }

  console.log('⚠️ Không tìm thấy user với prefix:', id);
  return null;
  // ✅ KHÔNG có fallback by-amount — tránh nhận nhầm tiền
}
