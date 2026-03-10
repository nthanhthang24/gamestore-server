// routes/sepay.js
const express = require('express');

module.exports = (db) => {
  const router = express.Router();

  const BANK = {
    bin:  process.env.BANK_BIN            || '970418',
    acc:  process.env.BANK_ACCOUNT_NUMBER || '1290702118',
    name: process.env.BANK_ACCOUNT_NAME   || 'NGUYEN NAM SON',
  };

  // POST /bank/webhook
  router.post('/webhook', async (req, res) => {
    try {
      console.log('SePay webhook:', JSON.stringify(req.body));

      const apiKey = process.env.SEPAY_API_KEY;
      if (apiKey) {
        const received = (req.headers['authorization'] || '').replace('Apikey ', '').trim();
        if (received !== apiKey) return res.status(401).json({ error: 'Unauthorized' });
      }

      const { id: sePayId, gateway, transactionDate, content,
        transferType, transferAmount, referenceCode, error: sePayError } = req.body;

      if (transferType !== 'in' || sePayError !== 0)
        return res.status(200).json({ message: 'Skipped' });
      if (!transferAmount || transferAmount <= 0)
        return res.status(200).json({ message: 'Invalid amount' });

      // Chống duplicate
      const existing = await db.query('transactions', [['sePayId', '==', String(sePayId)]], null, 1);
      if (existing.length > 0) return res.status(200).json({ message: 'Already processed' });

      // Tìm user
      const user = await findUser(db, content, transferAmount);
      if (!user) {
        await db.add('unmatchedTopups', {
          sePayId: String(sePayId), gateway, content,
          amount: transferAmount, transactionDate, referenceCode,
          status: 'unmatched', createdAt: db.FieldValue.serverTimestamp(),
        });
        console.log('Unmatched:', content, transferAmount);
        return res.status(200).json({ message: 'Unmatched' });
      }

      // Đọc balance
      const userDoc = await db.get('users', user.userId);
      if (!userDoc.exists) return res.status(404).json({ error: 'User not found' });
      const prev = userDoc.data().balance || 0;
      const next = prev + transferAmount;

      // Ghi tất cả
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

  // GET /bank/vietqr
  router.get('/vietqr', async (req, res) => {
    const { amount, userId, userEmail } = req.query;
    if (!amount || !userId) return res.status(400).json({ error: 'Missing params' });

    const content = `NAP ${(userEmail?.split('@')[0] || userId.slice(0, 8)).toUpperCase()}`;
    const qrUrl = `https://img.vietqr.io/image/${BANK.bin}-${BANK.acc}-compact2.png`
      + `?amount=${amount}&addInfo=${encodeURIComponent(content)}&accountName=${encodeURIComponent(BANK.name)}`;

    const ref = await db.add('topups', {
      userId, userEmail, amount: Number(amount),
      method: 'bank_transfer', transferContent: content,
      status: 'pending', createdAt: db.FieldValue.serverTimestamp(),
    });

    return res.json({
      qrUrl, transferContent: content,
      bankBin: BANK.bin, accountNumber: BANK.acc, accountName: BANK.name,
      amount: Number(amount), topupId: ref.id,
    });
  });

  return router;
};

async function findUser(db, content, amount) {
  if (!content) return null;

  const napMatch = content.match(/NAP\s+([^\s]+)/i);
  if (napMatch) {
    const id = napMatch[1].toLowerCase();

    if (id.includes('@')) {
      const r = await db.query('users', [['email', '==', id]], null, 1);
      if (r.length > 0) { const d = r[0].data(); return { userId: r[0].id, userEmail: d.email, displayName: d.displayName }; }
    }

    const all = await db.query('users', [], null, 100);
    const match = all.find(u => (u.data().email || '').toLowerCase().startsWith(id));
    if (match) { const d = match.data(); return { userId: match.id, userEmail: d.email, displayName: d.displayName }; }
  }

  const pending = await db.query('topups',
    [['method', '==', 'bank_transfer'], ['status', '==', 'pending'], ['amount', '==', amount]],
    'createdAt', 1);
  if (pending.length > 0) {
    const td = pending[0].data();
    const hrs = (Date.now() - (td.createdAt instanceof Date ? td.createdAt.getTime() : 0)) / 3600000;
    if (hrs <= 24) return { userId: td.userId, userEmail: td.userEmail, displayName: td.userName };
  }

  return null;
}
