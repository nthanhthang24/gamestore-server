require('dotenv').config();
const express = require('express');
const cors = require('cors');

const app = express();
app.use(cors({ origin: '*' }));
app.use(express.json());

// Dùng Firestore REST API thay vì firebase-admin
// Không cần Service Account key!
const db = require('./lib/firestore');

app.use('/bank', require('./routes/sepay')(db));

app.get('/', (req, res) => {
  res.json({ status: 'GameStore VN Server ✅', time: new Date().toISOString() });
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`✅ Server chạy port ${PORT}`);
  console.log(`   SePay Webhook: POST /bank/webhook`);
  console.log(`   VietQR:        GET  /bank/vietqr`);
});
