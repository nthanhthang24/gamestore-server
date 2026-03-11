# 🚀 Deploy lên Render.com - KHÔNG cần Service Account

## Cách hoạt động mới
Dùng Firestore REST API với Firebase API Key thay vì Service Account.
API Key này là public key, an toàn để dùng phía server.

---

## Bước 1: Upload code lên GitHub

1. Vào https://github.com → Đăng nhập
2. Bấm "New repository" → tên: gamestore-server → Create
3. Kéo thả toàn bộ file trong thư mục gamestore-server/ vào trang GitHub

---

## Bước 2: Deploy lên Render

1. Vào https://render.com → Sign up bằng GitHub (miễn phí, không cần thẻ)
2. Bấm "New +" → "Web Service"
3. Chọn repo gamestore-server
4. Điền:
   - Name: gamestore-server
   - Runtime: Node
   - Build Command: npm install
   - Start Command: node index.js
   - Instance Type: Free ✅
5. Bấm "Advanced" → "Add Environment Variable":

| Key                   | Value                                                              |
|-----------------------|--------------------------------------------------------------------|
| FIREBASE_PROJECT_ID   | gamestore-93186                                                    |
| FIREBASE_API_KEY      | AIzaSyC1efvwK3jBRT1rIK30dc6bMXrs7PYiI1E                          |
| SERVER_URL            | để trống trước                                                     |
| FRONTEND_URL          | https://gamestore-xxx.vercel.app (điền sau khi có URL Vercel)     |
| SEPAY_API_KEY         | KGFM0Y3KLBP06BWWNJADDQZILTAMZ7EKTMJ9QHXNRD2UYXUOSEFWJVFHZ5XRGQA8 |
| BANK_BIN              | 970418                                                             |
| BANK_ACCOUNT_NUMBER   | 1290702118                                                         |
| BANK_ACCOUNT_NAME     | NGUYEN NAM SON                                                     |
| SEPAY_BANK_ACCOUNT_ID | _(xem hướng dẫn bên dưới)_                                        |
| SKIP_IP_CHECK         | false                                                              |

6. Bấm "Create Web Service" → chờ 3 phút

---

## Bước 3: Lấy URL server

Render cấp URL dạng: https://gamestore-server-xxxx.onrender.com
→ Vào Environment → Sửa SERVER_URL thành URL đó → Save

---

## Bước 3b: Lấy SEPAY_BANK_ACCOUNT_ID (quan trọng cho VA QR)

Đây là ID tài khoản BIDV trong hệ thống SePay — không phải số tài khoản ngân hàng.

**Cách lấy (2 cách):**

**Cách 1 - Qua giao diện SePay:**
1. Vào https://my.sepay.vn → đăng nhập
2. Menu trái → Ngân hàng → chọn tài khoản BIDV
3. URL trên trình duyệt sẽ có dạng: 
4. Số  chính là SEPAY_BANK_ACCOUNT_ID

**Cách 2 - Qua API:**
Gọi: 
Header: 
Response trả về list tài khoản, lấy trường uid=0(root) gid=0(root) groups=0(root) của tài khoản BIDV.

**Nếu không điền SEPAY_BANK_ACCOUNT_ID:**
→ App vẫn chạy được nhưng dùng QR tĩnh
→ SePay **không tự động** match giao dịch → phải nhập đúng nội dung CK mới cộng tiền

---

## Bước 4: Cấu hình SePay Webhook

Vào sepay.vn → Tích hợp → Webhook → Thêm mới:
  URL: https://gamestore-server-xxxx.onrender.com/bank/webhook
  Method: POST → Bật Active ✅

---

## Bước 5: Deploy Frontend lên Vercel

Trong thư mục gamestore/ chạy:
  npm install
  npm run build

Vào vercel.com → kéo thả thư mục build/ → Deploy
→ Có URL: https://gamestore-xxx.vercel.app

Sau đó quay lại Render → cập nhật FRONTEND_URL thành URL Vercel vừa lấy

---

## Kiểm tra

Mở trình duyệt: https://gamestore-server-xxxx.onrender.com
Phải thấy: {"status": "GameStore VN Server ✅"}

---

## ⚠️ Lưu ý Free tier Render

Server sleep sau 15 phút không có request.
Để tránh: Dùng https://uptimerobot.com ping mỗi 10 phút (miễn phí).
