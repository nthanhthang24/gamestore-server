// lib/firestore.js
// Firestore wrapper dùng Firebase Admin SDK
// Admin SDK bypass Firestore rules hoàn toàn — bảo mật bằng service account credentials.
//
// KHÔNG dùng API key thường để write sensitive data (balance, transactions, v.v.)
// vì API key là public và Firestore rules client-side có thể bị bypass.
//
// Init: dùng GOOGLE_APPLICATION_CREDENTIALS (file JSON) hoặc FIREBASE_SERVICE_ACCOUNT (JSON string)
// Nếu không có service account → fallback dùng API key (read-only / non-sensitive ops).

const admin = require('firebase-admin');

const PROJECT_ID = process.env.FIREBASE_PROJECT_ID || 'gamestore-93186';

// ── Init Admin SDK ─────────────────────────────────────────────────────────
let adminDb = null;

function initAdmin() {
  if (adminDb) return adminDb;

  try {
    if (admin.apps.length === 0) {
      let credential;

      // Option 1: FIREBASE_SERVICE_ACCOUNT env var (JSON string) — recommended for Render
      if (process.env.FIREBASE_SERVICE_ACCOUNT) {
        const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
        credential = admin.credential.cert(serviceAccount);
        console.log('🔑 Firebase Admin: using service account from env var');
      }
      // Option 2: GOOGLE_APPLICATION_CREDENTIALS (file path)
      else if (process.env.GOOGLE_APPLICATION_CREDENTIALS) {
        credential = admin.credential.applicationDefault();
        console.log('🔑 Firebase Admin: using application default credentials');
      }
      // Option 3: No credentials — Admin SDK sẽ không có quyền ghi Firestore rules-protected paths
      else {
        // Vẫn init để dùng được một số features, nhưng log warning rõ ràng
        console.warn('⚠️  FIREBASE_SERVICE_ACCOUNT chưa được cấu hình!');
        console.warn('⚠️  Server sẽ không thể credit balance hoặc ghi processedWebhooks.');
        console.warn('⚠️  Xem RENDER_DEPLOY.md để biết cách cấu hình service account.');
        // Init với projectId only — một số ops như verifyIdToken vẫn hoạt động
        admin.initializeApp({ projectId: PROJECT_ID });
        adminDb = admin.firestore();
        return adminDb;
      }

      admin.initializeApp({ credential, projectId: PROJECT_ID });
    }

    adminDb = admin.firestore();
    console.log(`✅ Firebase Admin SDK initialized (project: ${PROJECT_ID})`);
    return adminDb;
  } catch (err) {
    console.error('❌ Firebase Admin SDK init failed:', err.message);
    throw err;
  }
}

// ── FieldValue shortcuts ──────────────────────────────────────────────────
const FieldValue = {
  serverTimestamp: () => admin.firestore.FieldValue.serverTimestamp(),
  increment: (n) => admin.firestore.FieldValue.increment(n),
  arrayUnion: (...items) => admin.firestore.FieldValue.arrayUnion(...items),
  arrayRemove: (...items) => admin.firestore.FieldValue.arrayRemove(...items),
  delete: () => admin.firestore.FieldValue.delete(),
};

// ── DB wrapper ────────────────────────────────────────────────────────────
const db = {
  FieldValue,

  // GET single document
  // collection: có thể là path "col/docId/subcol" hoặc "col"
  async get(collection, docId) {
    const firestore = initAdmin();
    // Nếu collection chứa '/' → đây là subcollection path
    // Ví dụ: get('accounts/ACC_ID/credentials', 'slots')
    const snap = await firestore.collection(collection).doc(docId).get();
    return {
      exists: snap.exists,
      id: docId,
      data: () => snap.data() || null,
    };
  },

  // SET document (create/overwrite with merge)
  async set(collection, docId, data) {
    const firestore = initAdmin();
    if (docId) {
      await firestore.collection(collection).doc(docId).set(data, { merge: true });
      return docId;
    } else {
      const ref = await firestore.collection(collection).add(data);
      return ref.id;
    }
  },

  // ADD document (auto ID)
  async add(collection, data) {
    const firestore = initAdmin();
    const ref = await firestore.collection(collection).add(data);
    return { id: ref.id };
  },

  // UPDATE document (partial) — supports FieldValue transforms natively
  async update(collection, docId, data) {
    const firestore = initAdmin();
    await firestore.collection(collection).doc(docId).update(data);
  },

  // QUERY documents
  async query(collection, filters = [], orderByField = null, limitN = 10) {
    const firestore = initAdmin();
    let q = firestore.collection(collection);

    for (const [field, op, value] of filters) {
      q = q.where(field, op, value);
    }
    if (orderByField) q = q.orderBy(orderByField, 'desc');
    if (limitN) q = q.limit(limitN);

    const snap = await q.get();
    return snap.docs.map(d => ({
      id: d.id,
      data: () => d.data(),
    }));
  },

  // CREATE with precondition "document must not exist" — atomic duplicate guard
  // Throws error with code ALREADY_EXISTS if doc exists
  async createIfNotExists(collection, docId, data) {
    const firestore = initAdmin();
    const ref = firestore.collection(collection).doc(docId);
    try {
      await firestore.runTransaction(async (tx) => {
        const snap = await tx.get(ref);
        if (snap.exists) {
          const err = new Error('ALREADY_EXISTS');
          err.code = 'ALREADY_EXISTS';
          err.response = { status: 409 };
          throw err;
        }
        tx.set(ref, data);
      });
    } catch (err) {
      // Re-throw with consistent shape for caller
      if (err.code === 'ALREADY_EXISTS' || (err.message || '').includes('ALREADY_EXISTS')) {
        const e = new Error('ALREADY_EXISTS');
        e.response = { status: 409 };
        throw e;
      }
      throw err;
    }
  },

  // BATCH writes (atomic)
  async batch(operations) {
    const firestore = initAdmin();
    const batch = firestore.batch();
    for (const op of operations) {
      const { type, collection: col, docId, data } = op;
      const ref = docId
        ? firestore.collection(col).doc(docId)
        : firestore.collection(col).doc();
      if (type === 'set')    batch.set(ref, data, { merge: true });
      if (type === 'update') batch.update(ref, data);
      if (type === 'delete') batch.delete(ref);
      if (type === 'add')    batch.set(ref, data);
    }
    await batch.commit();
  },

  // Expose admin for verifyIdToken
  get admin() { return admin; },

  // Run Firestore transaction (Admin SDK)
  // callback receives a Transaction object from Admin SDK
  async runTransaction(callback) {
    const firestore = initAdmin();
    return firestore.runTransaction(callback);
  },

  // Get Firestore instance (for building refs in transactions)
  getFirestore() { return initAdmin(); },

};

module.exports = db;
