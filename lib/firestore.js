// lib/firestore.js
// Dùng Firebase Admin SDK với Service Account — bypass Firestore rules hoàn toàn.
// Không cần bot user, không cần login, không phụ thuộc rules.
//
// Render.com env var: FIREBASE_SERVICE_ACCOUNT = nội dung file serviceAccountKey.json (JSON string)

const admin = require('firebase-admin');

if (!admin.apps.length) {
  const raw = process.env.FIREBASE_SERVICE_ACCOUNT;
  if (!raw) throw new Error('FIREBASE_SERVICE_ACCOUNT env var chưa được set!');
  const serviceAccount = JSON.parse(raw);
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  });
}

const firestore = admin.firestore();
const { FieldValue: AdminFieldValue } = admin.firestore;

// ── FieldValue markers — giữ API giống cũ ──────────────────────────────────
const FieldValue = {
  serverTimestamp: () => AdminFieldValue.serverTimestamp(),
  increment:       (n)        => AdminFieldValue.increment(n),
  arrayUnion:      (...items) => AdminFieldValue.arrayUnion(...items),
  arrayRemove:     (...items) => AdminFieldValue.arrayRemove(...items),
  delete:          ()         => AdminFieldValue.delete(),
};

// ── DB wrapper — giữ API giống cũ ─────────────────────────────────────────
const db = {
  FieldValue,

  async get(collection, docId) {
    const snap = await firestore.collection(collection).doc(docId).get();
    return {
      exists: snap.exists,
      id: snap.id,
      data: () => snap.exists ? snap.data() : null,
    };
  },

  async set(collection, docId, data) {
    await firestore.collection(collection).doc(docId).set(data, { merge: true });
    return docId;
  },

  async add(collection, data) {
    const ref = await firestore.collection(collection).add(data);
    return { id: ref.id };
  },

  async update(collection, docId, data) {
    await firestore.collection(collection).doc(docId).update(data);
  },

  async query(collection, filters = [], orderByField = null, limitN = 10) {
    let q = firestore.collection(collection);
    for (const [field, op, value] of filters) {
      q = q.where(field, op, value);
    }
    if (orderByField) q = q.orderBy(orderByField, 'desc');
    if (limitN) q = q.limit(limitN);
    const snap = await q.get();
    return snap.docs.map(d => ({ id: d.id, data: () => d.data() }));
  },

  async createIfNotExists(collection, docId, data) {
    const ref = firestore.collection(collection).doc(docId);
    try {
      await ref.create(data);
    } catch (err) {
      if (err.code === 6 || (err.message || '').includes('already exists')) {
        const e = new Error('ALREADY_EXISTS');
        e.response = { status: 409 };
        throw e;
      }
      throw err;
    }
  },

  async batch(operations) {
    const batch = firestore.batch();
    for (const { type, collection: col, docId, data } of operations) {
      const ref = firestore.collection(col).doc(docId);
      if (type === 'set')    batch.set(ref, data, { merge: true });
      if (type === 'update') batch.update(ref, data);
      if (type === 'delete') batch.delete(ref);
    }
    await batch.commit();
  },

  async runTransaction(callback) {
    return firestore.runTransaction(async (tx) => {
      const txWrapped = {
        async get(ref) {
          // ref có thể là { _col, _docId } hoặc Firestore DocumentReference
          const docRef = ref._col
            ? firestore.collection(ref._col).doc(ref._docId)
            : ref;
          const snap = await tx.get(docRef);
          return { exists: snap.exists, data: () => snap.exists ? snap.data() : null };
        },
        update(ref, data) {
          const docRef = ref._col
            ? firestore.collection(ref._col).doc(ref._docId)
            : ref;
          tx.update(docRef, data);
        },
      };
      return callback(txWrapped);
    });
  },

  async runTransactionWithRetry(callback, maxRetries = 3) {
    // Admin SDK tự retry transaction — nhưng giữ wrapper cho tương thích
    return this.runTransaction(callback);
  },

  getFirestore() {
    return {
      collection: (col) => ({
        doc: (docId) => ({
          _col: col,
          _docId: docId,
          // Expose real ref cho code dùng trực tiếp
          _ref: firestore.collection(col).doc(docId),
        }),
      }),
      runTransaction: (cb) => this.runTransaction(cb),
    };
  },

  // verifyIdToken — dùng Admin SDK
  async verifyIdToken(token) {
    return admin.auth().verifyIdToken(token);
  },
};

module.exports = db;
