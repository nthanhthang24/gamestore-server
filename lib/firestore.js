// lib/firestore.js
// Firestore wrapper — dùng Firebase Auth REST API + Firestore REST API
//
// KHÔNG dùng Admin SDK (không có service account key).
// Thay vào đó: server login bằng một Firebase user đặc biệt có role='admin'
// (FIREBASE_SERVER_EMAIL + FIREBASE_SERVER_PASSWORD trong env vars)
// → lấy idToken → dùng để call Firestore REST API
// → Firestore rules thấy isAdmin() = true → cho phép mọi write nhạy cảm
//
// Token được cache và tự refresh khi hết hạn (mỗi 55 phút).

const fetch = (...args) => import('node-fetch').then(({ default: f }) => f(...args));

const PROJECT_ID  = process.env.FIREBASE_PROJECT_ID || 'gamestore-93186';
const API_KEY     = process.env.FIREBASE_API_KEY;
const SERVER_EMAIL    = process.env.FIREBASE_SERVER_EMAIL;
const SERVER_PASSWORD = process.env.FIREBASE_SERVER_PASSWORD;

const FIRESTORE_BASE = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents`;
const AUTH_URL = `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${API_KEY}`;

// ── Token cache ────────────────────────────────────────────────────────────
let cachedToken     = null;
let tokenExpiresAt  = 0;
let refreshToken    = null;

async function getIdToken() {
  const now = Date.now();

  // Token còn hạn (buffer 2 phút)
  if (cachedToken && now < tokenExpiresAt - 120_000) {
    return cachedToken;
  }

  // Thử refresh trước
  if (refreshToken) {
    try {
      const res = await (await fetch(`https://securetoken.googleapis.com/v1/token?key=${API_KEY}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ grant_type: 'refresh_token', refresh_token: refreshToken }),
      })).json();
      if (res.id_token) {
        cachedToken    = res.id_token;
        refreshToken   = res.refresh_token;
        tokenExpiresAt = now + (parseInt(res.expires_in) || 3600) * 1000;
        return cachedToken;
      }
    } catch (_) { /* fall through to re-login */ }
  }

  // Login lại
  if (!SERVER_EMAIL || !SERVER_PASSWORD) {
    throw new Error('FIREBASE_SERVER_EMAIL hoặc FIREBASE_SERVER_PASSWORD chưa được cấu hình!');
  }

  const res = await (await fetch(AUTH_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: SERVER_EMAIL, password: SERVER_PASSWORD, returnSecureToken: true }),
  })).json();

  if (!res.idToken) {
    throw new Error(`Firebase login thất bại: ${res.error?.message || JSON.stringify(res)}`);
  }

  cachedToken    = res.idToken;
  refreshToken   = res.refreshToken;
  tokenExpiresAt = now + (parseInt(res.expiresIn) || 3600) * 1000;
  // Log UID để admin biết cần tạo /users/{uid} với role='server'
  try {
    const payload = JSON.parse(Buffer.from(res.idToken.split('.')[1], 'base64').toString());
    console.log(`🔑 Firebase server token refreshed — UID: ${payload.user_id || payload.sub}`);
  } catch(_) {
    console.log('🔑 Firebase server token refreshed');
  }
  return cachedToken;
}

// ── Firestore REST helpers ─────────────────────────────────────────────────

// Convert JS value → Firestore REST value
function toFirestoreValue(val) {
  if (val === null || val === undefined) return { nullValue: null };
  if (typeof val === 'boolean')  return { booleanValue: val };
  if (typeof val === 'number') {
    if (Number.isInteger(val))   return { integerValue: String(val) };
    return { doubleValue: val };
  }
  if (typeof val === 'string')   return { stringValue: val };
  if (val instanceof Date)       return { timestampValue: val.toISOString() };
  if (val && val._type === 'serverTimestamp') return { timestampValue: new Date().toISOString() };
  if (val && val._type === 'increment') {
    // increment() is applied via fieldTransforms, handled separately
    return { __transform: { increment: val._value } };
  }
  if (Array.isArray(val)) {
    return { arrayValue: { values: val.map(toFirestoreValue) } };
  }
  if (typeof val === 'object') {
    const fields = {};
    for (const [k, v] of Object.entries(val)) {
      fields[k] = toFirestoreValue(v);
    }
    return { mapValue: { fields } };
  }
  return { stringValue: String(val) };
}

// Convert Firestore REST value → JS value
function fromFirestoreValue(val) {
  if (!val) return null;
  if ('nullValue'     in val) return null;
  if ('booleanValue'  in val) return val.booleanValue;
  if ('integerValue'  in val) return Number(val.integerValue);
  if ('doubleValue'   in val) return val.doubleValue;
  if ('stringValue'   in val) return val.stringValue;
  if ('timestampValue'in val) return new Date(val.timestampValue);
  if ('arrayValue'    in val) return (val.arrayValue.values || []).map(fromFirestoreValue);
  if ('mapValue'      in val) {
    const obj = {};
    for (const [k, v] of Object.entries(val.mapValue.fields || {})) {
      obj[k] = fromFirestoreValue(v);
    }
    return obj;
  }
  return null;
}

function fromFirestoreDoc(doc) {
  if (!doc || !doc.fields) return null;
  const result = {};
  for (const [k, v] of Object.entries(doc.fields)) {
    result[k] = fromFirestoreValue(v);
  }
  return result;
}

// Build Firestore fields object from JS object (skip transforms)
function toFields(data) {
  const fields = {};
  for (const [k, v] of Object.entries(data)) {
    const fv = toFirestoreValue(v);
    if (!fv.__transform) fields[k] = fv;
  }
  return fields;
}

// Extract FieldTransforms (increment, serverTimestamp) for PATCH requests
function toFieldTransforms(docPath, data) {
  const transforms = [];
  for (const [k, v] of Object.entries(data)) {
    if (v && v._type === 'serverTimestamp') {
      transforms.push({ fieldPath: k, setToServerValue: 'REQUEST_TIME' });
    } else if (v && v._type === 'increment') {
      transforms.push({ fieldPath: k, increment: toFirestoreValue(v._value) });
    } else if (v && v._type === 'arrayUnion') {
      transforms.push({ fieldPath: k, appendMissingElements: { values: v._items.map(toFirestoreValue) } });
    } else if (v && v._type === 'arrayRemove') {
      transforms.push({ fieldPath: k, removeAllFromArray: { values: v._items.map(toFirestoreValue) } });
    }
  }
  return transforms;
}

// Encode document path for REST URL
function docPath(collection, docId) {
  // Support subcollection paths like 'accounts/ID/credentials'
  return `${FIRESTORE_BASE}/${collection}/${docId}`;
}

async function firestoreRequest(method, url, body = null) {
  const token = await getIdToken();
  const opts = {
    method,
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
  };
  if (body) opts.body = JSON.stringify(body);
  const res = await (await fetch(url, opts));
  const json = await res.json();
  if (!res.ok) {
    const msg = json.error?.message || JSON.stringify(json);
    const err = new Error(`Firestore ${method} ${url}: ${msg}`);
    err.status = res.status;
    if (res.status === 409) err.response = { status: 409 };
    throw err;
  }
  return json;
}

// ── FieldValue markers (match Admin SDK API) ───────────────────────────────
const FieldValue = {
  serverTimestamp: () => ({ _type: 'serverTimestamp' }),
  increment:  (n)      => ({ _type: 'increment', _value: n }),
  arrayUnion: (...items) => ({ _type: 'arrayUnion', _items: items }),
  arrayRemove:(...items) => ({ _type: 'arrayRemove', _items: items }),
  delete:     ()       => ({ _type: 'delete' }),
};

// ── DB wrapper ────────────────────────────────────────────────────────────
const db = {
  FieldValue,

  async get(collection, docId) {
    try {
      const url  = docPath(collection, docId);
      const json = await firestoreRequest('GET', url);
      return {
        exists: true,
        id: docId,
        data: () => fromFirestoreDoc(json),
      };
    } catch (err) {
      if (err.status === 404) return { exists: false, id: docId, data: () => null };
      throw err;
    }
  },

  async set(collection, docId, data) {
    const fields = toFields(data);
    const transforms = toFieldTransforms(`${collection}/${docId}`, data);
    if (transforms.length > 0) {
      // Use write with document transform
      const url = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents:commit`;
      const writes = [];
      if (Object.keys(fields).length > 0) {
        writes.push({ update: { name: `projects/${PROJECT_ID}/databases/(default)/documents/${collection}/${docId}`, fields } });
      }
      writes.push({ transform: { document: `projects/${PROJECT_ID}/databases/(default)/documents/${collection}/${docId}`, fieldTransforms: transforms } });
      await firestoreRequest('POST', url, { writes });
    } else {
      // FIX C2: Upsert (no precondition) — PATCH without currentDocument constraint
      await firestoreRequest('PATCH', docPath(collection, docId), { fields });
    }
    return docId;
  },

  async add(collection, data) {
    const fields = toFields(data);
    const transforms = toFieldTransforms(`${collection}/_new_`, data);

    if (transforms.length === 0) {
      // Simple case: no transforms, just POST to collection
      const json = await firestoreRequest('POST', `${FIRESTORE_BASE}/${collection}`, { fields });
      return { id: json.name.split('/').pop() };
    }

    // FIX C3: If transforms present, use commit with a new auto-ID document
    // Generate a random doc ID to keep atomicity
    const autoId = Array.from({length: 20}, () => 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'[Math.floor(Math.random()*62)]).join('');
    const docName = `projects/${PROJECT_ID}/databases/(default)/documents/${collection}/${autoId}`;
    const commitUrl = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents:commit`;
    const writes = [
      { update: { name: docName, fields }, currentDocument: { exists: false } },
      { transform: { document: docName, fieldTransforms: transforms } },
    ];
    await firestoreRequest('POST', commitUrl, { writes });
    return { id: autoId };
  },

  async update(collection, docId, data) {
    const fields = toFields(data);
    const transforms = toFieldTransforms(`${collection}/${docId}`, data);

    const commitUrl = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents:commit`;
    const writes = [];

    if (Object.keys(fields).length > 0) {
      const updateMask = { fieldPaths: Object.keys(fields) };
      writes.push({
        update: {
          name: `projects/${PROJECT_ID}/databases/(default)/documents/${collection}/${docId}`,
          fields,
        },
        updateMask,
        currentDocument: { exists: true },
      });
    }

    if (transforms.length > 0) {
      writes.push({
        transform: {
          document: `projects/${PROJECT_ID}/databases/(default)/documents/${collection}/${docId}`,
          fieldTransforms: transforms,
        }
      });
    }

    if (writes.length > 0) {
      await firestoreRequest('POST', commitUrl, { writes });
    }
  },

  async query(collection, filters = [], orderByField = null, limitN = 10) {
    const url = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents:runQuery`;
    const token = await getIdToken();

    const structuredQuery = {
      from: [{ collectionId: collection.split('/').pop() }],
    };

    // Handle subcollection — use collectionGroup or parent path
    const parts = collection.split('/');
    let parent = `projects/${PROJECT_ID}/databases/(default)/documents`;
    if (parts.length > 1) {
      parent += '/' + parts.slice(0, -1).join('/');
    }

    if (filters.length > 0) {
      structuredQuery.where = filters.length === 1
        ? buildFilter(filters[0])
        : { compositeFilter: { op: 'AND', filters: filters.map(buildFilter) } };
    }
    if (orderByField) {
      structuredQuery.orderBy = [{ field: { fieldPath: orderByField }, direction: 'DESCENDING' }];
    }
    if (limitN) structuredQuery.limit = limitN;

    const queryUrl = `https://firestore.googleapis.com/v1/${parent}:runQuery`;
    const res = await fetch(queryUrl, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ structuredQuery }),
    });
    const results = await res.json();

    if (!res.ok) throw new Error(`Query failed: ${JSON.stringify(results)}`);

    return (Array.isArray(results) ? results : [results])
      .filter(r => r.document)
      .map(r => ({
        id: r.document.name.split('/').pop(),
        data: () => fromFirestoreDoc(r.document),
      }));
  },

  async createIfNotExists(collection, docId, data) {
    const fields = toFields(data);
    const transforms = toFieldTransforms(`${collection}/${docId}`, data);
    const commitUrl = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents:commit`;
    const writes = [{
      update: {
        name: `projects/${PROJECT_ID}/databases/(default)/documents/${collection}/${docId}`,
        fields,
      },
      currentDocument: { exists: false }, // Precondition: must not exist
    }];
    if (transforms.length > 0) {
      writes.push({ transform: {
        document: `projects/${PROJECT_ID}/databases/(default)/documents/${collection}/${docId}`,
        fieldTransforms: transforms,
      }});
    }
    try {
      await firestoreRequest('POST', commitUrl, { writes });
    } catch (err) {
      if (err.status === 400 || (err.message || '').includes('FAILED_PRECONDITION') || (err.message || '').includes('already exists')) {
        const e = new Error('ALREADY_EXISTS');
        e.response = { status: 409 };
        throw e;
      }
      throw err;
    }
  },

  async batch(operations) {
    const commitUrl = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents:commit`;
    const writes = [];
    for (const { type, collection: col, docId, data } of operations) {
      const name = `projects/${PROJECT_ID}/databases/(default)/documents/${col}/${docId || '_auto_'}`;
      const fields = toFields(data || {});
      if (type === 'set' || type === 'add') writes.push({ update: { name, fields } });
      if (type === 'update') writes.push({ update: { name, fields }, updateMask: { fieldPaths: Object.keys(fields) } });
      if (type === 'delete') writes.push({ delete: name });
    }
    if (writes.length > 0) await firestoreRequest('POST', commitUrl, { writes });
  },

  // Run a transaction using Firestore REST API
  // Simplified: begin → read → commit (no retry for now)
  async runTransaction(callback) {
    const token = await getIdToken();
    const baseUrl = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents`;

    // Begin transaction
    const beginRes = await firestoreRequest('POST',
      `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents:beginTransaction`,
      { options: { readWrite: {} } }
    );
    const txId = beginRes.transaction;

    const reads = [];
    const writes = [];

    // Transaction proxy object
    const tx = {
      async get(docName) {
        const url = `https://firestore.googleapis.com/v1/${docName}?transaction=${txId}`;
        const res = await fetch(url, {
          headers: { Authorization: `Bearer ${token}` }
        });
        const json = await res.json();
        if (res.status === 404) return { exists: false, data: () => null };
        if (!res.ok) throw new Error(`tx.get failed: ${JSON.stringify(json)}`);
        return { exists: true, data: () => fromFirestoreDoc(json) };
      },
      update(ref, data) {
        const docName = ref._path || ref.path;
        const fields = toFields(data);
        // FIX: pass docName (not ref.path) so transforms get correct document path
        // ref from getFirestore().collection().doc() has _path but NOT path
        const transforms = toFieldTransforms(docName, data);
        if (Object.keys(fields).length > 0) {
          writes.push({
            update: { name: docName, fields },
            updateMask: { fieldPaths: Object.keys(fields) },
            currentDocument: { exists: true },
          });
        }
        if (transforms.length > 0) {
          writes.push({ transform: { document: docName, fieldTransforms: transforms } });
        }
      },
    };

    // Helper to make doc refs
    const makeRef = (collection, docId) => ({
      _path: `projects/${PROJECT_ID}/databases/(default)/documents/${collection}/${docId}`,
      path: `projects/${PROJECT_ID}/databases/(default)/documents/${collection}/${docId}`,
      collection: () => ({ doc: (id) => makeRef(`${collection}/${docId}`, id) }),
    });

    // Build a firestore-like object for the callback
    const fsProxy = {
      collection: (col) => ({
        doc: (docId) => {
          const ref = makeRef(col, docId);
          ref._col = col;
          ref._docId = docId;
          return ref;
        },
      }),
      runTransaction: async (cb) => {
        // Nested transaction — just run inline
        return cb(tx);
      },
    };

    // Wrap tx.get to use full path format
    const txWrapped = {
      get: async (ref) => {
        const url = `https://firestore.googleapis.com/v1/${ref._path}?transaction=${encodeURIComponent(txId)}`;
        const res = await fetch(url, {
          headers: { Authorization: `Bearer ${token}` }
        });
        const json = await res.json();
        if (res.status === 404) return { exists: false, data: () => null };
        if (!res.ok) throw new Error(`tx.get failed: ${JSON.stringify(json)}`);
        return { exists: true, data: () => fromFirestoreDoc(json) };
      },
      update: tx.update,
    };

    try {
      await callback(txWrapped);
    } catch (err) {
      // Rollback — just abandon (Firestore auto-expires stale transactions)
      throw err;
    }

    // Commit
    await firestoreRequest('POST',
      `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents:commit`,
      { transaction: txId, writes }
    );
  },

  // FIX M4: runTransactionWithRetry — wraps runTransaction with up to 3 retries on ABORTED
  async runTransactionWithRetry(callback, maxRetries = 3) {
    let lastErr;
    for (let attempt = 0; attempt < maxRetries; attempt++) {
      try {
        return await this.runTransaction(callback);
      } catch (err) {
        lastErr = err;
        const msg = (err.message || '').toUpperCase();
        const isContention = msg.includes('ABORTED') || msg.includes('CONTENTION') ||
                             msg.includes('CONFLICT') || err.status === 409;
        if (!isContention) throw err; // Non-retriable error
        const delay = 100 * Math.pow(2, attempt) + Math.random() * 100;
        console.warn(`⚠️ Transaction contention (attempt ${attempt + 1}/${maxRetries}), retrying in ${Math.round(delay)}ms`);
        await new Promise(r => setTimeout(r, delay));
      }
    }
    throw lastErr;
  },

  // Return a proxy that mimics Firestore instance for transaction usage
  getFirestore() {
    const self = this;
    return {
      collection: (col) => ({
        doc: (docId) => ({
          _path: `projects/${PROJECT_ID}/databases/(default)/documents/${col}/${docId}`,
          _col: col,
          _docId: docId,
        }),
      }),
      runTransaction: (callback) => self.runTransaction(callback),
    };
  },

  // Admin kept for verifyIdToken only — still needs firebase-admin for token verification
  get admin() {
    try { return require('firebase-admin'); } catch { return null; }
  },
};

function buildFilter([field, op, value]) {
  const opMap = { '==': 'EQUAL', '!=': 'NOT_EQUAL', '<': 'LESS_THAN', '<=': 'LESS_THAN_OR_EQUAL', '>': 'GREATER_THAN', '>=': 'GREATER_THAN_OR_EQUAL', 'array-contains': 'ARRAY_CONTAINS' };
  return {
    fieldFilter: {
      field: { fieldPath: field },
      op: opMap[op] || 'EQUAL',
      value: toFirestoreValue(value),
    }
  };
}

module.exports = db;
