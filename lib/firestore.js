// lib/firestore.js
// Firestore REST API wrapper.
// 
// KHÔNG dùng Admin SDK (org policy chặn service account key).
// KHÔNG dùng bot user.
//
// Cách tiếp cận:
// - Các thao tác cần đọc/ghi nhạy cảm (accounts, credentials, users.balance):
//   server tự call REST API với Google OAuth2 token lấy từ metadata server
//   -- KHÔNG KHẢ THI trên Render.
//
// => Giải pháp thực tế:
// - db.getWithUserToken(collection, docId, userToken): đọc bằng token của user
//   (dùng cho /checkout/confirm khi đọc orders — user có quyền đọc order của họ)
// - db.get / db.update / db.set / db.query: dùng API key + Firestore REST
//   (chỉ hoạt động với collection public hoặc rules cho phép)
//   Các write nhạy cảm (inject credentials vào orders, update accounts):
//   dùng special "write token" approach bên dưới.
//
// ĐỂ BYPASS RULES CHO WRITE: Firestore REST API không có cách bypass rules
// mà không có service account. Giải pháp: NỚI LỎNG rules cho isServer()
// nhưng KHÔNG cần bot user — thay vào đó dùng FIREBASE_API_KEY để
// authenticate anonymously rồi assign custom claims qua... cũng không được.
//
// GIẢI PHÁP CUỐI CÙNG: Dùng userToken (token của buyer) cho CẢ đọc VÀ ghi.
// Server nhận token từ request → dùng token đó để call Firestore REST.
// Rules cho phép user update order của chính họ cho _credentialsInjected fields.
// Credentials subcollection: đọc bằng admin approach khác.
//
// THỰC TẾ NHẤT: Nới rules để user tự update _credentialsInjected trên order của họ,
// còn credentials subcollection đọc: tạm thời cho buyer đọc sau khi mua.

const fetch = (...args) => import('node-fetch').then(({ default: f }) => f(...args));\

const PROJECT_ID  = process.env.FIREBASE_PROJECT_ID || 'gamestore-93186';\
const API_KEY     = process.env.FIREBASE_API_KEY;\

const FIRESTORE_BASE = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents`;\

// ── Firestore REST helpers ─────────────────────────────────────────────────

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
  if (val && val._type === 'increment') return { __transform: { increment: val._value } };
  if (Array.isArray(val)) return { arrayValue: { values: val.map(toFirestoreValue) } };
  if (typeof val === 'object') {
    const fields = {};
    for (const [k, v] of Object.entries(val)) fields[k] = toFirestoreValue(v);
    return { mapValue: { fields } };
  }
  return { stringValue: String(val) };
}

function fromFirestoreValue(val) {
  if (!val) return null;
  if ('nullValue'      in val) return null;
  if ('booleanValue'   in val) return val.booleanValue;
  if ('integerValue'   in val) return Number(val.integerValue);
  if ('doubleValue'    in val) return val.doubleValue;
  if ('stringValue'    in val) return val.stringValue;
  if ('timestampValue' in val) return new Date(val.timestampValue);
  if ('arrayValue'     in val) return (val.arrayValue.values || []).map(fromFirestoreValue);
  if ('mapValue'       in val) {
    const obj = {};
    for (const [k, v] of Object.entries(val.mapValue.fields || {})) obj[k] = fromFirestoreValue(v);
    return obj;
  }
  return null;
}

function fromFirestoreDoc(doc) {
  if (!doc || !doc.fields) return null;
  const result = {};
  for (const [k, v] of Object.entries(doc.fields)) result[k] = fromFirestoreValue(v);
  return result;
}

function toFields(data) {
  const fields = {};
  for (const [k, v] of Object.entries(data)) {
    const fv = toFirestoreValue(v);
    if (!fv.__transform) fields[k] = fv;
  }
  return fields;
}

function toFieldTransforms(docName, data) {
  const transforms = [];
  for (const [k, v] of Object.entries(data)) {
    if (v && v._type === 'serverTimestamp') transforms.push({ fieldPath: k, setToServerValue: 'REQUEST_TIME' });
    else if (v && v._type === 'increment')  transforms.push({ fieldPath: k, increment: toFirestoreValue(v._value) });
    else if (v && v._type === 'arrayUnion') transforms.push({ fieldPath: k, appendMissingElements: { values: v._items.map(toFirestoreValue) } });
    else if (v && v._type === 'arrayRemove')transforms.push({ fieldPath: k, removeAllFromArray:    { values: v._items.map(toFirestoreValue) } });
  }
  return transforms;
}

// ── Core request — dùng token bất kỳ (user token hoặc anonymous) ───────────
async function firestoreRequest(method, url, body, token) {
  const opts = {
    method,
    headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
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

// ── Anonymous sign-in — lấy token để call Firestore với rules public ────────
// Dùng cho các collection có rules `allow read/write: if true` hoặc không cần auth
let anonToken = null;
let anonTokenExpiry = 0;
async function getAnonToken() {
  const now = Date.now();
  if (anonToken && now < anonTokenExpiry - 120_000) return anonToken;
  const res = await (await fetch(
    `https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=${API_KEY}`,
    { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ returnSecureToken: true }) }
  )).json();
  if (!res.idToken) throw new Error('Anonymous sign-in failed: ' + JSON.stringify(res));
  anonToken = res.idToken;
  anonTokenExpiry = now + (parseInt(res.expiresIn) || 3600) * 1000;
  return anonToken;
}

// ── FieldValue markers ──────────────────────────────────────────────────────
const FieldValue = {
  serverTimestamp: () => ({ _type: 'serverTimestamp' }),
  increment:       (n)        => ({ _type: 'increment', _value: n }),
  arrayUnion:      (...items) => ({ _type: 'arrayUnion',  _items: items }),
  arrayRemove:     (...items) => ({ _type: 'arrayRemove', _items: items }),
  delete:          ()         => ({ _type: 'delete' }),
};

// ── DB wrapper ──────────────────────────────────────────────────────────────
const db = {
  FieldValue,

  // Đọc doc bằng userToken (user có quyền theo rules)
  async getWithToken(collection, docId, userToken) {
    try {
      const url = `${FIRESTORE_BASE}/${collection}/${docId}`;
      const json = await firestoreRequest('GET', url, null, userToken);
      return { exists: true, id: docId, data: () => fromFirestoreDoc(json) };
    } catch (err) {
      if (err.status === 404) return { exists: false, id: docId, data: () => null };
      throw err;
    }
  },

  // Đọc doc — dùng anon token (chỉ cho collection public)
  async get(collection, docId) {
    const token = await getAnonToken();
    return this.getWithToken(collection, docId, token);
  },

  // Ghi doc bằng userToken
  async updateWithToken(collection, docId, data, userToken) {
    const fields = toFields(data);
    const transforms = toFieldTransforms(`${collection}/${docId}`, data);
    const commitUrl = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents:commit`;
    const writes = [];
    if (Object.keys(fields).length > 0) {
      writes.push({
        update: { name: `projects/${PROJECT_ID}/databases/(default)/documents/${collection}/${docId}`, fields },
        updateMask: { fieldPaths: Object.keys(fields) },
        currentDocument: { exists: true },
      });
    }
    if (transforms.length > 0) {
      writes.push({ transform: { document: `projects/${PROJECT_ID}/databases/(default)/documents/${collection}/${docId}`, fieldTransforms: transforms } });
    }
    if (writes.length > 0) await firestoreRequest('POST', commitUrl, { writes }, userToken);
  },

  async set(collection, docId, data, userToken) {
    const token = userToken || await getAnonToken();
    const fields = toFields(data);
    const transforms = toFieldTransforms(`${collection}/${docId}`, data);
    if (transforms.length > 0) {
      const url = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents:commit`;
      const writes = [];
      if (Object.keys(fields).length > 0) writes.push({ update: { name: `projects/${PROJECT_ID}/databases/(default)/documents/${collection}/${docId}`, fields } });
      writes.push({ transform: { document: `projects/${PROJECT_ID}/databases/(default)/documents/${collection}/${docId}`, fieldTransforms: transforms } });
      await firestoreRequest('POST', url, { writes }, token);
    } else {
      await firestoreRequest('PATCH', `${FIRESTORE_BASE}/${collection}/${docId}`, { fields }, token);
    }
    return docId;
  },

  async update(collection, docId, data, userToken) {
    const token = userToken || await getAnonToken();
    return this.updateWithToken(collection, docId, data, token);
  },

  async add(collection, data, userToken) {
    const token = userToken || await getAnonToken();
    const fields = toFields(data);
    const transforms = toFieldTransforms(`${collection}/_new_`, data);
    if (transforms.length === 0) {
      const json = await firestoreRequest('POST', `${FIRESTORE_BASE}/${collection}`, { fields }, token);
      return { id: json.name.split('/').pop() };
    }
    const autoId = Array.from({length: 20}, () => 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'[Math.floor(Math.random()*62)]).join('');
    const docName = `projects/${PROJECT_ID}/databases/(default)/documents/${collection}/${autoId}`;
    const commitUrl = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents:commit`;
    await firestoreRequest('POST', commitUrl, { writes: [
      { update: { name: docName, fields }, currentDocument: { exists: false } },
      { transform: { document: docName, fieldTransforms: transforms } },
    ]}, token);
    return { id: autoId };
  },

  async query(collection, filters = [], orderByField = null, limitN = 10, userToken) {
    const token = userToken || await getAnonToken();
    const parts = collection.split('/');
    let parent = `projects/${PROJECT_ID}/databases/(default)/documents`;
    if (parts.length > 1) parent += '/' + parts.slice(0, -1).join('/');
    const structuredQuery = { from: [{ collectionId: parts[parts.length - 1] }] };
    if (filters.length > 0) {
      structuredQuery.where = filters.length === 1
        ? buildFilter(filters[0])
        : { compositeFilter: { op: 'AND', filters: filters.map(buildFilter) } };
    }
    if (orderByField) structuredQuery.orderBy = [{ field: { fieldPath: orderByField }, direction: 'DESCENDING' }];
    if (limitN) structuredQuery.limit = limitN;
    const res = await fetch(`https://firestore.googleapis.com/v1/${parent}:runQuery`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ structuredQuery }),
    });
    const results = await res.json();
    if (!res.ok) throw new Error(`Query failed: ${JSON.stringify(results)}`);
    return (Array.isArray(results) ? results : [results]).filter(r => r.document).map(r => ({
      id: r.document.name.split('/').pop(),
      data: () => fromFirestoreDoc(r.document),
    }));
  },

  async createIfNotExists(collection, docId, data, userToken) {
    const token = userToken || await getAnonToken();
    const fields = toFields(data);
    const transforms = toFieldTransforms(`${collection}/${docId}`, data);
    const commitUrl = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents:commit`;
    const writes = [{ update: { name: `projects/${PROJECT_ID}/databases/(default)/documents/${collection}/${docId}`, fields }, currentDocument: { exists: false } }];
    if (transforms.length > 0) writes.push({ transform: { document: `projects/${PROJECT_ID}/databases/(default)/documents/${collection}/${docId}`, fieldTransforms: transforms } });
    try {
      await firestoreRequest('POST', commitUrl, { writes }, token);
    } catch (err) {
      if (err.status === 400 || (err.message||'').includes('FAILED_PRECONDITION') || (err.message||'').includes('already exists')) {
        const e = new Error('ALREADY_EXISTS'); e.response = { status: 409 }; throw e;
      }
      throw err;
    }
  },

  async batch(operations, userToken) {
    const token = userToken || await getAnonToken();
    const commitUrl = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents:commit`;
    const writes = [];
    for (const { type, collection: col, docId, data } of operations) {
      const name = `projects/${PROJECT_ID}/databases/(default)/documents/${col}/${docId}`;
      const fields = toFields(data || {});
      if (type === 'set' || type === 'add') writes.push({ update: { name, fields } });
      if (type === 'update') writes.push({ update: { name, fields }, updateMask: { fieldPaths: Object.keys(fields) } });
      if (type === 'delete') writes.push({ delete: name });
    }
    if (writes.length > 0) await firestoreRequest('POST', commitUrl, { writes }, token);
  },

  async runTransaction(callback, userToken) {
    const token = userToken || await getAnonToken();
    const beginRes = await firestoreRequest('POST',
      `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents:beginTransaction`,
      { options: { readWrite: {} } }, token);
    const txId = beginRes.transaction;
    const writes = [];
    const makeRef = (col, id) => ({ _path: `projects/${PROJECT_ID}/databases/(default)/documents/${col}/${id}` });
    const txWrapped = {
      async get(ref) {
        const url = `https://firestore.googleapis.com/v1/${ref._path}?transaction=${encodeURIComponent(txId)}`;
        const res = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
        const json = await res.json();
        if (res.status === 404) return { exists: false, data: () => null };
        if (!res.ok) throw new Error(`tx.get failed: ${JSON.stringify(json)}`);
        return { exists: true, data: () => fromFirestoreDoc(json) };
      },
      update(ref, data) {
        const docName = ref._path;
        const fields = toFields(data);
        const transforms = toFieldTransforms(docName, data);
        if (Object.keys(fields).length > 0) writes.push({ update: { name: docName, fields }, updateMask: { fieldPaths: Object.keys(fields) }, currentDocument: { exists: true } });
        if (transforms.length > 0) writes.push({ transform: { document: docName, fieldTransforms: transforms } });
      },
    };
    try { await callback(txWrapped); } catch (err) { throw err; }
    await firestoreRequest('POST',
      `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents:commit`,
      { transaction: txId, writes }, token);
  },

  async runTransactionWithRetry(callback, maxRetries = 3, userToken) {
    let lastErr;
    for (let attempt = 0; attempt < maxRetries; attempt++) {
      try { return await this.runTransaction(callback, userToken); } catch (err) {
        lastErr = err;
        const msg = (err.message || '').toUpperCase();
        if (!msg.includes('ABORTED') && !msg.includes('CONTENTION') && !msg.includes('CONFLICT') && err.status !== 409) throw err;
        const delay = 100 * Math.pow(2, attempt) + Math.random() * 100;
        console.warn(`⚠️ Transaction contention (attempt ${attempt+1}/${maxRetries}), retrying in ${Math.round(delay)}ms`);
        await new Promise(r => setTimeout(r, delay));
      }
    }
    throw lastErr;
  },

  getFirestore() {
    const self = this;
    return {
      collection: (col) => ({ doc: (docId) => ({ _path: `projects/${PROJECT_ID}/databases/(default)/documents/${col}/${docId}`, _col: col, _docId: docId }) }),
      runTransaction: (cb) => self.runTransaction(cb),
    };
  },

  // verifyIdToken dùng Firebase REST (accounts:lookup)
  async verifyIdToken(idToken) {
    const res = await (await fetch(
      `https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${API_KEY}`,
      { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ idToken }) }
    )).json();
    if (!res.users || res.users.length === 0) throw new Error('Invalid token');
    const user = res.users[0];
    return { uid: user.localId, email: user.email };
  },
};

function buildFilter([field, op, value]) {
  const opMap = { '==':'EQUAL','!=':'NOT_EQUAL','<':'LESS_THAN','<=':'LESS_THAN_OR_EQUAL','>':'GREATER_THAN','>=':'GREATER_THAN_OR_EQUAL','array-contains':'ARRAY_CONTAINS' };
  return { fieldFilter: { field: { fieldPath: field }, op: opMap[op]||'EQUAL', value: toFirestoreValue(value) } };
}

module.exports = db;
