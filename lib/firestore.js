// lib/firestore.js
// Firestore REST API — dùng token của user từ request.
// Server không cần service account, không cần bot user.
// Mọi thao tác đều chạy với quyền của user đang mua hàng.

const fetch = (...args) => import('node-fetch').then(({ default: f }) => f(...args));

const PROJECT_ID = process.env.FIREBASE_PROJECT_ID || 'gamestore-93186';
const API_KEY    = process.env.FIREBASE_API_KEY;
const FIRESTORE_BASE = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents`;

// ── Server Bot Token Cache ─────────────────────────────────────────────────
// Server bot là một Firebase user có role='server' trong Firestore.
// Dùng cho các operations không có user context (webhook, transaction).
// Token tự refresh khi hết hạn (Firebase ID token sống 1 giờ).
const _serverBotCache = {
  token:     null,
  expiresAt: 0,   // ms timestamp
  refreshToken: null,
};

async function getServerBotToken() {
  const BOT_EMAIL    = process.env.SERVER_BOT_EMAIL;
  const BOT_PASSWORD = process.env.SERVER_BOT_PASSWORD;
  if (!BOT_EMAIL || !BOT_PASSWORD) return null; // graceful degradation

  const now = Date.now();
  // Refresh 5 minutes before expiry
  if (_serverBotCache.token && now < _serverBotCache.expiresAt - 5 * 60 * 1000) {
    return _serverBotCache.token;
  }

  try {
    let data;
    // Try refresh token first (cheaper than full sign-in)
    if (_serverBotCache.refreshToken) {
      const r = await (await import('node-fetch')).default(
        `https://securetoken.googleapis.com/v1/token?key=${API_KEY}`,
        { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: `grant_type=refresh_token&refresh_token=${encodeURIComponent(_serverBotCache.refreshToken)}` }
      );
      data = await r.json();
      if (r.ok && data.id_token) {
        _serverBotCache.token        = data.id_token;
        _serverBotCache.refreshToken = data.refresh_token;
        _serverBotCache.expiresAt    = now + Number(data.expires_in || 3600) * 1000;
        return _serverBotCache.token;
      }
    }

    // Full sign-in
    const res = await (await import('node-fetch')).default(
      `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${API_KEY}`,
      { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: BOT_EMAIL, password: BOT_PASSWORD, returnSecureToken: true }) }
    );
    data = await res.json();
    if (!res.ok || !data.idToken) {
      console.error('⛔ Server bot sign-in failed:', data.error?.message || JSON.stringify(data));
      return null;
    }
    _serverBotCache.token        = data.idToken;
    _serverBotCache.refreshToken = data.refreshToken;
    _serverBotCache.expiresAt    = now + Number(data.expiresIn || 3600) * 1000;
    console.log('✅ Server bot token refreshed');
    return _serverBotCache.token;
  } catch (e) {
    console.error('⛔ Server bot token error:', e.message);
    return null;
  }
}


// ── Value converters ──────────────────────────────────────────────────────
function toFirestoreValue(val) {
  if (val === null || val === undefined) return { nullValue: null };
  if (typeof val === 'boolean')  return { booleanValue: val };
  if (typeof val === 'number')   return Number.isInteger(val) ? { integerValue: String(val) } : { doubleValue: val };
  if (typeof val === 'string')   return { stringValue: val };
  if (val instanceof Date)       return { timestampValue: val.toISOString() };
  if (val?._type === 'serverTimestamp') return { timestampValue: new Date().toISOString() };
  if (val?._type === 'increment') return { __transform: { increment: val._value } };
  if (val?._type === 'arrayUnion') return { __transform: { arrayUnion: val._items } };
  if (val?._type === 'arrayRemove') return { __transform: { arrayRemove: val._items } };
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
  if (!doc?.fields) return null;
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

function toFieldTransforms(docPath, data) {
  const transforms = [];
  for (const [k, v] of Object.entries(data)) {
    if (v?._type === 'serverTimestamp') transforms.push({ fieldPath: k, setToServerValue: 'REQUEST_TIME' });
    else if (v?._type === 'increment')  transforms.push({ fieldPath: k, increment: toFirestoreValue(v._value) });
    else if (v?._type === 'arrayUnion') transforms.push({ fieldPath: k, appendMissingElements: { values: v._items.map(toFirestoreValue) } });
    else if (v?._type === 'arrayRemove')transforms.push({ fieldPath: k, removeAllFromArray: { values: v._items.map(toFirestoreValue) } });
  }
  return transforms;
}

// ── Core request — dùng token được truyền vào ─────────────────────────────
async function request(method, url, body, token) {
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers['Authorization'] = `Bearer ${token}`;
  const res  = await fetch(url, { method, headers, body: body ? JSON.stringify(body) : undefined });
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

// ── FieldValue markers ─────────────────────────────────────────────────────
const FieldValue = {
  serverTimestamp: () => ({ _type: 'serverTimestamp' }),
  increment:       (n)        => ({ _type: 'increment', _value: n }),
  arrayUnion:      (...items) => ({ _type: 'arrayUnion',  _items: items }),
  arrayRemove:     (...items) => ({ _type: 'arrayRemove', _items: items }),
  delete:          ()         => ({ _type: 'delete' }),
};

// ── DB wrapper ─────────────────────────────────────────────────────────────
// Tất cả method nhận thêm tham số `token` cuối (optional, mặc định null = unauthenticated)
const db = {
  FieldValue,

  async get(collection, docId, token = null) {
    const url = `${FIRESTORE_BASE}/${collection}/${docId}`;
    try {
      const json = await request('GET', url, null, token);
      // updateTime dùng cho optimistic locking (updateIf)
      return { exists: true, id: docId, updateTime: json.updateTime, data: () => fromFirestoreDoc(json) };
    } catch (err) {
      if (err.status === 404) return { exists: false, id: docId, data: () => null };
      throw err;
    }
  },

  // Alias rõ ràng cho code dễ đọc
  async getWithToken(collection, docId, token) {
    return this.get(collection, docId, token);
  },

  async set(collection, docId, data, token = null) {
    const fields = toFields(data);
    const transforms = toFieldTransforms(`${collection}/${docId}`, data);
    const commitUrl = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents:commit`;
    const writes = [];
    if (Object.keys(fields).length > 0)
      writes.push({ update: { name: `projects/${PROJECT_ID}/databases/(default)/documents/${collection}/${docId}`, fields } });
    if (transforms.length > 0)
      writes.push({ transform: { document: `projects/${PROJECT_ID}/databases/(default)/documents/${collection}/${docId}`, fieldTransforms: transforms } });
    await request('POST', commitUrl, { writes }, token);
    return docId;
  },

  async add(collection, data, token = null) {
    const fields = toFields(data);
    const transforms = toFieldTransforms(`${collection}/_`, data);
    if (transforms.length === 0) {
      const json = await request('POST', `${FIRESTORE_BASE}/${collection}`, { fields }, token);
      return { id: json.name.split('/').pop() };
    }
    const autoId = Array.from({length:20}, () => 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'[Math.floor(Math.random()*62)]).join('');
    const docName = `projects/${PROJECT_ID}/databases/(default)/documents/${collection}/${autoId}`;
    const commitUrl = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents:commit`;
    await request('POST', commitUrl, { writes: [
      { update: { name: docName, fields }, currentDocument: { exists: false } },
      { transform: { document: docName, fieldTransforms: transforms } },
    ]}, token);
    return { id: autoId };
  },

  async update(collection, docId, data, token = null) {
    const fields = toFields(data);
    const transforms = toFieldTransforms(`${collection}/${docId}`, data);
    const commitUrl = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents:commit`;
    const writes = [];
    if (Object.keys(fields).length > 0)
      writes.push({ update: { name: `projects/${PROJECT_ID}/databases/(default)/documents/${collection}/${docId}`, fields }, updateMask: { fieldPaths: Object.keys(fields) }, currentDocument: { exists: true } });
    if (transforms.length > 0)
      writes.push({ transform: { document: `projects/${PROJECT_ID}/databases/(default)/documents/${collection}/${docId}`, fieldTransforms: transforms } });
    if (writes.length > 0) await request('POST', commitUrl, { writes }, token);
  },

  async query(collection, filters = [], orderByField = null, limitN = 10, token = null) {
    const parts = collection.split('/');
    let parent = `projects/${PROJECT_ID}/databases/(default)/documents`;
    if (parts.length > 1) parent += '/' + parts.slice(0, -1).join('/');
    const structuredQuery = { from: [{ collectionId: parts[parts.length-1] }] };
    if (filters.length > 0) {
      const buildFilter = ([field, op, value]) => ({ fieldFilter: { field: { fieldPath: field }, op: { '==':'EQUAL','!=':'NOT_EQUAL','<':'LESS_THAN','<=':'LESS_THAN_OR_EQUAL','>':'GREATER_THAN','>=':'GREATER_THAN_OR_EQUAL','array-contains':'ARRAY_CONTAINS' }[op]||'EQUAL', value: toFirestoreValue(value) } });
      structuredQuery.where = filters.length === 1 ? buildFilter(filters[0]) : { compositeFilter: { op: 'AND', filters: filters.map(buildFilter) } };
    }
    if (orderByField) structuredQuery.orderBy = [{ field: { fieldPath: orderByField }, direction: 'DESCENDING' }];
    if (limitN) structuredQuery.limit = limitN;
    const res = await fetch(`https://firestore.googleapis.com/v1/${parent}:runQuery`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
      body: JSON.stringify({ structuredQuery }),
    });
    const results = await res.json();
    if (!res.ok) throw new Error(`Query failed: ${JSON.stringify(results)}`);
    return (Array.isArray(results) ? results : [results]).filter(r => r.document).map(r => ({ id: r.document.name.split('/').pop(), data: () => fromFirestoreDoc(r.document) }));
  },

  async createIfNotExists(collection, docId, data, token = null) {
    const fields = toFields(data);
    const commitUrl = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents:commit`;
    try {
      await request('POST', commitUrl, { writes: [{ update: { name: `projects/${PROJECT_ID}/databases/(default)/documents/${collection}/${docId}`, fields }, currentDocument: { exists: false } }] }, token);
    } catch (err) {
      if (err.status === 400 || (err.message||'').includes('FAILED_PRECONDITION') || (err.message||'').includes('already exists')) {
        const e = new Error('ALREADY_EXISTS'); e.response = { status: 409 }; throw e;
      }
      throw err;
    }
  },

  async batch(operations, token = null) {
    const commitUrl = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents:commit`;
    const writes = [];
    for (const { type, collection: col, docId, data } of operations) {
      const name = `projects/${PROJECT_ID}/databases/(default)/documents/${col}/${docId}`;
      const fields = toFields(data || {});
      if (type === 'set' || type === 'add') writes.push({ update: { name, fields } });
      if (type === 'update') writes.push({ update: { name, fields }, updateMask: { fieldPaths: Object.keys(fields) } });
      if (type === 'delete') writes.push({ delete: name });
    }
    if (writes.length > 0) await request('POST', commitUrl, { writes }, token);
  },

  async runTransaction(callback, token = null) {
    const beginRes = await request('POST',
      `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents:beginTransaction`,
      { options: { readWrite: {} } }, token);
    const txId = beginRes.transaction;
    const writes = [];
    const txWrapped = {
      async get(ref) {
        const path = ref._path || `projects/${PROJECT_ID}/databases/(default)/documents/${ref._col}/${ref._docId}`;
        const url = `https://firestore.googleapis.com/v1/${path}?transaction=${encodeURIComponent(txId)}`;
        const res = await fetch(url, { headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) } });
        const json = await res.json();
        if (res.status === 404) return { exists: false, data: () => null };
        if (!res.ok) throw new Error(`tx.get failed: ${JSON.stringify(json)}`);
        return { exists: true, data: () => fromFirestoreDoc(json) };
      },
      update(ref, data) {
        const docName = ref._path || `projects/${PROJECT_ID}/databases/(default)/documents/${ref._col}/${ref._docId}`;
        const fields = toFields(data);
        const transforms = toFieldTransforms(docName, data);
        if (Object.keys(fields).length > 0)
          writes.push({ update: { name: docName, fields }, updateMask: { fieldPaths: Object.keys(fields) }, currentDocument: { exists: true } });
        if (transforms.length > 0)
          writes.push({ transform: { document: docName, fieldTransforms: transforms } });
      },
    };
    try { await callback(txWrapped); } catch (err) { throw err; }
    await request('POST', `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents:commit`, { transaction: txId, writes }, token);
  },

  async runTransactionWithRetry(callback, maxRetries = 3, token = null) {
    let lastErr;
    for (let attempt = 0; attempt < maxRetries; attempt++) {
      try { return await this.runTransaction(callback, token); } catch (err) {
        lastErr = err;
        const msg = (err.message||'').toUpperCase();
        if (!msg.includes('ABORTED') && !msg.includes('CONTENTION') && !msg.includes('CONFLICT') && err.status !== 409) throw err;
        await new Promise(r => setTimeout(r, 100 * Math.pow(2, attempt) + Math.random() * 100));
      }
    }
    throw lastErr;
  },

  getFirestore() {
    const self = this;
    const makeRef = (col, docId) => ({
      _col: col, _docId: docId,
      _path: `projects/${PROJECT_ID}/databases/(default)/documents/${col}/${docId}`,
      collection: () => ({ doc: (id) => makeRef(`${col}/${docId}`, id) }),
    });
    return {
      collection: (col) => ({ doc: (docId) => makeRef(col, docId) }),
      runTransaction: (cb, token) => self.runTransaction(cb, token),
    };
  },

  // updateIf: update doc với precondition updateTime (optimistic locking)
  // Trả về true nếu thành công, throw nếu conflict (doc đã thay đổi)
  async updateIf(collection, docId, data, updateTime, token = null) {
    const docName = `projects/${PROJECT_ID}/databases/(default)/documents/${collection}/${docId}`;
    const fields = toFields(data);
    const transforms = toFieldTransforms(docName, data);
    const commitUrl = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents:commit`;
    const writes = [];
    if (Object.keys(fields).length > 0) {
      writes.push({
        update: { name: docName, fields },
        updateMask: { fieldPaths: Object.keys(fields) },
        currentDocument: { updateTime }, // precondition: doc chưa bị thay đổi
      });
    }
    if (transforms.length > 0) {
      writes.push({ transform: { document: docName, fieldTransforms: transforms } });
    }
    try {
      await request('POST', commitUrl, { writes }, token);
      return true;
    } catch (err) {
      // 400 = precondition failed (doc đã thay đổi bởi người khác)
      if (err.status === 400 || (err.message || '').includes('FAILED_PRECONDITION')) {
        const conflict = new Error('CONFLICT');
        conflict.isConflict = true;
        throw conflict;
      }
      throw err;
    }
  },

  // Get server bot token (for webhook/admin operations without user context)
  getServerBotToken,

  // Verify user idToken dùng Firebase REST
  // SECURITY: accounts:lookup KHÔNG enforce token expiry.
  // Fix: decode JWT payload thủ công để check exp TRƯỚC khi gọi lookup.
  async verifyIdToken(idToken) {
    // 1. Decode JWT exp claim (không cần verify signature ở đây — lookup sẽ verify)
    try {
      const parts = idToken.split('.');
      if (parts.length !== 3) throw new Error('Malformed JWT');
      const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
      const nowSec = Math.floor(Date.now() / 1000);
      if (!payload.exp || payload.exp < nowSec) {
        throw new Error('Token expired');
      }
    } catch (e) {
      throw new Error('Invalid or expired token: ' + e.message);
    }
    // 2. Verify signature + get user info via accounts:lookup
    const res  = await fetch(`https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${API_KEY}`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ idToken }),
    });
    const data = await res.json();
    if (!res.ok || !data.users?.length) throw new Error('Invalid or expired token');
    const user = data.users[0];
    return { uid: user.localId, email: user.email };
  },
};

module.exports = db;
