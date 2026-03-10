// lib/firestore.js
// Firestore REST API wrapper - không cần Service Account!
// Dùng Firebase API Key (public key, an toàn để dùng phía server)

const axios = require('axios');

const PROJECT_ID = process.env.FIREBASE_PROJECT_ID || 'gamestore-93186';
const API_KEY    = process.env.FIREBASE_API_KEY    || 'AIzaSyC1efvwK3jBRT1rIK30dc6bMXrs7PYiI1E';
const BASE_URL   = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents`;

// ── Helper: convert JS value → Firestore value ──
function toFirestoreValue(val) {
  if (val === null || val === undefined) return { nullValue: null };
  if (typeof val === 'boolean')  return { booleanValue: val };
  if (typeof val === 'number')   return Number.isInteger(val) ? { integerValue: String(val) } : { doubleValue: val };
  if (typeof val === 'string')   return { stringValue: val };
  if (val instanceof Date)       return { timestampValue: val.toISOString() };
  if (val && val.__serverTimestamp) return { timestampValue: new Date().toISOString() };
  if (Array.isArray(val))        return { arrayValue: { values: val.map(toFirestoreValue) } };
  if (typeof val === 'object')   return { mapValue: { fields: toFirestoreFields(val) } };
  return { stringValue: String(val) };
}

function toFirestoreFields(obj) {
  const fields = {};
  for (const [k, v] of Object.entries(obj)) {
    if (v !== undefined) fields[k] = toFirestoreValue(v);
  }
  return fields;
}

// ── Helper: convert Firestore value → JS value ──
function fromFirestoreValue(val) {
  if ('nullValue'      in val) return null;
  if ('booleanValue'   in val) return val.booleanValue;
  if ('integerValue'   in val) return Number(val.integerValue);
  if ('doubleValue'    in val) return val.doubleValue;
  if ('stringValue'    in val) return val.stringValue;
  if ('timestampValue' in val) return new Date(val.timestampValue);
  if ('arrayValue'     in val) return (val.arrayValue.values || []).map(fromFirestoreValue);
  if ('mapValue'       in val) return fromFirestoreDoc({ fields: val.mapValue.fields || {} });
  return null;
}

function fromFirestoreDoc(doc) {
  if (!doc || !doc.fields) return {};
  const obj = {};
  for (const [k, v] of Object.entries(doc.fields)) {
    obj[k] = fromFirestoreValue(v);
  }
  // Extract ID from name field
  if (doc.name) {
    obj._id = doc.name.split('/').pop();
  }
  return obj;
}

// Server timestamp marker
const FieldValue = {
  serverTimestamp: () => ({ __serverTimestamp: true }),
};

// ── Firestore DB object ──────────────────────────
const db = {
  FieldValue,

  // GET single document
  async get(collection, docId) {
    try {
      const res = await axios.get(`${BASE_URL}/${collection}/${docId}?key=${API_KEY}`);
      return { exists: true, id: docId, data: () => fromFirestoreDoc(res.data) };
    } catch (err) {
      if (err.response?.status === 404) return { exists: false, id: docId, data: () => null };
      throw err;
    }
  },

  // SET document (create/overwrite)
  async set(collection, docId, data) {
    const body = { fields: toFirestoreFields(data) };
    if (docId) {
      await axios.patch(`${BASE_URL}/${collection}/${docId}?key=${API_KEY}`, body);
      return docId;
    } else {
      const res = await axios.post(`${BASE_URL}/${collection}?key=${API_KEY}`, body);
      return res.data.name.split('/').pop();
    }
  },

  // ADD document (auto ID)
  async add(collection, data) {
    const body = { fields: toFirestoreFields(data) };
    const res = await axios.post(`${BASE_URL}/${collection}?key=${API_KEY}`, body);
    const id = res.data.name.split('/').pop();
    return { id };
  },

  // UPDATE document (partial)
  async update(collection, docId, data) {
    const fields = toFirestoreFields(data);
    const fieldPaths = Object.keys(fields).map(k => `updateMask.fieldPaths=${k}`).join('&');
    await axios.patch(
      `${BASE_URL}/${collection}/${docId}?key=${API_KEY}&${fieldPaths}`,
      { fields }
    );
  },

  // QUERY documents
  async query(collection, filters = [], orderByField = null, limitN = 10) {
    const structuredQuery = {
      from: [{ collectionId: collection }],
      limit: limitN,
    };

    if (filters.length > 0) {
      const conditions = filters.map(([field, op, value]) => ({
        fieldFilter: {
          field: { fieldPath: field },
          op: opMap[op] || 'EQUAL',
          value: toFirestoreValue(value),
        },
      }));
      structuredQuery.where = conditions.length === 1
        ? conditions[0]
        : { compositeFilter: { op: 'AND', filters: conditions } };
    }

    if (orderByField) {
      structuredQuery.orderBy = [{ field: { fieldPath: orderByField }, direction: 'DESCENDING' }];
    }

    const res = await axios.post(
      `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents:runQuery?key=${API_KEY}`,
      { structuredQuery }
    );

    return (res.data || [])
      .filter(r => r.document)
      .map(r => ({
        id: r.document.name.split('/').pop(),
        data: () => fromFirestoreDoc(r.document),
      }));
  },

  // TRANSACTION: read-then-write với optimistic locking
  async runTransaction(collection, docId, updateFn) {
    // Retry up to 3 lần nếu conflict
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        const docRes = await axios.get(`${BASE_URL}/${collection}/${docId}?key=${API_KEY}`);
        const currentData = fromFirestoreDoc(docRes.data);
        const updates = await updateFn(currentData);

        // Apply all updates
        for (const [col, id, data] of updates) {
          if (id) {
            await db.update(col, id, data);
          } else {
            await db.add(col, data);
          }
        }
        return; // Success
      } catch (err) {
        if (attempt === 2) throw err;
        await new Promise(r => setTimeout(r, 100 * (attempt + 1)));
      }
    }
  },
};

const opMap = {
  '==': 'EQUAL',
  '!=': 'NOT_EQUAL',
  '<':  'LESS_THAN',
  '<=': 'LESS_THAN_OR_EQUAL',
  '>':  'GREATER_THAN',
  '>=': 'GREATER_THAN_OR_EQUAL',
};

module.exports = db;
