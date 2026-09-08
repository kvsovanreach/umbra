/* Local encrypted history cache (IndexedDB).
 *
 * Each message record is sealed with nacl.secretbox under a key derived from
 * the in-memory keypair (CryptoBox.localKey), so the cache is unreadable at
 * rest without re-deriving the keypair from the passphrase. It is purely a
 * display accelerator + offline read path — Firebase stays the source of truth.
 *
 * Records are keyed by `${cid}::${pushId}`; a conversation is read back with a
 * prefix cursor. If IndexedDB is unavailable (private mode, old browser) every
 * call degrades to a no-op and the app simply runs without a cache.
 */
window.LocalCache = (function () {
  const DB = 'umbra-cache', STORE = 'msgs', VERSION = 1;
  let dbp = null;

  function open() {
    if (dbp) return dbp;
    dbp = new Promise((resolve, reject) => {
      let req;
      try { req = indexedDB.open(DB, VERSION); } catch (e) { return reject(e); }
      req.onupgradeneeded = () => {
        const db = req.result;
        if (!db.objectStoreNames.contains(STORE)) db.createObjectStore(STORE);
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
    return dbp;
  }
  const keyFor = (cid, id) => cid + '::' + id;

  // seal + store a batch of message records (dedup/overwrite by push id)
  async function put(cid, records, sealKey) {
    if (!records || !records.length || !sealKey) return;
    let db; try { db = await open(); } catch (e) { return; }
    return new Promise((resolve) => {
      const tx = db.transaction(STORE, 'readwrite'), st = tx.objectStore(STORE);
      records.forEach((m) => { if (m && m.id) st.put(CryptoBox.sealLocal(m, sealKey), keyFor(cid, m.id)); });
      tx.oncomplete = tx.onerror = tx.onabort = () => resolve();
    });
  }

  // decrypt + return all cached records for a conversation, oldest-first
  async function get(cid, sealKey) {
    if (!sealKey) return [];
    let db; try { db = await open(); } catch (e) { return []; }
    return new Promise((resolve) => {
      const out = [];
      const tx = db.transaction(STORE, 'readonly'), st = tx.objectStore(STORE);
      const req = st.openCursor(IDBKeyRange.bound(cid + '::', cid + '::￿'));
      req.onsuccess = () => {
        const cur = req.result;
        if (!cur) { out.sort((a, b) => (a.ts || 0) - (b.ts || 0)); return resolve(out); }
        const rec = CryptoBox.openLocal(cur.value, sealKey);
        if (rec) out.push(rec);
        cur.continue();
      };
      req.onerror = () => resolve(out);
    });
  }

  async function clearAll() {
    let db; try { db = await open(); } catch (e) { return; }
    return new Promise((resolve) => {
      const tx = db.transaction(STORE, 'readwrite');
      tx.objectStore(STORE).clear();
      tx.oncomplete = tx.onerror = () => resolve();
    });
  }

  return { put, get, clearAll };
})();
