import './style.css';
import '@fontsource/dm-sans/400.css';
import '@fontsource/dm-sans/500.css';
import '@fontsource/dm-sans/600.css';
import '@fontsource/dm-sans/700.css';
import '@fontsource/jetbrains-mono/400.css';
import '@fontsource/jetbrains-mono/500.css';
import '@fontsource/jetbrains-mono/600.css';
import '@fontsource/plus-jakarta-sans/600.css';
import '@fontsource/plus-jakarta-sans/700.css';
import { schnorr } from '@noble/curves/secp256k1';
import { ed25519, x25519 } from '@noble/curves/ed25519';
import { xchacha20poly1305 } from '@noble/ciphers/chacha';
import { sha256 } from '@noble/hashes/sha256';
import { hkdf } from '@noble/hashes/hkdf';
import { argon2idAsync } from '@noble/hashes/argon2';
import QRCode from 'qrcode';
import { Capacitor } from '@capacitor/core';
import { Filesystem, Directory } from '@capacitor/filesystem';
import { Share } from '@capacitor/share';
import { registerSW } from 'virtual:pwa-register';

/* --- PLATFORM HELPERS (native APK vs. web/PWA) --- */
const IS_NATIVE = Capacitor.isNativePlatform();
// Public web address used in share links when running inside the APK
// (inside the APK the origin is https://localhost, which is useless to share).
const PUBLIC_BASE_URL = (import.meta.env.VITE_PUBLIC_URL || '').replace(/\/+$/, '');

async function saveFile(filename, blobOrDataUrl, mime) {
  if (IS_NATIVE) {
    let data;
    if (typeof blobOrDataUrl === 'string') data = blobOrDataUrl.split(',')[1];
    else {
      const buf = new Uint8Array(await blobOrDataUrl.arrayBuffer());
      let bin = '';
      for (let i = 0; i < buf.length; i += 0x8000) bin += String.fromCharCode(...buf.subarray(i, i + 0x8000));
      data = btoa(bin);
    }
    const res = await Filesystem.writeFile({ path: filename, data, directory: Directory.Cache });
    await Share.share({ title: filename, url: res.uri, dialogTitle: 'Save or share ' + filename });
    return;
  }
  const url = typeof blobOrDataUrl === 'string' ? blobOrDataUrl : URL.createObjectURL(new Blob([blobOrDataUrl], { type: mime }));
  const a = document.createElement('a');
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click(); a.remove();
  if (typeof blobOrDataUrl !== 'string') setTimeout(() => URL.revokeObjectURL(url), 4000);
}

/* --- 1. CRYPTOGRAPHIC PRIMITIVES & SAFE DOM HELPERS --- */
const enc = new TextEncoder();
const dec = new TextDecoder();
const $ = (id) => document.getElementById(id);

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === null) continue;
    if (k === 'className') node.className = v;
    else if (k === 'textContent') node.textContent = v;
    else if (k === 'style' && typeof v === 'object') Object.assign(node.style, v);
    else if (k.startsWith('on') && typeof v === 'function') node[k] = v;
    else node.setAttribute(k, String(v));
  }
  for (const ch of children) {
    if (ch === null || ch === undefined || ch === false) continue;
    node.appendChild(typeof ch === 'string' ? document.createTextNode(ch) : ch);
  }
  return node;
}

function svgIcon(shapes, { className = 'w-4 h-4 shrink-0', fill = 'none', strokeWidth = '1.9' } = {}) {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('class', className);
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('fill', fill);
  svg.setAttribute('stroke', 'currentColor');
  svg.setAttribute('stroke-width', strokeWidth);
  svg.setAttribute('stroke-linecap', 'round');
  svg.setAttribute('stroke-linejoin', 'round');
  svg.setAttribute('aria-hidden', 'true');
  for (const [tag, attrs] of shapes) {
    const node = document.createElementNS('http://www.w3.org/2000/svg', tag);
    for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, String(v));
    svg.appendChild(node);
  }
  return svg;
}
const POST_ICONS = {
  reply: [['path', { d: 'M7.9 20A9 9 0 1 0 4 16.1L2 22Z' }]],
  like: [['path', { d: 'M19 14c1.49-1.46 3-3.21 3-5.5A5.5 5.5 0 0 0 16.5 3c-1.76 0-3 .5-4.5 2-1.5-1.5-2.74-2-4.5-2A5.5 5.5 0 0 0 2 8.5c0 2.3 1.5 4.05 3 5.5l7 7Z' }]],
  proof: [['path', { d: 'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z' }], ['path', { d: 'm9 12 2 2 4-4' }]],
  edit: [['path', { d: 'M12 20h9' }], ['path', { d: 'M16.376 3.622a1 1 0 0 1 3.002 3.002L7.368 18.635a2 2 0 0 1-.855.506l-2.872.838a.5.5 0 0 1-.62-.62l.838-2.872a2 2 0 0 1 .506-.854z' }]],
  trash: [['path', { d: 'M3 6h18' }], ['path', { d: 'M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6' }], ['path', { d: 'M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2' }], ['line', { x1: '10', x2: '10', y1: '11', y2: '17' }], ['line', { x1: '14', x2: '14', y1: '11', y2: '17' }]],
  flag: [['path', { d: 'M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z' }], ['line', { x1: '4', x2: '4', y1: '22', y2: '15' }]],
  send: [['path', { d: 'm22 2-7 20-4-9-9-4Z' }], ['path', { d: 'M22 2 11 13' }]]
};

const randomBytes = (n) => crypto.getRandomValues(new Uint8Array(n));
const utf8ToBytes = (s) => enc.encode(s);
const bytesToUtf8 = (b) => dec.decode(b);
const bytesToHex = (b) => Array.from(b, x => x.toString(16).padStart(2, '0')).join('');
function hexToBytes(hex) {
  if (typeof hex !== 'string' || hex.length % 2 || !/^[0-9a-fA-F]*$/.test(hex)) throw new Error('Invalid hex');
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}
function bytesToB64Url(bytes) {
  let bin = '';
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}
function b64UrlToBytes(str) {
  const b64 = (str + '='.repeat((4 - (str.length % 4)) % 4)).replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function canonicalStringify(obj) {
  if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
  if (Array.isArray(obj)) return '[' + obj.map(canonicalStringify).join(',') + ']';
  return '{' + Object.keys(obj).sort().map(k => JSON.stringify(k) + ':' + canonicalStringify(obj[k])).join(',') + '}';
}

function generateIdentity(name = 'Cipher Peer', handle = '') {
  const skSecp = schnorr.utils.randomPrivateKey();
  const skEd = ed25519.utils.randomPrivateKey();
  const skX = x25519.utils.randomPrivateKey();
  const pkEd = bytesToHex(ed25519.getPublicKey(skEd));
  return {
    name,
    handle: handle || ('peer_' + pkEd.slice(0, 6)),
    skSecpHex: bytesToHex(skSecp), pkSecp: bytesToHex(schnorr.getPublicKey(skSecp)),
    skEdHex: bytesToHex(skEd), pkEd,
    skXHex: bytesToHex(skX), pkX: bytesToHex(x25519.getPublicKey(skX)),
    createdAt: Math.floor(Date.now() / 1000)
  };
}

function signNostrEvent(kind, content, tags = [], createdAt = Math.floor(Date.now() / 1000)) {
  const idBytes = sha256(utf8ToBytes(JSON.stringify([0, state.identity.pkSecp, createdAt, kind, tags, content])));
  const id = bytesToHex(idBytes);
  const sig = bytesToHex(schnorr.sign(idBytes, hexToBytes(state.identity.skSecpHex)));
  return { id, pubkey: state.identity.pkSecp, created_at: createdAt, kind, tags, content, sig };
}

function verifyNostrEvent(ev) {
  try {
    if (!ev || typeof ev !== 'object' || ev.id?.length !== 64 || ev.pubkey?.length !== 64 || ev.sig?.length !== 128) return false;
    if (!Number.isInteger(ev.kind) || !Number.isInteger(ev.created_at) || !Array.isArray(ev.tags) || typeof ev.content !== 'string') return false;
    const expected = bytesToHex(sha256(utf8ToBytes(JSON.stringify([0, ev.pubkey, ev.created_at, ev.kind, ev.tags, ev.content]))));
    return expected === ev.id && schnorr.verify(hexToBytes(ev.sig), hexToBytes(ev.id), hexToBytes(ev.pubkey));
  } catch { return false; }
}

const signEdPayload = (obj) => bytesToHex(ed25519.sign(utf8ToBytes(canonicalStringify(obj)), hexToBytes(state.identity.skEdHex)));
const verifyEdPayload = (obj, sigHex, pkEdHex) => {
  try { return ed25519.verify(hexToBytes(sigHex), utf8ToBytes(canonicalStringify(obj)), hexToBytes(pkEdHex)); }
  catch { return false; }
};
const derivePairwiseKey = (mySkXHex, theirPkXHex, saltStr, infoStr) =>
  hkdf(sha256, x25519.getSharedSecret(hexToBytes(mySkXHex), hexToBytes(theirPkXHex)), utf8ToBytes(saltStr), utf8ToBytes(infoStr), 32);

function encryptXChaCha(key32, plaintextBytes, aadStr = '') {
  const nonce = randomBytes(24);
  const ct = xchacha20poly1305(key32, nonce, aadStr ? utf8ToBytes(aadStr) : undefined).encrypt(plaintextBytes);
  return { nonce: bytesToB64Url(nonce), ct: bytesToB64Url(ct) };
}
function decryptXChaCha(key32, nonceB64, ctB64, aadStr = '') {
  return xchacha20poly1305(key32, b64UrlToBytes(nonceB64), aadStr ? utf8ToBytes(aadStr) : undefined).decrypt(b64UrlToBytes(ctB64));
}

function encodeContactCard(peer) {
  return 'cipherpost:peer:' + bytesToB64Url(utf8ToBytes(JSON.stringify({
    v: 1, pkSecp: peer.pkSecp, pkEd: peer.pkEd, pkX: peer.pkX, name: peer.name, handle: peer.handle
  })));
}
function buildProfileShareUrl(peer, includeCard = true) {
  const base = (IS_NATIVE && PUBLIC_BASE_URL)
    ? PUBLIC_BASE_URL + '/'
    : (window.location.origin && window.location.origin !== 'null')
      ? (window.location.origin + window.location.pathname)
      : window.location.href.split('#')[0].split('?')[0];
  const hasCard = Boolean(includeCard && peer?.pkSecp && peer?.pkEd && peer?.pkX);
  if (!hasCard) return `${base}#profile/${peer.pkSecp}`;
  const payload = bytesToB64Url(utf8ToBytes(JSON.stringify({
    v: 1, pkSecp: peer.pkSecp, pkEd: peer.pkEd, pkX: peer.pkX, name: peer.name, handle: peer.handle
  })));
  return `${base}#profile/${peer.pkSecp}?c=${payload}`;
}
function parseProfileRoute(raw) {
  if (!raw || typeof raw !== 'string') return null;
  const hashIdx = raw.indexOf('#profile/');
  const slice = hashIdx >= 0 ? raw.slice(hashIdx) : raw.trim();
  const m = slice.match(/^#profile\/([0-9a-fA-F]{64})(?:\?(.*))?$/);
  if (!m) return null;
  const pkSecp = m[1].toLowerCase();
  let peer = null;
  if (m[2]) {
    try {
      const params = new URLSearchParams(m[2]);
      const cardB64 = params.get('c') || params.get('card');
      if (cardB64) {
        const obj = JSON.parse(bytesToUtf8(b64UrlToBytes(cardB64)));
        if (obj && /^[0-9a-fA-F]{64}$/.test(obj.pkSecp || '') && obj.pkSecp.toLowerCase() === pkSecp && /^[0-9a-fA-F]{64}$/.test(obj.pkEd || '') && /^[0-9a-fA-F]{64}$/.test(obj.pkX || '')) {
          peer = {
            pkSecp,
            pkEd: obj.pkEd.toLowerCase(),
            pkX: obj.pkX.toLowerCase(),
            name: String(obj.name || 'Peer').slice(0, 40),
            handle: String(obj.handle || ('peer_' + obj.pkEd.slice(0, 6))).slice(0, 32)
          };
        }
      }
    } catch {}
  }
  return { pkSecp, peer };
}
function decodeContactCard(raw) {
  const t = raw.trim();
  if (t.includes('#profile/')) {
    const parsed = parseProfileRoute(t);
    if (parsed?.peer) return parsed.peer;
  }
  const obj = t.startsWith('cipherpost:peer:')
    ? JSON.parse(bytesToUtf8(b64UrlToBytes(t.slice('cipherpost:peer:'.length))))
    : JSON.parse(t);
  if (!obj || obj.pkSecp?.length !== 64 || obj.pkEd?.length !== 64 || obj.pkX?.length !== 64) throw new Error('Invalid Contact Card');
  return { pkSecp: obj.pkSecp, pkEd: obj.pkEd, pkX: obj.pkX, name: String(obj.name || 'Peer').slice(0, 40), handle: String(obj.handle || ('peer_' + obj.pkEd.slice(0, 6))).slice(0, 32) };
}

/* --- 2. CLIENT-SIDE CANVAS EXIF STRIPPER & VALIDATORS --- */
async function stripImageExif(file) {
  if (!['image/png', 'image/jpeg', 'image/webp', 'image/gif'].includes(file.type)) throw new Error('Use PNG, JPEG, WebP, or GIF');
  if (file.size > 10 * 1024 * 1024) throw new Error('Image exceeds 10 MB');
  const objUrl = URL.createObjectURL(file);
  try {
    const img = await new Promise((res, rej) => { const i = new Image(); i.onload = () => res(i); i.onerror = () => rej(new Error('Image decode failed')); i.src = objUrl; });
    let w = img.naturalWidth || img.width, h = img.naturalHeight || img.height;
    if (w > 960 || h > 960) { const r = Math.min(960 / w, 960 / h); w = Math.max(1, Math.round(w * r)); h = Math.max(1, Math.round(h * r)); }
    const canvas = document.createElement('canvas');
    canvas.width = w; canvas.height = h;
    canvas.getContext('2d').drawImage(img, 0, 0, w, h);
    let dataUrl = canvas.toDataURL('image/webp', 0.84);
    if (!dataUrl.startsWith('data:image/webp')) dataUrl = canvas.toDataURL('image/jpeg', 0.84);
    if (dataUrl.length > 260000) dataUrl = canvas.toDataURL('image/jpeg', 0.65);
    return { dataUrl, width: w, height: h, strippedBytes: Math.round((dataUrl.length * 3) / 4) };
  } finally { URL.revokeObjectURL(objUrl); }
}
async function stripProfileMedia(file, targetW, targetH, maxBytes) {
  if (!['image/png', 'image/jpeg', 'image/webp'].includes(file.type)) throw new Error('Use PNG, JPEG, or WebP');
  if (file.size > 10 * 1024 * 1024) throw new Error('Image exceeds 10 MB');
  const objUrl = URL.createObjectURL(file);
  try {
    const img = await new Promise((res, rej) => { const i = new Image(); i.onload = () => res(i); i.onerror = () => rej(new Error('Image decode failed')); i.src = objUrl; });
    const sw = img.naturalWidth || img.width, sh = img.naturalHeight || img.height;
    const scale = Math.max(targetW / sw, targetH / sh);
    const cropW = targetW / scale, cropH = targetH / scale;
    const sx = Math.max(0, (sw - cropW) / 2), sy = Math.max(0, (sh - cropH) / 2);
    const canvas = document.createElement('canvas');
    canvas.width = targetW; canvas.height = targetH;
    canvas.getContext('2d').drawImage(img, sx, sy, cropW, cropH, 0, 0, targetW, targetH);
    let q = 0.84;
    let dataUrl = canvas.toDataURL('image/webp', q);
    if (!dataUrl.startsWith('data:image/webp')) dataUrl = canvas.toDataURL('image/jpeg', q);
    while (dataUrl.length > maxBytes && q > 0.45) {
      q -= 0.12;
      dataUrl = canvas.toDataURL('image/jpeg', q);
    }
    return dataUrl;
  } finally { URL.revokeObjectURL(objUrl); }
}
const isSafeImageDataUrl = (u) => typeof u === 'string' && /^data:image\/(png|jpeg|webp);base64,[A-Za-z0-9+/=]+$/.test(u);

/* --- 3. STATE & INDEXEDDB --- */
const DEFAULT_RELAYS = [
  { url: 'local://browser-relay', builtin: true, enabled: true, isLocal: true },
  { url: 'wss://nos.lol', builtin: true, enabled: true, isLocal: false },
  { url: 'wss://relay.damus.io', builtin: true, enabled: true, isLocal: false },
  { url: 'wss://relay.primal.net', builtin: true, enabled: true, isLocal: false },
  { url: 'wss://relay.snort.social', builtin: true, enabled: true, isLocal: false }
];
const DEFAULT_MOD_PKX = bytesToHex(x25519.getPublicKey(sha256(utf8ToBytes('cipherpost-community-moderation-escrow-v1'))));

const state = {
  db: null, identity: null, theme: 'dark', pcLayout: 'stream',
  view: 'feed', previousView: 'feed', feedFilter: 'all', searchQuery: '',
  composeMode: 'public', composeCircleId: null, composeMedia: null,
  replyingToId: null, editingPostId: null, confirmDeletePostId: null,
  activeDmPeerPkX: null, unreadDms: 0,
  visitedProfilePkSecp: null, profileTab: 'posts', connectionsOwnerPkSecp: null, connectionsModalTab: 'following',
  relays: [], peers: new Map(), circles: new Map(), posts: new Map(), likes: new Map(), likeMeta: new Map(), dms: new Map(),
  vaultKey: null, vaultMeta: null, legacyIdentity: null,
  following: new Set(), followers: new Set(), followingUpdatedAt: 0, peerFollowing: new Map(),
  deletedPostIds: new Set(), deletedPostAuthors: new Map(), postEdits: new Map(),
  seenEventIds: new Set(), eventSources: new Map(), processedSignals: new Set()
};

const openDb = () => new Promise((res, rej) => {
  const req = indexedDB.open('cipherpost_db_v1', 1);
  req.onupgradeneeded = (e) => {
    const db = e.target.result;
    if (!db.objectStoreNames.contains('kv')) db.createObjectStore('kv', { keyPath: 'key' });
    if (!db.objectStoreNames.contains('events')) db.createObjectStore('events', { keyPath: 'id' });
  };
  req.onsuccess = () => res(req.result);
  req.onerror = () => rej(req.error);
});
const kvGet = (k) => new Promise((res) => { const r = state.db.transaction('kv', 'readonly').objectStore('kv').get(k); r.onsuccess = () => res(r.result?.value ?? null); r.onerror = () => res(null); });
const kvSet = (k, v) => new Promise((res) => { const tx = state.db.transaction('kv', 'readwrite'); tx.objectStore('kv').put({ key: k, value: v }); tx.oncomplete = () => res(); });
const saveEventToIdb = (ev) => { try { state.db?.transaction('events', 'readwrite').objectStore('events').put(ev); } catch {} };
const deleteEventFromIdb = (id) => { try { state.db?.transaction('events', 'readwrite').objectStore('events').delete(id); } catch {} };
const loadAllEventsFromIdb = () => new Promise((res) => { const r = state.db.transaction('events', 'readonly').objectStore('events').getAll(); r.onsuccess = () => res(r.result || []); r.onerror = () => res([]); });

/* --- ACCOUNT VAULT: identity + circle keys are encrypted at rest with the user's passphrase --- */
const VAULT_KDF = { t: 2, m: 16384, p: 1 };
const deriveVaultKey = (pass, saltB64) => argon2idAsync(utf8ToBytes(pass), b64UrlToBytes(saltB64), { ...VAULT_KDF, dkLen: 32 });
async function kvSetSecure(k, v) {
  const e = encryptXChaCha(state.vaultKey, utf8ToBytes(JSON.stringify(v)), 'cipherpost-vault-v1:' + k);
  await kvSet(k, { enc: 1, nonce: e.nonce, ct: e.ct });
}
async function kvGetSecure(k) {
  const r = await kvGet(k);
  if (!r || !r.enc) return null;
  return JSON.parse(bytesToUtf8(decryptXChaCha(state.vaultKey, r.nonce, r.ct, 'cipherpost-vault-v1:' + k)));
}
async function createVault(pass) {
  const salt = bytesToB64Url(randomBytes(16));
  state.vaultKey = await deriveVaultKey(pass, salt);
  state.vaultMeta = { v: 1, salt, check: encryptXChaCha(state.vaultKey, utf8ToBytes('ok'), 'cipherpost-vault-check') };
}
async function unlockVault(pass) {
  const meta = state.vaultMeta;
  if (!meta) return false;
  const key = await deriveVaultKey(pass, meta.salt);
  try {
    if (bytesToUtf8(decryptXChaCha(key, meta.check.nonce, meta.check.ct, 'cipherpost-vault-check')) !== 'ok') return false;
  } catch { return false; }
  state.vaultKey = key;
  return true;
}

async function persistState() {
  if (!state.vaultKey) return;
  state.vaultMeta = { ...state.vaultMeta, name: state.identity.name, handle: state.identity.handle, pkEd: state.identity.pkEd };
  await kvSet('vaultMeta', state.vaultMeta);
  await kvSetSecure('identity', state.identity);
  await kvSet('theme', state.theme);
  await kvSet('pcLayout', state.pcLayout);
  await kvSetSecure('circles', Array.from(state.circles.values()));
  await kvSet('contacts', Array.from(state.peers.values()).filter(p => p.isContact));
  await kvSet('following', Array.from(state.following));
  await kvSet('followers', Array.from(state.followers));
  await kvSet('followingUpdatedAt', state.followingUpdatedAt);
  await kvSet('deletedPostIds', Array.from(state.deletedPostIds));
  await kvSet('postEdits', Array.from(state.postEdits.entries()));
  await kvSet('relays', state.relays.map(r => ({ url: r.url, builtin: r.builtin, enabled: r.enabled, isLocal: r.isLocal })));
}

/* --- 4. LOCAL RELAY (BROADCASTCHANNEL) + PUBLIC WEBSOCKET RELAYS --- */
const localChannel = typeof BroadcastChannel !== 'undefined' ? new BroadcastChannel('cipherpost_local_relay_bus_v1') : null;
if (localChannel) {
  localChannel.onmessage = (e) => {
    const msg = e.data;
    const lr = state.relays.find(r => r.isLocal);
    if (!msg || !lr?.enabled) return;
    if (msg.type === 'EVENT' && msg.event) {
      lr.recv++; ingestEvent(msg.event, 'Local Relay (BroadcastChannel)'); renderRelayPanels();
    } else if (msg.type === 'SYNC_REQ') {
      loadAllEventsFromIdb().then(events => localChannel.postMessage({ type: 'SYNC_RES', events: events.slice(-80) }));
      announceProfileLocal();
    } else if (msg.type === 'SYNC_RES' && Array.isArray(msg.events)) {
      msg.events.forEach(ev => { lr.recv++; ingestEvent(ev, 'Local Relay (BroadcastChannel)'); });
      renderRelayPanels();
    }
  };
}

function connectRelay(relay) {
  if (relay.isLocal) { relay.status = relay.enabled ? 'Connected' : 'Offline'; renderRelayPanels(); return; }
  if (!relay.enabled) {
    try { relay.ws?.close(); } catch {}
    relay.ws = null; relay.status = 'Offline'; clearTimeout(relay.timer); renderRelayPanels(); return;
  }
  if (relay.ws && (relay.ws.readyState === WebSocket.OPEN || relay.ws.readyState === WebSocket.CONNECTING)) return;
  relay.status = 'Connecting'; renderRelayPanels();
  try {
    const ws = new WebSocket(relay.url);
    relay.ws = ws;
    ws.onopen = () => {
      relay.status = 'Connected'; relay.retryMs = 3000; renderRelayPanels();
      const now = Math.floor(Date.now() / 1000);
      const knownAuthors = Array.from(new Set([
        state.identity.pkSecp,
        ...Array.from(state.following),
        ...Array.from(state.peers.values()).filter(p => p.isContact).map(p => p.pkSecp),
        ...Array.from(state.circles.values()).flatMap(c => (c.members || []).map(m => m.pkSecp))
      ].filter(Boolean)));
      ws.send(JSON.stringify(['REQ', 'cp-authors-' + state.identity.pkSecp.slice(0, 8), { kinds: [0, 1, 3, 5, 7, 30078], authors: knownAuthors, '#t': ['cipherpost'], since: now - 604800, limit: 120 }]));
      ws.send(JSON.stringify(['REQ', 'cp-inbox-' + state.identity.pkSecp.slice(0, 8), { kinds: [30078], '#p': [state.identity.pkSecp], '#t': ['cipherpost'], since: now - 604800, limit: 120 }]));
      ws.send(JSON.stringify(['REQ', 'cp-followers-' + state.identity.pkSecp.slice(0, 8), { kinds: [3], '#p': [state.identity.pkSecp], '#t': ['cipherpost'], limit: 120 }]));
      ws.send(JSON.stringify(['EVENT', buildProfileEvent()]));
      relay.sent++;
    };
    ws.onmessage = (evt) => {
      try {
        const msg = JSON.parse(evt.data);
        if (!Array.isArray(msg)) return;
        if (msg[0] === 'EVENT' && msg[2]) { relay.recv++; ingestEvent(msg[2], relay.url); }
        else if (msg[0] === 'OK') { msg[2] ? relay.ok++ : relay.err++; }
        renderRelayPanels();
      } catch {}
    };
    ws.onerror = () => { relay.err++; };
    ws.onclose = () => {
      relay.ws = null; relay.status = 'Offline'; renderRelayPanels();
      if (relay.enabled) {
        const d = relay.retryMs || 3000;
        relay.retryMs = Math.min(d * 2, 30000);
        clearTimeout(relay.timer);
        relay.timer = setTimeout(() => connectRelay(relay), d);
      }
    };
  } catch { relay.status = 'Offline'; relay.err++; renderRelayPanels(); }
}
function subscribeRelayAuthors(relay) {
  if (!relay.ws || relay.ws.readyState !== WebSocket.OPEN) return;
  const now = Math.floor(Date.now() / 1000);
  const knownAuthors = Array.from(new Set([
    state.identity.pkSecp,
    ...Array.from(state.following),
    ...Array.from(state.peers.values()).filter(p => p.isContact).map(p => p.pkSecp),
    ...Array.from(state.circles.values()).flatMap(c => (c.members || []).map(m => m.pkSecp))
  ].filter(Boolean)));
  relay.ws.send(JSON.stringify(['REQ', 'cp-authors-' + state.identity.pkSecp.slice(0, 8), { kinds: [0, 1, 3, 5, 7, 30078], authors: knownAuthors, '#t': ['cipherpost'], since: now - 604800, limit: 120 }]));
}
const resubscribeAllRelays = () => state.relays.forEach(subscribeRelayAuthors);
const connectAllRelays = () => state.relays.forEach(connectRelay);
function fetchPeerProfileFromRelays(pkSecp) {
  if (!/^[0-9a-fA-F]{64}$/.test(pkSecp || '')) return;
  for (const r of state.relays) {
    if (!r.isLocal && r.enabled && r.ws?.readyState === WebSocket.OPEN) {
      r.ws.send(JSON.stringify(['REQ', 'cp-visit-' + pkSecp.slice(0, 8), { kinds: [0, 1, 3, 5, 7], authors: [pkSecp], '#t': ['cipherpost'], limit: 60 }]));
    }
  }
  localChannel?.postMessage({ type: 'SYNC_REQ' });
}

function publishEvent(ev) {
  ingestEvent(ev, 'Local Device');
  saveEventToIdb(ev);
  const lr = state.relays.find(r => r.isLocal);
  if (lr?.enabled && localChannel) { localChannel.postMessage({ type: 'EVENT', event: ev }); lr.sent++; lr.ok++; }
  const frame = JSON.stringify(['EVENT', ev]);
  for (const r of state.relays) {
    if (!r.isLocal && r.enabled && r.ws?.readyState === WebSocket.OPEN) { try { r.ws.send(frame); r.sent++; } catch { r.err++; } }
  }
  renderRelayPanels(); renderSearchPanels();
}

/* --- 6. EVENT INGESTION & VERIFICATION --- */
const getTag = (ev, k) => ev.tags.find(t => Array.isArray(t) && t[0] === k)?.[1] ?? null;
function upsertPeer(p, isContact = false) {
  if (!p?.pkSecp) return;
  const ex = state.peers.get(p.pkSecp);
  const safeAvatar = isSafeImageDataUrl(p.avatarDataUrl) ? p.avatarDataUrl : (ex?.avatarDataUrl || null);
  const safeBanner = isSafeImageDataUrl(p.bannerDataUrl) ? p.bannerDataUrl : (ex?.bannerDataUrl || null);
  state.peers.set(p.pkSecp, {
    pkSecp: p.pkSecp, pkEd: p.pkEd || ex?.pkEd || '', pkX: p.pkX || ex?.pkX || '',
    name: p.name || ex?.name || ('Peer ' + p.pkSecp.slice(0, 6)),
    handle: p.handle || ex?.handle || ('peer_' + p.pkSecp.slice(0, 6)),
    bio: typeof p.bio === 'string' ? p.bio.slice(0, 160) : (ex?.bio || ''),
    avatarDataUrl: safeAvatar,
    bannerDataUrl: safeBanner,
    lastSeen: Math.floor(Date.now() / 1000), isContact: Boolean(ex?.isContact || isContact)
  });
}
const buildProfileEvent = () => signNostrEvent(0, JSON.stringify({
  name: state.identity.name, display_name: state.identity.name, handle: state.identity.handle,
  about: state.identity.bio || '', bio: state.identity.bio || '',
  pkEd: state.identity.pkEd, pkX: state.identity.pkX,
  picture: isSafeImageDataUrl(state.identity.avatarDataUrl) ? state.identity.avatarDataUrl : undefined,
  banner: isSafeImageDataUrl(state.identity.bannerDataUrl) ? state.identity.bannerDataUrl : undefined,
  cipherpost: true
}), [['t', 'cipherpost'], ['cp-type', 'profile']]);
function announceProfileLocal() { const ev = buildProfileEvent(); localChannel?.postMessage({ type: 'EVENT', event: ev }); saveEventToIdb(ev); }

function isKnownOrLocalSource(ev, sourceLabel) {
  if (sourceLabel === 'Local Device' || sourceLabel.startsWith('Local Relay')) return true;
  if (ev.pubkey === state.identity.pkSecp) return true;
  if (state.visitedProfilePkSecp && ev.pubkey === state.visitedProfilePkSecp) return true;
  if (state.following.has(ev.pubkey)) return true;
  if (state.peers.get(ev.pubkey)?.isContact) return true;
  for (const c of state.circles.values()) {
    if ((c.members || []).some(m => m.pkSecp === ev.pubkey)) return true;
  }
  if (ev.kind === 3 && ev.tags.some(t => Array.isArray(t) && t[0] === 'p' && t[1] === state.identity.pkSecp)) return true;
  if (ev.kind === 30078 && getTag(ev, 'p') === state.identity.pkSecp) return true;
  return false;
}

async function ingestEvent(ev, sourceLabel = 'Unknown') {
  if (!verifyNostrEvent(ev)) return;
  const isCpTagged = ev.tags.some(t => t[0] === 't' && t[1] === 'cipherpost');
  if (!isCpTagged) return;
  if (!isKnownOrLocalSource(ev, sourceLabel)) return;

  if (!state.eventSources.has(ev.id)) state.eventSources.set(ev.id, new Set());
  state.eventSources.get(ev.id).add(sourceLabel);
  if (state.seenEventIds.has(ev.id)) return;
  state.seenEventIds.add(ev.id);
  saveEventToIdb(ev);

  const cpType = getTag(ev, 'cp-type');
  if (ev.kind === 0) {
    try {
      const prof = JSON.parse(ev.content);
      const safePic = isSafeImageDataUrl(prof.picture) ? prof.picture : null;
      const safeBan = isSafeImageDataUrl(prof.banner) ? prof.banner : null;
      const profBio = typeof prof.about === 'string' ? prof.about : (typeof prof.bio === 'string' ? prof.bio : null);
      if (ev.pubkey === state.identity.pkSecp && ev.created_at > (state.identity.profileUpdatedAt || 0)) {
        let selfUpdated = false;
        if (safePic && !state.identity.avatarDataUrl) { state.identity.avatarDataUrl = safePic; selfUpdated = true; }
        if (safeBan && !state.identity.bannerDataUrl) { state.identity.bannerDataUrl = safeBan; selfUpdated = true; }
        if (profBio && !state.identity.bio) { state.identity.bio = profBio.slice(0, 160); selfUpdated = true; }
        if (selfUpdated) {
          state.identity.profileUpdatedAt = ev.created_at;
          await persistState();
          renderIdentitySummary();
        }
      }
      upsertPeer({
        pkSecp: ev.pubkey, pkEd: prof.pkEd || '', pkX: prof.pkX || '',
        name: prof.display_name || prof.name, handle: prof.handle || prof.name,
        bio: profBio !== null ? profBio.slice(0, 160) : undefined,
        avatarDataUrl: safePic,
        bannerDataUrl: safeBan
      }, false);
      renderDmPeers(); renderSearchPanels(); renderCardsProfileStats(); renderTimeline();
      if (state.view === 'profile') renderVisitedProfile();
    } catch {}
    return;
  }
  if (ev.kind === 3) {
    const pTags = Array.from(new Set(ev.tags.filter(t => Array.isArray(t) && t[0] === 'p' && /^[0-9a-fA-F]{64}$/.test(t[1] || '')).map(t => t[1])));
    try {
      const meta = ev.content ? JSON.parse(ev.content) : null;
      if (meta && (meta.name || meta.pkX)) {
        upsertPeer({ pkSecp: ev.pubkey, pkEd: meta.pkEd || '', pkX: meta.pkX || '', name: meta.name, handle: meta.handle }, false);
      }
    } catch {}
    const prevPeerRec = state.peerFollowing.get(ev.pubkey);
    if (!prevPeerRec || ev.created_at >= prevPeerRec.ts) {
      const nextSet = new Set(pTags);
      state.peerFollowing.set(ev.pubkey, { ts: ev.created_at, set: nextSet });
      if (ev.pubkey === state.identity.pkSecp) {
        if (ev.created_at > state.followingUpdatedAt) {
          state.following = nextSet;
          state.followingUpdatedAt = ev.created_at;
          await persistState();
          resubscribeAllRelays();
        }
      } else {
        if (nextSet.has(state.identity.pkSecp)) state.followers.add(ev.pubkey);
        else state.followers.delete(ev.pubkey);
        await persistState();
      }
      renderCardsProfileStats(); renderTimeline(); renderDmMessages(); renderSearchPanels();
    }
    return;
  }
  if (ev.kind === 5) {
    const targetIds = ev.tags.filter(t => Array.isArray(t) && t[0] === 'e' && t[1]).map(t => t[1]);
    let changed = false;
    let likesChanged = false;
    for (const tid of targetIds) {
      state.deletedPostAuthors.set(tid, ev.pubkey);
      const target = state.posts.get(tid);
      if (target && target.pubkey === ev.pubkey) {
        state.posts.delete(tid);
        state.deletedPostIds.add(tid);
        state.postEdits.delete(tid);
        deleteEventFromIdb(tid);
        changed = true;
      }
      for (const [likedPostId, authorMap] of state.likeMeta.entries()) {
        const meta = authorMap.get(ev.pubkey);
        if (meta && meta.eventId === tid && ev.created_at >= meta.createdAt) {
          authorMap.set(ev.pubkey, { liked: false, createdAt: ev.created_at, eventId: ev.id });
          state.likes.get(likedPostId)?.delete(ev.pubkey);
          state.deletedPostIds.add(tid);
          deleteEventFromIdb(tid);
          likesChanged = true;
        }
      }
    }
    if (changed) { await persistState(); renderTimeline(); renderCardsProfileStats(); renderSearchPanels(); }
    else if (likesChanged) { await persistState(); renderTimeline(); if (state.view === 'profile') renderVisitedProfile(); renderSearchPanels(); }
    return;
  }
  if (ev.kind === 7) {
    if (state.deletedPostIds.has(ev.id)) { deleteEventFromIdb(ev.id); return; }
    const t = getTag(ev, 'e');
    if (t) {
      const isUnlike = ev.content === '-' || ev.content === 'unlike';
      let postMeta = state.likeMeta.get(t);
      if (!postMeta) { postMeta = new Map(); state.likeMeta.set(t, postMeta); }
      const prev = postMeta.get(ev.pubkey);
      if (!prev || ev.created_at > prev.createdAt || (ev.created_at === prev.createdAt && ev.id !== prev.eventId && isUnlike)) {
        postMeta.set(ev.pubkey, { liked: !isUnlike, createdAt: ev.created_at, eventId: ev.id });
        if (!state.likes.has(t)) state.likes.set(t, new Set());
        if (isUnlike) state.likes.get(t).delete(ev.pubkey);
        else state.likes.get(t).add(ev.pubkey);
        renderTimeline();
        if (state.view === 'profile') renderVisitedProfile();
        renderSearchPanels();
      }
    }
    return;
  }
  if (ev.kind === 1) {
    if (state.deletedPostIds.has(ev.id) || state.deletedPostAuthors.get(ev.id) === ev.pubkey) {
      deleteEventFromIdb(ev.id); return;
    }
    const pkEd = getTag(ev, 'pkEd'), edSig = getTag(ev, 'edSig'), replyTo = getTag(ev, 'e');
    let text = ev.content, mediaDataUrl = null, verification = 'Schnorr BIP-340';
    if (pkEd && edSig) {
      try {
        const b = JSON.parse(ev.content);
        text = String(b.text || '');
        mediaDataUrl = isSafeImageDataUrl(b.mediaDataUrl) ? b.mediaDataUrl : null;
        const okEd = verifyEdPayload({ v: 1, type: 'public', pkEd, pkSecp: ev.pubkey, created_at: ev.created_at, text, mediaHash: mediaDataUrl ? bytesToHex(sha256(utf8ToBytes(mediaDataUrl))) : '' }, edSig, pkEd);
        verification = okEd ? 'Ed25519 + Schnorr' : 'Invalid Ed25519';
        if (b.authorName || b.pkX) upsertPeer({ pkSecp: ev.pubkey, pkEd, pkX: b.pkX || '', name: b.authorName, handle: b.authorHandle }, false);
      } catch {}
    }
    const savedEdit = state.postEdits.get(ev.id);
    let editedAt = null;
    if (savedEdit && savedEdit.pubkey === ev.pubkey) { text = savedEdit.text; editedAt = savedEdit.editedAt; }
    const peer = state.peers.get(ev.pubkey);
    state.posts.set(ev.id, {
      id: ev.id, pubkey: ev.pubkey, pkEd: pkEd || '',
      authorName: peer?.name || (ev.pubkey === state.identity.pkSecp ? state.identity.name : 'Peer ' + ev.pubkey.slice(0, 6)),
      authorHandle: peer?.handle || (ev.pubkey === state.identity.pkSecp ? state.identity.handle : ev.pubkey.slice(0, 8)),
      createdAt: ev.created_at, editedAt, text, mediaDataUrl, replyTo, mode: 'public',
      circleId: null, circleName: null, epoch: null, verification, locked: false, rawEvent: ev
    });
    renderTimeline(); renderCardsProfileStats(); renderSearchPanels(); return;
  }
  if (ev.kind === 30078 && cpType) {
    let d; try { d = JSON.parse(ev.content); } catch { return; }
    if (cpType === 'post-edit') {
      const { targetId, text, editedAt, pkEd, edSig } = d;
      if (!targetId || typeof text !== 'string' || !Number.isInteger(editedAt)) return;
      if (!verifyEdPayload({ v: 1, type: 'post-edit', targetId, text, editedAt }, edSig, pkEd)) return;
      if (state.deletedPostIds.has(targetId)) return;
      const prev = state.postEdits.get(targetId);
      if (!prev || editedAt >= prev.editedAt) {
        state.postEdits.set(targetId, { text, editedAt, pubkey: ev.pubkey });
        const target = state.posts.get(targetId);
        if (target && target.pubkey === ev.pubkey) { target.text = text; target.editedAt = editedAt; renderTimeline(); if (state.view === 'profile') renderVisitedProfile(); }
        await persistState();
      }
      return;
    }
    if (cpType === 'circle-post-edit') {
      const { targetId, circleId, epoch, nonce, ct, senderPkEd, edSig } = d;
      const circle = state.circles.get(circleId), keyHex = circle?.keys?.[String(epoch)];
      if (!keyHex || state.deletedPostIds.has(targetId)) return;
      try {
        const body = JSON.parse(bytesToUtf8(decryptXChaCha(hexToBytes(keyHex), nonce, ct, `${circleId}:${epoch}:${senderPkEd}:edit`)));
        if (!verifyEdPayload({ v: 1, type: 'circle-post-edit', targetId, circleId, epoch, nonce, ct }, edSig, senderPkEd)) return;
        const prev = state.postEdits.get(targetId);
        if (!prev || body.editedAt >= prev.editedAt) {
          state.postEdits.set(targetId, { text: String(body.text || ''), editedAt: body.editedAt, pubkey: ev.pubkey });
          const target = state.posts.get(targetId);
          if (target && target.pubkey === ev.pubkey) { target.text = String(body.text || ''); target.editedAt = body.editedAt; renderTimeline(); if (state.view === 'profile') renderVisitedProfile(); }
          await persistState();
        }
      } catch {}
      return;
    }
    if (cpType === 'circle-key') {
      if ((d.recipientPkSecp !== state.identity.pkSecp && d.senderPkX !== state.identity.pkX) || !d.senderPkX || !d.senderPkEd) return;
      if (ev.pubkey === state.identity.pkSecp && state.circles.has(d.circleId)) return;
      try {
        const pairKey = derivePairwiseKey(state.identity.skXHex, d.senderPkX, `${d.circleId}:${d.epoch}`, 'cipherpost-circle-wrap-v1');
        const kb = JSON.parse(bytesToUtf8(decryptXChaCha(pairKey, d.nonce, d.ct, `${d.circleId}:${d.epoch}:${state.identity.pkX}`)));
        if (!verifyEdPayload({ v: 1, type: 'circle-key', circleId: d.circleId, epoch: d.epoch, recipientPkX: state.identity.pkX, nonce: d.nonce, ct: d.ct }, d.edSig, d.senderPkEd)) return;
        const ex = state.circles.get(d.circleId) || { circleId: d.circleId, name: kb.circleName, ownerPkSecp: ev.pubkey, ownerPkEd: d.senderPkEd, ownerPkX: d.senderPkX, epoch: d.epoch, keys: {}, members: kb.members || [] };
        ex.name = kb.circleName; ex.keys[String(d.epoch)] = kb.circleKeyHex;
        if (d.epoch >= ex.epoch) { ex.epoch = d.epoch; ex.members = kb.members || ex.members; }
        state.circles.set(d.circleId, ex);
        upsertPeer({ pkSecp: ev.pubkey, pkEd: d.senderPkEd, pkX: d.senderPkX, name: kb.ownerName, handle: kb.ownerHandle }, false);
        await persistState(); await reprocessLockedCirclePosts(d.circleId);
        renderCircles(); renderComposerCircles(); renderCardsProfileStats();
        toast(`Received E2EE key for "${ex.name}" (Epoch ${d.epoch})`, 'ok');
      } catch {}
      return;
    }
    if (cpType === 'circle-post') {
      if (state.deletedPostIds.has(ev.id) || state.deletedPostAuthors.get(ev.id) === ev.pubkey) {
        deleteEventFromIdb(ev.id); return;
      }
      const { circleId, epoch, nonce, ct, senderPkEd, senderPkX, edSig } = d;
      const circle = state.circles.get(circleId), keyHex = circle?.keys?.[String(epoch)], peer = state.peers.get(ev.pubkey);
      if (keyHex) {
        try {
          const body = JSON.parse(bytesToUtf8(decryptXChaCha(hexToBytes(keyHex), nonce, ct, `${circleId}:${epoch}:${senderPkEd}`)));
          const validSig = verifyEdPayload({ v: 1, type: 'circle-post', circleId, epoch, nonce, ct }, edSig, senderPkEd);
          const mediaDataUrl = isSafeImageDataUrl(body.mediaDataUrl) ? body.mediaDataUrl : null;
          if (body.authorName) upsertPeer({ pkSecp: ev.pubkey, pkEd: senderPkEd, pkX: senderPkX, name: body.authorName, handle: body.authorHandle }, false);
          let text = String(body.text || ''), editedAt = null;
          const savedEdit = state.postEdits.get(ev.id);
          if (savedEdit && savedEdit.pubkey === ev.pubkey) { text = savedEdit.text; editedAt = savedEdit.editedAt; }
          state.posts.set(ev.id, {
            id: ev.id, pubkey: ev.pubkey, pkEd: senderPkEd, authorName: body.authorName || peer?.name || ('Peer ' + ev.pubkey.slice(0, 6)),
            authorHandle: body.authorHandle || peer?.handle || ev.pubkey.slice(0, 8), createdAt: ev.created_at, editedAt,
            text, mediaDataUrl, replyTo: body.replyTo || null, mode: 'circle',
            circleId, circleName: circle.name, epoch, verification: validSig ? 'XChaCha20-Poly1305 · Ed25519' : 'Invalid Signature', locked: false, rawEvent: ev
          });
          renderTimeline(); renderCardsProfileStats(); renderSearchPanels(); return;
        } catch {}
      }
      if (circle) {
        state.posts.set(ev.id, {
          id: ev.id, pubkey: ev.pubkey, pkEd: senderPkEd || '', authorName: peer?.name || ('Peer ' + ev.pubkey.slice(0, 6)),
          authorHandle: peer?.handle || ev.pubkey.slice(0, 8), createdAt: ev.created_at, editedAt: null,
          text: `Encrypted post for "${circle.name}" (Epoch ${epoch}). Epoch key not held (access revoked or not invited).`,
          mediaDataUrl: null, replyTo: null, mode: 'circle', circleId, circleName: circle.name, epoch, verification: 'Key Not Held', locked: true, rawEvent: ev
        });
        renderTimeline(); renderCardsProfileStats(); renderSearchPanels();
      }
      return;
    }
    if (cpType === 'dm') {
      const { senderPkEd, senderPkX, recipientPkSecp, recipientPkX, nonce, ct, edSig } = d;
      const isMe = ev.pubkey === state.identity.pkSecp;
      if (!isMe && recipientPkSecp !== state.identity.pkSecp && recipientPkX !== state.identity.pkX) return;
      const peerPkX = isMe ? recipientPkX : senderPkX, peerSecp = isMe ? recipientPkSecp : ev.pubkey;
      if (!peerPkX) return;
      try {
        const pairKey = derivePairwiseKey(state.identity.skXHex, peerPkX, [state.identity.pkX, peerPkX].sort().join(':'), 'cipherpost-dm-v1');
        const body = JSON.parse(bytesToUtf8(decryptXChaCha(pairKey, nonce, ct, `${senderPkX}:${recipientPkX}`)));
        const validSig = verifyEdPayload({ v: 1, type: 'dm', senderPkX, recipientPkX, nonce, ct }, edSig, senderPkEd);
        if (!isMe && body.senderName) upsertPeer({ pkSecp: peerSecp, pkEd: senderPkEd, pkX: senderPkX, name: body.senderName, handle: body.senderHandle }, false);
        if (!state.dms.has(peerPkX)) state.dms.set(peerPkX, []);
        const thread = state.dms.get(peerPkX);
        if (!thread.some(m => m.id === ev.id)) {
          thread.push({ id: ev.id, senderPkX, recipientPkX, text: String(body.text || ''), nonce, createdAt: ev.created_at, verified: validSig });
          thread.sort((a, b) => a.createdAt - b.createdAt);
          if (!isMe && (state.view !== 'dms' || state.activeDmPeerPkX !== peerPkX)) state.unreadDms++;
          renderDmPeers(); renderDmMessages(); updateNavBadges();
        }
      } catch {}
    }
  }
}

async function reprocessLockedCirclePosts(circleId) {
  for (const p of Array.from(state.posts.values()).filter(x => x.circleId === circleId && x.locked && x.rawEvent)) {
    state.seenEventIds.delete(p.id); await ingestEvent(p.rawEvent, 'Local Re-decrypt');
  }
}

/* --- 7. CIRCLES, KEY WRAPPING & PUBLISHING --- */
function buildCircle(name) {
  const circleId = bytesToHex(randomBytes(12));
  return {
    circleId, name: name.trim(), ownerPkSecp: state.identity.pkSecp, ownerPkEd: state.identity.pkEd, ownerPkX: state.identity.pkX,
    epoch: 1, keys: { '1': bytesToHex(randomBytes(32)) },
    members: [{ pkSecp: state.identity.pkSecp, pkEd: state.identity.pkEd, pkX: state.identity.pkX, name: state.identity.name, handle: state.identity.handle }]
  };
}
async function createCircle(name) {
  const c = buildCircle(name);
  state.circles.set(c.circleId, c);
  await persistState(); renderCircles(); renderComposerCircles(); renderCardsProfileStats(); updateNavBadges();
}

function distributeCircleKey(circle) {
  const bundleBytes = utf8ToBytes(JSON.stringify({ circleName: circle.name, circleKeyHex: circle.keys[String(circle.epoch)], ownerName: state.identity.name, ownerHandle: state.identity.handle, members: circle.members }));
  for (const m of circle.members) {
    if (m.pkX === state.identity.pkX) continue;
    const pairKey = derivePairwiseKey(state.identity.skXHex, m.pkX, `${circle.circleId}:${circle.epoch}`, 'cipherpost-circle-wrap-v1');
    const ew = encryptXChaCha(pairKey, bundleBytes, `${circle.circleId}:${circle.epoch}:${m.pkX}`);
    const edSig = signEdPayload({ v: 1, type: 'circle-key', circleId: circle.circleId, epoch: circle.epoch, recipientPkX: m.pkX, nonce: ew.nonce, ct: ew.ct });
    publishEvent(signNostrEvent(30078, JSON.stringify({ circleId: circle.circleId, epoch: circle.epoch, senderPkEd: state.identity.pkEd, senderPkX: state.identity.pkX, recipientPkSecp: m.pkSecp, nonce: ew.nonce, ct: ew.ct, edSig }), [['d', `ck-${circle.circleId}-${circle.epoch}-${m.pkSecp.slice(0, 8)}`], ['t', 'cipherpost'], ['cp-type', 'circle-key'], ['p', m.pkSecp]]));
  }
}

async function addCircleMember(circleId, peer) {
  const c = state.circles.get(circleId);
  if (!c || c.ownerPkSecp !== state.identity.pkSecp) return;
  if (c.members.some(m => m.pkX === peer.pkX)) return toast('Peer already in circle', 'warn');
  c.members.push({ pkSecp: peer.pkSecp, pkEd: peer.pkEd, pkX: peer.pkX, name: peer.name, handle: peer.handle });
  distributeCircleKey(c); await persistState(); renderCircles();
  toast(`Wrapped Epoch ${c.epoch} key for ${peer.name}`, 'ok');
}

async function rotateCircleKey(circleId, removePkX = null) {
  const c = state.circles.get(circleId);
  if (!c || c.ownerPkSecp !== state.identity.pkSecp) return;
  if (removePkX) c.members = c.members.filter(m => m.pkX !== removePkX);
  c.epoch += 1; c.keys[String(c.epoch)] = bytesToHex(randomBytes(32));
  distributeCircleKey(c); await persistState(); renderCircles(); renderComposerCircles();
  toast(removePkX ? `Removed member & rotated "${c.name}" to Epoch ${c.epoch}` : `Rotated "${c.name}" to Epoch ${c.epoch}`, 'ok');
}

function publishPublicPost(text, mediaDataUrl = null, replyTo = null) {
  const createdAt = Math.floor(Date.now() / 1000);
  const mediaHash = mediaDataUrl ? bytesToHex(sha256(utf8ToBytes(mediaDataUrl))) : '';
  const edSig = signEdPayload({ v: 1, type: 'public', pkEd: state.identity.pkEd, pkSecp: state.identity.pkSecp, created_at: createdAt, text, mediaHash });
  const tags = [['t', 'cipherpost'], ['pkEd', state.identity.pkEd], ['edSig', edSig]];
  if (replyTo) tags.push(['e', replyTo]);
  publishEvent(signNostrEvent(1, JSON.stringify({ text, mediaDataUrl: mediaDataUrl || undefined, authorName: state.identity.name, authorHandle: state.identity.handle, pkX: state.identity.pkX }), tags, createdAt));
}

function publishCirclePost(circleId, text, mediaDataUrl = null, replyTo = null) {
  const c = state.circles.get(circleId);
  if (!c || !c.keys[String(c.epoch)]) throw new Error('Missing circle epoch key');
  const createdAt = Math.floor(Date.now() / 1000);
  const ep = encryptXChaCha(hexToBytes(c.keys[String(c.epoch)]), utf8ToBytes(JSON.stringify({ text, mediaDataUrl: mediaDataUrl || undefined, replyTo: replyTo || undefined, authorName: state.identity.name, authorHandle: state.identity.handle, created_at: createdAt })), `${circleId}:${c.epoch}:${state.identity.pkEd}`);
  const edSig = signEdPayload({ v: 1, type: 'circle-post', circleId, epoch: c.epoch, nonce: ep.nonce, ct: ep.ct });
  publishEvent(signNostrEvent(30078, JSON.stringify({ circleId, epoch: c.epoch, senderPkEd: state.identity.pkEd, senderPkX: state.identity.pkX, nonce: ep.nonce, ct: ep.ct, edSig }), [['d', `cp-${circleId}-${bytesToHex(randomBytes(6))}`], ['t', 'cipherpost'], ['cp-type', 'circle-post']], createdAt));
}

async function toggleLike(postId) {
  if (!postId) return;
  const myPk = state.identity.pkSecp;
  const currentlyLiked = Boolean(state.likes.get(postId)?.has(myPk));
  let postMeta = state.likeMeta.get(postId);
  if (!postMeta) { postMeta = new Map(); state.likeMeta.set(postId, postMeta); }
  const prevMeta = postMeta.get(myPk);
  const createdAt = Math.max(Math.floor(Date.now() / 1000), (prevMeta?.createdAt || 0) + 1);

  if (currentlyLiked) {
    state.likes.get(postId)?.delete(myPk);
    if (prevMeta?.eventId) {
      state.deletedPostIds.add(prevMeta.eventId);
      deleteEventFromIdb(prevMeta.eventId);
      publishEvent(signNostrEvent(5, 'Like removed', [['e', prevMeta.eventId], ['t', 'cipherpost'], ['cp-type', 'like-delete']], createdAt));
    }
    const unlikeEv = signNostrEvent(7, '-', [['t', 'cipherpost'], ['e', postId]], createdAt);
    postMeta.set(myPk, { liked: false, createdAt, eventId: unlikeEv.id });
    await persistState();
    publishEvent(unlikeEv);
  } else {
    if (!state.likes.has(postId)) state.likes.set(postId, new Set());
    state.likes.get(postId).add(myPk);
    const likeEv = signNostrEvent(7, '+', [['t', 'cipherpost'], ['e', postId]], createdAt);
    postMeta.set(myPk, { liked: true, createdAt, eventId: likeEv.id });
    publishEvent(likeEv);
  }
  renderTimeline();
  if (state.view === 'profile') renderVisitedProfile();
  renderSearchPanels();
}

async function deleteOwnPost(post) {
  if (!post || post.pubkey !== state.identity.pkSecp) return;
  state.posts.delete(post.id);
  state.deletedPostIds.add(post.id);
  state.postEdits.delete(post.id);
  deleteEventFromIdb(post.id);
  if (state.editingPostId === post.id) state.editingPostId = null;
  if (state.confirmDeletePostId === post.id) state.confirmDeletePostId = null;
  await persistState();
  renderTimeline();
  renderCardsProfileStats();
  const edSig = signEdPayload({ v: 1, type: 'post-delete', targetId: post.id });
  publishEvent(signNostrEvent(5, 'Post deleted by author', [['e', post.id], ['t', 'cipherpost'], ['cp-type', 'post-delete'], ['pkEd', state.identity.pkEd], ['edSig', edSig]]));
  toast('Post deleted', 'info');
}

async function editOwnPost(post, newText) {
  if (!post || post.pubkey !== state.identity.pkSecp || post.locked) return;
  const cleanText = newText.trim();
  if (!cleanText && !post.mediaDataUrl) return toast('Post cannot be empty', 'err');
  const editedAt = Math.floor(Date.now() / 1000);
  post.text = cleanText;
  post.editedAt = editedAt;
  state.postEdits.set(post.id, { text: cleanText, editedAt, pubkey: state.identity.pkSecp });
  state.editingPostId = null;
  await persistState();
  renderTimeline();
  if (state.view === 'profile') renderVisitedProfile();

  if (post.mode === 'circle' && post.circleId && state.circles.has(post.circleId)) {
    const c = state.circles.get(post.circleId);
    const keyHex = c?.keys?.[String(post.epoch || c.epoch)];
    if (keyHex) {
      const epUsed = post.epoch || c.epoch;
      const ep = encryptXChaCha(hexToBytes(keyHex), utf8ToBytes(JSON.stringify({ targetId: post.id, text: cleanText, editedAt })), `${post.circleId}:${epUsed}:${state.identity.pkEd}:edit`);
      const edSig = signEdPayload({ v: 1, type: 'circle-post-edit', targetId: post.id, circleId: post.circleId, epoch: epUsed, nonce: ep.nonce, ct: ep.ct });
      publishEvent(signNostrEvent(30078, JSON.stringify({ targetId: post.id, circleId: post.circleId, epoch: epUsed, senderPkEd: state.identity.pkEd, nonce: ep.nonce, ct: ep.ct, edSig }), [['d', `cedit-${post.id.slice(0, 16)}`], ['e', post.id], ['t', 'cipherpost'], ['cp-type', 'circle-post-edit']], editedAt));
    }
  } else {
    const edSig = signEdPayload({ v: 1, type: 'post-edit', targetId: post.id, text: cleanText, editedAt });
    publishEvent(signNostrEvent(30078, JSON.stringify({ targetId: post.id, text: cleanText, editedAt, pkEd: state.identity.pkEd, edSig }), [['d', `edit-${post.id.slice(0, 16)}`], ['e', post.id], ['t', 'cipherpost'], ['cp-type', 'post-edit']], editedAt));
  }
  toast('Post updated', 'ok');
}

function publishFollowList() {
  const createdAt = Math.max(Math.floor(Date.now() / 1000), (state.followingUpdatedAt || 0) + 1);
  state.followingUpdatedAt = createdAt;
  const list = Array.from(state.following).filter(pk => /^[0-9a-fA-F]{64}$/.test(pk) && pk !== state.identity.pkSecp);
  const edSig = signEdPayload({ v: 1, type: 'follow-list', pkSecp: state.identity.pkSecp, created_at: createdAt, following: list });
  const tags = [['t', 'cipherpost'], ['cp-type', 'follow-list'], ['pkEd', state.identity.pkEd], ['edSig', edSig], ...list.map(pk => ['p', pk])];
  const meta = JSON.stringify({ v: 1, name: state.identity.name, handle: state.identity.handle, pkEd: state.identity.pkEd, pkX: state.identity.pkX });
  publishEvent(signNostrEvent(3, meta, tags, createdAt));
}

async function toggleFollow(targetPkSecp, peerMeta = null) {
  if (!targetPkSecp || targetPkSecp === state.identity.pkSecp) return;
  if (peerMeta) upsertPeer(peerMeta, true);
  const peer = state.peers.get(targetPkSecp);
  const label = peer?.name || ('Peer ' + targetPkSecp.slice(0, 6));
  if (state.following.has(targetPkSecp)) {
    state.following.delete(targetPkSecp);
    publishFollowList();
    await persistState();
    toast(`Unfollowed ${label}`, 'info');
  } else {
    state.following.add(targetPkSecp);
    if (peer) peer.isContact = true;
    else upsertPeer({ pkSecp: targetPkSecp }, true);
    publishFollowList();
    await persistState();
    resubscribeAllRelays();
    toast(`Following ${label}`, 'ok');
  }
  renderCardsProfileStats(); renderTimeline(); renderDmMessages(); renderSearchPanels();
  if (!$('connections-modal').classList.contains('hidden')) renderConnectionsModal();
  if (state.view === 'profile') renderVisitedProfile();
}

function publishDm(peerPkX, text) {
  const peer = Array.from(state.peers.values()).find(p => p.pkX === peerPkX);
  if (!peer) throw new Error('Peer not found');
  const createdAt = Math.floor(Date.now() / 1000);
  const pairKey = derivePairwiseKey(state.identity.skXHex, peer.pkX, [state.identity.pkX, peer.pkX].sort().join(':'), 'cipherpost-dm-v1');
  const encDm = encryptXChaCha(pairKey, utf8ToBytes(JSON.stringify({ text, senderName: state.identity.name, senderHandle: state.identity.handle, ts: createdAt })), `${state.identity.pkX}:${peer.pkX}`);
  const edSig = signEdPayload({ v: 1, type: 'dm', senderPkX: state.identity.pkX, recipientPkX: peer.pkX, nonce: encDm.nonce, ct: encDm.ct });
  publishEvent(signNostrEvent(30078, JSON.stringify({ senderPkEd: state.identity.pkEd, senderPkX: state.identity.pkX, recipientPkSecp: peer.pkSecp, recipientPkX: peer.pkX, nonce: encDm.nonce, ct: encDm.ct, edSig }), [['d', `dm-${bytesToHex(randomBytes(6))}`], ['t', 'cipherpost'], ['cp-type', 'dm'], ['p', peer.pkSecp]], createdAt));
}

/* --- 8. UI RENDERING (XSS-SAFE DOM CONSTRUCTION) --- */
const avatarColor = (hex) => ['#1D9BF0', '#0D9488', '#2563EB', '#D97706', '#DC2626', '#4F46E5', '#059669'][hex ? parseInt(hex.slice(0, 2), 16) % 7 : 0];
function setAvatar(node, name, hex, avatarDataUrl = null) {
  if (!node) return;
  node.textContent = '';
  node.classList.add('overflow-hidden');
  if (avatarDataUrl && isSafeImageDataUrl(avatarDataUrl)) {
    node.style.backgroundColor = 'transparent';
    node.appendChild(el('img', {
      src: avatarDataUrl,
      alt: `${name || 'Peer'} avatar`,
      referrerpolicy: 'no-referrer',
      className: 'w-full h-full object-cover'
    }));
  } else {
    node.style.backgroundColor = avatarColor(hex);
    node.textContent = (name || 'C').trim().slice(0, 2).toUpperCase();
  }
}
function applyCoverGradient(node, hex, bannerDataUrl = null) {
  if (!node) return;
  if (bannerDataUrl && isSafeImageDataUrl(bannerDataUrl)) {
    node.style.background = '';
    node.style.backgroundImage = `url("${bannerDataUrl}")`;
    node.style.backgroundSize = 'cover';
    node.style.backgroundPosition = 'center';
  } else {
    node.style.backgroundImage = '';
    const c1 = avatarColor(hex || '1d');
    const c2 = avatarColor((hex || '4f').slice(2));
    node.style.background = `linear-gradient(135deg, ${c1} 0%, ${c2} 100%)`;
  }
}
function formatTime(sec) {
  const diff = Math.max(0, Math.floor(Date.now() / 1000) - sec);
  if (diff < 60) return `${diff}s`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h`;
  return new Date(sec * 1000).toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
}
const statusColor = (s) => s === 'Connected' ? 'var(--ok)' : s === 'Connecting' ? 'var(--warn)' : 'var(--err)';

function toast(msg, kind = 'info') {
  const col = kind === 'ok' ? 'var(--ok)' : kind === 'err' ? 'var(--err)' : kind === 'warn' ? 'var(--warn)' : 'var(--accent)';
  const item = el('div', { className: 'pointer-events-auto px-3.5 py-2.5 rounded-xl border border-hairline surface-elevated text-xs font-medium text-main shadow-lg flex items-center gap-2' },
    el('span', { className: 'w-2 h-2 rounded-full shrink-0', style: { backgroundColor: col } }),
    el('span', { textContent: msg })
  );
  $('toast-stack').appendChild(item);
  setTimeout(() => item.remove(), 3500);
}

function applyThemeAndLayout() {
  document.documentElement.classList.toggle('light', state.theme === 'light');
  document.documentElement.dataset.pcLayout = state.pcLayout;
  renderSettingsView();
}

function switchView(v) {
  if (v === 'identity') {
    visitUserProfile(state.identity.pkSecp);
    return;
  }
  if (v !== 'profile' && state.view !== 'profile') state.previousView = v;
  state.view = v;
  const labels = {
    feed: 'Home',
    circles: 'Private Circles',
    dms: 'Messages',
    profile: 'Profile',
    settings: 'Settings'
  };
  Object.keys(labels).forEach(k => $('view-' + k)?.classList.toggle('hidden', k !== v));
  $('mobile-view-label').textContent = labels[v] || 'Home';
  const isOwnProfileNav = v === 'profile' && state.visitedProfilePkSecp === state.identity.pkSecp;
  document.querySelectorAll('.nav-item[data-nav]').forEach(b => {
    b.classList.toggle('active', b.dataset.nav === v || (b.dataset.nav === 'identity' && isOwnProfileNav));
  });
  document.querySelectorAll('.cards-top-nav-item[data-nav]').forEach(b => {
    b.classList.toggle('active', b.dataset.nav === v || (b.dataset.nav === 'identity' && isOwnProfileNav));
  });
  document.querySelectorAll('.mobile-nav-btn[data-nav]').forEach(b => {
    const a = b.dataset.nav === v || (b.dataset.nav === 'identity' && isOwnProfileNav);
    b.classList.toggle('text-main', a);
    b.classList.toggle('text-dim', !a);
  });
  if (v !== 'profile' && window.location.hash.startsWith('#profile/')) {
    try { history.replaceState(null, '', '#' + v); } catch {}
  }
  if (v === 'dms' && state.activeDmPeerPkX) { state.unreadDms = 0; updateNavBadges(); }
  if (v === 'profile') renderVisitedProfile();
  if (v === 'circles') renderCircles();
  if (v === 'settings') renderSettingsView();
  window.scrollTo(0, 0);
}

function updateNavBadges() {
  $('nav-circles-count').textContent = String(state.circles.size);
  $('nav-dms-count').textContent = String(state.unreadDms);
  const cardsDmBadge = $('cards-dms-badge');
  if (cardsDmBadge) {
    cardsDmBadge.textContent = String(state.unreadDms);
    cardsDmBadge.classList.toggle('hidden', state.unreadDms === 0);
  }
}

function renderIdentitySummary() {
  const avUrl = state.identity.avatarDataUrl || null;
  const bnUrl = state.identity.bannerDataUrl || null;
  setAvatar($('sidebar-avatar'), state.identity.name, state.identity.pkEd, avUrl);
  setAvatar($('composer-avatar'), state.identity.name, state.identity.pkEd, avUrl);
  setAvatar($('mobile-profile-btn'), state.identity.name, state.identity.pkEd, avUrl);
  setAvatar($('cards-topbar-avatar'), state.identity.name, state.identity.pkEd, avUrl);
  setAvatar($('cards-profile-avatar'), state.identity.name, state.identity.pkEd, avUrl);
  setAvatar($('profile-form-avatar-preview'), state.identity.name, state.identity.pkEd, avUrl);
  applyCoverGradient($('cards-profile-banner'), state.identity.pkEd, bnUrl);
  applyCoverGradient($('profile-form-banner-preview'), state.identity.pkEd, bnUrl);

  const hasAv = isSafeImageDataUrl(avUrl);
  const hasBn = isSafeImageDataUrl(bnUrl);
  $('profile-avatar-remove')?.classList.toggle('hidden', !hasAv);
  $('profile-banner-remove')?.classList.toggle('hidden', !hasBn);

  const bioText = (state.identity.bio || '').trim();
  $('sidebar-name').textContent = state.identity.name;
  $('sidebar-handle').textContent = '@' + state.identity.handle;
  $('cards-topbar-name').textContent = state.identity.name;
  $('cards-profile-name').textContent = state.identity.name;
  $('cards-profile-handle').textContent = '@' + state.identity.handle;
  $('cards-profile-bio').textContent = bioText;
  $('cards-profile-bio').classList.toggle('hidden', !bioText);
  renderCardsProfileStats();
}

function renderCardsProfileStats() {
  const postCount = state.posts.size;
  const followersCount = state.followers.size;
  const followingCount = state.following.size;

  $('cards-stat-posts').textContent = String(postCount);
  $('cards-stat-followers').textContent = String(followersCount);
  $('cards-stat-following').textContent = String(followingCount);

  if (!$('connections-modal').classList.contains('hidden')) renderConnectionsModal();
  if (state.view === 'profile') renderVisitedProfile();

  const shortcuts = $('cards-circles-shortcuts');
  if (shortcuts) {
    shortcuts.textContent = '';
    for (const c of state.circles.values()) {
      const icon = el('div', { className: 'w-7 h-7 rounded-full shrink-0 flex items-center justify-center font-display font-bold text-xs text-white' });
      setAvatar(icon, c.name, c.circleId);
      shortcuts.appendChild(el('button', {
        type: 'button',
        className: 'w-full flex items-center justify-between gap-2 px-2 py-1.5 rounded-xl hover-row text-left transition-colors',
        onclick: () => { state.composeMode = 'circle'; state.composeCircleId = c.circleId; renderComposerCircles(); switchView('feed'); $('composer-input').focus(); }
      },
        el('div', { className: 'flex items-center gap-2.5 min-w-0' },
          icon,
          el('span', { className: 'text-xs font-semibold text-main truncate', textContent: c.name })
        ),
        el('span', { className: 'text-[11px] font-mono-code text-dim shrink-0 tabular-nums', textContent: `E${c.epoch}` })
      ));
    }
  }
}

function openEditProfileModal() {
  $('profile-name-input').value = state.identity.name;
  $('profile-handle-input').value = state.identity.handle;
  const bioVal = state.identity.bio || '';
  $('profile-bio-input').value = bioVal;
  $('profile-bio-count').textContent = `${bioVal.length} / 160`;
  setAvatar($('profile-form-avatar-preview'), state.identity.name, state.identity.pkEd, state.identity.avatarDataUrl || null);
  applyCoverGradient($('profile-form-banner-preview'), state.identity.pkEd, state.identity.bannerDataUrl || null);
  $('edit-profile-modal').classList.remove('hidden');
}

function openKeysModal() {
  $('key-ed25519').textContent = state.identity.pkEd;
  $('key-x25519').textContent = state.identity.pkX;
  $('key-secp256k1').textContent = state.identity.pkSecp;
  QRCode.toCanvas($('identity-qr-canvas'), encodeContactCard(state.identity), { width: 112, margin: 1 }, () => {});
  $('keys-modal').classList.remove('hidden');
}

function renderIdentityView() {
  if (state.view === 'profile') renderVisitedProfile();
}

function renderSettingsView() {
  const isStream = state.pcLayout === 'stream';
  const optStream = $('layout-opt-stream'), optCards = $('layout-opt-cards');
  if (optStream && optCards) {
    optStream.style.borderColor = isStream ? 'var(--accent)' : 'var(--border-hairline)';
    optCards.style.borderColor = !isStream ? 'var(--accent)' : 'var(--border-hairline)';
    $('layout-badge-stream').classList.toggle('hidden', !isStream);
    $('layout-badge-cards').classList.toggle('hidden', isStream);
  }
  const isDark = state.theme === 'dark';
  const darkBtn = $('settings-theme-dark'), lightBtn = $('settings-theme-light');
  if (darkBtn && lightBtn) {
    darkBtn.className = `px-3.5 py-1.5 rounded-full text-xs font-semibold whitespace-nowrap ${isDark ? 'btn-primary' : 'text-dim hover:text-main'}`;
    lightBtn.className = `px-3.5 py-1.5 rounded-full text-xs font-semibold whitespace-nowrap ${!isDark ? 'btn-primary' : 'text-dim hover:text-main'}`;
  }
  const vm = $('settings-viewport-mode');
  if (vm) {
    vm.textContent = window.innerWidth >= 1024 ? 'Active: PC Viewport' : 'Active: Mobile (<1024px)';
  }
}

function renderComposerCircles() {
  const sel = $('composer-circle-select'); sel.textContent = '';
  const circles = Array.from(state.circles.values());
  if (!circles.length) sel.appendChild(el('option', { value: '', textContent: 'No circles yet' }));
  else {
    circles.forEach(c => {
      const opt = el('option', { value: c.circleId, textContent: `${c.name} (Epoch ${c.epoch})` });
      if (state.composeCircleId === c.circleId) opt.selected = true;
      sel.appendChild(opt);
    });
    if (!state.composeCircleId) state.composeCircleId = circles[0].circleId;
  }
  const isC = state.composeMode === 'circle';
  sel.classList.toggle('hidden', !isC);
  $('mode-public-btn').className = `px-2.5 py-1 text-xs font-medium rounded-full whitespace-nowrap ${!isC ? 'surface-canvas text-main shadow-xs' : 'text-dim hover:text-main'}`;
  $('mode-circle-btn').className = `px-2.5 py-1 text-xs font-medium rounded-full whitespace-nowrap ${isC ? 'surface-canvas text-main shadow-xs' : 'text-dim hover:text-main'}`;
}

function renderPostArticle(p, isCardsPc) {
  const isMine = p.pubkey === state.identity.pkSecp;
  const av = el('button', {
    type: 'button',
    className: 'w-10 h-10 rounded-full shrink-0 flex items-center justify-center font-display font-bold text-sm text-white overflow-hidden cursor-pointer',
    'aria-label': `Visit profile for ${p.authorName}`,
    onclick: () => visitUserProfile(p.pubkey)
  });
  const postAvatarUrl = isMine ? state.identity.avatarDataUrl : state.peers.get(p.pubkey)?.avatarDataUrl;
  setAvatar(av, p.authorName, p.pkEd || p.pubkey, postAvatarUrl || null);
  const verCol = p.locked ? 'var(--warn)' : p.verification.includes('Invalid') ? 'var(--err)' : 'var(--ok)';
  const verTxt = p.mode === 'circle' ? (p.locked ? `Locked · ${p.circleName} · E${p.epoch}` : `E2EE · ${p.circleName} · E${p.epoch}`) : `Verified · ${p.verification}`;
  const likeCount = state.likes.get(p.id)?.size || 0;
  const likedByMe = state.likes.get(p.id)?.has(state.identity.pkSecp);

  const isEditing = isMine && state.editingPostId === p.id && !p.locked;
  const isConfirmingDel = isMine && state.confirmDeletePostId === p.id;

  const editForm = isEditing ? (() => {
    const edArea = el('textarea', { rows: '3', maxlength: '1000', className: 'input-field w-full rounded-xl p-2.5 text-[15px] leading-relaxed resize-y' });
    edArea.value = p.text;
    setTimeout(() => { edArea.focus(); edArea.setSelectionRange(edArea.value.length, edArea.value.length); }, 0);
    return el('form', {
      className: 'mt-1 flex flex-col gap-2',
      onsubmit: (e) => { e.preventDefault(); editOwnPost(p, edArea.value); }
    },
      edArea,
      el('div', { className: 'flex items-center justify-end gap-2' },
        el('button', { type: 'button', className: 'btn-ghost px-3.5 py-1.5 rounded-full text-xs font-semibold', textContent: 'Cancel', onclick: () => { state.editingPostId = null; renderTimeline(); if (state.view === 'profile') renderVisitedProfile(); } }),
        el('button', { type: 'submit', className: 'btn-primary px-4 py-1.5 rounded-full text-xs font-semibold', textContent: 'Save Edit' })
      )
    );
  })() : null;

  const body = el('div', { className: 'flex-1 min-w-0 flex flex-col gap-1.5' },
    el('div', { className: 'flex items-start justify-between gap-2' },
      el('div', { className: 'flex flex-wrap items-center gap-x-1.5 gap-y-0.5 text-xs min-w-0' },
        el('button', {
          type: 'button',
          className: 'font-bold text-sm text-main truncate max-w-[180px] hover:underline text-left',
          textContent: p.authorName,
          onclick: () => visitUserProfile(p.pubkey)
        }),
        el('button', {
          type: 'button',
          className: 'text-dim font-mono-code truncate max-w-[130px] hover:underline text-left',
          textContent: '@' + p.authorHandle,
          onclick: () => visitUserProfile(p.pubkey)
        }),
        el('span', { className: 'text-dim', 'aria-hidden': 'true', textContent: '·' }),
        el('span', { className: 'text-dim font-mono-code tabular-nums', textContent: formatTime(p.createdAt) }),
        p.editedAt ? el('span', { className: 'text-dim', 'aria-hidden': 'true', textContent: '·' }) : null,
        p.editedAt ? el('span', { className: 'text-dim', textContent: 'Edited' }) : null,
        el('span', { className: 'text-dim', 'aria-hidden': 'true', textContent: '·' }),
        el('span', { className: 'font-medium', style: { color: verCol }, textContent: verTxt })
      ),
      !isMine ? makeFollowButton(p.pubkey, { pkSecp: p.pubkey, pkEd: p.pkEd, name: p.authorName, handle: p.authorHandle }, 'xs') : null
    ),
    p.replyTo ? el('div', { className: 'text-xs text-dim font-mono-code', textContent: `Replying to ${p.replyTo.slice(0, 12)}...` }) : null,
    isEditing ? editForm : el('div', { className: `text-[15px] leading-relaxed whitespace-pre-wrap break-words ${p.locked ? 'text-dim italic' : 'text-main'}`, textContent: p.text }),
    (p.mediaDataUrl && isSafeImageDataUrl(p.mediaDataUrl)) ? el('img', { src: p.mediaDataUrl, alt: 'EXIF-stripped post attachment', referrerpolicy: 'no-referrer', className: 'mt-1.5 max-h-80 w-auto rounded-2xl border border-hairline object-contain' }) : null,
    el('div', { className: 'flex flex-wrap items-center gap-x-4 gap-y-1 pt-1.5 text-xs text-dim' },
      (() => {
        const replyCount = Array.from(state.posts.values()).filter(x => x.replyTo === p.id).length;
        return el('button', {
          type: 'button',
          className: 'hover:text-main font-medium py-1.5 min-h-[36px] inline-flex items-center gap-1.5 whitespace-nowrap tabular-nums transition-colors',
          style: state.replyingToId === p.id ? { color: 'var(--accent)' } : {},
          onclick: () => { state.replyingToId = state.replyingToId === p.id ? null : p.id; renderTimeline(); if (state.view === 'profile') renderVisitedProfile(); }
        }, svgIcon(POST_ICONS.reply), el('span', { textContent: replyCount > 0 ? `Reply (${replyCount})` : 'Reply' }));
      })(),
      el('button', {
        type: 'button',
        className: 'hover:text-main font-medium py-1.5 min-h-[36px] inline-flex items-center gap-1.5 whitespace-nowrap tabular-nums transition-colors',
        style: likedByMe ? { color: '#f91880' } : {},
        onclick: () => toggleLike(p.id)
      }, svgIcon(POST_ICONS.like, { fill: likedByMe ? 'currentColor' : 'none' }), el('span', { textContent: `Like (${likeCount})` })),
      el('button', {
        type: 'button',
        className: 'hover:text-main font-medium py-1.5 min-h-[36px] inline-flex items-center gap-1.5 whitespace-nowrap transition-colors',
        onclick: () => openProofModal(p)
      }, svgIcon(POST_ICONS.proof), el('span', { textContent: 'Proof' })),
      (isMine && !p.locked) ? el('button', {
        type: 'button',
        className: 'hover:text-main font-medium py-1.5 min-h-[36px] inline-flex items-center gap-1.5 whitespace-nowrap transition-colors',
        style: isEditing ? { color: 'var(--accent)' } : {},
        onclick: () => { state.confirmDeletePostId = null; state.editingPostId = isEditing ? null : p.id; renderTimeline(); if (state.view === 'profile') renderVisitedProfile(); }
      }, svgIcon(POST_ICONS.edit), el('span', { textContent: 'Edit' })) : null,
      (isMine && !isConfirmingDel) ? el('button', {
        type: 'button',
        className: 'font-medium py-1.5 min-h-[36px] hover:underline inline-flex items-center gap-1.5 whitespace-nowrap transition-colors',
        style: { color: 'var(--err)' },
        onclick: () => { state.editingPostId = null; state.confirmDeletePostId = p.id; renderTimeline(); if (state.view === 'profile') renderVisitedProfile(); }
      }, svgIcon(POST_ICONS.trash), el('span', { textContent: 'Delete' })) : null,
      isConfirmingDel ? el('span', { className: 'inline-flex items-center gap-2' },
        el('button', { type: 'button', className: 'font-semibold py-1.5 px-2.5 rounded-full text-white min-h-[32px] inline-flex items-center gap-1 whitespace-nowrap', style: { backgroundColor: 'var(--err)' }, onclick: () => deleteOwnPost(p) }, svgIcon(POST_ICONS.trash, { className: 'w-3.5 h-3.5 shrink-0' }), el('span', { textContent: 'Confirm Delete' })),
        el('button', { type: 'button', className: 'btn-ghost py-1.5 px-2.5 rounded-full font-medium min-h-[32px]', textContent: 'Cancel', onclick: () => { state.confirmDeletePostId = null; renderTimeline(); if (state.view === 'profile') renderVisitedProfile(); } })
      ) : null,
      !isMine ? el('button', {
        type: 'button',
        className: 'hover:text-main font-medium py-1.5 min-h-[36px] ml-auto inline-flex items-center gap-1.5 whitespace-nowrap transition-colors',
        onclick: () => openReportModal(p)
      }, svgIcon(POST_ICONS.flag), el('span', { textContent: 'Report' })) : null
    )
  );

  if (state.replyingToId === p.id || (isCardsPc && !p.locked)) {
    const rInput = el('input', { type: 'text', required: 'true', maxlength: '500', placeholder: p.mode === 'circle' ? `Encrypted reply to ${p.circleName}...` : 'Write a signed reply...', className: 'input-field flex-1 rounded-full px-3.5 py-1.5 text-xs' });
    const rForm = el('form', {
      className: 'mt-2 pt-2.5 border-t border-hairline flex gap-2',
      onsubmit: (e) => {
        e.preventDefault();
        const val = rInput.value.trim(); if (!val) return;
        if (p.mode === 'circle' && !p.locked && state.circles.has(p.circleId)) publishCirclePost(p.circleId, val, null, p.id);
        else publishPublicPost(val, null, p.id);
        state.replyingToId = null; renderTimeline(); if (state.view === 'profile') renderVisitedProfile();
      }
    }, rInput, el('button', { type: 'submit', className: 'btn-primary px-3.5 py-1.5 rounded-full text-xs font-semibold whitespace-nowrap inline-flex items-center gap-1.5' }, svgIcon(POST_ICONS.send, { className: 'w-3.5 h-3.5 shrink-0' }), el('span', { textContent: 'Reply' })));
    body.appendChild(rForm);
  }

  return el('article', { className: 'p-4 hover-row transition-colors flex gap-3' }, av, body);
}

function renderTimeline() {
  const container = $('timeline-list'); container.textContent = '';
  const rawQ = state.searchQuery.trim();
  const q = rawQ.toLowerCase();
  $('active-search-banner').classList.toggle('hidden', !q);
  if (q) $('active-search-label').textContent = `Local search: "${rawQ}"`;
  document.querySelectorAll('.underline-tab[data-feed-filter]').forEach(t => {
    t.classList.toggle('active', t.dataset.feedFilter === state.feedFilter);
  });

  if (q) {
    const { matchedPeers } = searchPeopleAndPosts(rawQ);
    if (matchedPeers.length) {
      const peopleCard = el('div', { className: 'p-3.5 surface-panel flex flex-col gap-2' },
        el('div', { className: 'text-xs font-semibold text-dim', textContent: 'People & Profiles' })
      );
      for (const mp of matchedPeers.slice(0, 6)) {
        const av = el('div', { className: 'w-9 h-9 rounded-full shrink-0 flex items-center justify-center font-display font-bold text-xs text-white overflow-hidden' });
        setAvatar(av, mp.name, mp.pkEd || mp.pkSecp, mp.avatarDataUrl || null);
        const isSelf = mp.pkSecp === state.identity.pkSecp;
        peopleCard.appendChild(el('div', { className: 'flex items-center justify-between gap-2.5 p-2 rounded-xl hover-row transition-colors' },
          el('button', {
            type: 'button',
            className: 'flex items-center gap-2.5 min-w-0 flex-1 text-left',
            onclick: () => { if (mp._needsUpsert) upsertPeer(mp, false); visitUserProfile(mp.pkSecp); }
          },
            av,
            el('div', { className: 'min-w-0 flex-1' },
              el('div', { className: 'text-sm font-semibold text-main truncate', textContent: mp.name }),
              el('div', { className: 'text-xs text-dim font-mono-code truncate', textContent: '@' + mp.handle })
            )
          ),
          el('div', { className: 'flex items-center gap-2 shrink-0' },
            el('button', {
              type: 'button',
              className: 'btn-ghost px-3 py-1 rounded-full text-xs font-medium whitespace-nowrap',
              textContent: 'View Profile',
              onclick: () => { if (mp._needsUpsert) upsertPeer(mp, false); visitUserProfile(mp.pkSecp); }
            }),
            !isSelf ? makeFollowButton(mp.pkSecp, mp, 'xs') : el('span', { className: 'text-[11px] font-medium text-dim px-2', textContent: 'You' })
          )
        ));
      }
      container.appendChild(peopleCard);
    }
  }

  const qClean = q.startsWith('@') ? q.slice(1) : q;
  const filtered = Array.from(state.posts.values()).sort((a, b) => b.createdAt - a.createdAt).filter(p => {
    if (state.feedFilter === 'following') {
      if (p.pubkey !== state.identity.pkSecp && !state.following.has(p.pubkey)) return false;
    } else if (state.feedFilter !== 'all' && p.mode !== state.feedFilter) {
      return false;
    }
    if (qClean && !`${p.authorName} @${p.authorHandle} ${p.authorHandle} ${p.text} ${p.circleName || ''} ${p.pkEd} ${p.pubkey}`.toLowerCase().includes(qClean)) return false;
    return true;
  });
  $('feed-sync-summary').textContent = `${filtered.length} post${filtered.length === 1 ? '' : 's'}`;

  if (!filtered.length) {
    const emptyTitle = q
      ? 'No decrypted posts match your search'
      : state.feedFilter === 'following'
        ? 'No posts from people you follow yet'
        : 'No posts in this feed yet';
    const emptyBody = q
      ? 'Search filters locally over decrypted posts and peers in memory.'
      : state.feedFilter === 'following'
        ? 'Follow peers from posts, profiles, Messages, or Followers & Following to see their signed posts here.'
        : 'Publish a signed public post or E2EE Circle post above, or open a second tab to test instant cross-tab sync.';
    container.appendChild(el('div', { className: 'p-8 text-center flex flex-col items-center gap-2 cards-surface' },
      el('div', { className: 'font-display font-semibold text-base text-main', textContent: emptyTitle }),
      el('p', { className: 'text-xs text-dim max-w-sm m-0', textContent: emptyBody })
    ));
    return;
  }

  const isCardsPc = state.pcLayout === 'cards' && window.innerWidth >= 1024;
  for (const p of filtered) {
    container.appendChild(renderPostArticle(p, isCardsPc));
  }
}

function renderCircles() {
  const container = $('circles-list'); container.textContent = '';
  const circles = Array.from(state.circles.values());
  if (!circles.length) { container.appendChild(el('div', { className: 'p-6 text-center text-xs text-dim', textContent: 'No circles yet.' })); return; }
  const discovered = Array.from(state.peers.values()).filter(p => p.pkX && p.pkSecp !== state.identity.pkSecp);

  for (const c of circles) {
    const isOwner = c.ownerPkSecp === state.identity.pkSecp;
    const card = el('div', { className: 'p-4 flex flex-col gap-3' },
      el('div', { className: 'flex flex-wrap items-center justify-between gap-2' },
        el('div', {},
          el('div', { className: 'font-display font-semibold text-base text-main', textContent: c.name }),
          el('div', { className: 'text-xs text-dim font-mono-code tabular-nums', textContent: `${isOwner ? 'Owner' : 'Member'} · Epoch ${c.epoch} · ${c.members.length} member(s) · ID ${c.circleId.slice(0, 8)}` })
        ),
        el('div', { className: 'flex items-center gap-2' },
          el('button', { type: 'button', className: 'btn-primary px-3.5 py-1.5 rounded-full text-xs font-semibold whitespace-nowrap', textContent: 'Post to Circle', onclick: () => { state.composeMode = 'circle'; state.composeCircleId = c.circleId; renderComposerCircles(); switchView('feed'); $('composer-input').focus(); } }),
          isOwner ? el('button', { type: 'button', className: 'btn-ghost px-3.5 py-1.5 rounded-full text-xs font-medium whitespace-nowrap', textContent: 'Rotate Key', onclick: () => rotateCircleKey(c.circleId) }) : null
        )
      )
    );

    const mWrap = el('div', { className: 'border border-hairline rounded-xl divide-y divide-[var(--border-hairline)] overflow-hidden' });
    for (const m of c.members) {
      mWrap.appendChild(el('div', { className: 'px-3 py-2 flex items-center justify-between gap-2 text-xs surface-panel' },
        el('button', {
          type: 'button',
          className: 'min-w-0 text-left hover:underline',
          onclick: () => m.pkSecp ? visitUserProfile(m.pkSecp) : switchView('identity')
        },
          el('span', { className: 'font-medium text-main', textContent: m.name + (m.pkX === state.identity.pkX ? ' (You)' : '') }),
          el('span', { className: 'text-dim font-mono-code ml-2', textContent: 'x25519:' + m.pkX.slice(0, 10) })
        ),
        (isOwner && m.pkX !== state.identity.pkX) ? el('button', { type: 'button', className: 'text-xs font-medium hover:underline whitespace-nowrap', style: { color: 'var(--err)' }, textContent: 'Remove & Rotate Key', onclick: () => rotateCircleKey(c.circleId, m.pkX) }) : null
      ));
    }
    card.appendChild(mWrap);

    if (isOwner) {
      const peerSel = discovered.length ? el('select', { className: 'input-field rounded-xl px-2.5 py-1.5 text-xs' }, el('option', { value: '', textContent: 'Select discovered peer...' })) : null;
      if (peerSel) {
        discovered.filter(dp => !c.members.some(m => m.pkX === dp.pkX)).forEach(dp => peerSel.appendChild(el('option', { value: dp.pkSecp, textContent: `${dp.name} (@${dp.handle})` })));
        peerSel.onchange = () => { const p = state.peers.get(peerSel.value); if (p) addCircleMember(c.circleId, p); };
      }
      const cardIn = el('input', { type: 'text', placeholder: 'Or paste Contact Card (cipherpost:peer:...)', className: 'input-field flex-1 rounded-xl px-3 py-1.5 text-xs font-mono-code' });
      card.appendChild(el('form', {
        className: 'flex flex-col sm:flex-row gap-2',
        onsubmit: (e) => {
          e.preventDefault(); if (!cardIn.value.trim()) return;
          try { const p = decodeContactCard(cardIn.value); upsertPeer(p, true); persistState(); addCircleMember(c.circleId, p); cardIn.value = ''; }
          catch (err) { toast(err.message, 'err'); }
        }
      }, peerSel, cardIn, el('button', { type: 'submit', className: 'btn-ghost px-3.5 py-1.5 rounded-full text-xs font-medium whitespace-nowrap', textContent: 'Add Member' })));
    }
    container.appendChild(card);
  }
}

function renderDmPeers() {
  const list = $('dm-peer-list'); list.textContent = '';
  const peers = Array.from(state.peers.values()).filter(p => p.pkX && p.pkSecp !== state.identity.pkSecp);
  if (!peers.length) { list.appendChild(el('div', { className: 'p-4 text-xs text-dim', textContent: 'No peers yet. Open another tab or paste a Contact Card.' })); return; }
  for (const p of peers) {
    const active = state.activeDmPeerPkX === p.pkX;
    const av = el('button', {
      type: 'button',
      className: 'w-8 h-8 rounded-full shrink-0 flex items-center justify-center font-display font-bold text-xs text-white overflow-hidden',
      'aria-label': `Visit profile for ${p.name}`,
      onclick: (e) => { e.stopPropagation(); visitUserProfile(p.pkSecp); }
    });
    setAvatar(av, p.name, p.pkEd || p.pkSecp, p.avatarDataUrl || null);
    list.appendChild(el('div', {
      className: `w-full px-3 py-2.5 flex items-center justify-between gap-2 transition-colors ${active ? 'surface-elevated' : 'hover-row'}`
    },
      av,
      el('button', {
        type: 'button',
        className: 'min-w-0 flex-1 text-left',
        onclick: () => { state.activeDmPeerPkX = p.pkX; state.unreadDms = 0; updateNavBadges(); renderDmPeers(); renderDmMessages(); }
      }, el('div', { className: 'text-xs font-semibold text-main truncate', textContent: p.name }), el('div', { className: 'text-[11px] text-dim font-mono-code truncate', textContent: '@' + p.handle })),
      el('span', { className: 'text-[11px] text-dim font-mono-code tabular-nums shrink-0', textContent: String((state.dms.get(p.pkX) || []).length) })
    ));
  }
}

function renderDmMessages() {
  const box = $('dm-messages'); box.textContent = '';
  const peer = Array.from(state.peers.values()).find(p => p.pkX === state.activeDmPeerPkX);
  const input = $('dm-compose-input'), sendBtn = $('dm-send-btn'), profBtn = $('dm-view-profile-btn');
  const nameBtn = $('dm-active-name-btn'), followSlot = $('dm-follow-slot');
  followSlot.textContent = '';
  if (!peer) {
    $('dm-active-name').textContent = 'Select a peer';
    $('dm-active-meta').textContent = 'X25519 + XChaCha20-Poly1305 encrypted thread';
    nameBtn.disabled = true; nameBtn.onclick = null;
    profBtn.classList.add('hidden');
    input.disabled = true; sendBtn.disabled = true; return;
  }
  $('dm-active-name').textContent = peer.name;
  $('dm-active-meta').textContent = `x25519:${peer.pkX.slice(0, 14)}... · XChaCha20-Poly1305`;
  nameBtn.disabled = false; nameBtn.onclick = () => visitUserProfile(peer.pkSecp);
  profBtn.classList.remove('hidden'); profBtn.onclick = () => visitUserProfile(peer.pkSecp);
  followSlot.appendChild(makeFollowButton(peer.pkSecp, peer, 'sm'));
  input.disabled = false; sendBtn.disabled = false;

  const msgs = state.dms.get(peer.pkX) || [];
  if (!msgs.length) { box.appendChild(el('div', { className: 'm-auto text-center text-xs text-dim max-w-xs', textContent: `No messages with ${peer.name} yet. Each DM uses a fresh 24-byte random nonce.` })); return; }
  for (const m of msgs) {
    const mine = m.senderPkX === state.identity.pkX;
    box.appendChild(el('div', { className: `flex flex-col max-w-[82%] ${mine ? 'self-end items-end' : 'self-start items-start'}` },
      el('div', { className: `px-3.5 py-2 rounded-2xl text-sm break-words ${mine ? 'btn-primary' : 'surface-panel border border-hairline text-main'}`, textContent: m.text }),
      el('div', { className: 'text-[11px] text-dim font-mono-code mt-1 tabular-nums', textContent: `${formatTime(m.createdAt)} · ${m.verified ? 'Verified' : 'Unverified'} · nonce:${m.nonce.slice(0, 6)}` })
    ));
  }
  box.scrollTop = box.scrollHeight;
}

function getKnownAccounts(includeSelf = false) {
  const accountsMap = new Map();
  const ensureAcc = (pk) => {
    if (!pk || (!includeSelf && pk === state.identity.pkSecp)) return null;
    if (!accountsMap.has(pk)) {
      const rec = resolvePeerRecord(pk);
      accountsMap.set(pk, {
        ...rec,
        followersCount: getFollowersForPk(pk).length,
        postsCount: 0,
        likesReceived: 0,
        score: 0
      });
    }
    return accountsMap.get(pk);
  };

  for (const pk of state.peers.keys()) ensureAcc(pk);
  for (const pk of state.followers) ensureAcc(pk);
  for (const pk of state.following) ensureAcc(pk);
  if (includeSelf) ensureAcc(state.identity.pkSecp);

  for (const post of state.posts.values()) {
    const acc = ensureAcc(post.pubkey);
    if (acc) {
      acc.postsCount++;
      acc.likesReceived += (state.likes.get(post.id)?.size || 0);
    }
  }

  const list = Array.from(accountsMap.values());
  for (const a of list) {
    a.score = (a.followersCount * 4) + (a.postsCount * 2) + a.likesReceived + (a.isContact ? 1 : 0) + (a.bio ? 1 : 0);
  }
  return list.sort((a, b) => (b.score - a.score) || (b.followersCount - a.followersCount) || (b.postsCount - a.postsCount) || a.name.localeCompare(b.name));
}

function searchPeopleAndPosts(rawQuery) {
  const rawQ = (rawQuery || '').trim();
  const q = rawQ.toLowerCase();
  const qClean = q.startsWith('@') ? q.slice(1) : q;
  if (!qClean) return { matchedPeers: [], matchedPosts: [] };

  let lookupPeer = null;
  if (rawQ.startsWith('cipherpost:peer:')) {
    try { lookupPeer = decodeContactCard(rawQ); } catch {}
  } else if (rawQ.includes('#profile/')) {
    const parsed = parseProfileRoute(rawQ);
    if (parsed) {
      lookupPeer = parsed.peer || state.peers.get(parsed.pkSecp) || { pkSecp: parsed.pkSecp, pkEd: '', pkX: '', name: 'Peer ' + parsed.pkSecp.slice(0, 6), handle: 'peer_' + parsed.pkSecp.slice(0, 6) };
    }
  } else if (/^[0-9a-fA-F]{64}$/.test(rawQ)) {
    lookupPeer = state.peers.get(rawQ.toLowerCase()) || { pkSecp: rawQ.toLowerCase(), pkEd: '', pkX: '', name: 'Peer ' + rawQ.slice(0, 6), handle: 'peer_' + rawQ.slice(0, 6) };
  }

  const allAccounts = getKnownAccounts(true);
  const matchedPeers = allAccounts
    .filter(acc => `${acc.name} @${acc.handle} ${acc.handle} ${acc.bio || ''} ${acc.pkSecp} ${acc.pkEd || ''}`.toLowerCase().includes(qClean))
    .sort((a, b) => {
      const aExact = a.handle.toLowerCase().startsWith(qClean) || a.name.toLowerCase().startsWith(qClean) ? 1 : 0;
      const bExact = b.handle.toLowerCase().startsWith(qClean) || b.name.toLowerCase().startsWith(qClean) ? 1 : 0;
      return (bExact - aExact) || (b.score - a.score);
    });

  if (lookupPeer && !matchedPeers.some(x => x.pkSecp === lookupPeer.pkSecp)) {
    matchedPeers.unshift({ ...lookupPeer, followersCount: getFollowersForPk(lookupPeer.pkSecp).length, postsCount: 0, likesReceived: 0, score: 0, _needsUpsert: true });
  }

  const matchedPosts = Array.from(state.posts.values())
    .sort((a, b) => b.createdAt - a.createdAt)
    .filter(p => `${p.authorName} @${p.authorHandle} ${p.authorHandle} ${p.text} ${p.circleName || ''} ${p.pkEd} ${p.pubkey}`.toLowerCase().includes(qClean));

  return { matchedPeers, matchedPosts };
}

function makeSearchAccountRow(acc, closeDrawerOnClick = false) {
  const av = el('div', { className: 'w-9 h-9 rounded-full shrink-0 flex items-center justify-center font-display font-bold text-xs text-white overflow-hidden' });
  setAvatar(av, acc.name, acc.pkEd || acc.pkSecp, acc.avatarDataUrl || null);
  const isSelf = acc.pkSecp === state.identity.pkSecp;
  const statsText = `@${acc.handle}` + (acc.followersCount > 0 || acc.postsCount > 0 ? ` · ${acc.followersCount} follower${acc.followersCount === 1 ? '' : 's'}` : '');
  return el('div', { className: 'flex items-center justify-between gap-2.5 p-2 rounded-xl hover-row transition-colors' },
    el('button', {
      type: 'button',
      className: 'flex items-center gap-2.5 min-w-0 flex-1 text-left',
      onclick: () => {
        if (acc._needsUpsert) upsertPeer(acc, false);
        if (closeDrawerOnClick) $('mobile-drawer-backdrop').classList.add('hidden');
        visitUserProfile(acc.pkSecp);
      }
    },
      av,
      el('div', { className: 'min-w-0 flex-1' },
        el('div', { className: 'text-xs font-semibold text-main truncate', textContent: acc.name }),
        el('div', { className: 'text-[11px] text-dim font-mono-code truncate', textContent: statsText })
      )
    ),
    !isSelf ? makeFollowButton(acc.pkSecp, acc, 'xs') : el('span', { className: 'text-[11px] font-medium text-dim px-2 shrink-0', textContent: 'You' })
  );
}

function renderSearchPanels() {
  const rawQ = state.searchQuery.trim();
  const popular = getKnownAccounts(false).slice(0, 5);

  for (const [cid, closeOnNav] of [['right-suggested-list', false], ['mobile-suggested-list', true]]) {
    const box = $(cid); if (!box) continue; box.textContent = '';
    if (!popular.length) {
      box.appendChild(el('div', { className: 'text-xs text-dim py-1', textContent: 'No accounts discovered yet. Sync from relays or paste a Contact Card / Profile link.' }));
    } else {
      for (const acc of popular) box.appendChild(makeSearchAccountRow(acc, closeOnNav));
    }
  }

  const { matchedPeers, matchedPosts } = searchPeopleAndPosts(rawQ);
  for (const [cid, closeOnNav] of [['right-search-results', false], ['mobile-search-results', true]]) {
    const resBox = $(cid); if (!resBox) continue; resBox.textContent = '';
    if (!rawQ) {
      resBox.classList.add('hidden');
      resBox.classList.remove('flex');
      continue;
    }
    resBox.classList.remove('hidden');
    resBox.classList.add('flex');

    if (!matchedPeers.length && !matchedPosts.length) {
      resBox.appendChild(el('div', { className: 'text-xs text-dim py-1', textContent: `No users or posts match "${rawQ}".` }));
      continue;
    }

    if (matchedPeers.length) {
      resBox.appendChild(el('div', { className: 'text-xs font-semibold text-dim', textContent: 'Accounts' }));
      const listWrap = el('div', { className: 'flex flex-col gap-1' });
      for (const mp of matchedPeers.slice(0, 5)) listWrap.appendChild(makeSearchAccountRow(mp, closeOnNav));
      resBox.appendChild(listWrap);
    }

    if (matchedPosts.length) {
      resBox.appendChild(el('div', { className: 'text-xs font-semibold text-dim' + (matchedPeers.length ? ' pt-2 border-t border-hairline' : ''), textContent: `Posts (${matchedPosts.length})` }));
      const postWrap = el('div', { className: 'flex flex-col gap-1.5' });
      for (const p of matchedPosts.slice(0, 4)) {
        postWrap.appendChild(el('button', {
          type: 'button',
          className: 'w-full text-left p-2 rounded-xl hover-row transition-colors flex flex-col gap-0.5',
          onclick: () => {
            if (closeOnNav) $('mobile-drawer-backdrop').classList.add('hidden');
            switchView('feed');
          }
        },
          el('div', { className: 'flex items-center gap-1.5 text-[11px]' },
            el('span', { className: 'font-semibold text-main truncate', textContent: p.authorName }),
            el('span', { className: 'text-dim font-mono-code truncate', textContent: '@' + p.authorHandle })
          ),
          el('div', { className: 'text-xs text-sub line-clamp-2 break-words', textContent: p.text || (p.mediaDataUrl ? '[Image attachment]' : '') })
        ));
      }
      resBox.appendChild(postWrap);
    }
  }
}

function renderRelayPanels() {
  updateNavBadges();
}

/* --- 9. FOLLOW UI, CONNECTIONS, USER PROFILE VIEW, MEDIA LIGHTBOX, PROOF & ABUSE REPORT --- */
function makeFollowButton(pkSecp, peerMeta = null, size = 'sm') {
  const isFollowing = state.following.has(pkSecp);
  const pad = size === 'xs' ? 'px-3 py-1 text-[11px] min-h-[28px]' : 'px-3.5 py-1.5 text-xs min-h-[34px]';
  if (isFollowing) {
    return el('button', {
      type: 'button',
      className: `following-btn rounded-full font-semibold whitespace-nowrap shrink-0 ${pad}`,
      onclick: (e) => { e.stopPropagation(); toggleFollow(pkSecp, peerMeta); }
    },
      el('span', { className: 'following-text', textContent: 'Following' }),
      el('span', { className: 'unfollow-text', textContent: 'Unfollow' })
    );
  }
  return el('button', {
    type: 'button',
    className: `follow-btn rounded-full font-semibold whitespace-nowrap shrink-0 ${pad}`,
    textContent: 'Follow',
    onclick: (e) => { e.stopPropagation(); toggleFollow(pkSecp, peerMeta); }
  });
}

function openConnectionsModal(tab = 'following', ownerPkSecp = null) {
  state.connectionsOwnerPkSecp = (ownerPkSecp && ownerPkSecp !== state.identity.pkSecp) ? ownerPkSecp : null;
  state.connectionsModalTab = tab;
  $('connections-modal').classList.remove('hidden');
  renderConnectionsModal();
}

function getFollowersForPk(pkSecp) {
  if (pkSecp === state.identity.pkSecp) return Array.from(state.followers);
  const res = new Set();
  if (state.following.has(pkSecp)) res.add(state.identity.pkSecp);
  for (const [otherPk, rec] of state.peerFollowing.entries()) {
    if (otherPk !== state.identity.pkSecp && rec?.set?.has(pkSecp)) res.add(otherPk);
  }
  return Array.from(res);
}

function getFollowingForPk(pkSecp) {
  if (pkSecp === state.identity.pkSecp) return Array.from(state.following);
  return Array.from(state.peerFollowing.get(pkSecp)?.set || []);
}

function resolvePeerRecord(pkSecp) {
  if (pkSecp === state.identity.pkSecp) {
    return { pkSecp: state.identity.pkSecp, pkEd: state.identity.pkEd, pkX: state.identity.pkX, name: state.identity.name, handle: state.identity.handle, bio: state.identity.bio || '', avatarDataUrl: state.identity.avatarDataUrl || null, bannerDataUrl: state.identity.bannerDataUrl || null };
  }
  return state.peers.get(pkSecp) || { pkSecp, pkEd: '', pkX: '', name: 'Peer ' + pkSecp.slice(0, 6), handle: 'peer_' + pkSecp.slice(0, 6), bio: '', avatarDataUrl: null, bannerDataUrl: null };
}

function renderConnectionsModal() {
  const ownerPk = state.connectionsOwnerPkSecp || state.identity.pkSecp;
  const isSelf = ownerPk === state.identity.pkSecp;
  const ownerPeer = resolvePeerRecord(ownerPk);
  $('connections-modal-title').textContent = isSelf ? 'Followers & Following' : `${ownerPeer.name} · Connections`;
  $('connections-add-form').classList.toggle('hidden', !isSelf);
  $('connections-tab-peers').classList.toggle('hidden', !isSelf);
  $('connections-tabs-row').className = `${isSelf ? 'grid-cols-3' : 'grid-cols-2'} grid border-b border-hairline`;

  const followingPks = getFollowingForPk(ownerPk);
  const followerPks = getFollowersForPk(ownerPk);
  const discovered = Array.from(state.peers.values()).filter(p => p.pkSecp !== state.identity.pkSecp);

  $('connections-tab-following').textContent = `Following (${followingPks.length})`;
  $('connections-tab-followers').textContent = `Followers (${followerPks.length})`;
  $('connections-tab-peers').textContent = `Discovered (${discovered.length})`;

  $('connections-tab-following').classList.toggle('active', state.connectionsModalTab === 'following');
  $('connections-tab-followers').classList.toggle('active', state.connectionsModalTab === 'followers');
  $('connections-tab-peers').classList.toggle('active', isSelf && state.connectionsModalTab === 'peers');

  const list = $('connections-modal-list');
  list.textContent = '';

  let rows = [];
  if (state.connectionsModalTab === 'following') rows = followingPks.map(resolvePeerRecord);
  else if (state.connectionsModalTab === 'followers') rows = followerPks.map(resolvePeerRecord);
  else rows = discovered;

  if (!rows.length) {
    const emptyMsg = state.connectionsModalTab === 'following'
      ? (isSelf ? 'You are not following anyone yet. Paste a Contact Card above or click Follow on any peer.' : `No following records cached for ${ownerPeer.name} yet.`)
      : state.connectionsModalTab === 'followers'
        ? (isSelf ? 'No followers recorded yet. Share your Contact Card so peers can follow you.' : `No known followers cached for ${ownerPeer.name} yet.`)
        : 'No peers discovered yet. Open another tab or paste a Contact Card above.';
    list.appendChild(el('div', { className: 'p-8 text-center text-xs text-dim', textContent: emptyMsg }));
    return;
  }

  for (const peer of rows) {
    const isMe = peer.pkSecp === state.identity.pkSecp;
    const av = el('div', { className: 'w-10 h-10 rounded-full shrink-0 flex items-center justify-center font-display font-bold text-sm text-white overflow-hidden' });
    setAvatar(av, peer.name, peer.pkEd || peer.pkSecp, peer.avatarDataUrl || null);
    const followsYou = !isMe && state.followers.has(peer.pkSecp);
    list.appendChild(el('div', { className: 'px-4 py-3 flex items-center justify-between gap-3 hover-row transition-colors' },
      el('button', {
        type: 'button',
        className: 'flex items-center gap-3 min-w-0 flex-1 text-left',
        onclick: () => { $('connections-modal').classList.add('hidden'); visitUserProfile(peer.pkSecp); }
      },
        av,
        el('div', { className: 'min-w-0 flex-1' },
          el('div', { className: 'text-sm font-semibold text-main truncate', textContent: peer.name + (isMe ? ' (You)' : '') }),
          el('div', { className: 'text-xs text-dim font-mono-code truncate', textContent: `@${peer.handle}${followsYou ? ' · Follows you' : ''}` })
        )
      ),
      !isMe ? el('div', { className: 'flex items-center gap-2 shrink-0' },
        peer.pkX ? el('button', {
          type: 'button',
          className: 'btn-ghost px-3 py-1.5 rounded-full text-xs font-medium whitespace-nowrap min-h-[34px]',
          textContent: 'Message',
          onclick: () => { $('connections-modal').classList.add('hidden'); state.activeDmPeerPkX = peer.pkX; switchView('dms'); renderDmPeers(); renderDmMessages(); }
        }) : null,
        makeFollowButton(peer.pkSecp, peer, 'sm')
      ) : null
    ));
  }
}

function openMediaModal(post) {
  if (!post || !isSafeImageDataUrl(post.mediaDataUrl)) return;
  $('media-modal-author').textContent = `${post.authorName} (@${post.authorHandle})`;
  $('media-modal-img').src = post.mediaDataUrl;
  $('media-modal-caption').textContent = post.text || '';
  $('media-modal-caption').classList.toggle('hidden', !post.text);
  $('media-modal').classList.remove('hidden');
}

function visitUserProfile(pkSecp, tab = 'posts') {
  if (!pkSecp) return;
  state.visitedProfilePkSecp = pkSecp;
  state.profileTab = tab;
  try { history.replaceState(null, '', '#profile/' + pkSecp); } catch {}
  switchView('profile');
  if (pkSecp !== state.identity.pkSecp) fetchPeerProfileFromRelays(pkSecp);
}

const openPeerModal = visitUserProfile;

function renderVisitedProfile() {
  const pkSecp = state.visitedProfilePkSecp;
  if (!pkSecp) return;
  const isSelf = pkSecp === state.identity.pkSecp;
  const peer = resolvePeerRecord(pkSecp);
  const allUserPosts = Array.from(state.posts.values()).filter(p => p.pubkey === pkSecp).sort((a, b) => b.createdAt - a.createdAt);

  $('profile-top-name').textContent = peer.name;
  $('profile-top-count').textContent = `${allUserPosts.length} post${allUserPosts.length === 1 ? '' : 's'}`;
  const bannerEl = $('profile-cover-banner');
  const hasCustomBanner = isSafeImageDataUrl(peer.bannerDataUrl || null);
  bannerEl.classList.toggle('hidden', !hasCustomBanner);
  bannerEl.classList.add('lg:block');
  applyCoverGradient(bannerEl, peer.pkEd || peer.pkSecp, peer.bannerDataUrl || null);
  setAvatar($('profile-hero-avatar'), peer.name, peer.pkEd || peer.pkSecp, peer.avatarDataUrl || null);

  const peerBio = (peer.bio || '').trim();
  $('profile-hero-name').textContent = peer.name;
  $('profile-hero-handle').textContent = '@' + peer.handle;
  $('profile-follows-you-badge').classList.toggle('hidden', isSelf || !state.followers.has(pkSecp));
  $('profile-hero-bio').textContent = peerBio;
  $('profile-hero-bio').classList.toggle('hidden', !peerBio);
  $('profile-hero-meta').textContent = `secp256k1:${pkSecp.slice(0, 18)}...${peer.pkEd ? ' · ed25519:' + peer.pkEd.slice(0, 10) + '...' : ''}`;

  const shareBtn = $('profile-share-btn');
  shareBtn.onclick = () => openShareProfileModal(peer, isSelf);

  const msgBtn = $('profile-message-btn');
  msgBtn.classList.toggle('hidden', isSelf || !peer.pkX);
  msgBtn.onclick = () => {
    if (!peer.pkX) return;
    state.activeDmPeerPkX = peer.pkX;
    switchView('dms');
    renderDmPeers();
    renderDmMessages();
  };


  $('profile-edit-self-btn').classList.toggle('hidden', !isSelf);
  $('profile-edit-self-btn').onclick = openEditProfileModal;
  $('profile-keys-btn').classList.toggle('hidden', !isSelf);
  $('profile-keys-btn').onclick = openKeysModal;

  const followSlot = $('profile-follow-slot');
  followSlot.textContent = '';
  followSlot.classList.toggle('hidden', isSelf);
  followSlot.classList.toggle('flex', !isSelf);
  if (!isSelf) followSlot.appendChild(makeFollowButton(pkSecp, peer, 'sm'));

  const followingPks = getFollowingForPk(pkSecp);
  const followerPks = getFollowersForPk(pkSecp);
  $('profile-stat-following').textContent = String(followingPks.length);
  $('profile-stat-followers').textContent = String(followerPks.length);
  $('profile-stat-posts').textContent = String(allUserPosts.length);

  const favWrap = $('profile-follower-avatars');
  favWrap.textContent = '';
  if (followerPks.length) {
    favWrap.classList.remove('hidden');
    favWrap.classList.add('inline-flex');
    followerPks.slice(0, 3).forEach(fpk => {
      const fp = resolvePeerRecord(fpk);
      const mini = el('span', { className: 'w-5 h-5 rounded-full border-2 border-[var(--bg-canvas)] -ml-1.5 first:ml-0 inline-flex items-center justify-center font-display font-bold text-[8px] text-white overflow-hidden shrink-0' });
      setAvatar(mini, fp.name, fp.pkEd || fp.pkSecp, fp.avatarDataUrl || null);
      favWrap.appendChild(mini);
    });
  } else {
    favWrap.classList.remove('inline-flex');
    favWrap.classList.add('hidden');
  }

  $('profile-open-following-btn').onclick = () => openConnectionsModal('following', pkSecp);
  $('profile-open-followers-btn').onclick = () => openConnectionsModal('followers', pkSecp);

  document.querySelectorAll('[data-profile-tab]').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.profileTab === state.profileTab);
  });

  const whatsNew = $('profile-whats-new-row');
  const showWhatsNew = isSelf && state.profileTab === 'posts';
  whatsNew.classList.toggle('hidden', !showWhatsNew);
  whatsNew.classList.toggle('flex', showWhatsNew);
  if (showWhatsNew) {
    setAvatar($('profile-whats-new-avatar'), state.identity.name, state.identity.pkEd, state.identity.avatarDataUrl || null);
    $('profile-whats-new-handle').textContent = '@' + state.identity.handle;
    whatsNew.onclick = () => { switchView('feed'); $('composer-input').focus(); };
  }

  const listEl = $('profile-posts-list');
  listEl.textContent = '';
  const isCardsPc = state.pcLayout === 'cards' && window.innerWidth >= 1024;

  if (state.profileTab === 'media') {
    const mediaPosts = allUserPosts.filter(p => p.mediaDataUrl && isSafeImageDataUrl(p.mediaDataUrl));
    if (!mediaPosts.length) {
      listEl.appendChild(el('div', { className: 'p-10 text-center text-xs text-dim', textContent: `${peer.name} hasn't shared any image posts cached here yet.` }));
      return;
    }
    const grid = el('div', { className: 'grid grid-cols-3 gap-1 p-1' });
    for (const mp of mediaPosts) {
      grid.appendChild(el('button', {
        type: 'button',
        className: 'aspect-square overflow-hidden surface-panel relative group focus:outline-none',
        onclick: () => openMediaModal(mp)
      },
        el('img', { src: mp.mediaDataUrl, alt: 'Media post', referrerpolicy: 'no-referrer', className: 'w-full h-full object-cover group-hover:scale-105 transition-transform duration-200' })
      ));
    }
    listEl.appendChild(grid);
    return;
  }

  const tabPosts = state.profileTab === 'likes'
    ? Array.from(state.posts.values()).filter(p => state.likes.get(p.id)?.has(pkSecp)).sort((a, b) => b.createdAt - a.createdAt)
    : state.profileTab === 'replies'
      ? allUserPosts.filter(p => Boolean(p.replyTo))
      : allUserPosts.filter(p => !p.replyTo);

  if (!tabPosts.length) {
    const emptyText = state.profileTab === 'likes'
      ? `No liked posts by ${peer.name} cached yet.`
      : state.profileTab === 'replies'
        ? `No replies from ${peer.name} cached yet.`
        : `No posts from ${peer.name} cached yet. Click Refresh or Follow to sync from relays.`;
    listEl.appendChild(el('div', { className: 'p-10 text-center text-xs text-dim', textContent: emptyText }));
    return;
  }

  for (const p of tabPosts) {
    listEl.appendChild(renderPostArticle(p, isCardsPc));
  }
}

let shareTargetPeer = null;
function refreshShareProfileModalContent() {
  if (!shareTargetPeer) return;
  const peer = shareTargetPeer;
  const hasCardKeys = Boolean(peer.pkSecp && peer.pkEd && peer.pkX);
  const includeWrap = $('share-profile-include-keys-wrap');
  const includeToggle = $('share-profile-include-keys');
  includeWrap.classList.toggle('hidden', !hasCardKeys);
  const url = buildProfileShareUrl(peer, hasCardKeys && includeToggle.checked);
  $('share-profile-url-input').value = url;

  const shareText = `Check out ${peer.name} (@${peer.handle}) on CipherPost`;
  $('share-profile-x-link').href = `https://twitter.com/intent/tweet?text=${encodeURIComponent(shareText)}&url=${encodeURIComponent(url)}`;
  $('share-profile-wa-link').href = `https://wa.me/?text=${encodeURIComponent(shareText + '\n' + url)}`;

  QRCode.toCanvas($('share-profile-qr-canvas'), url, {
    width: 164,
    margin: 1,
    color: { dark: '#0f1419', light: '#ffffff' }
  }, () => {});
}

async function copyTextSafe(text, inputEl = null) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    try {
      if (inputEl) {
        inputEl.focus();
        inputEl.select();
        if (document.execCommand('copy')) return true;
      }
      const ta = el('textarea', { style: { position: 'fixed', left: '-9999px', top: '0' } });
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      const ok = document.execCommand('copy');
      ta.remove();
      return ok;
    } catch { return false; }
  }
}

function openShareProfileModal(peer, isSelf) {
  shareTargetPeer = peer;
  $('share-profile-modal-title').textContent = isSelf ? 'Share your profile' : `Share ${peer.name}'s profile`;
  setAvatar($('share-profile-avatar'), peer.name, peer.pkEd || peer.pkSecp, peer.avatarDataUrl || null);
  $('share-profile-name').textContent = peer.name;
  $('share-profile-handle').textContent = '@' + peer.handle;

  const hasCardKeys = Boolean(peer.pkSecp && peer.pkEd && peer.pkX);
  const copyCardBtn = $('share-profile-copy-card-btn');
  copyCardBtn.classList.toggle('hidden', !hasCardKeys);
  copyCardBtn.onclick = async () => {
    if (!hasCardKeys) return;
    const ok = await copyTextSafe(encodeContactCard(peer));
    toast(ok ? `Copied ${isSelf ? 'your' : peer.name + "'s"} Contact Card` : 'Select and copy your Contact Card manually', ok ? 'ok' : 'info');
  };

  $('share-profile-include-keys').checked = hasCardKeys;
  refreshShareProfileModalContent();
  $('share-profile-modal').classList.remove('hidden');
}

function openProofModal(post) {
  const s = $('proof-modal-summary'); s.textContent = '';
  const sources = Array.from(state.eventSources.get(post.id) || ['Local']);
  [`Verification: ${post.verification}`, `Event ID: ${post.id}`, `Author secp256k1: ${post.pubkey}`, post.pkEd ? `Author Ed25519: ${post.pkEd}` : null, `Sources: ${sources.join(', ')}`]
    .filter(Boolean).forEach(l => s.appendChild(el('div', { className: 'font-mono-code break-all', textContent: l })));
  $('proof-modal-json').textContent = JSON.stringify(post.rawEvent, null, 2);
  $('proof-modal').classList.remove('hidden');
}

let reportingPost = null, lastReportBundleJson = '';
function openReportModal(post) {
  reportingPost = post;
  $('report-mod-pkx').value = DEFAULT_MOD_PKX;
  $('report-notes').value = '';
  $('report-output-box').classList.add('hidden');
  $('report-modal').classList.remove('hidden');
}

$('report-form').onsubmit = (e) => {
  e.preventDefault();
  if (!reportingPost) return;
  const modPkX = $('report-mod-pkx').value.trim();
  if (!/^[0-9a-fA-F]{64}$/.test(modPkX)) return toast('Moderator X25519 key must be 64 hex chars', 'err');
  const evidence = {
    v: 1, reportedEventId: reportingPost.id, reportedAuthorSecp: reportingPost.pubkey, reportedAuthorPkEd: reportingPost.pkEd || '',
    reason: $('report-reason').value, notes: $('report-notes').value.trim(),
    contentSha256: bytesToHex(sha256(utf8ToBytes(reportingPost.text))),
    excerpt: $('report-include-excerpt').checked ? reportingPost.text.slice(0, 400) : undefined,
    reporterPkEd: state.identity.pkEd, reporterPkX: state.identity.pkX, timestamp: Math.floor(Date.now() / 1000)
  };
  const pairKey = derivePairwiseKey(state.identity.skXHex, modPkX, 'abuse-report', 'cipherpost-report-v1');
  const encB = encryptXChaCha(pairKey, utf8ToBytes(JSON.stringify(evidence)), reportingPost.id);
  const edSig = signEdPayload({ v: 1, type: 'abuse-report', reportedEventId: reportingPost.id, moderatorPkX: modPkX, nonce: encB.nonce, ct: encB.ct });
  lastReportBundleJson = JSON.stringify({ format: 'cipherpost-abuse-proof-v1', cipher: 'x25519-xchacha20-poly1305', reportedEventId: reportingPost.id, moderatorPkX: modPkX, reporterPkEd: state.identity.pkEd, reporterPkX: state.identity.pkX, nonce: encB.nonce, ciphertext: encB.ct, ed25519Signature: edSig }, null, 2);
  $('report-output-json').textContent = lastReportBundleJson;
  $('report-output-box').classList.remove('hidden');
  toast('Signed encrypted abuse proof bundle generated', 'ok');
};
$('report-copy-btn').onclick = async () => { await navigator.clipboard.writeText(lastReportBundleJson); toast('Proof bundle copied', 'ok'); };
$('report-download-btn').onclick = () => { saveFile(`abuse-proof-${reportingPost?.id?.slice(0, 8) || 'report'}.json`, new Blob([lastReportBundleJson], { type: 'application/json' }), 'application/json').catch(err => toast('Save failed: ' + err.message, 'err')); };

/* --- 10. EVENT BINDING & BOOTSTRAP --- */
let isFeedRefreshing = false;
function triggerFeedRefresh() {
  if (isFeedRefreshing) return;
  isFeedRefreshing = true;
  const ptrEl = $('feed-ptr-indicator');
  const spinEl = $('feed-ptr-spinner');
  const lblEl = $('feed-ptr-label');
  if (ptrEl && spinEl && lblEl) {
    ptrEl.style.transition = '';
    ptrEl.style.height = '48px';
    ptrEl.style.opacity = '1';
    spinEl.style.transform = '';
    spinEl.classList.add('animate-spin');
    lblEl.textContent = 'Refreshing posts...';
  }
  localChannel?.postMessage({ type: 'SYNC_REQ' });
  connectAllRelays();
  resubscribeAllRelays();
  setTimeout(() => {
    renderTimeline();
    renderSearchPanels();
    if (ptrEl && spinEl && lblEl) {
      ptrEl.style.height = '0px';
      ptrEl.style.opacity = '0';
      spinEl.classList.remove('animate-spin');
      lblEl.textContent = 'Pull down to refresh';
    }
    isFeedRefreshing = false;
  }, 950);
}

function bindEvents() {
  let lastFeedNavTap = 0;
  document.querySelectorAll('[data-nav]').forEach(b => b.addEventListener('click', (e) => {
    e.preventDefault();
    const target = b.dataset.nav;
    if (target === 'feed') {
      const now = Date.now();
      const isDoubleTap = (now - lastFeedNavTap) < 380;
      lastFeedNavTap = isDoubleTap ? 0 : now;
      switchView('feed');
      if (isDoubleTap) triggerFeedRefresh();
      return;
    }
    lastFeedNavTap = 0;
    switchView(target);
  }));

  const feedViewEl = $('view-feed');
  let ptrStartY = null, ptrPull = 0;
  feedViewEl.addEventListener('touchstart', (e) => {
    if (state.view !== 'feed' || isFeedRefreshing || window.scrollY > 2 || e.touches.length !== 1) { ptrStartY = null; return; }
    const tag = e.target?.tagName;
    if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') { ptrStartY = null; return; }
    ptrStartY = e.touches[0].clientY;
    ptrPull = 0;
  }, { passive: true });
  feedViewEl.addEventListener('touchmove', (e) => {
    if (ptrStartY === null || isFeedRefreshing) return;
    if (window.scrollY > 2) { ptrStartY = null; ptrPull = 0; return; }
    const dy = e.touches[0].clientY - ptrStartY;
    if (dy <= 12) {
      if (ptrPull > 0) {
        ptrPull = 0;
        $('feed-ptr-indicator').style.height = '0px';
        $('feed-ptr-indicator').style.opacity = '0';
      }
      return;
    }
    ptrPull = Math.min(88, (dy - 12) * 0.5);
    const ptrEl = $('feed-ptr-indicator');
    const spinEl = $('feed-ptr-spinner');
    const lblEl = $('feed-ptr-label');
    ptrEl.style.transition = 'none';
    ptrEl.style.height = `${ptrPull}px`;
    ptrEl.style.opacity = String(Math.min(1, ptrPull / 42));
    spinEl.style.transform = `rotate(${Math.round(ptrPull * 4)}deg)`;
    lblEl.textContent = ptrPull >= 54 ? 'Release to refresh' : 'Pull down to refresh';
  }, { passive: true });
  const endPtrDrag = () => {
    if (ptrStartY === null) return;
    const pulled = ptrPull;
    ptrStartY = null;
    ptrPull = 0;
    if (pulled >= 54) {
      triggerFeedRefresh();
    } else {
      const ptrEl = $('feed-ptr-indicator');
      ptrEl.style.transition = '';
      ptrEl.style.height = '0px';
      ptrEl.style.opacity = '0';
      $('feed-ptr-spinner').style.transform = '';
    }
  };
  feedViewEl.addEventListener('touchend', endPtrDrag, { passive: true });
  feedViewEl.addEventListener('touchcancel', endPtrDrag, { passive: true });

  let wheelPull = 0, wheelResetTimer = null;
  window.addEventListener('wheel', (e) => {
    if (state.view !== 'feed' || isFeedRefreshing || window.scrollY > 0 || e.deltaY >= -18) return;
    wheelPull += Math.abs(e.deltaY);
    clearTimeout(wheelResetTimer);
    wheelResetTimer = setTimeout(() => { wheelPull = 0; }, 320);
    if (wheelPull >= 140) {
      wheelPull = 0;
      triggerFeedRefresh();
    }
  }, { passive: true });

  $('sidebar-compose-btn').onclick = () => { switchView('feed'); $('composer-input').focus(); };

  const setTheme = async (t) => {
    state.theme = t;
    applyThemeAndLayout();
    await persistState();
  };
  const toggleTheme = () => setTheme(state.theme === 'dark' ? 'light' : 'dark');
  $('desktop-theme-btn').onclick = toggleTheme;
  $('cards-theme-btn').onclick = toggleTheme;
  $('settings-theme-dark').onclick = () => setTheme('dark');
  $('settings-theme-light').onclick = () => setTheme('light');

  const setPcLayout = async (layout) => {
    state.pcLayout = layout;
    applyThemeAndLayout();
    renderTimeline();
    await persistState();
    toast(layout === 'cards' ? 'Switched PC layout to Modern Cards' : 'Switched PC layout to Classic Stream', 'ok');
  };
  $('layout-opt-stream').onclick = () => setPcLayout('stream');
  $('layout-opt-cards').onclick = () => setPcLayout('cards');

  let lastIsDesktop = window.innerWidth >= 1024;
  window.addEventListener('resize', () => {
    const nowDesktop = window.innerWidth >= 1024;
    if (nowDesktop !== lastIsDesktop) {
      lastIsDesktop = nowDesktop;
      renderTimeline();
      renderSettingsView();
    }
  });

  $('mobile-drawer-open-btn').onclick = () => $('mobile-drawer-backdrop').classList.remove('hidden');
  $('mobile-drawer-close-btn').onclick = () => $('mobile-drawer-backdrop').classList.add('hidden');
  $('mobile-drawer-backdrop').onclick = (e) => { if (e.target === $('mobile-drawer-backdrop')) $('mobile-drawer-backdrop').classList.add('hidden'); };
  $('proof-modal-close').onclick = () => $('proof-modal').classList.add('hidden');
  $('report-modal-close').onclick = () => $('report-modal').classList.add('hidden');
  $('connections-modal-close').onclick = () => $('connections-modal').classList.add('hidden');
  $('connections-modal').onclick = (e) => { if (e.target === $('connections-modal')) $('connections-modal').classList.add('hidden'); };
  $('media-modal-close').onclick = () => $('media-modal').classList.add('hidden');
  $('media-modal').onclick = (e) => { if (e.target === $('media-modal')) $('media-modal').classList.add('hidden'); };
  $('edit-profile-modal-close').onclick = () => $('edit-profile-modal').classList.add('hidden');
  $('edit-profile-cancel-btn').onclick = () => $('edit-profile-modal').classList.add('hidden');
  $('edit-profile-modal').onclick = (e) => { if (e.target === $('edit-profile-modal')) $('edit-profile-modal').classList.add('hidden'); };
  $('keys-modal-close').onclick = () => $('keys-modal').classList.add('hidden');
  $('keys-modal').onclick = (e) => { if (e.target === $('keys-modal')) $('keys-modal').classList.add('hidden'); };
  $('share-profile-modal-close').onclick = () => $('share-profile-modal').classList.add('hidden');
  $('share-profile-modal').onclick = (e) => { if (e.target === $('share-profile-modal')) $('share-profile-modal').classList.add('hidden'); };
  $('share-profile-include-keys').onchange = refreshShareProfileModalContent;
  $('share-profile-url-input').onclick = (e) => e.target.select();
  $('share-profile-copy-url-btn').onclick = async () => {
    const inp = $('share-profile-url-input');
    const url = inp.value;
    if (!url) return;
    const ok = await copyTextSafe(url, inp);
    const btn = $('share-profile-copy-url-btn');
    if (ok) {
      btn.textContent = 'Copied!';
      setTimeout(() => { btn.textContent = 'Copy link'; }, 1600);
      toast('Profile link copied', 'ok');
    } else {
      inp.focus(); inp.select();
      toast('Link selected — press Copy', 'info');
    }
  };
  $('share-profile-native-btn').onclick = async () => {
    const inp = $('share-profile-url-input');
    const url = inp.value;
    if (!url || !shareTargetPeer) return;
    const shareData = {
      title: `${shareTargetPeer.name} (@${shareTargetPeer.handle}) · CipherPost`,
      text: `Follow ${shareTargetPeer.name} (@${shareTargetPeer.handle}) on CipherPost`,
      url
    };
    if (navigator.share) {
      try {
        await navigator.share(shareData);
        return;
      } catch (err) {
        if (err && err.name === 'AbortError') return;
      }
    }
    const ok = await copyTextSafe(url, inp);
    toast(ok ? 'Profile link copied — paste in your app to share' : 'Link selected — copy and share', ok ? 'ok' : 'info');
  };
  $('share-profile-download-qr-btn').onclick = () => {
    const qrCanvas = $('share-profile-qr-canvas');
    if (!qrCanvas || !shareTargetPeer) return;
    const out = document.createElement('canvas');
    out.width = 440; out.height = 520;
    const ctx = out.getContext('2d');
    ctx.fillStyle = '#ffffff';
    ctx.fillRect(0, 0, out.width, out.height);
    ctx.fillStyle = '#0f1419';
    ctx.font = 'bold 24px sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText(shareTargetPeer.name.slice(0, 28), 220, 62);
    ctx.fillStyle = '#536471';
    ctx.font = '16px monospace';
    ctx.fillText('@' + shareTargetPeer.handle.slice(0, 32), 220, 90);
    ctx.drawImage(qrCanvas, 70, 118, 300, 300);
    ctx.fillStyle = '#71767b';
    ctx.font = '14px sans-serif';
    ctx.fillText('CipherPost Profile', 220, 464);
    const dlUrl = out.toDataURL('image/png');
    saveFile(`cipherpost-${shareTargetPeer.handle}-qr.png`, dlUrl, 'image/png')
      .then(() => toast('Profile QR card saved', 'ok'))
      .catch(err => toast('Save failed: ' + err.message, 'err'));
  };

  $('cards-profile-open-btn').onclick = () => visitUserProfile(state.identity.pkSecp);
  $('cards-edit-profile-btn').onclick = openEditProfileModal;
  $('profile-back-btn').onclick = () => switchView(state.previousView || 'feed');
  $('profile-refresh-btn').onclick = () => {
    if (!state.visitedProfilePkSecp) return;
    fetchPeerProfileFromRelays(state.visitedProfilePkSecp);
    toast('Refreshing profile from relays...', 'info');
  };
  document.querySelectorAll('[data-profile-tab]').forEach(btn => {
    btn.onclick = () => { state.profileTab = btn.dataset.profileTab; renderVisitedProfile(); };
  });

  $('cards-open-following-btn').onclick = () => openConnectionsModal('following', null);
  $('cards-open-followers-btn').onclick = () => openConnectionsModal('followers', null);
  $('connections-tab-following').onclick = () => { state.connectionsModalTab = 'following'; renderConnectionsModal(); };
  $('connections-tab-followers').onclick = () => { state.connectionsModalTab = 'followers'; renderConnectionsModal(); };
  $('connections-tab-peers').onclick = () => { state.connectionsModalTab = 'peers'; renderConnectionsModal(); };
  $('connections-add-form').onsubmit = async (e) => {
    e.preventDefault();
    try {
      const p = decodeContactCard($('connections-add-input').value);
      $('connections-add-input').value = '';
      if (!state.following.has(p.pkSecp)) await toggleFollow(p.pkSecp, p);
      else { upsertPeer(p, true); await persistState(); renderConnectionsModal(); toast(`Already following ${p.name}`, 'info'); }
    } catch (err) { toast(err.message, 'err'); }
  };

  $('logout-btn').onclick = () => { window.location.hash = ''; window.location.reload(); };
  $('reset-identity-open-btn').onclick = () => $('reset-modal').classList.remove('hidden');
  $('reset-modal-cancel').onclick = () => $('reset-modal').classList.add('hidden');
  $('reset-modal-confirm').onclick = async () => {
    state.identity = generateIdentity(state.identity.name, state.identity.handle); state.circles.clear(); state.dms.clear();
    state.following.clear(); state.followers.clear(); state.followingUpdatedAt = 0; state.peerFollowing.clear();
    await createCircle('My Private Circle'); await persistState(); renderIdentitySummary(); renderIdentityView(); renderTimeline(); announceProfileLocal();
    $('reset-modal').classList.add('hidden'); toast('Fresh Ed25519 / X25519 / secp256k1 identity generated', 'ok');
  };

  document.querySelectorAll('.underline-tab[data-feed-filter]').forEach(t => { t.onclick = () => { state.feedFilter = t.dataset.feedFilter; renderTimeline(); }; });
  const handleSearch = (v) => {
    state.searchQuery = v;
    $('desktop-search-input').value = v;
    $('cards-search-input').value = v;
    $('mobile-search-input').value = v;
    renderSearchPanels();
    renderTimeline();
  };
  $('desktop-search-input').oninput = (e) => handleSearch(e.target.value);
  $('cards-search-input').oninput = (e) => handleSearch(e.target.value);
  $('mobile-search-input').oninput = (e) => handleSearch(e.target.value);
  for (const sid of ['desktop-search-input', 'cards-search-input']) {
    $(sid).onkeydown = (e) => { if (e.key === 'Enter' && state.view !== 'feed') { e.preventDefault(); switchView('feed'); } };
  }
  $('clear-search-btn').onclick = () => handleSearch('');
  const syncDiscovery = () => { localChannel?.postMessage({ type: 'SYNC_REQ' }); connectAllRelays(); resubscribeAllRelays(); toast('Refreshing popular accounts & posts...', 'info'); };
  $('right-sync-accounts-btn').onclick = syncDiscovery;
  $('mobile-sync-accounts-btn').onclick = syncDiscovery;

  $('composer-input').oninput = (e) => { $('composer-char-count').textContent = `${e.target.value.length} / 1000`; };
  $('mode-public-btn').onclick = () => { state.composeMode = 'public'; renderComposerCircles(); };
  $('mode-circle-btn').onclick = () => { state.composeMode = 'circle'; renderComposerCircles(); };
  $('composer-circle-select').onchange = (e) => { state.composeCircleId = e.target.value; };
  $('composer-file-input').onchange = async (e) => {
    const file = e.target.files?.[0]; if (!file) return;
    try {
      const s = await stripImageExif(file); state.composeMedia = s;
      $('composer-media-img').src = s.dataUrl;
      $('composer-media-meta').textContent = `EXIF & GPS stripped via Canvas · ${s.width}x${s.height} · ${(s.strippedBytes / 1024).toFixed(1)} KB`;
      $('composer-media-preview').classList.remove('hidden');
    } catch (err) { toast(err.message, 'err'); }
    e.target.value = '';
  };
  $('composer-media-remove').onclick = () => { state.composeMedia = null; $('composer-media-preview').classList.add('hidden'); $('composer-media-img').removeAttribute('src'); };
  $('composer-form').onsubmit = (e) => {
    e.preventDefault(); const text = $('composer-input').value.trim(); if (!text && !state.composeMedia) return;
    try {
      if (state.composeMode === 'circle') { if (!state.composeCircleId) throw new Error('Select a Private Circle'); publishCirclePost(state.composeCircleId, text, state.composeMedia?.dataUrl || null); toast('E2EE Circle post published', 'ok'); }
      else { publishPublicPost(text, state.composeMedia?.dataUrl || null); toast('Signed public post published', 'ok'); }
      $('composer-input').value = ''; $('composer-char-count').textContent = '0 / 1000';
      state.composeMedia = null; $('composer-media-preview').classList.add('hidden'); $('composer-media-img').removeAttribute('src');
    } catch (err) { toast(err.message, 'err'); }
  };

  $('create-circle-form').onsubmit = async (e) => { e.preventDefault(); const nm = $('new-circle-name').value.trim(); if (!nm) return; await createCircle(nm); $('new-circle-name').value = ''; toast(`Created circle "${nm}"`, 'ok'); };
  $('dm-add-peer-form').onsubmit = async (e) => {
    e.preventDefault();
    try { const p = decodeContactCard($('dm-add-card-input').value); upsertPeer(p, true); await persistState(); resubscribeAllRelays(); state.activeDmPeerPkX = p.pkX; $('dm-add-card-input').value = ''; renderDmPeers(); renderDmMessages(); renderCardsProfileStats(); toast(`Added ${p.name}`, 'ok'); }
    catch (err) { toast(err.message, 'err'); }
  };
  $('dm-compose-form').onsubmit = (e) => {
    e.preventDefault(); const t = $('dm-compose-input').value.trim(); if (!t || !state.activeDmPeerPkX) return;
    try { publishDm(state.activeDmPeerPkX, t); $('dm-compose-input').value = ''; } catch (err) { toast(err.message, 'err'); }
  };


  async function handleAvatarUpload(file) {
    if (!file) return;
    try {
      state.identity.avatarDataUrl = await stripProfileMedia(file, 256, 256, 70000);
      state.identity.profileUpdatedAt = Math.floor(Date.now() / 1000);
      await persistState(); renderIdentitySummary(); renderTimeline(); publishEvent(buildProfileEvent());
      toast('Profile picture updated & announced', 'ok');
    } catch (err) { toast(err.message, 'err'); }
  }
  async function handleBannerUpload(file) {
    if (!file) return;
    try {
      state.identity.bannerDataUrl = await stripProfileMedia(file, 1200, 400, 140000);
      state.identity.profileUpdatedAt = Math.floor(Date.now() / 1000);
      await persistState(); renderIdentitySummary(); publishEvent(buildProfileEvent());
      toast('Banner image updated & announced', 'ok');
    } catch (err) { toast(err.message, 'err'); }
  }
  async function removeAvatar() {
    delete state.identity.avatarDataUrl;
    state.identity.profileUpdatedAt = Math.floor(Date.now() / 1000);
    await persistState(); renderIdentitySummary(); renderTimeline(); publishEvent(buildProfileEvent());
    toast('Profile picture reset', 'info');
  }
  async function removeBanner() {
    delete state.identity.bannerDataUrl;
    state.identity.profileUpdatedAt = Math.floor(Date.now() / 1000);
    await persistState(); renderIdentitySummary(); publishEvent(buildProfileEvent());
    toast('Banner image reset', 'info');
  }
  $('profile-avatar-input').onchange = (e) => { handleAvatarUpload(e.target.files?.[0]); e.target.value = ''; };
  $('profile-banner-input').onchange = (e) => { handleBannerUpload(e.target.files?.[0]); e.target.value = ''; };
  $('profile-avatar-remove').onclick = removeAvatar;
  $('profile-banner-remove').onclick = removeBanner;

  $('profile-bio-input').oninput = (e) => { $('profile-bio-count').textContent = `${e.target.value.length} / 160`; };
  $('profile-form').onsubmit = async (e) => {
    e.preventDefault();
    state.identity.name = $('profile-name-input').value.trim() || 'Cipher Peer';
    state.identity.handle = $('profile-handle-input').value.trim().replace(/^@/, '') || 'peer';
    state.identity.bio = $('profile-bio-input').value.trim().slice(0, 160);
    state.identity.profileUpdatedAt = Math.floor(Date.now() / 1000);
    await persistState(); renderIdentitySummary(); renderIdentityView(); renderTimeline(); publishEvent(buildProfileEvent());
    $('edit-profile-modal').classList.add('hidden');
    toast('Profile saved & broadcast', 'ok');
  };
  const copyCard = async () => { await navigator.clipboard.writeText(encodeContactCard(state.identity)); toast('Contact Card copied', 'ok'); };
  $('sidebar-copy-card-btn').onclick = copyCard; $('identity-copy-card-btn').onclick = copyCard;
  document.querySelectorAll('.copy-key-btn').forEach(b => { b.onclick = async () => { await navigator.clipboard.writeText($(b.dataset.copyTarget).textContent); toast('Public key copied', 'ok'); }; });
  $('identity-import-card-form').onsubmit = async (e) => {
    e.preventDefault();
    try { const p = decodeContactCard($('identity-import-card-input').value); upsertPeer(p, true); await persistState(); resubscribeAllRelays(); $('identity-import-card-input').value = ''; renderDmPeers(); renderSearchPanels(); renderCircles(); renderCardsProfileStats(); toast(`Added peer ${p.name}`, 'ok'); }
    catch (err) { toast(err.message, 'err'); }
  };

  async function buildEncryptedBackupEnvelope(pass, compactForLink = false) {
    const salt = randomBytes(16);
    const key = await argon2idAsync(utf8ToBytes(pass), salt, { t: 2, m: 16384, p: 1, dkLen: 32 });
    const identityPayload = compactForLink
      ? { ...state.identity, avatarDataUrl: undefined, bannerDataUrl: undefined }
      : state.identity;
    const encB = encryptXChaCha(key, utf8ToBytes(JSON.stringify({
      identity: identityPayload,
      circles: Array.from(state.circles.values()),
      contacts: Array.from(state.peers.values()).filter(p => p.isContact),
      following: Array.from(state.following),
      followers: Array.from(state.followers)
    })), 'cipherpost-backup-v1');
    return { format: 'cipherpost-backup-v1', kdf: 'argon2id', kdfParams: { t: 2, m: 16384, p: 1 }, cipher: 'xchacha20-poly1305', salt: bytesToB64Url(salt), nonce: encB.nonce, ciphertext: encB.ct, exportedAt: new Date().toISOString() };
  }

  async function applyRestoredBackupObject(obj, pass) {
    if (!obj || obj.format !== 'cipherpost-backup-v1') throw new Error('Invalid format');
    toast('Decrypting account bundle with Argon2id...', 'info');
    const { t, m, p } = obj.kdfParams || { t: 2, m: 16384, p: 1 };
    const key = await argon2idAsync(utf8ToBytes(pass), b64UrlToBytes(obj.salt), { t, m, p, dkLen: 32 });
    const res = JSON.parse(bytesToUtf8(decryptXChaCha(key, obj.nonce, obj.ciphertext, 'cipherpost-backup-v1')));
    if (!res.identity?.skEdHex || !res.identity?.skXHex || !res.identity?.skSecpHex) throw new Error('Incomplete backup');
    state.identity = res.identity; state.circles.clear(); state.following.clear(); state.followers.clear();
    (res.circles || []).forEach(c => state.circles.set(c.circleId, c));
    (res.contacts || []).forEach(c => upsertPeer(c, true));
    (res.following || []).forEach(pk => state.following.add(pk));
    (res.followers || []).forEach(pk => state.followers.add(pk));
    await persistState(); resubscribeAllRelays(); renderIdentitySummary(); renderIdentityView(); renderCircles(); renderComposerCircles(); renderDmPeers(); renderTimeline();
    if (state.identity.avatarDataUrl || state.identity.bannerDataUrl) announceProfileLocal();
    else fetchPeerProfileFromRelays(state.identity.pkSecp);
    toast(`Device linked as @${state.identity.handle}`, 'ok');
  }

  $('backup-export-form').onsubmit = async (e) => {
    e.preventDefault();
    const pass = $('backup-export-passphrase').value;
    if (pass.length < 6) return toast('Passphrase min 6 chars', 'err');
    toast('Deriving Argon2id link key...', 'info');
    const envelope = await buildEncryptedBackupEnvelope(pass, true);
    const linkCode = 'cipherpost:link:' + bytesToB64Url(utf8ToBytes(JSON.stringify(envelope)));
    $('link-device-code-output').value = linkCode;
    $('link-device-output-box').classList.remove('hidden');
    const qrCanvas = $('link-device-qr-canvas');
    const qrNote = $('link-device-qr-note');
    if (linkCode.length <= 1800) {
      qrCanvas.classList.remove('hidden');
      qrNote.textContent = 'Scan the QR code or paste this encrypted code into Settings on your other device.';
      QRCode.toCanvas(qrCanvas, linkCode, { width: 132, margin: 1 }, (err) => {
        if (err) { qrCanvas.classList.add('hidden'); qrNote.textContent = 'Link code generated — copy and paste into Settings on your other device.'; }
      });
    } else {
      qrCanvas.classList.add('hidden');
      qrNote.textContent = 'Account bundle exceeds QR density — use Copy Code or Download .json instead.';
    }
    toast('Encrypted Link Device Code generated', 'ok');
  };

  $('link-device-copy-btn').onclick = async () => {
    const code = $('link-device-code-output').value;
    if (!code) return;
    await navigator.clipboard.writeText(code);
    toast('Encrypted Link Device Code copied', 'ok');
  };

  $('backup-download-file-btn').onclick = async () => {
    const pass = $('backup-export-passphrase').value;
    if (pass.length < 6) return toast('Enter a passphrase (min 6 chars) first', 'err');
    toast('Deriving Argon2id backup key...', 'info');
    const envelope = await buildEncryptedBackupEnvelope(pass, false);
    try {
      await saveFile(`cipherpost-backup-${state.identity.handle}.json`, new Blob([JSON.stringify(envelope, null, 2)], { type: 'application/json' }), 'application/json');
      $('backup-export-passphrase').value = '';
      toast('Encrypted backup saved', 'ok');
    } catch (err) { toast('Save failed: ' + err.message, 'err'); }
  };

  $('link-device-restore-form').onsubmit = async (e) => {
    e.preventDefault();
    const raw = $('link-device-restore-code').value.trim();
    const pass = $('link-device-restore-passphrase').value;
    if (!raw || !pass) return;
    try {
      const obj = raw.startsWith('cipherpost:link:')
        ? JSON.parse(bytesToUtf8(b64UrlToBytes(raw.slice('cipherpost:link:'.length))))
        : JSON.parse(raw);
      await applyRestoredBackupObject(obj, pass);
      $('link-device-restore-code').value = '';
      $('link-device-restore-passphrase').value = '';
    } catch { toast('Link failed — check code or passphrase', 'err'); }
  };

  $('backup-restore-form').onsubmit = async (e) => {
    e.preventDefault();
    const file = $('backup-restore-file').files?.[0], pass = $('backup-restore-passphrase').value;
    if (!file || !pass) return;
    try {
      const obj = JSON.parse(await file.text());
      await applyRestoredBackupObject(obj, pass);
      $('backup-restore-passphrase').value = '';
    } catch { toast('Decryption failed — check passphrase or file', 'err'); }
  };
}

async function decryptBackupObject(obj, pass) {
  if (!obj || obj.format !== 'cipherpost-backup-v1') throw new Error('Invalid format');
  const { t, m, p } = obj.kdfParams || { t: 2, m: 16384, p: 1 };
  const key = await argon2idAsync(utf8ToBytes(pass), b64UrlToBytes(obj.salt), { t, m, p, dkLen: 32 });
  const res = JSON.parse(bytesToUtf8(decryptXChaCha(key, obj.nonce, obj.ciphertext, 'cipherpost-backup-v1')));
  if (!res.identity?.skEdHex || !res.identity?.skXHex || !res.identity?.skSecpHex) throw new Error('Incomplete backup');
  return res;
}
function parseLinkCodeOrJson(raw) {
  const t = raw.trim();
  return t.startsWith('cipherpost:link:') ? JSON.parse(bytesToUtf8(b64UrlToBytes(t.slice('cipherpost:link:'.length)))) : JSON.parse(t);
}

/* --- AUTH SCREEN (sign in / create account / link device) --- */
let authBusy = false;
function setAuthError(msg) {
  const e = $('auth-error');
  e.textContent = msg || '';
  e.classList.toggle('hidden', !msg);
}
function setAuthTab(tab) {
  setAuthError('');
  document.querySelectorAll('[data-auth-tab]').forEach(b => b.classList.toggle('active', b.dataset.authTab === tab));
  $('auth-login-form').classList.toggle('hidden', tab !== 'login');
  $('auth-create-form').classList.toggle('hidden', tab !== 'create');
  $('auth-link-form').classList.toggle('hidden', tab !== 'link');
}
function showAuth(tab) {
  const meta = state.vaultMeta;
  const chip = $('auth-account-chip');
  chip.classList.toggle('hidden', !meta);
  chip.classList.toggle('flex', Boolean(meta));
  if (meta) {
    setAvatar($('auth-account-avatar'), meta.name || 'C', meta.pkEd || '', null);
    $('auth-account-name').textContent = meta.name || 'Account';
    $('auth-account-handle').textContent = '@' + (meta.handle || '');
  }
  $('auth-login-empty').classList.toggle('hidden', Boolean(meta));
  $('auth-login-fields').classList.toggle('hidden', !meta);
  if (state.legacyIdentity && !meta) {
    $('auth-legacy-note').classList.remove('hidden');
    $('auth-create-name').value = state.legacyIdentity.name || '';
    $('auth-create-handle').value = state.legacyIdentity.handle || '';
  }
  $('auth-screen').classList.remove('hidden');
  setAuthTab(tab);
}
async function withAuthBusy(btnId, busyText, fn) {
  if (authBusy) return;
  authBusy = true;
  const btn = $(btnId), label = btn.textContent;
  btn.disabled = true; btn.textContent = busyText; setAuthError('');
  try { await fn(); }
  catch (err) { setAuthError(err?.message || 'Something went wrong'); }
  finally { authBusy = false; btn.disabled = false; btn.textContent = label; }
}
async function enterApp() {
  await persistState();
  $('auth-screen').classList.add('hidden');
  await startApp();
}
function bindAuthEvents() {
  document.querySelectorAll('[data-auth-tab]').forEach(b => { b.onclick = () => setAuthTab(b.dataset.authTab); });

  $('auth-login-form').onsubmit = (e) => {
    e.preventDefault();
    withAuthBusy('auth-login-btn', 'Unlocking...', async () => {
      if (!state.vaultMeta) throw new Error('No account on this device. Create an account or link a device.');
      const ok = await unlockVault($('auth-login-pass').value);
      if (!ok) throw new Error('Wrong passphrase');
      state.identity = await kvGetSecure('identity');
      const circles = await kvGetSecure('circles');
      if (!state.identity?.skEdHex) throw new Error('Account data is corrupted. Use Link device with a backup.');
      (circles || []).forEach(c => state.circles.set(c.circleId, c));
      if (!state.circles.size) { const c = buildCircle('My Private Circle'); state.circles.set(c.circleId, c); }
      $('auth-login-pass').value = '';
      await enterApp();
    });
  };

  $('auth-create-form').onsubmit = (e) => {
    e.preventDefault();
    withAuthBusy('auth-create-btn', 'Creating account...', async () => {
      const name = $('auth-create-name').value.trim();
      const handle = $('auth-create-handle').value.trim().replace(/^@/, '');
      const pass = $('auth-create-pass').value;
      if (!name) throw new Error('Enter a display name');
      if (!/^[A-Za-z0-9_]{3,32}$/.test(handle)) throw new Error('Handle must be 3-32 letters, numbers or underscores');
      if (pass.length < 8) throw new Error('Passphrase must be at least 8 characters');
      if (pass !== $('auth-create-pass2').value) throw new Error('Passphrases do not match');
      if (state.vaultMeta && !confirm('An account already exists on this device. Creating a new one will replace it. Continue?')) return;
      await createVault(pass);
      const legacy = state.legacyIdentity;
      state.identity = legacy ? { ...legacy, name, handle } : generateIdentity(name, handle);
      state.circles.clear();
      const legacyCircles = legacy ? await kvGet('circles') : null;
      if (Array.isArray(legacyCircles) && legacyCircles.length) legacyCircles.forEach(c => state.circles.set(c.circleId, c));
      else { const c = buildCircle('My Private Circle'); state.circles.set(c.circleId, c); }
      state.legacyIdentity = null;
      $('auth-create-pass').value = ''; $('auth-create-pass2').value = '';
      await enterApp();
    });
  };

  $('auth-link-form').onsubmit = (e) => {
    e.preventDefault();
    withAuthBusy('auth-link-btn', 'Linking...', async () => {
      const pass = $('auth-link-pass').value;
      const file = $('auth-link-file').files?.[0];
      const code = $('auth-link-code').value.trim();
      if (!file && !code) throw new Error('Paste a Link Code or choose a backup file');
      let obj;
      try { obj = file ? JSON.parse(await file.text()) : parseLinkCodeOrJson(code); }
      catch { throw new Error('That code or file is not a valid CipherPost backup'); }
      let res;
      try { res = await decryptBackupObject(obj, pass); }
      catch { throw new Error('Could not decrypt: wrong passphrase or damaged backup'); }
      await createVault(pass);
      state.identity = res.identity;
      state.circles.clear();
      (res.circles || []).forEach(c => state.circles.set(c.circleId, c));
      if (!state.circles.size) { const c = buildCircle('My Private Circle'); state.circles.set(c.circleId, c); }
      (res.contacts || []).forEach(c => upsertPeer(c, true));
      (res.following || []).forEach(pk => { if (/^[0-9a-fA-F]{64}$/.test(pk)) state.following.add(pk); });
      (res.followers || []).forEach(pk => { if (/^[0-9a-fA-F]{64}$/.test(pk)) state.followers.add(pk); });
      $('auth-link-pass').value = ''; $('auth-link-code').value = ''; $('auth-link-file').value = '';
      await enterApp();
    });
  };
}

async function bootstrap() {
  state.db = await openDb();
  const savedTheme = await kvGet('theme');
  if (savedTheme === 'light' || savedTheme === 'dark') state.theme = savedTheme;
  const savedLayout = await kvGet('pcLayout');
  if (savedLayout === 'stream' || savedLayout === 'cards') state.pcLayout = savedLayout;
  applyThemeAndLayout();

  const meta = await kvGet('vaultMeta');
  state.vaultMeta = meta?.salt && meta?.check ? meta : null;
  const legacy = await kvGet('identity');
  state.legacyIdentity = (!state.vaultMeta && legacy?.skEdHex && legacy?.skXHex && legacy?.skSecpHex) ? legacy : null;

  bindAuthEvents();
  showAuth(state.legacyIdentity ? 'create' : 'login');
}

async function startApp() {
  const savedContacts = await kvGet('contacts');
  if (Array.isArray(savedContacts)) savedContacts.forEach(p => upsertPeer(p, true));

  const savedFollowing = await kvGet('following');
  if (Array.isArray(savedFollowing)) savedFollowing.forEach(pk => { if (/^[0-9a-fA-F]{64}$/.test(pk) && pk !== state.identity.pkSecp) state.following.add(pk); });

  const savedFollowers = await kvGet('followers');
  if (Array.isArray(savedFollowers)) savedFollowers.forEach(pk => { if (/^[0-9a-fA-F]{64}$/.test(pk) && pk !== state.identity.pkSecp) state.followers.add(pk); });

  const savedFollowingTs = await kvGet('followingUpdatedAt');
  if (Number.isInteger(savedFollowingTs)) state.followingUpdatedAt = savedFollowingTs;

  const savedDeleted = await kvGet('deletedPostIds');
  if (Array.isArray(savedDeleted)) savedDeleted.forEach(id => state.deletedPostIds.add(id));

  const savedEdits = await kvGet('postEdits');
  if (Array.isArray(savedEdits)) savedEdits.forEach(([id, val]) => { if (id && val) state.postEdits.set(id, val); });

  const savedRelays = await kvGet('relays');
  const savedRelayMap = new Map(Array.isArray(savedRelays) ? savedRelays.map(r => [r.url, r]) : []);
  state.relays = DEFAULT_RELAYS.map(r => {
    const prev = savedRelayMap.get(r.url);
    const enabled = prev ? prev.enabled !== false : r.enabled !== false;
    return { url: r.url, builtin: true, enabled, isLocal: !!r.isLocal, status: r.isLocal && enabled ? 'Connected' : 'Offline', sent: 0, recv: 0, ok: 0, err: 0, retryMs: 3000, ws: null, timer: null };
  });

  bindEvents(); renderIdentitySummary(); renderComposerCircles(); renderCircles(); renderDmPeers(); renderDmMessages(); renderRelayPanels(); renderSearchPanels(); renderSearchPanels();
  for (const ev of await loadAllEventsFromIdb()) {
    const isCpTagged = Array.isArray(ev?.tags) && ev.tags.some(t => t[0] === 't' && t[1] === 'cipherpost');
    if (!isCpTagged || !isKnownOrLocalSource(ev, 'IndexedDB Cache') || state.deletedPostIds.has(ev.id)) {
      try { state.db.transaction('events', 'readwrite').objectStore('events').delete(ev.id); } catch {}
      continue;
    }
    await ingestEvent(ev, 'IndexedDB Cache');
  }
  renderTimeline();
  renderSearchPanels();
  announceProfileLocal();
  localChannel?.postMessage({ type: 'SYNC_REQ' });
  connectAllRelays();
  const handleProfileHashRoute = () => {
    const parsed = parseProfileRoute(window.location.hash);
    if (!parsed) return;
    if (parsed.peer && parsed.pkSecp !== state.identity.pkSecp) upsertPeer(parsed.peer, false);
    visitUserProfile(parsed.pkSecp);
  };
  handleProfileHashRoute();
  window.addEventListener('hashchange', handleProfileHashRoute);
  const reconnectRelays = () => { if (document.visibilityState === 'visible' && navigator.onLine !== false) { connectAllRelays(); resubscribeAllRelays(); } };
  window.addEventListener('online', reconnectRelays);
  document.addEventListener('visibilitychange', reconnectRelays);
}

bootstrap().catch((err) => toast('Init failed: ' + err.message, 'err'));

/* --- 11. PWA: SERVICE WORKER + INSTALL PROMPT --- */
if (!IS_NATIVE) {
  registerSW({ immediate: true });

  let deferredInstallPrompt = null;
  const installCard = document.getElementById('install-app-card');
  const installBtn = document.getElementById('install-app-btn');
  const installText = document.getElementById('install-app-text');
  const isStandalone = () => window.matchMedia('(display-mode: standalone)').matches || window.navigator.standalone === true;
  const isIos = /iphone|ipad|ipod/i.test(navigator.userAgent) || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);

  const refreshInstallCard = () => {
    if (!installCard) return;
    if (isStandalone()) { installCard.classList.add('hidden'); return; }
    installCard.classList.remove('hidden');
    if (deferredInstallPrompt) {
      installBtn.classList.remove('hidden');
    } else if (isIos) {
      installBtn.classList.add('hidden');
      installText.textContent = 'On iPad / iPhone: tap the Share button in Safari, then "Add to Home Screen".';
    } else {
      installBtn.classList.add('hidden');
      installText.textContent = 'Use your browser menu (Install app / Add to Home Screen) to install CipherPost on this device.';
    }
  };
  window.addEventListener('beforeinstallprompt', (e) => { e.preventDefault(); deferredInstallPrompt = e; refreshInstallCard(); });
  window.addEventListener('appinstalled', () => { deferredInstallPrompt = null; refreshInstallCard(); toast('CipherPost installed', 'ok'); });
  installBtn?.addEventListener('click', async () => {
    if (!deferredInstallPrompt) return;
    deferredInstallPrompt.prompt();
    await deferredInstallPrompt.userChoice;
    deferredInstallPrompt = null;
    refreshInstallCard();
  });
  refreshInstallCard();
} else {
  document.getElementById('install-app-card')?.classList.add('hidden');
}
