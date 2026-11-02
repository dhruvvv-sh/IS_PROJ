const $ = id => document.getElementById(id);
const encoder = new TextEncoder();
const decoder = new TextDecoder();
let me = null, keys = null, peer = null, captured = [], chat = null, seenMessages = new Set(), envelopes = new Map(), refreshTimer = null, releaseRoleLock = null;

async function reserveTab(username) {
  if (!navigator.locks) return;
  let signal;
  const acquired = new Promise(resolve => { signal = resolve; });
  navigator.locks.request(`cipherchat-role-${username}`, {ifAvailable:true}, async lock => {
    signal(Boolean(lock));
    if (lock) await new Promise(resolve => { releaseRoleLock = resolve; });
  }).catch(() => signal(false));
  if (!await acquired) throw new Error(`${username[0].toUpperCase()}${username.slice(1)} is already open in another tab.`);
}
function freeTab() { if (releaseRoleLock) { releaseRoleLock(); releaseRoleLock = null; } }

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;
  return JSON.stringify(value);
}
function b64(data) {
  const bytes = new Uint8Array(data); let binary = '';
  for (let i = 0; i < bytes.length; i += 8192) binary += String.fromCharCode(...bytes.slice(i, i + 8192));
  return btoa(binary);
}
function raw(value) { return Uint8Array.from(atob(value), c => c.charCodeAt(0)); }
function hex(data) { return [...new Uint8Array(data)].map(v => v.toString(16).padStart(2, '0')).join(''); }
function unhex(value) { return Uint8Array.from(value.match(/../g) || [], x => parseInt(x, 16)); }
function escapeHtml(value) { return String(value).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
function aad(envelope) {
  const fields = ['protocol_version','session_id','conversation_id','sender_id','receiver_id','message_id','sequence_number','timestamp'];
  return encoder.encode(canonical(Object.fromEntries(fields.map(k => [k, envelope[k]]))));
}
function signingBytes(envelope) {
  const unsigned = {...envelope}; delete unsigned.signature;
  const prefix = encoder.encode('cipherchat:encrypted-message:v3\0');
  const body = encoder.encode(canonical(unsigned));
  const joined = new Uint8Array(prefix.length + body.length); joined.set(prefix); joined.set(body, prefix.length);
  return joined;
}
async function api(path, options = {}) {
  const response = await fetch(path, {...options, credentials:'same-origin'});
  const body = await response.text();
  let value;
  try { value = JSON.parse(body); } catch { throw new Error(response.ok ? 'Invalid server response' : `Server error (${response.status}). Check database settings or deployment logs.`); }
  if (!response.ok) throw new Error(value.detail || value.error || `Request failed (${response.status})`);
  return value;
}
function showError(message) { $('login-error').textContent = message; }
function status(id, value, kind = '') { const el = $(id); el.textContent = value; el.className = `pill ${kind}`; }

function openKeyDb(username) {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(`cipherchat-keys-${username}`, 1);
    request.onupgradeneeded = () => request.result.createObjectStore('keys');
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}
async function keyRecord(username, newValue) {
  const db = await openKeyDb(username);
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction('keys', newValue ? 'readwrite' : 'readonly');
      const req = newValue ? tx.objectStore('keys').put(newValue, 'identity') : tx.objectStore('keys').get('identity');
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  } finally { db.close(); }
}
async function prepareKeys() {
  const registered = (await api(`/api/identity/${me}`)).keys;
  keys = await keyRecord(me);
  if (!keys && registered) throw new Error('This account already has public keys. Use its original browser profile; private keys cannot be recovered from the server.');
  if (!keys) {
    const exchange = await crypto.subtle.generateKey('X25519', false, ['deriveBits']);
    const signing = await crypto.subtle.generateKey('Ed25519', false, ['sign','verify']);
    keys = {exchange, signing,
      exchange_public:hex(await crypto.subtle.exportKey('raw', exchange.publicKey)),
      signing_public:hex(await crypto.subtle.exportKey('raw', signing.publicKey))};
    await keyRecord(me, keys);
  }
  await api('/api/identity', {method:'POST', headers:{'Content-Type':'application/json'},
    body:JSON.stringify({exchange_public:keys.exchange_public, signing_public:keys.signing_public})});
  const fingerprint = hex(await crypto.subtle.digest('SHA-256', unhex(keys.signing_public)));
  $('fingerprints').textContent = `Your Ed25519 public-key fingerprint: ${fingerprint}`;
  await refreshPeer();
}
async function refreshPeer() {
  if (!me || me === 'mallory') return;
  const other = me === 'alice' ? 'bob' : 'alice';
  const found = (await api(`/api/identity/${other}`)).keys;
  if (found) {
    const pinKey = `cipherchat-peer-pin-${me}-${other}`;
    const pin = localStorage.getItem(pinKey);
    const material = `${found.exchange_public}:${found.signing_public}`;
    if (pin && pin !== material) {
      peer = null;
      status('peer-status', 'PEER KEY CHANGED · CHAT BLOCKED', 'bad');
      throw new Error('Peer public key differs from the locally pinned value');
    }
    if (!pin) localStorage.setItem(pinKey, material);
  }
  peer = found;
}
async function sessionKey() {
  if (!peer) await refreshPeer();
  if (!peer) throw new Error('Peer public key is not registered yet');
  const remote = await crypto.subtle.importKey('raw', unhex(peer.exchange_public), 'X25519', false, []);
  const shared = await crypto.subtle.deriveBits({name:'X25519', public:remote}, keys.exchange.privateKey, 256);
  const base = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey({name:'HKDF',hash:'SHA-256',salt:new Uint8Array(32),
    info:encoder.encode(`cipherchat-v1|cipherchat-realtime:${chat.session_id}`)}, base,
    {name:'AES-GCM',length:256}, false, ['encrypt','decrypt']);
}
async function makeEnvelope(plaintext) {
  const sequenceKey = `cipherchat-next-${me}-${chat.session_id}`;
  const sequence = Number(localStorage.getItem(sequenceKey) || 0) + 1;
  localStorage.setItem(sequenceKey, String(sequence)); // reserve before network send
  const envelope = {protocol_version:3, session_id:chat.session_id,conversation_id:'alice-bob',sender_id:me,
    receiver_id:me === 'alice' ? 'bob' : 'alice',message_id:crypto.randomUUID(),sequence_number:sequence,
    timestamp:new Date().toISOString()};
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({name:'AES-GCM',iv:nonce,additionalData:aad(envelope)},
    await sessionKey(), encoder.encode(plaintext));
  envelope.nonce = b64(nonce); envelope.ciphertext = b64(ciphertext);
  envelope.signature = b64(await crypto.subtle.sign('Ed25519', keys.signing.privateKey, signingBytes(envelope)));
  return envelope;
}
function addMessage(text, meta, cls = '') {
  document.querySelector('.empty-chat')?.remove();
  const line = document.createElement('div'); line.className = `message ${cls}`;
  line.innerHTML = `${escapeHtml(text)}<span class="meta">${escapeHtml(meta)}</span>`;
  $('messages').append(line); $('messages').scrollTop = $('messages').scrollHeight;
}
async function receive(envelope, historical = false) {
  try {
    if (envelope.receiver_id !== me) throw new Error('wrong recipient');
    await refreshPeer();
    if (!peer) throw new Error('peer key unavailable');
    const signing = await crypto.subtle.importKey('raw', unhex(peer.signing_public), 'Ed25519', false, ['verify']);
    if (!await crypto.subtle.verify('Ed25519', signing, raw(envelope.signature), signingBytes(envelope))) throw new Error('invalid signature');
    const stateKey = `cipherchat-seen-${me}-${envelope.session_id}`;
    const highest = Number(localStorage.getItem(stateKey) || 0);
    if (!historical && envelope.sequence_number <= highest) return;
    if (envelope.session_id !== chat.session_id) throw new Error('message belongs to another session');
    const plain = await crypto.subtle.decrypt({name:'AES-GCM',iv:raw(envelope.nonce),additionalData:aad(envelope)},
      await sessionKey(), raw(envelope.ciphertext));
    localStorage.setItem(stateKey, String(Math.max(highest, envelope.sequence_number)));
    addMessage(decoder.decode(plain), `Verified signature · seq ${envelope.sequence_number}`);
    await api('/api/delivered', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({message_id:envelope.message_id})});
  } catch (error) { addMessage(`REJECTED: ${error.message}`, envelope.message_id, 'rejected'); }
}
async function showOwn(envelope) {
  try {
    const plain = await crypto.subtle.decrypt({name:'AES-GCM',iv:raw(envelope.nonce),additionalData:aad(envelope)},
      await sessionKey(), raw(envelope.ciphertext));
    addMessage(decoder.decode(plain), `Sent · seq ${envelope.sequence_number}`, 'own');
  } catch (error) { addMessage(`Unable to read sent message: ${error.message}`, envelope.message_id, 'rejected'); }
}
function addDelivery(id, value) {
  let line = document.querySelector(`[data-delivery="${id}"]`);
  if (!line) { line = document.createElement('p'); line.dataset.delivery = id; $('delivery-list').prepend(line); }
  line.textContent = `${id.slice(0, 8)} · ${value}`;
}
function addEvidence(envelope) {
  if (!envelopes.has(envelope.message_id)) {
    envelopes.set(envelope.message_id, envelope);
    const option = document.createElement('option');
    option.value = envelope.message_id;
    option.textContent = `${envelope.sender_id} → ${envelope.receiver_id} · ${envelope.message_id.slice(0, 8)} · ${envelope.session_id}`;
    $('evidence-list').append(option);
  }
  if (!$('evidence-list').value) $('evidence-list').value = envelope.message_id;
  $('envelope-view').textContent = JSON.stringify(envelopes.get($('evidence-list').value), null, 2);
}
async function refreshDashboard() {
  if (!me) return;
  try {
    const data = await api('/api/dashboard');
    chat = data.chat;
    if (me !== 'mallory') {
      const other = me === 'alice' ? 'bob' : 'alice';
      const online = Boolean(data.presence?.[other]);
      $('peer-status').className = `peer-presence ${online ? 'online' : 'offline'}`;
      $('peer-status').innerHTML = `<span class="presence-dot"></span>${online ? 'Online now' : 'Offline · messages will be queued'}`;
    }
    status('audit-status', !data.audit_valid ? 'AUDIT FAILED · CHAT BLOCKED' : chat.blocked ? 'CHAT BLOCKED · START NEW CHAT' : `Audit valid · ${chat.session_id}`, !data.audit_valid || chat.blocked ? 'bad' : 'good');
    $('rekey').hidden = me === 'mallory' || !chat.blocked || !data.audit_valid;
    $('send-form').querySelector('button').disabled = chat.blocked || !data.audit_valid;
    const counts = data.stats || {};
    const metrics = [['Sent',counts.messages_sent || 0],['Delivered',counts.messages_delivered || 0],
      ['Signatures verified',counts.signatures_verified || 0],['Failed signatures',counts.signature_failures || 0],
      ['Replays',counts.events?.REPLAY || 0],['Tampering',counts.events?.TAMPERING || 0],
      ['Impersonation',counts.events?.IMPERSONATION || 0],['Eavesdropping',counts.events?.EAVESDROP || 0],
      ['Key substitution',counts.events?.KEY_SUBSTITUTION || 0]];
    $('counters').innerHTML = metrics.map(([label,value]) => `<div class="counter"><strong>${value}</strong><span>${label}</span></div>`).join('');
    $('events').innerHTML = (data.events || []).map(e => `<div class="event"><b>${escapeHtml(e.event_type)}</b> · ${escapeHtml(e.actor)} · ${escapeHtml(e.message_id || '')}<time>${escapeHtml(e.timestamp)}</time><br>${escapeHtml(JSON.stringify(e.detail || {}))}</div>`).join('');
  } catch (error) { status('audit-status', `Audit unavailable: ${error.message}`, 'bad'); }
}
async function refreshCaptured() {
  captured = (await api('/api/history')).messages;
  $('captured-list').innerHTML = captured.map(row => `<option value="${escapeHtml(row.envelope.message_id)}">${escapeHtml(row.envelope.sender_id)} → ${escapeHtml(row.envelope.receiver_id)} · ${escapeHtml(row.envelope.message_id.slice(0, 8))} · seq ${row.envelope.sequence_number}</option>`).join('');
  if (captured.length) $('captured-list').selectedIndex = 0;
}
async function loadHistory() {
  const records = (await api('/api/history')).messages;
  for (const row of records) {
    const e = row.envelope;
    addDelivery(e.message_id, row.delivery_status);
    addEvidence(e);
    if (seenMessages.has(e.message_id)) continue;
    seenMessages.add(e.message_id);
    if (e.receiver_id === me && e.session_id === chat.session_id) await receive(e, true);
    else if (e.sender_id === me && e.session_id === chat.session_id) await showOwn(e);
    else addMessage(`Encrypted history · ${e.sender_id} → ${e.receiver_id}`,
      `${e.message_id.slice(0, 8)} · sequence ${e.sequence_number} · ${row.delivery_status}`);
  }
}
async function syncSequence() {
  const value = (await api('/api/sequence')).highest_sequence;
  const key = `cipherchat-next-${me}-${chat.session_id}`;
  localStorage.setItem(key, String(Math.max(Number(localStorage.getItem(key) || 0), value)));
}
async function refreshAudit() {
  const records = (await api('/api/mallory/audit')).records;
  $('audit-records').innerHTML = records.map(row => `<option value="${row.number}">#${row.number} · ${escapeHtml(row.kind)} · ${escapeHtml(row.record_hash.slice(0, 12))}</option>`).join('');
  if (records.length) $('audit-records').selectedIndex = 0;
}
async function start(username) {
  if (!crypto.subtle || !indexedDB) throw new Error('Use HTTPS or localhost in a browser supporting Web Crypto and IndexedDB');
  me = username; $('login-panel').hidden = true; $('workspace').hidden = false;
  chat = (await api('/api/me')).chat;
  $('session-label').textContent = username.toUpperCase();
  $('workspace-title').textContent = username === 'mallory' ? 'Attack laboratory' : 'Messages';
  $('chat-panel').hidden = username === 'mallory'; $('mallory-panel').hidden = username !== 'mallory';
  if (username !== 'mallory') { const other = username === 'alice' ? 'Bob' : 'Alice'; $('chat-title').textContent = other; $('peer-avatar').textContent = other[0]; await prepareKeys(); await syncSequence(); await loadHistory(); }
  else { await refreshCaptured(); await refreshAudit(); }
  status('connection-status', 'HTTP refresh', 'good'); await refreshDashboard();
  refreshTimer = setInterval(async () => {
    try { await refreshDashboard(); if (me !== 'mallory') { await refreshPeer(); await loadHistory(); } }
    catch (error) { if (error.message.includes('session expired or replaced')) { location.reload(); return; } status('connection-status', `Refresh failed: ${error.message}`, 'bad'); }
  }, 3000);
}
$('login-form').onsubmit = async event => {
  event.preventDefault(); showError('');
  let loggedIn = false;
  try {
    await reserveTab($('username').value);
    const response = await api('/api/login', {method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({username:$('username').value,password:$('password').value})});
    loggedIn = true;
    await start(response.username);
  } catch (error) { if (loggedIn) await api('/api/logout', {method:'POST'}).catch(() => {}); freeTab(); me = null; showError(error.message); $('login-panel').hidden = false; $('workspace').hidden = true; }
};
$('send-form').onsubmit = async event => {
  event.preventDefault();
  const plaintext = $('message-text').value.trim();
  if (!plaintext) return;
  try {
    if (encoder.encode(plaintext).length > 65536) throw new Error('Message exceeds 65,536 bytes');
    if (chat.blocked) throw new Error('Chat blocked; start a new chat');
    const envelope = await makeEnvelope(plaintext);
    const result = await api('/api/send', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({envelope})});
    if (!result.accepted) throw new Error(result.reason);
    seenMessages.add(envelope.message_id);
    addMessage(plaintext, `Encrypted and signed · seq ${envelope.sequence_number}`, 'own');
    addDelivery(envelope.message_id, result.delivery_status);
    addEvidence(envelope);
    $('message-text').value = '';
  } catch (error) { addMessage(`SEND FAILED: ${error.message}`, 'local', 'rejected'); }
};
$('refresh-captured').onclick = refreshCaptured;
$('evidence-list').onchange = () => {
  $('envelope-view').textContent = JSON.stringify(envelopes.get($('evidence-list').value) || {}, null, 2);
};
$('refresh-audit').onclick = refreshAudit;
$('delete-record').onclick = async () => {
  const number = Number($('audit-records').value);
  if (!number || !confirm(`Delete audit record #${number}? This will block chat until the database is restored.`)) return;
  try {
    const result = await api('/api/mallory/attack', {method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({attack:'delete_record',record_number:number})});
    $('attack-result').textContent = `RECORD #${number} DELETED · AUDIT FAILED · CHAT BLOCKED: ${result.reason}`;
    $('original-envelope').textContent = JSON.stringify(result.deleted_record, null, 2);
    $('submitted-envelope').textContent = 'Row removed from MySQL; chain head retained.';
    await refreshDashboard();
  } catch (error) { $('attack-result').textContent = `Deletion error: ${error.message}`; }
};
document.querySelectorAll('[data-attack]').forEach(button => button.onclick = async () => {
  const attack = button.dataset.attack;
  const message_id = $('captured-list').value;
  try {
    const result = await api('/api/mallory/attack', {method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({attack,message_id})});
    $('attack-result').textContent = `${attack.toUpperCase()}: ${result.accepted === false ? 'REJECTED' : attack === 'eavesdrop' ? 'CIPHERTEXT ONLY' : 'OBSERVED'} · ${result.reason || ''}`;
    $('original-envelope').textContent = JSON.stringify(result.original || {}, null, 2);
    $('submitted-envelope').textContent = JSON.stringify(result.submitted || {}, null, 2);
    await refreshDashboard();
  } catch (error) { $('attack-result').textContent = `Attack error: ${error.message}`; }
});
$('logout').onclick = async () => {
  await api('/api/logout', {method:'POST'});
  me = null; freeTab(); if (refreshTimer) clearInterval(refreshTimer); location.reload();
};
$('rekey').onclick = async () => {
  try {
    const result = await api('/api/rekey', {method:'POST'});
    chat = result.chat;
    await syncSequence();
    await refreshDashboard();
    addMessage(`New chat started: ${chat.session_id}`, 'new encryption context', 'own');
  } catch (error) { addMessage(`REKEY FAILED: ${error.message}`, 'local', 'rejected'); }
};
(async () => { try { const value = await api('/api/me'); await reserveTab(value.username); await start(value.username); } catch (error) { if (error.message.includes('already open in another tab')) showError(error.message); } })();
