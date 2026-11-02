const $ = id => document.getElementById(id);
const encoder = new TextEncoder(), decoder = new TextDecoder();
let me = null, keys = null, peer = null, pendingPeer = null, chat = null;
let healthy = false, auditValid = false, busy = false, pollFlight = null, pollTimer = null, failures = 0;
let releaseRoleLock = null, historyOffset = 0, captureOffset = 0, pendingSend = null;
const seenMessages = new Set(), envelopes = new Map(), captures = new Map(), pendingAcks = new Set(), pendingDeliveries = new Set();

async function reserveTab(username) {
  if (!navigator.locks) throw new Error('This browser needs Web Locks support. Use a current browser over HTTPS or localhost.');
  let signal;
  const acquired = new Promise(resolve => { signal = resolve; });
  navigator.locks.request(`cipherchat-role-${username}`, {ifAvailable:true}, async lock => {
    signal(Boolean(lock));
    if (lock) await new Promise(resolve => { releaseRoleLock = resolve; });
  }).catch(() => signal(false));
  if (!await acquired) throw new Error(`${username} is already open in another tab of this browser profile.`);
}
function freeTab() { releaseRoleLock?.(); releaseRoleLock = null; }
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
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15000);
  try {
    const response = await fetch(path, {...options, credentials:'same-origin', cache:'no-store', signal:controller.signal});
    const body = await response.text();
    let value;
    try { value = JSON.parse(body); } catch { throw new Error(`Server response unavailable (${response.status}). Try again.`); }
    if (!response.ok) {
      const error = new Error(typeof value.detail === 'string' ? value.detail : `Request failed (${response.status})`);
      error.status = response.status; throw error;
    }
    return value;
  } catch (error) {
    if (error.name === 'AbortError') throw new Error('Request timed out. Reconnecting...');
    throw error;
  } finally { clearTimeout(timeout); }
}
const post = (path, data, extra = {}) => api(path, {method:'POST',headers:{'Content-Type':'application/json', ...extra},body:JSON.stringify(data || {})});
function status(id, value, kind = '') { const el = $(id); el.textContent = value; el.className = `pill ${kind}`; }
function workspaceError(message = '') { $('workspace-error').textContent = message; $('workspace-error').hidden = !message; }
function updateControls() {
  const ready = healthy && auditValid && !busy;
  const canSend = ready && keys && peer && !pendingPeer && chat && !chat.blocked && !pendingSend;
  $('send-form').querySelector('button').disabled = !canSend;
  $('composer-status').textContent = pendingSend ? 'Confirming delivery / your message will not be duplicated.' :
    busy ? 'Working...' : !healthy ? 'Connecting / draft stays here' : !auditValid ? 'Audit failed / sending blocked' :
    chat?.blocked ? `${chat.state} / verify the incident to continue` : !keys ? 'Local identity needed' :
    pendingPeer ? 'Compare and approve your partner\u2019s fingerprint' : !peer ? 'Waiting for your partner\u2019s identity' : 'Encrypted + signed in this browser';
  document.querySelectorAll('[data-attack]').forEach(button => {
    button.disabled = !ready || (button.dataset.attack !== 'key_substitution' && !$('captured-list').value) || Boolean(chat?.blocked);
  });
  for (const id of ['rekey','move-identity','approve-peer','refresh-captured','refresh-audit','delete-record','load-more-history','load-more-captures']) $(id).disabled = busy || !healthy;
  $('login-form').querySelector('button').disabled = busy;
  $('takeover-login').disabled = busy;
  $('logout').disabled = busy;
}
async function action(fn) {
  if (busy) return;
  busy = true; updateControls();
  try { if (pollFlight) await pollFlight; await fn(); }
  catch (error) {
    if (error.status === 401 && me) signedOut(error.message);
    else workspaceError(error.message);
  } finally { busy = false; updateControls(); }
}
function signedOut(message = '') {
  clearTimeout(pollTimer); freeTab();
  me = keys = peer = pendingPeer = chat = null;
  healthy = auditValid = false; pendingSend = null;
  historyOffset = captureOffset = 0;
  seenMessages.clear(); envelopes.clear(); captures.clear(); pendingAcks.clear(); pendingDeliveries.clear();
  $('messages').innerHTML = '<div class="empty-chat"><p>Secure channel initialized.<br>Messages sent between Alice and Bob will appear here.</p></div>'; $('delivery-list').replaceChildren(); $('captured-list').replaceChildren();
  $('evidence-list').replaceChildren(new Option('No message selected',''));
  $('envelope-view').textContent = 'Waiting for an envelope_';
  if ($('breakdown-view')) $('breakdown-view').textContent = 'Select a message above to inspect its cryptographic breakdown_';
  if ($('kdf-view')) $('kdf-view').textContent = 'Cryptographic session & key derivation details will appear here_';
  try { $('keys-modal')?.close(); } catch (e) {}
  $('message-text').value = ''; $('fingerprints').textContent = '';
  $('peer-fingerprint-confirm').value = ''; $('peer-change').hidden = true; $('identity-move').hidden = true;
  $('login-panel').hidden = false; $('workspace').hidden = true;
  $('session-label').textContent = 'CLIENT DISCONNECTED'; $('login-error').textContent = message;
}
function openKeyDb(username) {
  return new Promise((resolve,reject) => {
    const request = indexedDB.open(`cipherchat-keys-${username}`,1);
    request.onupgradeneeded = () => request.result.createObjectStore('keys');
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
    request.onblocked = () => reject(new Error('Key storage is blocked. Close other CipherChat tabs and retry.'));
  });
}
async function keyRecord(username, value, slot = 'identity') {
  const db = await openKeyDb(username);
  try {
    return await new Promise((resolve,reject) => {
      const tx = db.transaction('keys', value ? 'readwrite' : 'readonly');
      const req = value ? tx.objectStore('keys').put(value,slot) : tx.objectStore('keys').get(slot);
      let result;
      req.onsuccess = () => { result = req.result; };
      tx.oncomplete = () => resolve(result);
      tx.onerror = tx.onabort = () => reject(tx.error || new Error('Unable to save browser keys'));
    });
  } finally { db.close(); }
}
async function createKeys() {
  const exchange = await crypto.subtle.generateKey('X25519',false,['deriveBits']);
  const signing = await crypto.subtle.generateKey('Ed25519',false,['sign','verify']);
  return {exchange,signing,exchange_public:hex(await crypto.subtle.exportKey('raw',exchange.publicKey)),signing_public:hex(await crypto.subtle.exportKey('raw',signing.publicKey))};
}
const material = value => `${value.exchange_public}:${value.signing_public}`;
const fingerprint = async value => hex(await crypto.subtle.digest('SHA-256',encoder.encode(`cipherchat-identity-v1|${material(value)}`)));
const pinKey = () => `cipherchat-verified-peer-${me}`;
function rememberEpoch() {
  if (keys && peer && chat) localStorage.setItem(`cipherchat-epoch-${me}-${chat.session_id}`,JSON.stringify({own:material(keys),peer}));
}
function epochPeer(sessionId) {
  if (!keys) return null;
  const value = localStorage.getItem(`cipherchat-epoch-${me}-${sessionId}`);
  if (value) { const saved = JSON.parse(value); if (saved.own === material(keys)) return saved.peer; }
  return peer;
}
async function prepareKeys() {
  const registered = (await api(`/api/identity/${me}`)).keys;
  keys = await keyRecord(me);
  const pending = await keyRecord(me,undefined,'pending');
  if (registered && pending && material(pending) === material(registered)) { keys = pending; await keyRecord(me,keys); }
  if (registered && (!keys || material(keys) !== material(registered))) {
    keys = null; $('identity-move').hidden = false; $('chat-panel').hidden = true;
    $('identity-move-text').textContent = 'This role has keys in another browser. This browser cannot decrypt with those keys.';
    return;
  }
  if (!keys) { keys = await createKeys(); await keyRecord(me,keys); }
  await post('/api/identity',{exchange_public:keys.exchange_public,signing_public:keys.signing_public});
  $('fingerprints').textContent = `Your identity fingerprint: ${await fingerprint(keys)}`;
  await refreshPeer();
}
async function refreshPeer() {
  if (!me || me === 'mallory' || !keys) return;
  const other = me === 'alice' ? 'bob' : 'alice';
  const found = (await api(`/api/identity/${other}`)).keys;
  const pin = localStorage.getItem(pinKey());
  if (found && pin !== material(found)) {
    if (!pin) {
      localStorage.setItem(pinKey(), material(found));
      peer = found; pendingPeer = null;
      $('peer-change').hidden = true;
      rememberEpoch();
    } else {
      peer = null; pendingPeer = found;
      $('peer-change-title').textContent = 'Security Alert: Partner identity key changed';
      $('peer-change-fingerprint').textContent = await fingerprint(found);
      $('peer-change').hidden = false;
    }
  } else { peer = found; pendingPeer = null; $('peer-change').hidden = true; rememberEpoch(); }
  updateControls();
}
async function sessionKey(sessionId, partner) {
  if (!partner || !keys) throw new Error('Verified identity material is unavailable');
  const remote = await crypto.subtle.importKey('raw',unhex(partner.exchange_public),'X25519',false,[]);
  const shared = await crypto.subtle.deriveBits({name:'X25519',public:remote},keys.exchange.privateKey,256);
  const base = await crypto.subtle.importKey('raw',shared,'HKDF',false,['deriveKey']);
  return crypto.subtle.deriveKey({name:'HKDF',hash:'SHA-256',salt:new Uint8Array(32),info:encoder.encode(`cipherchat-v1|cipherchat-realtime:${sessionId}`)},base,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
}
async function makeEnvelope(plaintext) {
  const sequenceKey = `cipherchat-next-${me}-${chat.session_id}`;
  const sequence = Number(localStorage.getItem(sequenceKey) || 0)+1;
  localStorage.setItem(sequenceKey,String(sequence));
  const envelope = {protocol_version:3,session_id:chat.session_id,conversation_id:'alice-bob',sender_id:me,receiver_id:me === 'alice' ? 'bob' : 'alice',message_id:crypto.randomUUID(),sequence_number:sequence,timestamp:new Date().toISOString()};
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  envelope.nonce = b64(nonce);
  envelope.ciphertext = b64(await crypto.subtle.encrypt({name:'AES-GCM',iv:nonce,additionalData:aad(envelope)},await sessionKey(envelope.session_id,peer),encoder.encode(plaintext)));
  envelope.signature = b64(await crypto.subtle.sign('Ed25519',keys.signing.privateKey,signingBytes(envelope)));
  return envelope;
}
function addMessage(text,meta,cls='') {
  const container = $('messages');
  const atBottom = container.scrollHeight-container.scrollTop-container.clientHeight < 80;
  document.querySelector('.empty-chat')?.remove();
  const line = document.createElement('div'); line.className = `message ${cls}`;
  line.innerHTML = `${escapeHtml(text)}<span class="meta">${escapeHtml(meta)}</span>`;
  container.append(line);
  if (atBottom || cls === 'own') { container.scrollTop = container.scrollHeight; $('new-messages').hidden = true; }
  else $('new-messages').hidden = false;
}
function addDelivery(id,value) {
  let line = document.getElementById(`delivery-${id}`);
  if (!line) { line = document.createElement('p'); line.id = `delivery-${id}`; $('delivery-list').prepend(line); }
  line.textContent = `${id.slice(0,8)} / ${value}`;
}
function renderBreakdown(envelope) {
  if (!envelope) return 'Select a message above to inspect its cryptographic breakdown_';
  const aadFields = ['protocol_version','session_id','conversation_id','sender_id','receiver_id','message_id','sequence_number','timestamp'];
  const aadObj = Object.fromEntries(aadFields.map(k => [k, envelope[k]]));
  const aadJson = canonical(aadObj);
  return `=== CRYPTOGRAPHIC PIPELINE INSPECTION ===

[1] AEAD CIPHER:
    Algorithm: AES-256-GCM (NIST SP 800-38D)
    Mode: Galois/Counter Mode (Authenticated Encryption)

[2] FRESH 96-BIT NONCE (IV):
    Base64: ${envelope.nonce}
    Length: 12 bytes (96 bits)
    Security: Fresh random IV generated per message; prevents keystream reuse.

[3] ASSOCIATED AUTHENTICATED DATA (AAD):
    Canonical AAD: ${aadJson}
    Byte Length: ${encoder.encode(aadJson).length} bytes
    Integrity: Authenticated by GCM tag without encryption; binds protocol
               version, session, sender, receiver, sequence, and timestamps.

[4] CIPHERTEXT + 128-BIT AUTHENTICATION TAG:
    Payload Base64: ${envelope.ciphertext}
    Polyval/GHASH Tag: Final 16 bytes authenticate ciphertext & AAD integrity.

[5] ASYMMETRIC DIGITAL SIGNATURE (Ed25519):
    Algorithm: PureEd25519 (RFC 8032)
    Signer: ${envelope.sender_id}
    Domain Prefix: cipherchat:encrypted-message:v3\\0
    Signature Base64: ${envelope.signature}
    Non-Repudiation: Proves envelope originated from ${envelope.sender_id}'s
                     private signing key; cannot be forged with AES key alone.

[6] SEQUENCE & REPLAY POLICY:
    Sequence: #${envelope.sequence_number} (strict monotonic ordering)
    Message UUID: ${envelope.message_id}`;
}

function renderKdf(envelope) {
  const sessId = envelope?.session_id || chat?.session_id || 'N/A';
  const partnerName = me === 'alice' ? 'BOB' : 'ALICE';
  return `=== ECDH KEY AGREEMENT & KDF PIPELINE ===

[1] ASYMMETRIC KEY AGREEMENT (X25519):
    Algorithm: Curve25519 ECDH scalar multiplication
    Local Role: ${me ? me.toUpperCase() : 'N/A'}
    Shared Secret: X25519(k_priv, K_pub) -> 32-byte raw shared secret
    Confidentiality: Shared secret is never transmitted over the network.

[2] KEY DERIVATION FUNCTION (HKDF-SHA-256, RFC 5869):
    PRK = HMAC-SHA-256(Salt, Shared_Secret)
    Salt: 32 zero bytes
    Info Label: cipherchat-v1|cipherchat-realtime:${sessId}
    Expand: HMAC-SHA-256(PRK, Info || 0x01) -> 32-byte AES-256 session key

[3] LOCAL CRYPTOGRAPHIC IDENTITY:
    Exchange Public (X25519): ${keys?.exchange_public || 'Loading...'}
    Signing Public (Ed25519): ${keys?.signing_public || 'Loading...'}

[4] PEER IDENTITY & PINNING:
    Partner Role: ${partnerName}
    Exchange Public: ${peer?.exchange_public || pendingPeer?.exchange_public || 'Waiting for registration'}
    Signing Public: ${peer?.signing_public || pendingPeer?.signing_public || 'Waiting for registration'}
    Trust Model: TOFU (Trust-On-First-Use) with pinned fingerprint.`;
}

let activeInspectorTab = 'envelope';
function updateInspector() {
  const selectedId = $('evidence-list').value;
  const envelope = envelopes.get(selectedId);
  $('envelope-view').textContent = envelope ? JSON.stringify(envelope, null, 2) : 'Waiting for an envelope_';
  $('breakdown-view').textContent = renderBreakdown(envelope);
  $('kdf-view').textContent = renderKdf(envelope);
}

function switchInspectorTab(tab) {
  activeInspectorTab = tab;
  $('tab-envelope').classList.toggle('active-tab', tab === 'envelope');
  $('tab-breakdown').classList.toggle('active-tab', tab === 'breakdown');
  $('tab-kdf').classList.toggle('active-tab', tab === 'kdf');
  $('envelope-view').hidden = tab !== 'envelope';
  $('breakdown-view').hidden = tab !== 'breakdown';
  $('kdf-view').hidden = tab !== 'kdf';
  updateInspector();
}

function addEvidence(envelope) {
  if (!envelopes.has(envelope.message_id)) {
    envelopes.set(envelope.message_id,envelope);
    $('evidence-list').append(new Option(`${envelope.sender_id} / ${envelope.receiver_id} / ${envelope.message_id.slice(0,8)}`,envelope.message_id));
  }
  if (!$('evidence-list').value) $('evidence-list').value = envelope.message_id;
  updateInspector();
}
async function displayEnvelope(row) {
  const e = row.envelope;
  addEvidence(e); addDelivery(e.message_id,row.delivery_status);
  if (row.delivery_status !== 'DELIVERED' && e.sender_id === me) pendingDeliveries.add(e.message_id);
  if (seenMessages.has(e.message_id)) return true;
  let partner = epochPeer(e.session_id) || peer || pendingPeer;
  if (!partner && me && me !== 'mallory') {
    const other = me === 'alice' ? 'bob' : 'alice';
    try {
      const resp = await api(`/api/identity/${other}`);
      if (resp && resp.keys) partner = resp.keys;
    } catch {}
  }
  if (!partner) {
    addMessage('Archived ciphertext / verified keys for this session are unavailable.',e.message_id);
    seenMessages.add(e.message_id); return true;
  }
  try {
    const own = e.sender_id === me;
    if (e.conversation_id !== 'alice-bob' || e.receiver_id !== (own ? (me === 'alice' ? 'bob' : 'alice') : me)) throw new Error('Invalid message routing');
    const signing = await crypto.subtle.importKey('raw',unhex(own ? keys.signing_public : partner.signing_public),'Ed25519',false,['verify']);
    if (!await crypto.subtle.verify('Ed25519',signing,raw(e.signature),signingBytes(e))) throw new Error('Signature verification failed');
    const plain = await crypto.subtle.decrypt({name:'AES-GCM',iv:raw(e.nonce),additionalData:aad(e)},await sessionKey(e.session_id,partner),raw(e.ciphertext));
    addMessage(decoder.decode(plain),`${own ? 'Sent' : 'Verified signature'} / seq ${e.sequence_number} / ${e.session_id}`,own ? 'own' : '');
    seenMessages.add(e.message_id);
    if (!own && row.delivery_status !== 'DELIVERED') pendingAcks.add(e.message_id);
    return true;
  } catch (error) {
    if (e.session_id !== chat.session_id) addMessage('Archived ciphertext / this browser cannot verify or decrypt the original identity.',e.message_id);
    else addMessage(`REJECTED: ${error.message || 'Decryption failed'}`,e.message_id,'rejected');
    seenMessages.add(e.message_id); return true;
  }
}
async function flushReceipts() {
  for (const id of [...pendingAcks].slice(0,20)) {
    try { await post('/api/delivered',{message_id:id}); pendingAcks.delete(id); addDelivery(id,'DELIVERED'); }
    catch (error) { if (error.status === 401) throw error; addDelivery(id,'Verified locally / receipt pending'); break; }
  }
  for (const id of [...pendingDeliveries].slice(0,20)) {
    const row = await api(`/api/messages/${encodeURIComponent(id)}`);
    addDelivery(id,row.delivery_status);
    if (row.delivery_status === 'DELIVERED') pendingDeliveries.delete(id);
  }
}
async function loadHistory() {
  const page = await api(`/api/history?limit=50&offset=${historyOffset}`);
  for (const row of page.messages) { if (!await displayEnvelope(row)) break; historyOffset++; }
  $('load-more-history').hidden = historyOffset >= page.total;
}
async function refreshCaptured() {
  const selected = $('captured-list').value;
  const page = await api(`/api/history?limit=50&offset=${captureOffset}`);
  for (const row of page.messages) captures.set(row.envelope.message_id,row);
  captureOffset += page.messages.length;
  $('captured-list').replaceChildren(...[...captures.values()].reverse().map(row => new Option(`${row.envelope.sender_id} / ${row.envelope.receiver_id} / ${row.envelope.message_id.slice(0,8)} / seq ${row.envelope.sequence_number}`,row.envelope.message_id)));
  if (captures.has(selected)) $('captured-list').value = selected;
  else if ($('captured-list').options.length) $('captured-list').selectedIndex = 0;
  $('load-more-captures').hidden = captureOffset >= page.total;
  updateControls();
}
async function syncSequence() {
  const value = (await api('/api/sequence')).highest_sequence;
  const key = `cipherchat-next-${me}-${chat.session_id}`;
  localStorage.setItem(key,String(Math.max(Number(localStorage.getItem(key) || 0),value)));
}
async function refreshDashboard() {
  const data = await api('/api/dashboard');
  const previous = chat?.session_id;
  const previousState = chat?.state;
  chat = data.chat; auditValid = data.audit_valid;
  if (previousState !== 'SECURE' && chat.state === 'SECURE') workspaceError();
  if (me !== 'mallory') {
    const other = me === 'alice' ? 'bob' : 'alice';
    const online = Boolean(data.presence?.[other]);
    $('peer-status').className = `peer-presence ${online ? 'online' : 'offline'}`;
    $('peer-status').textContent = online ? 'Online now' : 'Offline / messages will be queued';
    if (keys && previous !== chat.session_id) await syncSequence();
  }
  const recovery = chat.state || (chat.blocked ? 'BLOCKED' : 'SECURE');
  status('audit-status',!auditValid ? 'AUDIT FAILED / BLOCKED' : recovery === 'SECURE' ? `AUDIT VALID / ${chat.session_id}` : `${recovery} / ${chat.incident_type || 'INCIDENT'}`,!auditValid || recovery === 'BLOCKED' ? 'bad' : recovery === 'SECURE' ? 'good' : 'warning');
  $('rekey').hidden = me === 'mallory' || recovery !== 'QUARANTINED' || !auditValid;
  $('destructive-demo').hidden = me !== 'mallory' || !data.destructive_demo;
  if (recovery === 'BLOCKED') workspaceError('Verification failed. Ask the lab operator to start a fresh run; the incident evidence will be retained.');
  else if (!auditValid) workspaceError('Audit integrity failed. The operator must restore the disposable lab snapshot. Sending is blocked.');
  const counts = data.stats || {};
  const metrics = [['Sent',counts.messages_sent || 0],['Delivered',counts.messages_delivered || 0],['Signatures verified',counts.signatures_verified || 0],['Failed signatures',counts.signature_failures || 0],['Replays',counts.events?.REPLAY || 0],['Tampering',counts.events?.TAMPERING || 0],['Impersonation',counts.events?.IMPERSONATION || 0],['Eavesdropping',counts.events?.EAVESDROP || 0],['Key substitution',counts.events?.KEY_SUBSTITUTION || 0]];
  $('counters').innerHTML = metrics.map(([label,value]) => `<div class="counter"><strong>${Number(value)}</strong><span>${label}</span></div>`).join('');
  const eventsHtml = (data.events || []).map(e => `<div class="event"><b>${escapeHtml(e.event_type)}</b> / ${escapeHtml(e.actor)}<time>${escapeHtml(e.timestamp)}</time>${escapeHtml(e.message_id || '')}<br>${escapeHtml(JSON.stringify(e.detail || {}))}</div>`).join('') || '<p>No security incidents recorded.</p>';
  if ($('events').innerHTML !== eventsHtml) $('events').innerHTML = eventsHtml;
}
async function reconcileSend() {
  if (!pendingSend) return;
  const envelope = pendingSend.envelope;
  let row;
  try { row = await api(`/api/messages/${encodeURIComponent(envelope.message_id)}`); }
  catch (error) { if (error.status !== 404) throw error; }
  if (!row) {
    if (envelope.session_id !== chat.session_id || chat.blocked || Date.now()-Date.parse(envelope.timestamp) > 240000) {
      pendingSend = null; sessionStorage.removeItem(`cipherchat-pending-${me}`);
      workspaceError('The unconfirmed message was not found and its session is no longer sendable. Your draft has been preserved.'); return;
    }
    const result = await post('/api/send',{envelope},{'X-CipherChat-Request-Id':envelope.message_id});
    if (!result.accepted) {
      if (result.event_type === 'DATABASE_FAILURE') throw new Error('Delivery uncertain; checking the server again shortly.');
      pendingSend = null; sessionStorage.removeItem(`cipherchat-pending-${me}`);
      throw new Error(`Send rejected: ${result.reason}`);
    }
    row = {envelope,delivery_status:result.delivery_status};
  }
  if (canonical(row.envelope) !== canonical(envelope)) throw new Error('Message receipt does not match the submitted envelope');
  await displayEnvelope(row);
  if (pendingSend.draft !== undefined && $('message-text').value === pendingSend.draft) $('message-text').value = '';
  pendingSend = null; sessionStorage.removeItem(`cipherchat-pending-${me}`); workspaceError();
}
async function refreshAll() {
  await refreshDashboard();
  if (me === 'mallory') await refreshCaptured();
  else if (keys) { await refreshPeer(); if (auditValid) { await reconcileSend(); await loadHistory(); await flushReceipts(); } }
  healthy = true; failures = 0; status('connection-status','CONNECTED / HTTP','good'); updateControls();
}
function schedulePoll() {
  clearTimeout(pollTimer);
  if (!me) return;
  pollTimer = setTimeout(async () => {
    if (!me) return;
    if (!busy) {
      pollFlight = (async () => {
        try { await refreshAll(); }
        catch (error) {
          healthy = false; failures++;
          if (error.status === 401) signedOut(error.message);
          else status('connection-status',`RECONNECTING / ${error.message}`,'bad');
          updateControls();
        }
      })();
      await pollFlight; pollFlight = null;
    }
    schedulePoll();
  },Math.min(15000,3000*2**Math.min(failures,3)));
}
async function start(username) {
  if (!window.isSecureContext || !crypto.subtle || !window.indexedDB) throw new Error('Open this lab using HTTPS or localhost in a browser supporting Web Crypto and IndexedDB.');
  me = username;
  chat = (await api('/api/me')).chat;
  $('session-label').textContent = `${username.toUpperCase()} / AUTHENTICATED`;
  $('workspace-title').textContent = username === 'mallory' ? 'Adversarial Traffic Console' : 'Secure Channel Session';
  $('chat-panel').hidden = username === 'mallory'; $('mallory-panel').hidden = username !== 'mallory';
  if (username !== 'mallory') {
    const other = username === 'alice' ? 'Bob' : 'Alice';
    $('chat-title').textContent = other; $('peer-avatar').textContent = other[0];
    await prepareKeys();
    if (keys) await syncSequence();
    const saved = sessionStorage.getItem(`cipherchat-pending-${me}`);
    if (saved) pendingSend = JSON.parse(saved);
  }
  workspaceError(); await refreshAll();
  $('login-panel').hidden = true; $('workspace').hidden = false; $('password').value = '';
  schedulePoll();
}
async function loginAttempt(replaceExisting=false) {
  $('login-error').textContent = ''; $('takeover-login').hidden = true;
  let loggedIn = false;
  try {
    const username = $('username').value;
    await reserveTab(username);
    await post('/api/login',{username,password:$('password').value,replace_existing:replaceExisting});
    loggedIn = true; await start(username);
  } catch (error) {
    if (loggedIn) await post('/api/logout').catch(() => {});
    signedOut(error.message); $('takeover-login').hidden = !error.message.includes('already online');
  }
}
$('login-form').onsubmit = event => { event.preventDefault(); action(() => loginAttempt()); };
$('takeover-login').onclick = () => action(() => loginAttempt(true));
$('move-identity').onclick = () => action(async () => {
  $('move-error').textContent = '';
  const replacement = await createKeys();
  await keyRecord(me,replacement,'pending');
  let result;
  try {
    result = await post('/api/identity/rotate',{exchange_public:replacement.exchange_public,signing_public:replacement.signing_public,confirm_new_browser:true});
  } catch (error) {
    const registered = (await api(`/api/identity/${me}`)).keys;
    if (!registered || material(registered) !== material(replacement)) throw error;
    result = await api('/api/me');
  }
  await keyRecord(me,replacement); keys = replacement; chat = result.chat;
  $('fingerprints').textContent = `Your identity fingerprint: ${await fingerprint(keys)}`;
  $('identity-move').hidden = true; $('chat-panel').hidden = false;
  await refreshPeer(); await syncSequence(); await refreshAll();
});
async function approveCandidatePeer(explicitValue) {
  if (!pendingPeer) return;
  const candidate = pendingPeer;
  const expected = await fingerprint(candidate);
  const entered = (explicitValue !== undefined ? explicitValue : $('peer-fingerprint-confirm').value).trim().toLowerCase();
  if (entered && entered !== expected) {
    $('peer-change-error').textContent = 'Fingerprint mismatch. Compare it with your partner before approving.';
    return;
  }
  localStorage.setItem(pinKey(), material(candidate));
  $('peer-fingerprint-confirm').value = '';
  $('peer-change-error').textContent = '';
  await refreshPeer();
  await refreshAll();
}

$('approve-peer').onclick = () => action(() => approveCandidatePeer());
$('auto-approve-peer')?.addEventListener('click', () => action(async () => {
  if (pendingPeer) {
    const expected = await fingerprint(pendingPeer);
    $('peer-fingerprint-confirm').value = expected;
    await approveCandidatePeer(expected);
  }
}));
$('copy-fill-fingerprint')?.addEventListener('click', async () => {
  if (pendingPeer) {
    const expected = await fingerprint(pendingPeer);
    $('peer-fingerprint-confirm').value = expected;
    navigator.clipboard?.writeText(expected).catch(() => {});
  }
});
$('peer-change-fingerprint')?.addEventListener('click', async () => {
  if (pendingPeer) {
    const expected = await fingerprint(pendingPeer);
    $('peer-fingerprint-confirm').value = expected;
  }
});

$('operator-reset-btn')?.addEventListener('click', () => action(async () => {
  try {
    const result = await post('/api/operator/new-run');
    chat = result.chat;
    workspaceError();
    await syncSequence();
    rememberEpoch();
    addMessage(`Fresh laboratory run started (Generation ${chat.generation}): ${chat.session_id}`, 'Operator Reset');
    await refreshAll();
  } catch (error) {
    workspaceError(`Reset failed: ${error.message}`);
  }
}));

$('open-keys-inspector')?.addEventListener('click', async () => {
  if (!keys) return;
  $('modal-role').textContent = me ? me.toUpperCase() : 'UNKNOWN';
  $('modal-local-exchange').textContent = keys.exchange_public;
  $('modal-local-signing').textContent = keys.signing_public;
  $('modal-local-fingerprint').textContent = await fingerprint(keys);
  const other = me === 'alice' ? 'bob' : 'alice';
  $('modal-peer-role').textContent = other.toUpperCase();
  const partner = peer || pendingPeer;
  if (partner) {
    $('modal-peer-fingerprint').textContent = await fingerprint(partner);
    const pin = localStorage.getItem(pinKey());
    const isPinned = pin && pin === material(partner);
    $('modal-pin-status').textContent = isPinned ? 'PINNED & TRUSTED (TOFU)' : 'PENDING APPROVAL';
    $('modal-pin-status').className = `pill ${isPinned ? 'good' : 'warning'}`;
  } else {
    $('modal-peer-fingerprint').textContent = 'Partner not yet registered on server';
    $('modal-pin-status').textContent = 'OFFLINE';
    $('modal-pin-status').className = 'pill';
  }
  $('modal-kdf-info').textContent = chat ? `cipherchat-v1|cipherchat-realtime:${chat.session_id}` : 'N/A';
  $('keys-modal').showModal();
});
$('close-keys-modal')?.addEventListener('click', () => $('keys-modal').close());
$('close-keys-modal-btn')?.addEventListener('click', () => $('keys-modal').close());
$('send-form').onsubmit = event => {
  event.preventDefault();
  if ($('send-form').querySelector('button').disabled) return;
  const draft = $('message-text').value;
  action(async () => {
    if (!draft.trim()) return;
    if (encoder.encode(draft).length > 65536) throw new Error('Message exceeds 65,536 bytes. Shorten it and try again.');
    workspaceError(); await refreshDashboard(); await refreshPeer();
    if (!peer || pendingPeer || chat.blocked || !auditValid) throw new Error('Verify the identities and session before sending.');
    pendingSend = {envelope:await makeEnvelope(draft),draft};
    sessionStorage.setItem(`cipherchat-pending-${me}`,JSON.stringify({envelope:pendingSend.envelope}));
    await reconcileSend(); await refreshDashboard();
  });
};
$('refresh-captured').onclick = () => action(refreshCaptured);
$('load-more-captures').onclick = () => action(refreshCaptured);
$('load-more-history').onclick = () => action(loadHistory);
$('captured-list').onchange = updateControls;
$('evidence-list').onchange = updateInspector;
$('tab-envelope')?.addEventListener('click', () => switchInspectorTab('envelope'));
$('tab-breakdown')?.addEventListener('click', () => switchInspectorTab('breakdown'));
$('tab-kdf')?.addEventListener('click', () => switchInspectorTab('kdf'));
$('new-messages').onclick = () => { $('messages').scrollTop = $('messages').scrollHeight; $('new-messages').hidden = true; };
$('messages').onscroll = () => { if ($('messages').scrollHeight-$('messages').scrollTop-$('messages').clientHeight < 80) $('new-messages').hidden = true; };
async function refreshAudit() {
  const data = await api('/api/mallory/audit');
  $('audit-records').replaceChildren(...data.records.map(row => new Option(`#${row.number} / ${row.kind}`,String(row.number))));
}
$('refresh-audit').onclick = () => action(refreshAudit);
$('delete-record').onclick = () => action(async () => {
  const number = Number($('audit-records').value);
  if (!number || !confirm(`Delete audit record #${number} from this disposable lab? Restore its database snapshot to continue.`)) return;
  const result = await post('/api/mallory/attack',{attack:'delete_record',record_number:number});
  $('attack-result').textContent = `AUDIT BROKEN / ${result.reason}`;
  $('original-envelope').textContent = JSON.stringify(result.deleted_record,null,2);
  $('submitted-envelope').textContent = 'Record deleted. Restore the disposable database snapshot.';
  await refreshDashboard();
});
document.querySelectorAll('[data-attack]').forEach(button => button.onclick = () => action(async () => {
  const attack = button.dataset.attack, message_id = $('captured-list').value;
  const result = await post('/api/mallory/attack',{attack,message_id:message_id || undefined,field:$('tamper-field').value});
  const outcome = attack === 'eavesdrop' ? 'CIPHERTEXT ONLY / wrong-key decryption rejected' : result.accepted === false ? 'REJECTED' : 'OBSERVED';
  $('attack-result').textContent = `${attack.toUpperCase()} / ${outcome} / ${result.reason || 'No plaintext access'}${message_id ? ' / capture '+message_id.slice(0,8) : ''}`;
  $('original-envelope').textContent = JSON.stringify(result.original || {expected_public_key:result.expected_public_key},null,2);
  $('submitted-envelope').textContent = JSON.stringify(result.submitted || (attack === 'key_substitution' ? {presented_public_key:result.presented_public_key} : {ciphertext:result.observed_ciphertext,plaintext_access:result.plaintext_access,wrong_key_rejected:result.wrong_key_rejected}),null,2);
  await refreshDashboard();
}));
$('rekey').onclick = () => action(async () => {
  await refreshPeer();
  if (!peer || pendingPeer) throw new Error('Verify your partner\u2019s identity before recovery.');
  const result = await post('/api/rekey'); chat = result.chat;
  if (!result.verified) workspaceError('Key verification failed. The relationship is blocked; ask the operator to start a fresh run.');
  else { workspaceError(); await syncSequence(); rememberEpoch(); addMessage(`New encryption context: ${chat.session_id}`,'Recovery complete'); }
  await refreshAll();
});
$('logout').onclick = () => action(async () => { await post('/api/logout'); signedOut(); });
function setCrt(enabled) {
  document.documentElement.classList.toggle('crt-off',!enabled);
  $('crt-toggle').setAttribute('aria-pressed',String(enabled));
  $('crt-toggle').textContent = `[ CRT: ${enabled ? 'ON' : 'OFF'} ]`;
}
let crtEnabled = localStorage.getItem('cipherchat-crt') !== 'off' && !matchMedia('(prefers-reduced-motion: reduce)').matches;
setCrt(crtEnabled);
$('crt-toggle').onclick = () => { crtEnabled = !crtEnabled; localStorage.setItem('cipherchat-crt',crtEnabled ? 'on' : 'off'); setCrt(crtEnabled); };
(async () => {
  busy = true; updateControls();
  try { const value = await api('/api/me'); await reserveTab(value.username); await start(value.username); }
  catch (error) { signedOut(error.status === 401 ? '' : error.message); }
  finally { busy = false; updateControls(); }
})();
