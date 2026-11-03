const $ = selector => document.querySelector(selector);
const $$ = selector => [...document.querySelectorAll(selector)];
const escapeHtml = value => String(value ?? '').replace(/[&<>"']/g, character => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
}[character]));
const short = (value, length = 18) => value ? `${String(value).slice(0, length)}…` : '—';
const time = value => value ? new Date(value).toLocaleTimeString([], {hour: '2-digit', minute: '2-digit'}) : '—';

let state = {events: [], deliveries: [], evidence: {records: [], checkpoint: {}, chain_valid: true}};
let selectedEvent = 0;

async function api(path, options = {}) {
  const response = await fetch(path, options);
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || 'Request failed');
  return data;
}

function rows(items) {
  return items.map(([label, value]) => `<dt>${escapeHtml(label)}</dt><dd>${escapeHtml(value)}</dd>`).join('');
}

function showModal(message) {
  $('#modal-message').textContent = message;
  $('#system-modal').hidden = false;
  $('#modal-ok').focus();
}

function closeModal() { $('#system-modal').hidden = true; }

function switchScreen(name) {
  const allowed = state.role === 'alice' ? ['sender', 'administrative']
    : state.role === 'bob' ? ['receiver', 'administrative']
    : state.role === 'eva' ? ['attacker', 'administrative'] : null;
  if (allowed && !allowed.includes(name)) name = allowed[0];
  $$('.screen').forEach(screen => { screen.hidden = screen.dataset.view !== name; });
  $$('[data-screen]').forEach(button => {
    if (button.dataset.screen === name) button.setAttribute('aria-current', 'page');
    else button.removeAttribute('aria-current');
  });
  history.replaceState(null, '', `#${name}`);
  const labels = {sender: 'Alice', receiver: 'Bob', attacker: 'Attacker', administrative: 'Audit'};
  document.title = `CipherChat :: ${labels[name]}`;
}

function applyRole() {
  const allowed = state.role === 'alice' ? ['sender', 'administrative']
    : state.role === 'bob' ? ['receiver', 'administrative']
    : state.role === 'eva' ? ['attacker', 'administrative'] : null;
  if (!allowed) return;
  $('.dateline').textContent = 'LAN LAB';
  if (state.role === 'eva') {
    $('[data-view="attacker"] .screen-heading .presence').textContent = 'controlled tests // local lab network';
  }
  $$('[data-screen]').forEach(button => { button.hidden = !allowed.includes(button.dataset.screen); });
  const current = location.hash.slice(1);
  if (!allowed.includes(current)) switchScreen(allowed[0]);
}

function conversationFor(viewer) {
  const deliveries = state.deliveries || [];
  if (!deliveries.length) return '<p class="empty">No messages yet.</p>';
  return deliveries.map(delivery => {
    const own = delivery.sender === viewer;
    const label = own ? 'you' : delivery.sender;
    return `<article class="message ${own ? 'outgoing' : 'incoming'}">
      <p class="message-line"><span>${escapeHtml(label)}</span> ${escapeHtml(delivery.plaintext)}</p>
      <p class="message-meta">${escapeHtml(time(delivery.timestamp))} // encrypted // authenticated</p>
    </article>`;
  }).join('');
}

function renderConversation() {
  $('#alice-conversation').innerHTML = conversationFor('alice');
  $('#bob-conversation').innerHTML = conversationFor('bob');

  for (const person of ['alice', 'bob']) {
    const last = [...(state.deliveries || [])].reverse().find(delivery => delivery.sender === person);
    const detail = $(`#${person}-details`);
    detail.hidden = !last;
    if (!last) continue;
    $(`#${person}-technical`).innerHTML = rows([
      ['message', last.message_id],
      ['sequence', last.sequence_number],
      ['aad hash', last.aad_sha256],
      ['envelope hash', last.envelope_sha256],
      ['signature', short(last.signature, 28)],
      ['signature verified', last.signature_verified ? 'yes // Ed25519' : 'no']
    ]);
  }
}

function renderChatState() {
  const status = state.recovery?.state || 'SECURE';
  const unavailable = status !== 'SECURE' || Boolean(state.connection_error);
  const message = state.connection_error ? 'RELAY DISCONNECTED // sending paused'
    : status === 'WAITING' ? 'WAITING FOR PEER // sending will start when both connect'
    : status === 'REKEYING' || status === 'VERIFYING' ? 'VERIFYING AND REKEYING // sending paused'
    : status === 'QUARANTINED'
    ? 'CHAT QUARANTINED // sending paused until verification and rekey'
    : 'CHAT BLOCKED // start a new session to send again';
  $$('[data-chat-alert]').forEach(alert => {
    alert.hidden = !unavailable;
    alert.querySelector('[data-chat-state]').textContent = unavailable ? message : '';
    alert.querySelector('[data-recover]').hidden = status !== 'QUARANTINED' || Boolean(state.connection_error);
  });
  $$('.composer').forEach(form => {
    form.querySelector('textarea').disabled = unavailable;
    form.querySelector('button[type="submit"]').disabled = unavailable;
  });
  for (const [view, peer] of [['sender', 'Bob'], ['receiver', 'Alice']]) {
    $(`[data-view="${view}"] .screen-heading .presence`).textContent = unavailable
      ? `${status.toLowerCase()} // sending disabled`
      : `connected to ${peer} // encrypted // signed`;
  }
}

function renderAttack() {
  const attack = state.attack || state.attacks?.at(-1);
  $('#attack-empty').hidden = Boolean(attack);
  $('#attack-result').hidden = !attack;
  if (!attack) return;
  $('#attack-result').innerHTML = rows([
    ['attack', attack.attack_type],
    ['detected', attack.detected ? 'yes' : 'no'],
    ['evidence', attack.evidence_generated ? short(attack.evidence_hash, 24) : 'not recorded'],
    ['response', attack.attack_type === 'EVIDENCE_DELETION'
      ? `checkpoint rejected ${attack.original_record_count} → ${attack.altered_copy_count} records // chat ${attack.recovery_state.toLowerCase()}`
      : attack.rekeyed ? 'session rekeyed' : attack.recovery_state.toLowerCase()],
    ['detail', attack.detail]
  ]);
}

function filteredEvents() {
  const query = $('#event-query').value.trim().toLowerCase();
  return (state.events || []).map((event, index) => ({event, index})).filter(({event}) =>
    !query || `${event.title} ${event.category}`.toLowerCase().includes(query)
  );
}

function renderEvents() {
  if (!state.events?.length) return;
  selectedEvent = Math.min(selectedEvent, state.events.length - 1);
  $('#event-list').innerHTML = filteredEvents().map(({event, index}) => `
    <button type="button" class="result-row" data-event="${index}" role="option" aria-selected="${index === selectedEvent}">
      <span>[${String(index + 1).padStart(2, '0')}]</span>
      <span>${escapeHtml(event.title.toLowerCase())}</span>
      <span>${escapeHtml(time(event.timestamp))}</span>
    </button>`).join('');
  $$('[data-event]').forEach(button => button.onclick = () => {
    selectedEvent = Number(button.dataset.event);
    renderEvents();
  });
  const event = state.events[selectedEvent];
  $('#event-title').textContent = event.title;
  $('#event-data').textContent = JSON.stringify(event.data, null, 2);
  $('#event-explanation').textContent = event.explanation;
}

function renderEvidence() {
  const evidence = state.evidence || {records: [], chain_valid: true};
  const records = evidence.records || [];
  $('#evidence-state').textContent = `chain ${evidence.chain_valid ? 'valid' : 'invalid'} // ${records.length} record${records.length === 1 ? '' : 's'}`;
  $('#evidence-empty').hidden = records.length > 0;
  $('#evidence-table').innerHTML = records.map(record => `
    <tr>
      <td>${escapeHtml(record.attack_type)}</td>
      <td>${escapeHtml(time(record.timestamp))}</td>
      <td title="${escapeHtml(record.incident_id)}">${escapeHtml(short(record.incident_id, 12))}</td>
      <td title="${escapeHtml(record.evidence_hash)}">${escapeHtml(short(record.evidence_hash, 20))}</td>
    </tr>`).join('');
  $('#audit-summary').textContent = `${state.deliveries?.length || 0} messages // ${records.length} incidents`;
}

function render() {
  applyRole();
  renderChatState();
  renderConversation();
  renderAttack();
  renderEvents();
  renderEvidence();
}

function setState(nextState, preserveSelection = false) {
  state = nextState;
  if (!preserveSelection) selectedEvent = Math.max(0, (state.events || []).length - 1);
  render();
}

async function send(sender, message) {
  return api('/api/send', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({sender, message})
  });
}

$$('[data-screen]').forEach(button => button.onclick = () => switchScreen(button.dataset.screen));

$$('.composer').forEach(form => form.onsubmit = async event => {
  event.preventDefault();
  const sender = form.dataset.sender;
  const input = form.querySelector('textarea');
  const message = input.value.trim();
  if (!message) { input.focus(); return; }
  try {
    setState(await send(sender, message));
    input.value = '';
  } catch (error) { showModal(error.message); }
});

$$('[data-attack]').forEach(button => button.onclick = async () => {
  try {
    setState(await api('/api/attack', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({attack: button.dataset.attack})
    }));
  } catch (error) { showModal(error.message); }
});

$$('[data-recover]').forEach(button => button.onclick = async () => {
  try {
    setState(await api('/api/recover', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: '{}'}));
  } catch (error) { showModal(error.message); }
});

$('#reset').onclick = async () => {
  try {
    setState(await api('/api/reset'));
    switchScreen('sender');
  } catch (error) { showModal(error.message); }
};

$('#event-query').oninput = renderEvents;
$('#modal-ok').onclick = closeModal;
document.addEventListener('keydown', event => {
  if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
    event.preventDefault();
    switchScreen('administrative');
    $('#event-query').focus();
  }
  if (event.key === 'Escape') closeModal();
});

const screen = ['sender', 'receiver', 'attacker', 'administrative'].includes(location.hash.slice(1))
  ? location.hash.slice(1) : 'sender';
switchScreen(screen);
api('/api/state').then(setState).catch(error => showModal(error.message));

let polling = false;
setInterval(async () => {
  if (!state.role || polling) return;
  polling = true;
  try {
    const next = await api('/api/state');
    if (next.revision !== state.revision || next.connection_error !== state.connection_error) {
      setState(next, true);
    }
  } catch (_) { /* The next successful poll refreshes the local UI. */ }
  finally { polling = false; }
}, 750);
