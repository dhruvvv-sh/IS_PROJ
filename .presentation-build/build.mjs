import fs from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { Presentation, PresentationFile } from '@oai/artifact-tool';

const ROOT = 'C:/Users/Muhir/Code/IS_PROJ';
const BUILD = ROOT + '/.presentation-build';
const SKILL = 'C:/Users/Muhir/.codex/plugins/cache/openai-primary-runtime/presentations/26.1011.11113/skills/presentations';
const PYTHON = 'C:/Users/Muhir/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/python.exe';
process.env.RUNTIME_NODE_MODULES = 'C:/Users/Muhir/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules';
const C = {cream:'#FFF9EC',pink:'#FF4C9A',yellow:'#FFE34D',cyan:'#54D8ED',black:'#111111'};
const p = Presentation.create({slideSize:{width:1280,height:720}});
const bg = await fs.readFile(BUILD+'/pixel-grid.png');
const bgBuffer = bg.buffer.slice(bg.byteOffset,bg.byteOffset+bg.byteLength);
let n=0;

function text(s,content,x,y,w,h,size=26,font='Arial',bold=false){
  const sh=s.shapes.add({geometry:'textbox',position:{left:x,top:y,width:w,height:h},fill:'none',line:{fill:'none',width:0}});
  sh.text=content;
  sh.text.style={typeface:font,fontSize:size,bold,color:C.black,wrap:'square',autoFit:'none',insets:0,verticalAlignment:'top'};
  return sh;
}
function box(s,x,y,w,h,color=C.cream){return s.shapes.add({geometry:'rect',position:{left:x,top:y,width:w,height:h},fill:color,line:{style:'solid',fill:C.black,width:3}});}
function slide(title,section,color,notes,sources=[]){
  const s=p.slides.add();n++;
  s.images.add({blob:bgBuffer,contentType:'image/png',alt:'Cream engineering grid with colorful pixel icons along the right edge',fit:'cover',position:{left:0,top:0,width:1280,height:720}});
  box(s,48,32,998,45,color);
  text(s,section.toUpperCase(),65,42,910,30,20,'Consolas',true);
  text(s,title,48,100,990,113,58,'Impact');
  text(s,'CIPHERCHAT  /  LAB EXPLANATION',50,665,700,24,16,'Consolas');
  text(s,String(n).padStart(2,'0'),985,662,58,30,22,'Consolas',true);
  s.speakerNotes.text=notes+'\n\nPROJECT SOURCES\n'+sources.map(f=>ROOT+'/'+f).join('\n');
  return s;
}
function card(s,x,y,w,h,label,body,color){
  box(s,x,y,w,h,color);text(s,label,x+20,y+18,w-40,60,34,'Impact');
  text(s,body,x+20,y+90,w-40,h-108,25,'Arial');
}
function bar(s,x,y,w,h,label,body,color){
  box(s,x,y,w,h,color);text(s,label,x+20,y+12,300,h-20,30,'Impact');
  text(s,body,x+340,y+15,w-360,h-22,24,'Arial');
}
function arrow(s,x,y,w=35,h=30){s.shapes.add({geometry:'rightArrow',position:{left:x,top:y,width:w,height:h},fill:C.black,line:{fill:C.black,width:0}});}
function qa(s,y,q,a,color){box(s,48,y,998,118,C.cream);box(s,48,y,12,118,color);text(s,q,82,y+16,925,35,28,'Arial',true);text(s,a,82,y+61,925,48,23,'Arial');}

{
 const s=slide('CIPHERCHAT','INFORMATION SECURITY LAB',C.pink,
 'OPENING SCRIPT\nCipherChat is an educational encrypted messaging prototype. It establishes shared keys, encrypts and digitally signs messages, detects protocol attacks, records evidence and demonstrates controlled recovery. The demo runs locally in Python and exposes results through a browser.\n\nPRESENTATION ROUTE\nSlides 1–17 cover the project in about 12–15 minutes. Slides 18–21 are viva preparation and can be used as an appendix. Explain one example, Alice sending Hello Bob, throughout.', ['README.md','cipherchat/ui/server.py']);
 box(s,48,237,997,245,C.yellow);text(s,'ENCRYPTED MESSAGES.\nSIGNED SENDERS.\nVISIBLE SECURITY EVENTS.',74,257,922,196,53,'Impact');
 text(s,'An educational messaging prototype',51,527,970,50,31,'Arial');
 text(s,'X25519   HKDF   AES-GCM   Ed25519',51,594,970,37,27,'Consolas',true);
}
{
 const s=slide('The problem and the goal','01 / PURPOSE',C.cyan,
 'A normal message can be observed, modified or replayed by an attacker. Encryption solves reading the content, but a secure protocol also needs to verify identity, bind the message to a session and reject reuse. CipherChat demonstrates these separate checks and records the resulting security failures. Confidentiality means hiding content. Integrity means detecting changes. Authenticity means verifying the source. Replay protection means rejecting a message that has already been accepted.', ['README.md','cipherchat/protocol/messages.py']);
 card(s,48,241,480,298,'ATTACKER CAPABILITIES','Read captured bytes\nChange a message\nReplay a valid message\nPresent a different key',C.cream);
 card(s,560,258,486,298,'PROJECT RESPONSE','Hide message content\nVerify the sender\nReject reuse\nRecord detected violations',C.cyan);
 text(s,'Each security control answers a different question',49,594,990,45,29,'Arial',true);
}
{
 const s=slide('The system architecture','02 / LAYERS',C.yellow,
 'Read the architecture from top to bottom. The browser has Alice, Bob, attacker and audit views. It sends HTTP requests to DemonstrationController. The controller calls SessionManager, SenderSession and ReceiverSession. The crypto package implements primitives through the cryptography library. The security package classifies failures, builds evidence and controls recovery. The browser only renders results. Attack buttons run isolated simulator scenarios, so their recovery state does not automatically change the active chat state.', ['cipherchat/ui/server.py','cipherchat/protocol/session.py','cipherchat/security/simulator.py']);
 bar(s,48,225,998,91,'BROWSER UI','Alice, Bob, attacker and audit views',C.cyan);
 bar(s,62,331,984,91,'CONTROLLER','HTTP requests become Python operations',C.yellow);
 bar(s,48,437,998,91,'PROTOCOL + CRYPTO','Sessions, message validation and real cryptography',C.pink);
 bar(s,62,543,984,91,'SECURITY LAYER','Attack classification, evidence and recovery',C.yellow);
}
{
 const s=slide('Two key pairs per identity','03 / IDENTITY',C.pink,
 'Alice owns two independent key pairs. X25519 is a key agreement algorithm. Ed25519 is a digital signature algorithm. These names look similar, but they perform different jobs. Private keys stay in the Identity object. Public keys can be serialized and exchanged. The peer public keys must be trusted before use. Identity IDs are labels, and a label alone does not authenticate a person. In the demo, fresh local identities provide both key pairs.', ['cipherchat/crypto/identity.py','cipherchat/protocol/session.py']);
 card(s,48,238,480,291,'X25519','Private key + peer public key\n\nCreates a shared secret\n\nKey agreement',C.yellow);
 card(s,560,256,486,291,'Ed25519','Private key signs\nPeer public key verifies\n\nBinds a message to a signer\n\nDigital signature',C.pink);
 text(s,'Private keys stay secret. Public keys can travel.',48,591,996,48,31,'Arial',true);
}
{
 const s=slide('Session establishment','04 / SHARED KEY',C.yellow,
 'First, compare presented X25519 and Ed25519 public keys with the trusted pins. A mismatch stops the operation before ECDH. Alice combines her X25519 private key with Bob’s public key. Bob combines his private key with Alice’s public key. Both obtain the same secret without sending it. HKDF-SHA-256 derives a 32-byte AES key using the secret, an application label and a non-empty context. The context identifies the use of the key. Each side installs its own sender and receiver objects.', ['cipherchat/protocol/session.py','cipherchat/crypto/key_exchange.py','cipherchat/crypto/kdf.py']);
 const items=[['PIN CHECK','Expected public keys',C.cream],['X25519','Same shared secret',C.yellow],['HKDF','32-byte AES key',C.yellow],['SESSION','Sender + receiver',C.cyan]];
 items.forEach((v,i)=>{let x=48+i*255;box(s,x,250,233,205,v[2]);text(s,v[0],x+16,274,200,56,35,'Impact');text(s,v[1],x+16,347,200,89,24);if(i<3)arrow(s,x+236,330,17,24);});
 box(s,48,513,998,110,C.cream);text(s,'Alice private + Bob public = Bob private + Alice public',70,541,950,54,27,'Consolas',true);
}
{
 const s=slide('AES-GCM protects the message','05 / ENCRYPTION',C.cyan,
 'AES-256-GCM is authenticated encryption. The key is 32 bytes, equal to 256 bits. A nonce is a public per-message value and must be unique under the same key. CipherChat generates 12 random bytes using os.urandom. The cryptography library returns ciphertext with the 16-byte GCM tag appended. If a wrong key, modified ciphertext or changed AAD causes authentication failure, plaintext is not returned. Random nonces provide probabilistic uniqueness. A production design should manage usage limits and nonce reuse carefully.', ['cipherchat/crypto/encryption.py']);
 bar(s,48,231,998,97,'32-BYTE KEY','Shared AES-256 key derived by HKDF',C.cyan);
 bar(s,62,345,984,97,'12-BYTE NONCE','Fresh random value for every encryption',C.cream);
 bar(s,48,459,998,97,'16-BYTE TAG','Authenticates ciphertext and metadata',C.cyan);
 text(s,'The nonce is public. Reuse under one key breaks security.',48,593,998,50,28,'Arial',true);
}
{
 const s=slide('AAD protects visible metadata','06 / MESSAGE FORMAT',C.yellow,
 'AAD stands for Additional Authenticated Data. It is not encrypted. It authenticates protocol version, session ID, sender ID, message ID and sequence number. Canonical JSON sorts keys and uses compact separators so both parties construct identical bytes. Nonce and ciphertext do not belong to the metadata AAD. The later signature covers metadata, nonce and ciphertext together. UUID means Universally Unique Identifier. It identifies a message but is not a secret or a cryptographic key.', ['cipherchat/protocol/messages.py']);
 box(s,48,232,601,381,C.yellow);
 text(s,'AAD FIELDS',70,250,550,47,32,'Impact');
 text(s,'protocol_version: 2\nsession_id: conversation UUID\nsender_id: alice\nmessage_id: random UUID\nsequence_number: 1',70,320,550,254,28,'Consolas');
 box(s,686,253,360,319,C.cream);text(s,'VISIBLE\nAUTHENTICATED',709,274,315,110,38,'Impact');
 text(s,'Metadata can be read.\n\nChanging it invalidates its cryptographic checks.',709,413,315,146,25);
}
{
 const s=slide('Alice sends “Hello Bob”','07 / SEND FLOW',C.pink,
 'SenderSession.encrypt performs the entire sequence. It checks that the session is active, assigns a random UUID and the next sequence number, builds canonical AAD and encrypts UTF-8 plaintext using AES-GCM. It then signs the canonical encrypted envelope with Alice’s Ed25519 private key. The signing bytes begin with cipherchat:encrypted-message:v2 and a null separator. Binary fields become Base64 strings in the final JSON. Base64 is encoding for transport, not encryption. The signature field is excluded from its own signed material.', ['cipherchat/protocol/messages.py','cipherchat/crypto/encryption.py']);
 bar(s,48,229,998,83,'01  METADATA','UUID, sender, session and sequence number',C.cream);
 bar(s,62,326,984,83,'02  AES-GCM','Encrypt plaintext with nonce and AAD',C.cyan);
 bar(s,48,423,998,83,'03  Ed25519','Sign metadata, nonce and ciphertext',C.pink);
 bar(s,62,520,984,83,'04  JSON','Base64 encodes the binary fields',C.yellow);
}
{
 const s=slide('Bob verifies before accepting','08 / RECEIVE FLOW',C.cyan,
 'The actual order is: active session check, schema validation, Ed25519 signature verification, expected session and sender binding, replay checks, AES-GCM authentication and decryption, replay-state update, UTF-8 return. The signature detects changes before decryption. The receiver updates highest_sequence and the seen-ID set only after GCM succeeds. This avoids poisoning replay state with a message that never authenticated. If any check fails, the receiver raises an exception and does not deliver the message.', ['cipherchat/protocol/messages.py']);
 const steps=[['01','Schema + signature'],['02','Session + sender binding'],['03','Sequence + message ID'],['04','GCM check + decryption'],['05','Update accepted-message state']];
 steps.forEach((v,i)=>{let y=222+i*79;box(s,48,y,998,67,i===4?C.yellow:(i%2?C.cream:C.cyan));text(s,v[0],66,y+12,63,45,30,'Impact');text(s,v[1],151,y+15,869,45,29,'Arial',i===4);});
}
{
 const s=slide('A shared key cannot prove authorship','09 / DIGITAL SIGNATURES',C.pink,
 'Alice and Bob both know the AES session key. Bob can therefore create an AES-GCM ciphertext that claims sender_id alice, but he cannot sign that envelope with Alice’s private Ed25519 key. The peer-forgery evaluation uses Bob’s signing key while claiming to be Alice. Bob’s receiver verifies against Alice’s pinned signing public key and rejects it. The digital signature supports evidence of possession of a private key, subject to correct public-key identity binding and private-key custody. It does not by itself create legal non-repudiation or prove a human personally typed a message.', ['cipherchat/security/evaluation.py','cipherchat/protocol/messages.py']);
 card(s,48,240,480,293,'AES-GCM','Both peers know the AES key.\n\nEither can generate authenticated ciphertext.',C.cream);
 card(s,560,258,486,293,'Ed25519','Only Alice has Alice’s signing private key.\n\nBob cannot forge her signature.',C.pink);
 text(s,'The signature covers the complete encrypted envelope',48,595,998,44,28,'Arial',true);
}
{
 const s=slide('Replay and tampering detection','10 / ATTACKS',C.yellow,
 'Replay means submitting unchanged valid bytes again. The signature still verifies, so signature verification alone cannot prevent replay. The receiver rejects a sequence at or below its highest accepted value and independently rejects a reused message UUID. Tampering means changing bytes or metadata. The simulator changes ciphertext, nonce, sequence number, message ID, session ID and sender ID. With the current protocol, these changes invalidate the Ed25519 signature. The project keeps strict ordering, so an older message arriving after a newer one is rejected. The seen-ID set is unbounded and in memory.', ['cipherchat/security/simulator.py','cipherchat/protocol/messages.py']);
 card(s,48,235,480,317,'REPLAY','Attacker resends valid bytes\n\nSequence already accepted?\nMessage ID already accepted?\n\nReject with ReplayError',C.yellow);
 card(s,560,253,486,317,'TAMPERING','Attacker changes a field\n\nSignature no longer matches\nGCM adds authentication\n\nReject before delivery',C.cream);
 text(s,'A valid signature alone does not stop replay',48,601,998,41,30,'Arial',true);
}
{
 const s=slide('Key substitution stops at the pin','11 / TRUST',C.pink,
 'Mallory offers her public key when Alice expects Bob’s key. SessionManager compares both presented public keys against the expected pins before key agreement. The example simulator replaces the X25519 key and fails immediately. The tests also exercise replacing the signing public key. Pinning detects disagreement with an already trusted key. This prototype obtains pins directly from locally created peer identities. It provides no certificate authority, key transparency system or safe first-contact distribution process. A mismatch does not prove which real-world attacker caused it.', ['cipherchat/protocol/session.py','cipherchat/security/simulator.py','tests/test_security.py']);
 box(s,48,235,998,166,C.pink);text(s,'EXPECTED BOB KEY',70,260,640,56,43,'Impact');text(s,'Presented Mallory key does not match',70,329,940,50,30);
 box(s,61,439,985,135,C.cream);text(s,'ESTABLISHMENT REJECTED',83,458,937,53,38,'Impact');text(s,'The simulator’s failed verification path reaches BLOCKED',83,518,937,48,25);
 text(s,'The initial trusted pin must come from a trusted channel',48,607,998,37,27,'Arial',true);
}
{
 const s=slide('Evidence forms a hash chain','12 / AUDIT',C.yellow,
 'An IncidentEvidence record stores an incident ID, timestamp, session ID, attack type, optional message ID and sequence, description, previous hash and current hash. SHA-256 hashes canonical JSON of all fields except the current evidence hash. The first record points to a fixed genesis hash of 64 zeros. Changing any covered field changes its hash. Reordering or removing a middle record breaks links. Evidence callers should not put plaintext or secrets in description, because the description is free-form. The incident evidence differs from UI ObservationEvents, which deliberately expose plaintext and session keys for teaching.', ['cipherchat/security/evidence.py','cipherchat/ui/server.py']);
 const labels=['GENESIS','RECORD 1','RECORD 2','RECORD 3'];
 labels.forEach((label,i)=>{let x=48+i*255;box(s,x,252,233,159,i===0?C.cream:C.yellow);text(s,label,x+17,273,203,48,32,'Impact');text(s,i===0?'000…000':'previous hash\n+ record fields',x+17,338,203,64,23,'Consolas');if(i<3)arrow(s,x+236,316,17,24);});
 bar(s,48,464,998,92,'EVIDENCE FIELDS','Incident, time, session, classification and hashes',C.cream);
 text(s,'Incident evidence excludes plaintext and key material',48,598,998,43,28,'Arial',true);
}
{
 const s=slide('The checkpoint decides what is trusted','13 / LOG INTEGRITY',C.pink,
 'A trusted checkpoint contains the expected record count and final hash. An attacker deleting the last record leaves the remaining internal links valid, but the count and tip disagree with the checkpoint. Rewriting all records and recalculating all hashes also fails if the original checkpoint remains independently protected. The current browser controller computes a fresh checkpoint from the current log before verifying it. It can detect many inconsistent edits, but cannot reliably detect a full rewrite or tail deletion against a separately retained original checkpoint. The requested administrator warning, active-chat lockout and forced new-conversation workflow has not been implemented. Present that as planned, not completed.', ['cipherchat/security/evidence.py','cipherchat/ui/server.py']);
 card(s,48,231,480,245,'TRUSTED CHECKPOINT','Expected record count\nExpected final hash\n\nStore separately from the log',C.pink);
 card(s,560,248,486,245,'CURRENT UI LIMIT','The UI derives a checkpoint from its current log.\n\nIndependent retention is missing.',C.cream);
 box(s,48,529,998,105,C.yellow);text(s,'PLANNED: administrator alert + messaging lockout + new conversation',70,546,950,74,28,'Arial',true);
}
{
 const s=slide('Recovery follows explicit states','14 / RECOVERY',C.cyan,
 'RecoveryMachine allows only specified transitions. report_violation moves from SECURE through SUSPECTED_ATTACK to QUARANTINED. begin_verification moves to VERIFYING. Successful verification moves to REKEYING, and rekey_complete moves to SECURE. Failed verification moves to BLOCKED. BLOCKED has no permitted transition back to SECURE inside that machine. SessionManager.rekey installs a new session ID and context and invalidates old sender and receiver objects. Current rekey uses the existing X25519 identity private keys, so it does not create a fresh ECDH exchange or a Signal-style ratchet. The simulator automatically calls verification success for its controlled recoverable cases. UI attacks run separate scenarios.', ['cipherchat/security/recovery.py','cipherchat/protocol/session.py','cipherchat/security/simulator.py']);
 const top=[['SECURE',48,C.cyan],['SUSPECTED',383,C.yellow],['QUARANTINED',718,C.pink]];
 top.forEach(([l,x,c],i)=>{box(s,x,239,300,90,c);text(s,l,x+17,262,266,48,31,'Impact');if(i<2)arrow(s,x+302,268,31,25);});
 box(s,383,367,328,90,C.yellow);text(s,'VERIFYING',403,389,287,48,33,'Impact');
 box(s,48,518,480,97,C.cyan);text(s,'REKEYING  /  SECURE',68,540,440,54,34,'Impact');
 box(s,560,518,486,97,C.pink);text(s,'BLOCKED',580,540,440,54,34,'Impact');
 text(s,'verification succeeds',49,471,479,34,23,'Consolas');text(s,'verification fails',561,471,484,34,23,'Consolas');
 s.shapes.add({geometry:'downArrow',position:{left:867,top:330,width:27,height:28},fill:C.black,line:{width:0,fill:C.black}});
 s.shapes.add({geometry:'leftArrow',position:{left:712,top:397,width:170,height:28},fill:C.black,line:{width:0,fill:C.black}});
}
{
 const s=slide('Demo route and verification','15 / LAB WALKTHROUGH',C.yellow,
 'DEMO SCRIPT\nStart python -m cipherchat.ui.server and open http://127.0.0.1:8000. Send Hello Bob from Alice, reply from Bob, then open audit to inspect the actual nonce, signature and encrypted envelope. Run replay and inspect the detected violation and simulator recovery history. Run key substitution and show the simulator BLOCKED result. Explain that these buttons use isolated simulator sessions.\n\nCOMMANDS\npython -m pytest -q\npython -m cipherchat.security.simulator\npython -m cipherchat.security.evaluation\n\nRECORDED RESULTS\nThe 11 October 2026 report evaluates 100 confidentiality samples and records six passing property cases. The previous completed implementation run passed 31 tests. These are recorded results, not a fresh execution claim. The six cases cover confidentiality, authenticity, integrity, peer forgery resistance, evidence tampering and protocol access checks.', ['cipherchat/ui/server.py','security_test_results/SECURITY_TEST_REPORT.md','tests/test_ui_observation.py']);
 bar(s,48,224,998,83,'01  SEND','Alice sends a message. Bob replies.',C.cyan);
 bar(s,62,320,984,83,'02  INSPECT','Audit shows the envelope and signature verification.',C.cream);
 bar(s,48,416,998,83,'03  ATTACK','Replay recovers. Key substitution blocks its scenario.',C.yellow);
 box(s,48,531,998,106,C.yellow);text(s,'RECORDED VERIFICATION',68,546,459,39,28,'Impact');text(s,'31 tests passed   /   6 property cases passed',68,592,940,36,25,'Consolas',true);
}
{
 const s=slide('Current boundaries and next steps','16 / LIMITATIONS',C.pink,
 'Be honest about boundaries. This is one local Python process and a teaching browser. It has no real peer transport, persistent replay database, user login or role authorization. The audit tab is a view, not a privileged authenticated administrator account. The UI intentionally exposes AES session keys and plaintext for demonstration, which is unsuitable for production. The current session replacement uses the same identity key agreement keys and a new HKDF context, not a fresh ECDH ratchet. Production improvements include independent protected checkpoint storage, log-compromise alert and chat blocking, secure first-contact key verification, persistent bounded replay state and proper endpoint key storage. Digital signatures remain limited by private-key custody and public-key provenance.', ['README.md','cipherchat/ui/server.py','cipherchat/protocol/session.py']);
 card(s,48,231,480,356,'CURRENT PROTOTYPE','Local Python process\nIn-memory state\nExternal trust for pins\nStrict message ordering\nDemo exposes the AES key',C.cream);
 card(s,560,249,486,356,'NEXT IMPLEMENTATION','Protected checkpoints\nLog-compromise alert\nBlock both chat senders\nExplicit new conversation\nFresh ECDH session keys',C.pink);
}
{
 const s=slide('Viva: keys and encryption','APPENDIX / Q&A 01',C.yellow,
 'PRACTICE\nAnswer each question in one sentence before expanding.\n1. X25519 is agreement and Ed25519 is signing. They use separate private keys.\n2. HKDF processes secret material and binds derived keys to a domain and context.\n3. Nonces are public but must remain unique for a given AES-GCM key. Reuse can expose information and allow forgery.\nFOLLOW-UP\nDoes X25519 encrypt the message? No, AES-GCM performs message encryption. Does Base64 protect it? No, Base64 converts binary values into JSON-safe text.', ['cipherchat/crypto/key_exchange.py','cipherchat/crypto/kdf.py','cipherchat/crypto/encryption.py','cipherchat/crypto/identity.py']);
 qa(s,225,'Why X25519 and Ed25519?','X25519 establishes the shared secret. Ed25519 signs messages.',C.yellow);
 qa(s,361,'Why HKDF before AES?','It derives a 32-byte key bound to the application and context.',C.yellow);
 qa(s,497,'Does the nonce need to be secret?','No. It needs to be unique under the same AES-GCM key.',C.yellow);
}
{
 const s=slide('Viva: message protection','APPENDIX / Q&A 02',C.cyan,
 'PRACTICE\nAAD is visible metadata authenticated by AES-GCM. A signature covers canonical envelope bytes and uses a private signing key. Both peers know the AES key, but each has a separate signing private key. An attacker can replay the original signed bytes, so valid signature verification does not establish freshness. Sequence and UUID checks solve that in this protocol.\nFOLLOW-UP\nWhich checks occur before decryption? Schema, signature, session binding, sender binding and replay checks.\nWhy update replay state after authentication? To avoid remembering attacker-controlled invalid messages.', ['cipherchat/protocol/messages.py','cipherchat/security/evaluation.py']);
 qa(s,225,'What is AAD?','Visible metadata whose integrity AES-GCM authenticates.',C.cyan);
 qa(s,361,'Why sign a message that already has a GCM tag?','Both peers know the AES key. Only Alice has her signing private key.',C.cyan);
 qa(s,497,'Does a valid signature prevent replay?','No. Sequence numbers and accepted message IDs detect reuse.',C.cyan);
}
{
 const s=slide('Viva: evidence and trust','APPENDIX / Q&A 03',C.pink,
 'PRACTICE\nA hash chain detects inconsistency, but a powerful attacker can rewrite the whole chain and recompute hashes. A separately protected original checkpoint anchors verification. Pinning rejects keys that differ from trusted expected keys. It cannot safely identify first contact if the expected pin was supplied by the attacker. The UI log-compromise enforcement request remains planned.\nFOLLOW-UP\nDoes the evidence hash prove who wrote it? No. SHA-256 is not a digital signature.\nDoes a key mismatch prove MITM? No. It indicates a trust binding failure, not a proven attribution.', ['cipherchat/security/evidence.py','cipherchat/protocol/session.py','cipherchat/ui/server.py']);
 qa(s,225,'Can a hash chain detect every rewrite by itself?','A trusted independent checkpoint must anchor the count and tip.',C.pink);
 qa(s,361,'Does pinning solve first-time identity verification?','It checks a trusted expected key. Initial provisioning stays external.',C.pink);
 qa(s,497,'Does log compromise currently disable both senders?','No. Administrator warning and chat lockout remain planned.',C.pink);
}
{
 const s=slide('Viva: recovery and claims','APPENDIX / Q&A 04',C.yellow,
 'PRACTICE\nRekeying replaces sender and receiver sessions and invalidates old objects. The project changes session IDs and HKDF context but reuses X25519 identity key material, so it does not establish a fresh ECDH secret on every rekey. The Ed25519 test demonstrates recipient forgery resistance. Legal non-repudiation additionally depends on identity verification, key protection, timestamps and policy. The prototype demonstrates protocol behavior, not production security.\nCLOSING SCRIPT\nCipherChat combines authenticated encryption and digital signatures with replay checks, evidence chains and explicit recovery. Its strongest educational value is showing how these controls perform different jobs and how their trust assumptions affect the outcome.', ['cipherchat/protocol/session.py','cipherchat/security/recovery.py','cipherchat/security/evaluation.py']);
 qa(s,225,'What happens during rekeying?','New session ID and HKDF context. Old session objects become inactive.',C.yellow);
 qa(s,361,'Do signatures guarantee legal non-repudiation?','They prove key possession. Identity binding and key custody still matter.',C.yellow);
 qa(s,497,'Is CipherChat ready for production?','It demonstrates controls. Transport, persistence and secure key storage remain.',C.yellow);
}

await fs.mkdir(BUILD+'/previews',{recursive:true});
await (await PresentationFile.exportPptx(p)).save(BUILD+'/candidate.pptx');
for(let i=0;i<p.slides.items.length;i++){
 const s=p.slides.items[i];
 const png=await p.export({slide:s,format:'png',scale:1});
 await fs.writeFile(BUILD+'/previews/slide-'+String(i+1).padStart(2,'0')+'.png',new Uint8Array(await png.arrayBuffer()));
 console.log('Rendered slide',i+1);
}
const {finalizePresentation}=await import(pathToFileURL(SKILL+'/container_tools/artifact_tool_utils.mjs').href);
await finalizePresentation({workspaceDir:ROOT,candidatePath:BUILD+'/candidate.pptx',finalPath:ROOT+'/output/CipherChat-Lab-Presentation.pptx',pythonExecutable:PYTHON,integrityValidatorPath:SKILL+'/container_tools/inspect_presentation_package_integrity.py',layoutValidatorPath:SKILL+'/container_tools/inspect_presentation_layout_geometry.py',layoutArgs:['--expected-slide-size-emu','12192000,6858000','--validate-heading-fit'],fontPolicy:{basis:'design',families:['Impact','Arial','Consolas']},verifyArtifactToolImport:true,receiptPath:BUILD+'/validation.json',explicitTotalSlideCount:21,requiredNativeTableOwnerSlides:[],requiredNativeChartOwnerSlides:[]});
console.log('Final deck created');
