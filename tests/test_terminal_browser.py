"""Opt-in real Chromium/WebCrypto tests against an isolated in-memory HTTP backend.
Run: CIPHERCHAT_TEST_BROWSER=1 pytest tests/test_terminal_browser.py
Install the browser extra and run python -m playwright install chromium first.
"""
import os
import socket
import threading
import time
from pathlib import Path
import pytest
import uvicorn
from cipherchat.realtime import server
from tests.test_realtime import MemoryDatabase

pytestmark = pytest.mark.skipif(os.getenv("CIPHERCHAT_TEST_BROWSER") != "1", reason="opt-in browser tests")

@pytest.fixture
def browser_lab(monkeypatch):
    playwright = pytest.importorskip("playwright.sync_api")
    db = MemoryDatabase()
    monkeypatch.setattr(server, "_database", lambda: db)
    for name in ("CIPHERCHAT_API_UPSTREAM_URL", "CIPHERCHAT_CENTRAL_ONLY", "CIPHERCHAT_ENABLE_DESTRUCTIVE_DEMO"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("CIPHERCHAT_COOKIE_SECURE", "0")
    monkeypatch.setenv("CIPHERCHAT_RATE_LIMIT", "0")
    monkeypatch.setenv("CIPHERCHAT_SESSION_SECRET", "browser-test-only-" * 3)
    for role in ("alice", "bob", "mallory"):
        monkeypatch.setenv(f"CIPHERCHAT_{role.upper()}_PASSWORD", role + "-password")
    sock = socket.socket(); sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    service = uvicorn.Server(uvicorn.Config(server.app, log_level="error"))
    thread = threading.Thread(target=lambda: service.run(sockets=[sock]), daemon=True); thread.start()
    deadline = time.monotonic() + 10
    while not service.started:
        if time.monotonic() > deadline: raise RuntimeError("test server failed to start")
        time.sleep(.05)
    with playwright.sync_playwright() as pw:
        browser = pw.chromium.launch()
        try: yield browser, f"http://127.0.0.1:{port}", db, playwright.expect
        finally: browser.close()
    service.should_exit = True; thread.join(timeout=5); sock.close()


def login(browser, url, role, expect):
    context = browser.new_context(viewport={"width":1440,"height":1000})
    page = context.new_page(); page.goto(url)
    expect(page.locator('.login-button')).to_be_enabled()
    page.select_option('#username', role); page.fill('#password', role + '-password'); page.click('.login-button')
    expect(page.locator('#workspace')).to_be_visible(timeout=20000)
    return page


def approve(a, b, expect):
    expect(a.locator('#peer-change')).to_be_visible(timeout=15000)
    fingerprint = b.locator('#fingerprints').inner_text().split(': ')[-1]
    a.fill('#peer-fingerprint-confirm',fingerprint); a.click('#approve-peer')
    expect(a.locator('#peer-change')).to_be_hidden(timeout=15000)
    expect(a.locator('#send-form button')).to_be_enabled(timeout=15000)


def send(a, b, text, expect):
    expect(a.locator('#send-form button')).to_be_enabled(timeout=15000)
    a.fill('#message-text',text); a.click('#send-form button')
    expect(b.locator('#messages')).to_contain_text(text,timeout=20000)
    expect(a.locator('#message-text')).to_have_value('')


def test_three_roles_crypto_attacks_recovery_and_network_failures(browser_lab):
    browser,url,db,expect = browser_lab
    alice = login(browser,url,'alice',expect); bob = login(browser,url,'bob',expect); mallory = login(browser,url,'mallory',expect)
    approve(alice,bob,expect); approve(bob,alice,expect)
    send(alice,bob,'Hello Bob / \u0928\u092e\u0938\u094d\u0924\u0947 / \U0001f510',expect)
    send(bob,alice,'Hello Alice - verified reply',expect)
    assert 'Hello Bob' not in str(db.saved)
    expect(mallory.locator('#captured-list option')).to_have_count(2,timeout=15000)
    mallory.click('[data-attack=eavesdrop]')
    expect(mallory.locator('#attack-result')).to_contain_text('CIPHERTEXT ONLY')
    for index,attack in enumerate(('replay','tamper','impersonate','stale')):
        mallory.click(f'[data-attack={attack}]')
        expect(mallory.locator('#attack-result')).to_contain_text('REJECTED',timeout=15000)
        expect(alice.locator('#rekey')).to_be_visible(timeout=15000)
        expect(alice.locator('#send-form button')).to_be_disabled()
        alice.click('#rekey')
        expect(alice.locator('#audit-status')).to_contain_text('AUDIT VALID',timeout=15000)
        send(alice,bob,f'After recovery {index}',expect)
        expect(mallory.locator('#captured-list option')).to_have_count(index+3,timeout=15000)
        mallory.select_option('#captured-list',index=0)
    # Old sessions remain readable in the same browser after reload.
    alice.reload(); expect(alice.locator('#messages')).to_contain_text('Hello Bob',timeout=20000)
    expect(alice.locator('#messages')).to_contain_text('After recovery 3',timeout=20000)
    # Drop an ACK: plaintext stays verified, retry succeeds without a rejection bubble.
    failures = [0]
    def drop_ack(route):
        failures[0] += 1
        if failures[0] == 1: route.abort()
        else: route.continue_()
    bob.route('**/api/delivered',drop_ack)
    send(alice,bob,'Receipt retry is separate',expect)
    receipt_id = list(db.saved)[-1]
    expect(bob.locator('#delivery-'+receipt_id)).to_contain_text('DELIVERED',timeout=20000)
    assert 'REJECTED' not in bob.locator('#messages').inner_text()
    # Lose a response after server commit: reconcile the existing envelope.
    calls = [0]
    def drop_response(route):
        calls[0] += 1
        if calls[0] == 1: route.fetch(); route.abort()
        else: route.continue_()
    alice.route('**/api/send',drop_response)
    before = len(db.saved)
    send(alice,bob,'Exactly one committed message',expect)
    assert len(db.saved) == before+1
    assert db.chat_state()['state'] == 'SECURE'
    # Key substitution has a different payload and a deliberately blocked outcome.
    expect(mallory.locator('[data-attack=key_substitution]')).to_be_enabled(timeout=15000)
    mallory.click('[data-attack=key_substitution]')
    expect(mallory.locator('#submitted-envelope')).to_contain_text('presented_public_key')
    expect(alice.locator('#rekey')).to_be_visible(timeout=15000); alice.click('#rekey')
    expect(alice.locator('#audit-status')).to_contain_text('BLOCKED',timeout=15000)
    expect(alice.locator('#workspace-error')).to_contain_text('operator')
    assert db.chat_state()['state'] == 'BLOCKED'
    out=Path('output/terminal-ui'); out.mkdir(parents=True,exist_ok=True)
    alice.screenshot(path=str(out/'alice-desktop.png'),full_page=True)
    mallory.screenshot(path=str(out/'mallory-desktop.png'),full_page=True)
    for width in (320,390,768,1280,1440):
        alice.set_viewport_size({'width':width,'height':900})
        assert alice.evaluate('document.documentElement.scrollWidth <= innerWidth'), f'workspace overflow at {width}'
    alice.screenshot(path=str(out/'workspace-final.png'),full_page=True)


def test_login_responsive_theme_and_accessibility(browser_lab):
    browser,url,db,expect = browser_lab
    page=browser.new_page(); errors=[]; page.on('pageerror',lambda error: errors.append(str(error)))
    page.goto(url); page.evaluate('document.fonts.ready')
    out=Path('output/terminal-ui'); out.mkdir(parents=True,exist_ok=True)
    for width in (320,390,768,1280,1440):
        page.set_viewport_size({'width':width,'height':1000})
        page.screenshot(path=str(out/f'debug-{width}.png'),full_page=True)
        assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'), page.evaluate('Array.from(document.querySelectorAll("body *")).filter(e=>e.getBoundingClientRect().right>innerWidth).map(e=>[e.tagName,e.className,e.getBoundingClientRect().right])')
        if width in (390,1440): page.screenshot(path=str(out/f'login-{width}.png'),full_page=True)
    assert page.locator('.scanlines').evaluate("e => getComputedStyle(e).pointerEvents") == 'none'
    assert page.locator('.card').first.evaluate("e => getComputedStyle(e).borderRadius") == '0px'
    page.evaluate("document.documentElement.style.zoom = '2'")
    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'), 'overflow at 200% zoom'
    page.evaluate("document.documentElement.style.zoom = '1'")
    page.locator('#crt-toggle').focus(); page.keyboard.press('Space')
    expect(page.locator('#crt-toggle')).to_have_attribute('aria-pressed','false')
    page.reload(); expect(page.locator('#crt-toggle')).to_have_attribute('aria-pressed','false')
    page.emulate_media(reduced_motion='reduce')
    assert page.locator('.cursor').evaluate("e => getComputedStyle(e).animationName") == 'none'
    assert not errors


def test_identity_handoff_takeover_and_connection_recovery(browser_lab):
    browser,url,db,expect = browser_lab
    alice=login(browser,url,'alice',expect); bob=login(browser,url,'bob',expect)
    approve(alice,bob,expect); approve(bob,alice,expect)
    send(alice,bob,'Before identity movement',expect)
    # A temporary transport failure must disable sends, retain drafts, and recover.
    alice.fill('#message-text','Keep this draft')
    alice.route('**/api/dashboard',lambda route: route.abort())
    expect(alice.locator('#connection-status')).to_contain_text('RECONNECTING',timeout=15000)
    expect(alice.locator('#send-form button')).to_be_disabled()
    expect(alice.locator('#message-text')).to_have_value('Keep this draft')
    alice.unroute('**/api/dashboard')
    expect(alice.locator('#connection-status')).to_contain_text('CONNECTED',timeout=20000)
    expect(alice.locator('#send-form button')).to_be_enabled()
    # Password-authorized takeover invalidates the old session but cannot recover keys.
    fresh=browser.new_context().new_page(); fresh.goto(url)
    expect(fresh.locator('.login-button')).to_be_enabled()
    fresh.select_option('#username','alice'); fresh.fill('#password','alice-password'); fresh.click('.login-button')
    expect(fresh.locator('#takeover-login')).to_be_visible(); fresh.click('#takeover-login')
    expect(fresh.locator('#identity-move')).to_be_visible(timeout=15000)
    expect(alice.locator('#login-panel')).to_be_visible(timeout=15000)
    fresh.click('#move-identity')
    expect(fresh.locator('#identity-move')).to_be_hidden(timeout=15000)
    approve(fresh,bob,expect); approve(bob,fresh,expect)
    send(fresh,bob,'After identity movement',expect)
    expect(fresh.locator('#messages')).to_contain_text('Archived ciphertext')
    fresh.reload(); expect(fresh.locator('#messages')).to_contain_text('After identity movement',timeout=15000)
    expect(fresh.locator('#send-form button')).to_be_enabled()
