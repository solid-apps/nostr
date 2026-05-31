// nostr — your Nostr control center, on your pod. The bridge between your Nostr
// keys and your Solid identity (WebID). It:
//   • inspects your profile and tells you whether your key is wired in
//     (verificationMethod + authentication) so JSS upgrades a NIP-98 request
//     to your WebID instead of a bare did:nostr — with a one-click Fix;
//   • holds / generates / imports keys (persisted to /private behind the auth
//     ladder — there can be many ways; this is one);
//   • points you at the Nostr-native apps;
//   • explains how it fits together.
//
// The CANONICAL key is the 64-char hex. npub/nsec are bech32 *display* sugar —
// a side gig, computed lazily, never the source of truth.
//
// Crypto stays lean: @noble/secp256k1 for keygen, @scure/base for bech32.
// Loaded on demand. NOT nostr-tools.

const appEl = document.getElementById('app')
const authFetch = (url, opts) => ((window.xlogin && window.xlogin.authFetch) || fetch)(url, opts)
const loggedIn = () => !!(window.xlogin && window.xlogin.id)
const loginType = () => (window.xlogin && window.xlogin.type) || null
const myId = () => (window.xlogin && window.xlogin.id) || null
const esc = (s) => String(s == null ? '' : s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]))
const toArr = (v) => v == null ? [] : Array.isArray(v) ? v : [v]

const CARD = new URL('../../../profile/card.jsonld', location.href)
const KEYSTORE = new URL('../../../private/nostr/keys.jsonld', location.href)
const PRIV_DIR = new URL('../../../private/nostr/', location.href)
const POD_ROOT = new URL('../../../', location.href)
const PROFILE_DIR = new URL('../../../profile/', location.href)

// --- canonical-key plumbing (hex is the source of truth) ---
const isHex64 = (s) => /^[0-9a-f]{64}$/i.test(s || '')
const hexToBytes = (h) => Uint8Array.from(h.match(/.{1,2}/g).map((b) => parseInt(b, 16)))
const bytesToHex = (b) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('')
// JSS multibase form for a nostr pubkey: 'f' + e701(multicodec) + 02(even-y) + hex
const MB_PREFIX = 'fe70102'
const mbFromHex = (hex) => MB_PREFIX + hex.toLowerCase()
const hexFromMb = (mb) => (typeof mb === 'string' && mb.startsWith(MB_PREFIX) && mb.length === MB_PREFIX.length + 64) ? mb.slice(MB_PREFIX.length).toLowerCase() : null
const didNostr = (hex) => 'did:nostr:' + hex

// --- lean deps, lazy ---
let _secp = null, _base = null
const secp = async () => (_secp || (_secp = await import('https://esm.sh/@noble/secp256k1@1.7.1')))
const base = async () => (_base || (_base = await import('https://esm.sh/@scure/base@1.1.6')))
async function genKey() { const s = await secp(); const sk = s.utils.randomPrivateKey(); return { sk: s.utils.bytesToHex(sk), pk: s.utils.bytesToHex(s.schnorr.getPublicKey(sk)) } }
async function npub(hex) { try { const { bech32 } = await base(); return bech32.encode('npub', bech32.toWords(hexToBytes(hex))) } catch { return '' } }
async function nsec(hex) { try { const { bech32 } = await base(); return bech32.encode('nsec', bech32.toWords(hexToBytes(hex))) } catch { return '' } }
async function decodeBech(str) { const { bech32 } = await base(); const d = bech32.decode(str); return { prefix: d.prefix, hex: bytesToHex(bech32.fromWords(d.words)) } }

const DEFAULT_RELAYS = ['wss://nos.lol', 'wss://relay.damus.io']

let KEYS = []        // [{ label, pubkey(hex), secret(hex|null), source, created, primary }]
let RELAYS = []
let CARDDOC = null
let TAB = 'identity'
let ECO = null       // wider Nostr ecosystem directory (lazy-loaded JSON)
let ECO_CAT = 'All'
let PROFILE = null   // working kind-0 metadata model for the Profile tab

const toast = (m, err) => { let t = document.querySelector('.toast'); if (!t) { t = document.createElement('div'); t.className = 'toast'; document.body.appendChild(t) } t.className = 'toast' + (err ? ' error' : ''); t.textContent = m; requestAnimationFrame(() => t.classList.add('show')); setTimeout(() => t.classList.remove('show'), 2400) }
async function copy(t) { try { await navigator.clipboard.writeText(t); toast('Copied') } catch { toast('Copy failed', true) } }

// ---- pod I/O ----
async function loadCard() { try { const r = await authFetch(CARD, { headers: { Accept: 'application/ld+json' } }); CARDDOC = r.ok ? await r.json() : null } catch { CARDDOC = null } }
async function loadStore() {
  try { const r = await authFetch(KEYSTORE, { headers: { Accept: 'application/ld+json' } }); if (r.ok) { const d = await r.json(); KEYS = Array.isArray(d.keys) ? d.keys : []; RELAYS = Array.isArray(d.relays) ? d.relays : [] } } catch { /* none */ }
  if (!RELAYS.length) RELAYS = DEFAULT_RELAYS.slice()
}
async function saveStore() {
  const doc = { '@context': { wallet: 'urn:solid:Wallet#', schema: 'https://schema.org/' }, '@id': '#this', '@type': 'urn:solid:NostrKeys', keys: KEYS, relays: RELAYS }
  const put = () => authFetch(KEYSTORE, { method: 'PUT', headers: { 'Content-Type': 'application/ld+json' }, body: JSON.stringify(doc, null, 2) })
  let r = await put()
  if (!r.ok && (r.status === 404 || r.status === 409)) { await authFetch(PRIV_DIR, { method: 'PUT', headers: { 'Content-Type': 'text/turtle' }, body: '' }).catch(() => {}); r = await put() }
  if (!r.ok) throw new Error('save ' + r.status)
}

// pubkeys currently asserted in the profile (hex) + whether each is in authentication
function cardKeys() {
  if (!CARDDOC) return []
  const vms = toArr(CARDDOC.verificationMethod)
  const auth = toArr(CARDDOC.authentication).map((a) => (a && a['@id']) || a)
  return vms.map((vm) => ({ id: vm['@id'], hex: hexFromMb(vm.publicKeyMultibase), inAuth: auth.includes(vm['@id']) })).filter((v) => v.hex)
}

// The pubkey this control center is reasoning about: your signed-in Nostr key,
// else your primary/first stored key.
function subjectHex() {
  if (loginType() === 'nostr' && isHex64(myId())) return myId().toLowerCase()
  const k = KEYS.find((k) => k.primary) || KEYS[0]
  return k ? k.pubkey : null
}

// ---- write the key into the profile (the centerpiece Fix) ----
async function linkKeyToProfile(hex) {
  if (!CARDDOC) { await loadCard() }
  if (!CARDDOC) throw new Error('No profile card to update')
  const subject = CARDDOC['@id'] || (CARD.href + '#me')
  const docUrl = CARD.href
  const vmId = `${docUrl}#nostr-${hex.slice(0, 8)}`
  CARDDOC.verificationMethod = toArr(CARDDOC.verificationMethod)
  if (!CARDDOC.verificationMethod.some((vm) => hexFromMb(vm.publicKeyMultibase) === hex)) {
    CARDDOC.verificationMethod.push({ '@id': vmId, '@type': 'Multikey', controller: subject, publicKeyMultibase: mbFromHex(hex) })
  }
  CARDDOC.authentication = toArr(CARDDOC.authentication).map((a) => (a && a['@id']) || a)
  if (!CARDDOC.authentication.includes(vmId)) CARDDOC.authentication.push(vmId)
  const r = await authFetch(CARD, { method: 'PUT', headers: { 'Content-Type': 'application/ld+json' }, body: JSON.stringify(CARDDOC, null, 2) })
  if (!r.ok) throw new Error('profile write ' + r.status)
}

// ---- nostr events: build, sign (schnorr), publish to relays ----
// A profile is a kind-0 "metadata" event; content is a JSON blob and the
// 32-byte event id (sha256 of the canonical array) is what gets signed.
function serializeEvent(e) { return JSON.stringify([0, e.pubkey, e.created_at, e.kind, e.tags, e.content]) }
async function sha256hex(str) { const s = await secp(); const h = await s.utils.sha256(new TextEncoder().encode(str)); return s.utils.bytesToHex(h) }
async function signEvent(unsigned, secretHex) {
  const s = await secp()
  const e = { pubkey: unsigned.pubkey, created_at: unsigned.created_at, kind: unsigned.kind, tags: unsigned.tags || [], content: unsigned.content }
  e.id = await sha256hex(serializeEvent(e))
  e.sig = s.utils.bytesToHex(await s.schnorr.sign(e.id, secretHex))
  return e
}

// Publish to one relay; resolves { url, ok, msg } on the relay's OK / error / timeout.
function publishToRelay(url, evt) {
  return new Promise((resolve) => {
    let done = false
    const finish = (ok, msg, ws, t) => { if (done) return; done = true; clearTimeout(t); try { ws && ws.close() } catch {} resolve({ url, ok, msg }) }
    try {
      const ws = new WebSocket(url)
      const t = setTimeout(() => finish(false, 'timeout', ws), 7000)
      ws.onopen = () => ws.send(JSON.stringify(['EVENT', evt]))
      ws.onmessage = (m) => { try { const d = JSON.parse(m.data); if (d[0] === 'OK' && d[1] === evt.id) finish(d[2] === true, d[3] || (d[2] ? 'accepted' : 'rejected'), ws, t) } catch {} }
      ws.onerror = () => finish(false, 'connection error', ws, t)
    } catch (e) { resolve({ url, ok: false, msg: String(e.message || e) }) }
  })
}
async function publishEvent(evt) { return Promise.all(RELAYS.map((u) => publishToRelay(u, evt))) }

// Best-effort fetch of the newest kind-0 for a pubkey across relays (to prefill the form).
function fetchKind0FromRelay(url, hex) {
  return new Promise((resolve) => {
    let best = null, done = false
    const finish = (ws, t) => { if (done) return; done = true; clearTimeout(t); try { ws && ws.close() } catch {} resolve(best) }
    try {
      const ws = new WebSocket(url); const sub = 'p' + hex.slice(0, 8)
      const t = setTimeout(() => finish(ws), 6000)
      ws.onopen = () => ws.send(JSON.stringify(['REQ', sub, { authors: [hex], kinds: [0], limit: 1 }]))
      ws.onmessage = (m) => { try { const d = JSON.parse(m.data); if (d[0] === 'EVENT' && d[1] === sub) { const ev = d[2]; if (!best || ev.created_at > best.created_at) best = ev } else if ((d[0] === 'EOSE' || d[0] === 'CLOSED') && d[1] === sub) finish(ws, t) } catch {} }
      ws.onerror = () => finish(ws, t)
    } catch { resolve(null) }
  })
}
async function fetchCurrentProfile(hex) {
  const evs = (await Promise.all(RELAYS.map((u) => fetchKind0FromRelay(u, hex)))).filter(Boolean)
  const best = evs.sort((a, b) => b.created_at - a.created_at)[0]
  if (!best) return null
  try { return JSON.parse(best.content) } catch { return null }
}

// ---- WebID card alignment (read + write name/avatar) ----
function firstOf(obj, keys) { for (const k of keys) { const v = obj && obj[k]; if (v != null) return (typeof v === 'object') ? (v['@id'] || v['@value'] || (Array.isArray(v) ? firstOf({ a: v[0] }, ['a']) : null)) : v } return null }
function cardName() { return CARDDOC ? firstOf(CARDDOC, ['name', 'foaf:name', 'http://xmlns.com/foaf/0.1/name', 'vcard:fn', 'fn']) : null }
function cardAvatar() { return CARDDOC ? firstOf(CARDDOC, ['img', 'foaf:img', 'http://xmlns.com/foaf/0.1/img', 'picture', 'vcard:hasPhoto', 'hasPhoto']) : null }

// Additive, namespaced write-back so the WebID card mirrors the Nostr profile.
async function writeProfileToCard(name, picture) {
  if (!CARDDOC) await loadCard()
  if (!CARDDOC) throw new Error('No profile card to update')
  let ctx = CARDDOC['@context']
  if (ctx == null) ctx = [{}]
  if (typeof ctx === 'string') ctx = [ctx, {}]
  if (Array.isArray(ctx)) { if (!ctx.some((c) => c && typeof c === 'object')) ctx.push({}) } else ctx = [ctx]
  const cobj = ctx.find((c) => c && typeof c === 'object')
  cobj.foaf = cobj.foaf || 'http://xmlns.com/foaf/0.1/'
  CARDDOC['@context'] = ctx
  // Update an existing name/img key if the card already uses one, else use foaf:*.
  if (name) { const k = ['name', 'foaf:name'].find((x) => x in CARDDOC) || 'foaf:name'; CARDDOC[k] = name }
  if (picture) { const k = ['img', 'foaf:img'].find((x) => x in CARDDOC) || 'foaf:img'; CARDDOC[k] = { '@id': picture } }
  const r = await authFetch(CARD, { method: 'PUT', headers: { 'Content-Type': 'application/ld+json' }, body: JSON.stringify(CARDDOC, null, 2) })
  if (!r.ok) throw new Error('card write ' + r.status)
}

// Upload an image into the pod's /profile/ and return its URL (so WebID + Nostr share one file).
async function uploadAvatar(file) {
  const ext = ((file.name.split('.').pop() || 'png').toLowerCase().replace(/[^a-z0-9]/g, '') || 'png')
  const dest = new URL('avatar.' + ext, PROFILE_DIR)
  const r = await authFetch(dest, { method: 'PUT', headers: { 'Content-Type': file.type || 'application/octet-stream' }, body: await file.arrayBuffer() })
  if (!r.ok) throw new Error('upload ' + r.status)
  return dest.href
}

// NIP-05: make the pod the verifier. '_' is the root identifier → displays as just the domain.
const nip05Default = () => '_@' + location.host
async function writeWellKnown(hex) {
  const url = location.origin + '/.well-known/nostr.json'
  const doc = { names: { _: hex }, relays: { [hex]: RELAYS } }
  const r = await authFetch(url, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(doc, null, 2) })
  return r.ok
}

// ---- render ----
const TABS = [
  { id: 'identity', emoji: '🪪', label: 'Identity' },
  { id: 'profile', emoji: '🦤', label: 'Profile' },
  { id: 'keys', emoji: '🔑', label: 'Keys' },
  { id: 'apps', emoji: '🧩', label: 'Apps' },
  { id: 'relays', emoji: '📡', label: 'Relays' },
  { id: 'guide', emoji: '📖', label: 'Guide' }
]

async function render() {
  if (!loggedIn()) { appEl.innerHTML = '<div class="signin-note">Sign in (the login pill, bottom-right) — ideally with <b>Nostr</b> — to wire your key into your pod identity.</div>'; return }
  appEl.innerHTML = '<p class="muted">Loading…</p>'
  await Promise.all([loadCard(), loadStore()])
  paint()
}

function paint() {
  appEl.innerHTML = '<div class="tabs"></div><div class="panel"></div>'
  const tabs = appEl.querySelector('.tabs')
  TABS.forEach((t) => {
    const b = document.createElement('button'); b.className = 'tab' + (t.id === TAB ? ' on' : '')
    b.innerHTML = `<span class="te">${t.emoji}</span><span>${t.label}</span>`
    b.onclick = () => { TAB = t.id; paint() }
    tabs.appendChild(b)
  })
  const panel = appEl.querySelector('.panel')
  ;({ identity: paintIdentity, profile: paintProfile, keys: paintKeys, apps: paintApps, relays: paintRelays, guide: paintGuide }[TAB])(panel)
}

function check(ok, label, detail) {
  return `<li class="${ok ? 'ok' : 'no'}"><span class="ci">${ok ? '✅' : '❌'}</span><div><b>${esc(label)}</b>${detail ? `<small>${detail}</small>` : ''}</div></li>`
}

async function paintIdentity(p) {
  const hex = subjectHex()
  const ck = cardKeys()
  const inVM = hex ? ck.find((c) => c.hex === hex) : null
  const isNostr = loginType() === 'nostr'
  p.innerHTML = `
    <h2>Identity bridge</h2>
    <p class="sub muted">Whether your Nostr key is wired into your profile so a signed request becomes <b>your WebID</b>, not a bare <code>did:nostr</code>.</p>
    <ul class="checks">
      ${check(isNostr, 'Signed in with Nostr', isNostr ? '' : 'You’re signed in with Solid — works too, but Nostr signing is what this wires up.')}
      ${check(!!hex, 'A key to wire', hex ? '' : 'No key yet. Generate or import one in the Keys tab.')}
      ${check(!!inVM, 'Key in your profile (verificationMethod)', inVM ? '' : 'Your profile doesn’t assert this key yet.')}
      ${check(!!(inVM && inVM.inAuth), 'Referenced in authentication (backlink)', (inVM && inVM.inAuth) ? '' : 'Needed for the verified did:nostr → WebID resolution.')}
    </ul>
    ${hex && !(inVM && inVM.inAuth) ? '<button class="primary fix">Wire this key into my profile</button>' : ''}
    ${hex ? `<div class="idbox">
      <div class="kv"><span class="kl">hex (canonical)</span><code class="mono">${esc(hex)}</code><button class="mini cp" data-v="${esc(hex)}">⧉</button></div>
      <div class="kv"><span class="kl">npub</span><code class="mono npub" data-hex="${esc(hex)}">…</code><button class="mini cp-npub" data-hex="${esc(hex)}">⧉</button></div>
      <div class="kv"><span class="kl">did:nostr</span><code class="mono">${esc(didNostr(hex))}</code><button class="mini cp" data-v="${esc(didNostr(hex))}">⧉</button></div>
    </div>` : ''}`
  const fix = p.querySelector('.fix')
  if (fix) fix.onclick = async () => { try { await linkKeyToProfile(hex); await loadCard(); paint(); toast('Key wired into your profile') } catch (e) { toast(String(e.message || e), true) } }
  p.querySelectorAll('.cp').forEach((b) => { b.onclick = () => copy(b.dataset.v) })
  const npubEl = p.querySelector('.npub'); if (npubEl) npub(npubEl.dataset.hex).then((v) => { npubEl.textContent = v || '(bech32 unavailable)' })
  const cpn = p.querySelector('.cp-npub'); if (cpn) cpn.onclick = async () => copy(await npub(cpn.dataset.hex))
}

function paintProfile(p) {
  const hex = subjectHex()
  const held = hex ? KEYS.find((k) => k.pubkey === hex && k.secret) : null
  const m = PROFILE || {}
  const v = {
    name: m.name != null ? m.name : (cardName() || ''),
    about: m.about || '',
    picture: m.picture != null ? m.picture : (cardAvatar() || ''),
    website: m.website != null ? m.website : POD_ROOT.href,
    nip05: m.nip05 != null ? m.nip05 : nip05Default()
  }
  if (!hex) { p.innerHTML = '<h2>Profile</h2><div class="empty">No key yet. Generate or import one in the <b>Keys</b> tab, then come back to publish your profile.</div>'; return }
  p.innerHTML = `
    <h2>Profile</h2>
    <p class="sub muted">Your public Nostr profile (kind&nbsp;0). Publishing signs it with your key and broadcasts to your relays — and keeps your <b>WebID card</b> in sync.</p>
    ${held ? '' : `<div class="warn">This app doesn’t hold the secret for your active key, so it can’t sign. Import its <code>nsec</code> in the <b>Keys</b> tab first. <button class="mini gokeys" style="margin-left:6px">🔑 Keys</button></div>`}
    <div class="pform">
      <label class="fld"><span class="fl">Display name</span><input class="f-name" placeholder="Your name" value="${esc(v.name)}"></label>
      <label class="fld"><span class="fl">About</span><textarea class="f-about" rows="3" placeholder="A short bio">${esc(v.about)}</textarea></label>
      <label class="fld"><span class="fl">Avatar</span>
        <div class="avrow">
          <img class="avprev" alt="" ${v.picture ? `src="${esc(v.picture)}"` : 'style="display:none"'}>
          <input class="f-pic" placeholder="https://… image URL" value="${esc(v.picture)}">
          <button class="mini up" type="button">⤴ Upload to pod</button>
          <input class="f-file" type="file" accept="image/*" hidden>
        </div>
      </label>
      <label class="fld"><span class="fl">Website</span><input class="f-web" value="${esc(v.website)}"></label>
      <label class="fld"><span class="fl">NIP-05 (pod handle)</span><input class="f-nip" value="${esc(v.nip05)}"></label>
      <label class="chk"><input type="checkbox" class="f-sync" checked> Also update my WebID card (name + avatar)</label>
      <label class="chk"><input type="checkbox" class="f-wk" checked> Host NIP-05 on my pod (<code>/.well-known/nostr.json</code>)</label>
    </div>
    <div class="key-actions">
      <button class="ghost pull">↧ Pull from WebID</button>
      <button class="ghost fetch">↺ Fetch current from relays</button>
      <button class="primary publish" ${held ? '' : 'disabled'}>Publish to relays</button>
    </div>
    <div class="pub-status"></div>`

  const $ = (s) => p.querySelector(s)
  const readForm = () => ({ name: $('.f-name').value.trim(), about: $('.f-about').value.trim(), picture: $('.f-pic').value.trim(), website: $('.f-web').value.trim(), nip05: $('.f-nip').value.trim() })
  const gokeys = p.querySelector('.gokeys'); if (gokeys) gokeys.onclick = () => { TAB = 'keys'; paint() }

  const prev = $('.avprev'); const picIn = $('.f-pic')
  picIn.oninput = () => { if (picIn.value.trim()) { prev.src = picIn.value.trim(); prev.style.display = '' } else prev.style.display = 'none' }

  $('.up').onclick = () => $('.f-file').click()
  $('.f-file').onchange = async (e) => {
    const file = e.target.files[0]; if (!file) return
    toast('Uploading avatar…')
    try { const url = await uploadAvatar(file); picIn.value = url; picIn.dispatchEvent(new Event('input')); toast('Avatar uploaded to pod') }
    catch (err) { toast('Upload failed: ' + (err.message || err), true) }
  }

  $('.pull').onclick = () => { PROFILE = { ...readForm(), name: cardName() || '', picture: cardAvatar() || '' }; paint(); toast('Pulled name + avatar from WebID') }

  $('.fetch').onclick = async () => {
    toast('Fetching from relays…')
    const cur = await fetchCurrentProfile(hex)
    if (!cur) { toast('No published profile found', true); return }
    PROFILE = { name: cur.name || cur.display_name || '', about: cur.about || '', picture: cur.picture || '', website: cur.website || POD_ROOT.href, nip05: cur.nip05 || nip05Default() }
    paint(); toast('Loaded your published profile')
  }

  const pubBtn = $('.publish'); if (pubBtn) pubBtn.onclick = async () => {
    if (!held) { toast('No held secret to sign with', true); return }
    const f = readForm(); PROFILE = { ...f }
    const content = {}
    if (f.name) content.name = f.name
    if (f.about) content.about = f.about
    if (f.picture) content.picture = f.picture
    if (f.website) content.website = f.website
    if (f.nip05) content.nip05 = f.nip05
    const status = $('.pub-status'); pubBtn.disabled = true; status.innerHTML = '<div class="muted">Signing & publishing…</div>'
    try {
      const evt = await signEvent({ pubkey: hex, created_at: Math.floor(Date.now() / 1000), kind: 0, tags: [], content: JSON.stringify(content) }, held.secret)
      const results = await publishEvent(evt)
      const ok = results.filter((r) => r.ok).length
      // alignment side-effects (best-effort, reported individually)
      const extras = []
      if ($('.f-sync').checked) { try { await writeProfileToCard(f.name, f.picture); await loadCard(); extras.push('<li class="ok"><span class="ci">✅</span><div>WebID card updated (name + avatar)</div></li>') } catch (e) { extras.push(`<li class="no"><span class="ci">⚠️</span><div>WebID card not updated: ${esc(e.message || e)}</div></li>`) } }
      if ($('.f-wk').checked) { try { const wk = await writeWellKnown(hex); extras.push(wk ? '<li class="ok"><span class="ci">✅</span><div>NIP-05 hosted at <code>/.well-known/nostr.json</code></div></li>' : '<li class="no"><span class="ci">⚠️</span><div>Could not host NIP-05 (pod may not allow writing <code>/.well-known/</code>) — handle will show unverified</div></li>') } catch (e) { extras.push(`<li class="no"><span class="ci">⚠️</span><div>NIP-05 hosting failed: ${esc(e.message || e)}</div></li>`) } }
      status.innerHTML = `
        <ul class="checks pubres">
          ${results.map((r) => `<li class="${r.ok ? 'ok' : 'no'}"><span class="ci">${r.ok ? '✅' : '⛔'}</span><div><b>${esc(r.url)}</b><small>${esc(r.msg)}</small></div></li>`).join('')}
          ${extras.join('')}
        </ul>
        <div class="evid muted">event id <code class="mono">${esc(evt.id)}</code></div>`
      toast(ok ? `Published to ${ok}/${results.length} relays` : 'No relay accepted the event', !ok)
    } catch (e) { status.innerHTML = `<div class="warn">Publish failed: ${esc(e.message || e)}</div>`; toast('Publish failed', true) }
    finally { pubBtn.disabled = false }
  }
}

function paintKeys(p) {
  const sub = subjectHex()
  p.innerHTML = `
    <h2>Keys</h2>
    <p class="sub muted">The 64-char hex is the key; nsec/npub are display sugar. Stored keys live in <code>/private/nostr/</code> (owner-only).</p>
    <div class="key-actions"><button class="primary gen">Generate new key</button><button class="ghost imp">Import (nsec or hex)</button></div>
    <div class="keylist"></div>`
  p.querySelector('.gen').onclick = doGenerate
  p.querySelector('.imp').onclick = doImport
  const list = p.querySelector('.keylist')
  const rows = [...KEYS]
  if (loginType() === 'nostr' && isHex64(myId()) && !rows.some((k) => k.pubkey === myId().toLowerCase())) {
    rows.unshift({ label: 'Signed-in key', pubkey: myId().toLowerCase(), secret: null, source: 'session', created: '' })
  }
  if (!rows.length) { list.innerHTML = '<div class="empty">No keys yet. Generate one — it becomes your Nostr identity and can be wired into your profile.</div>'; return }
  rows.forEach((k) => list.appendChild(keyRow(k, sub)))
}

function keyRow(k, sub) {
  const el = document.createElement('div'); el.className = 'card key'
  const active = k.pubkey === sub
  el.innerHTML = `
    <div class="key-h"><b>${esc(k.label || 'key')}</b>${active ? '<span class="badge">active</span>' : ''}<span class="src">${esc(k.source || '')}</span></div>
    <div class="kv"><span class="kl">hex</span><code class="mono">${esc(k.pubkey)}</code><button class="mini cp" data-v="${esc(k.pubkey)}">⧉</button></div>
    <div class="kv"><span class="kl">npub</span><code class="mono npub" data-hex="${esc(k.pubkey)}">…</code></div>
    <div class="key-foot">
      <button class="mini link">↪ Use in profile</button>
      ${k.secret ? '<button class="mini reveal">👁 Reveal secret</button>' : '<span class="mini muted">secret not held here</span>'}
      ${k.source !== 'session' ? '<button class="mini del">🗑</button>' : ''}
    </div>`
  el.querySelector('.cp').onclick = (e) => copy(e.target.dataset.v)
  const ne = el.querySelector('.npub'); npub(k.pubkey).then((v) => { ne.textContent = v || '—' })
  el.querySelector('.link').onclick = async () => { try { await linkKeyToProfile(k.pubkey); await loadCard(); toast('Wired into your profile') } catch (e) { toast(String(e.message || e), true) } }
  const rv = el.querySelector('.reveal'); if (rv) rv.onclick = () => revealSecret(k)
  const dl = el.querySelector('.del'); if (dl) dl.onclick = async () => { if (!confirm(`Delete “${k.label}” from your pod?`)) return; KEYS = KEYS.filter((x) => x.pubkey !== k.pubkey); try { await saveStore(); paint(); toast('Deleted') } catch (e) { toast(String(e.message || e), true) } }
  return el
}

async function doGenerate() {
  const label = prompt('Label for this key', 'My Nostr key'); if (label == null) return
  let kp; try { kp = await genKey() } catch (e) { toast('Keygen failed: ' + (e.message || e), true); return }
  KEYS.unshift({ label: label.trim() || 'My Nostr key', pubkey: kp.pk, secret: kp.sk, source: 'generated', created: new Date().toISOString() })
  try { await saveStore(); paint(); revealSecret(KEYS[0]) } catch (e) { toast(String(e.message || e), true) }
}

async function doImport() {
  const raw = prompt('Paste an nsec, or a 64-char hex secret key'); if (!raw) return
  let secretHex
  try {
    if (raw.trim().toLowerCase().startsWith('nsec')) { const d = await decodeBech(raw.trim()); if (d.prefix !== 'nsec') throw new Error('not an nsec'); secretHex = d.hex }
    else if (isHex64(raw.trim())) secretHex = raw.trim().toLowerCase()
    else throw new Error('expected nsec… or 64-hex')
  } catch (e) { toast('Import failed: ' + (e.message || e), true); return }
  let pk; try { const s = await secp(); pk = s.utils.bytesToHex(s.schnorr.getPublicKey(hexToBytes(secretHex))) } catch (e) { toast('Bad key: ' + (e.message || e), true); return }
  if (KEYS.some((k) => k.pubkey === pk)) { toast('Already have that key'); return }
  const label = prompt('Label', 'Imported key') || 'Imported key'
  KEYS.unshift({ label: label.trim(), pubkey: pk, secret: secretHex, source: 'imported', created: new Date().toISOString() })
  try { await saveStore(); paint(); toast('Imported') } catch (e) { toast(String(e.message || e), true) }
}

function revealSecret(k) {
  const dlg = document.createElement('dialog'); dlg.className = 'sheet'
  dlg.innerHTML = `
    <h2>Secret key — ${esc(k.label || '')}</h2>
    <p class="warn">Anyone with this can act as you. It is stored in your pod's <code>/private/</code> (owner-only); treat copies with care.</p>
    <div class="kv col"><span class="kl">hex (canonical)</span><code class="mono secret">${esc(k.secret)}</code><button class="mini cp" data-v="${esc(k.secret)}">⧉</button></div>
    <div class="kv col"><span class="kl">nsec</span><code class="mono nsecv">…</code><button class="mini cp-nsec">⧉</button></div>
    <div class="sheet-actions"><button type="button" class="primary">Done</button></div>`
  document.body.appendChild(dlg); dlg.addEventListener('close', () => dlg.remove())
  dlg.querySelector('.cp').onclick = (e) => copy(e.target.dataset.v)
  const nv = dlg.querySelector('.nsecv'); nsec(k.secret).then((v) => { nv.textContent = v || '(bech32 unavailable)' })
  dlg.querySelector('.cp-nsec').onclick = async () => copy(await nsec(k.secret))
  dlg.querySelector('.primary').onclick = () => dlg.close()
  dlg.showModal()
}

const PLAT = { web: 'web', ios: 'iOS', android: 'Android', desktop: 'desktop', ext: 'extension' }

async function paintApps(p) {
  p.innerHTML = `
    <h2>Apps</h2>
    <div class="login-strip card">
      <div><b>One key, every app.</b><small>Your <b>npub</b> is your handle; your <b>nsec</b> (or a signer like Amber / Alby / nos2x) signs. Same identity everywhere.</small></div>
      <div class="login-key"><code class="mono npub" data-hex="${esc(subjectHex() || '')}">${subjectHex() ? '…' : 'no key yet'}</code>
        ${subjectHex() ? '<button class="mini cp-npub" data-hex="' + esc(subjectHex()) + '">⧉ npub</button>' : ''}
        <button class="mini gokeys">🔑 my keys</button></div>
    </div>

    <p class="sub muted">Real Nostr clients — sign in to any with the same key (npub to read, nsec or a signer to post). <span class="src-link"><a href="https://nostrapps.com/" target="_blank" rel="noopener">more at nostrapps.com ↗</a></span></p>
    <div class="cat-filter"></div>
    <div class="gallery eco"></div>`

  // login strip
  const npubEl = p.querySelector('.npub'); if (npubEl && npubEl.dataset.hex) npub(npubEl.dataset.hex).then((v) => { npubEl.textContent = v || '(bech32 unavailable)' })
  const cpn = p.querySelector('.cp-npub'); if (cpn) cpn.onclick = async () => copy(await npub(cpn.dataset.hex))
  p.querySelector('.gokeys').onclick = () => { TAB = 'keys'; paint() }

  // ecosystem (lazy-load once)
  const eco = p.querySelector('.gallery.eco')
  const filt = p.querySelector('.cat-filter')
  if (!ECO) {
    eco.innerHTML = '<div class="muted" style="padding:8px">Loading directory…</div>'
    try { const r = await fetch('./nostr-ecosystem.json'); ECO = r.ok ? await r.json() : { apps: [], categories: [] } } catch { ECO = { apps: [], categories: [] } }
  }
  const cats = ['All', ...(ECO.categories || [])]
  filt.innerHTML = cats.map((c) => `<button class="chip ${c === ECO_CAT ? 'on' : ''}">${esc(c)}</button>`).join('')
  filt.querySelectorAll('.chip').forEach((b, i) => { b.onclick = () => { ECO_CAT = cats[i]; paint() } })
  eco.innerHTML = ''
  const apps = (ECO.apps || []).filter((a) => ECO_CAT === 'All' || (a.cats || []).includes(ECO_CAT))
  apps.forEach((a) => {
    const el = document.createElement('a'); el.className = 'card app ext'; el.href = a.url; el.target = '_blank'; el.rel = 'noopener'
    const tags = (a.platforms || []).map((pl) => `<span class="tag">${esc(PLAT[pl] || pl)}</span>`).join('')
    el.innerHTML = `<div class="app-main"><b>${esc(a.name)}</b><small>${esc(a.what)}</small><div class="tags">${tags}</div></div><span class="open">Open ↗</span>`
    eco.appendChild(el)
  })
}

function paintRelays(p) {
  p.innerHTML = `
    <h2>Relays</h2>
    <p class="sub muted">Where your Nostr events are published and read (NIP-65). Saved to your pod.</p>
    <div class="relaylist"></div>
    <div class="key-actions"><button class="ghost add">+ Add relay</button></div>`
  const list = p.querySelector('.relaylist')
  if (!RELAYS.length) list.innerHTML = '<div class="empty">No relays.</div>'
  RELAYS.forEach((url) => {
    const row = document.createElement('div'); row.className = 'card relay'
    row.innerHTML = `<code class="mono">${esc(url)}</code><span class="rstat">·</span><button class="mini test">test</button><button class="mini del">🗑</button>`
    row.querySelector('.test').onclick = () => testRelay(url, row.querySelector('.rstat'))
    row.querySelector('.del').onclick = async () => { RELAYS = RELAYS.filter((r) => r !== url); try { await saveStore(); paint(); toast('Removed') } catch (e) { toast(String(e.message || e), true) } }
    list.appendChild(row)
  })
  p.querySelector('.add').onclick = async () => { const u = prompt('Relay URL', 'wss://'); if (!u || !u.startsWith('wss://')) { if (u) toast('Use a wss:// URL', true); return } if (RELAYS.includes(u)) return; RELAYS.push(u); try { await saveStore(); paint() } catch (e) { toast(String(e.message || e), true) } }
}

function testRelay(url, el) {
  el.textContent = '⏳'; el.className = 'rstat'
  let done = false
  try {
    const ws = new WebSocket(url)
    const t = setTimeout(() => { if (!done) { done = true; el.textContent = '⛔ timeout'; el.className = 'rstat no'; try { ws.close() } catch {} } }, 5000)
    ws.onopen = () => { if (!done) { done = true; clearTimeout(t); el.textContent = '✅ up'; el.className = 'rstat ok'; ws.close() } }
    ws.onerror = () => { if (!done) { done = true; clearTimeout(t); el.textContent = '⛔ down'; el.className = 'rstat no' } }
  } catch { el.textContent = '⛔'; el.className = 'rstat no' }
}

function paintGuide(p) {
  p.innerHTML = `
    <h2>How this fits together</h2>
    <div class="guide">
      <h3>Your key is the canonical thing</h3>
      <p>A Nostr identity is just a keypair. The <b>64-char hex</b> public key <i>is</i> your identity; <code>npub</code>/<code>nsec</code> are only a friendlier bech32 encoding of the same bytes — convenient for sharing, never the source of truth. The secret (<code>nsec</code> / hex) signs on your behalf; guard it.</p>
      <h3>The Solid bridge</h3>
      <p>Your pod authenticates a signed (NIP-98) request and tries to resolve it to <b>your WebID</b>. It can only do that if your profile <i>declares</i> the key — as a <code>verificationMethod</code> referenced from <code>authentication</code>. Without that, you stay an anonymous <code>did:nostr:&lt;pubkey&gt;</code>. The <b>Identity</b> tab checks this and fixes it in one click.</p>
      <h3>Why it matters</h3>
      <p>Once wired, sharing a wallet card or a file with your key resolves to a stable identity, agents you control can act as themselves, and any Nostr-native app here can sign as the same you.</p>
      <h3>Keys can live in many places</h3>
      <p>A browser extension (NIP-07), this control center's <code>/private/</code> store, or just in your head as an nsec. This app holds keys you generate/import in <code>/private/nostr/</code>, behind your pod's auth — one way of several.</p>
    </div>`
}

render()
document.addEventListener('xlogin', render)
document.addEventListener('xlogout', render)
