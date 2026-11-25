// REDLINE push-сервер (Cloudflare Worker).
// Принимает подписки Web Push, по запросу рассылает «пустые» уведомления без текста сообщений.
// Секрет VAPID_PRIVATE_KEY НЕ хранится в репозитории: добавьте его как Secret (см. README).

const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', ...headers }
  });

const b64u = {
  enc(bytes) {
    let s = '';
    for (const b of bytes) s += String.fromCharCode(b);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
  },
  dec(s) {
    s = s.replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    return Uint8Array.from(atob(s), c => c.charCodeAt(0));
  }
};

const te = new TextEncoder();

function cors(request, env) {
  const origin = request.headers.get('Origin') || '';
  const allowed = env.ALLOWED_ORIGIN || 'https://k0ugek1.github.io';
  return {
    'access-control-allow-origin': origin === allowed ? origin : allowed,
    'access-control-allow-methods': 'GET,POST,OPTIONS',
    'access-control-allow-headers': 'content-type',
    'vary': 'Origin'
  };
}

async function readJson(request) {
  try { return await request.json(); } catch (_) { return null; }
}

function concat(...arrays) {
  const out = new Uint8Array(arrays.reduce((n, a) => n + a.length, 0));
  let p = 0;
  for (const a of arrays) { out.set(a, p); p += a.length; }
  return out;
}

function u32(n) {
  return Uint8Array.of(n >>> 24, n >>> 16, n >>> 8, n);
}

async function hmac(keyBytes, data) {
  const key = await crypto.subtle.importKey(
    'raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, data));
}

// HKDF-Expand: T(1) = HMAC(PRK, info || 0x01) ...
async function hkdfExpand(prk, info, length) {
  let out = new Uint8Array(0);
  let previous = new Uint8Array(0);
  let counter = 1;
  while (out.length < length) {
    previous = await hmac(prk, concat(previous, info, Uint8Array.of(counter++)));
    out = concat(out, previous);
  }
  return out.slice(0, length);
}

async function vapidAuthorization(endpoint, env) {
  const url = new URL(endpoint);
  const now = Math.floor(Date.now() / 1000);

  const header = b64u.enc(te.encode(JSON.stringify({ typ: 'JWT', alg: 'ES256' })));
  const claims = b64u.enc(te.encode(JSON.stringify({
    aud: url.origin,
    exp: now + 12 * 60 * 60,
    sub: env.VAPID_SUBJECT || 'mailto:admin@example.com'
  })));

  const unsigned = header + '.' + claims;
  const pub = b64u.dec(env.VAPID_PUBLIC_KEY);
  if (pub.length !== 65 || pub[0] !== 4) throw new Error('Invalid VAPID public key');

  const jwk = {
    kty: 'EC', crv: 'P-256',
    x: b64u.enc(pub.slice(1, 33)),
    y: b64u.enc(pub.slice(33, 65)),
    d: env.VAPID_PRIVATE_KEY,
    ext: true, key_ops: ['sign']
  };

  const key = await crypto.subtle.importKey(
    'jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']
  );
  const sig = new Uint8Array(
    await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, te.encode(unsigned))
  );

  return 'vapid t=' + unsigned + '.' + b64u.enc(sig) + ', k=' + env.VAPID_PUBLIC_KEY;
}

// Шифрование по RFC 8291 (Web Push) + RFC 8188 (aes128gcm).
async function encryptPush(payload, subscription) {
  const clientPub = b64u.dec(subscription.keys.p256dh);
  const auth = b64u.dec(subscription.keys.auth);
  if (clientPub.length !== 65 || auth.length < 16) throw new Error('Invalid subscription keys');

  const receiverKey = await crypto.subtle.importKey(
    'raw', clientPub, { name: 'ECDH', namedCurve: 'P-256' }, false, []
  );
  const ephemeral = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']
  );
  const serverPub = new Uint8Array(await crypto.subtle.exportKey('raw', ephemeral.publicKey));
  const shared = new Uint8Array(await crypto.subtle.deriveBits(
    { name: 'ECDH', public: receiverKey }, ephemeral.privateKey, 256
  ));

  const prkKey = await hmac(auth, shared);                                   // HKDF-Extract(auth, ecdh)
  const keyInfo = concat(te.encode('WebPush: info\0'), clientPub, serverPub);
  const ikm = await hkdfExpand(prkKey, keyInfo, 32);                          // HKDF-Expand (с байтом 0x01)
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const prk = await hmac(salt, ikm);

  const cek = await hkdfExpand(prk, te.encode('Content-Encoding: aes128gcm\0'), 16);
  const nonce = await hkdfExpand(prk, te.encode('Content-Encoding: nonce\0'), 12);

  // Данные + разделитель 0x02 (последняя запись), как требует RFC 8188.
  const plain = concat(te.encode(JSON.stringify(payload)), Uint8Array.of(2));

  const aesKey = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt']);
  const encrypted = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, tagLength: 128 }, aesKey, plain
  ));

  // salt(16) | record size(4) | key id length(1) | key id (server public key) | ciphertext
  return concat(salt, u32(4096), Uint8Array.of(serverPub.length), serverPub, encrypted);
}

async function sendWebPush(subscription, payload, env) {
  const body = await encryptPush(payload, subscription);
  const authorization = await vapidAuthorization(subscription.endpoint, env);

  return fetch(subscription.endpoint, {
    method: 'POST',
    headers: {
      'Authorization': authorization,
      'Content-Type': 'application/octet-stream',
      'Content-Encoding': 'aes128gcm',
      'TTL': '86400',
      'Urgency': 'high'
    },
    body
  });
}

// Короткий разбор ответа push-сервиса для диагностики (Apple отвечает {"reason":"..."}).
async function describeResponse(response) {
  let reason = '';
  if (!response.ok) {
    try {
      const t = (await response.text()).slice(0, 160);
      try { reason = JSON.parse(t).reason || t; } catch (_) { reason = t; }
    } catch (_) {}
  }
  return { status: response.status, ok: response.ok, reason };
}

function validSubscription(sub) {
  return !!sub &&
    typeof sub.endpoint === 'string' &&
    sub.endpoint.startsWith('https://') &&
    !!sub.keys &&
    typeof sub.keys.p256dh === 'string' &&
    typeof sub.keys.auth === 'string';
}

async function handleApi(request, env) {
  const url = new URL(request.url);
  const h = cors(request, env);

  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: h });

  if (request.method === 'GET' && url.pathname === '/health') {
    return json({
      ok: true,
      service: 'redline-push',
      vapidConfigured: !!(env.VAPID_PUBLIC_KEY && env.VAPID_PRIVATE_KEY),
      publicKey: env.VAPID_PUBLIC_KEY || ''
    }, 200, h);
  }

  if (request.method !== 'POST') return json({ error: 'Not found' }, 404, h);

  if (!env.VAPID_PUBLIC_KEY || !env.VAPID_PRIVATE_KEY) {
    return json({ error: 'VAPID keys are not configured on the server' }, 500, h);
  }

  const data = await readJson(request);
  if (!data || typeof data !== 'object') return json({ error: 'Invalid JSON' }, 400, h);

  // Тест: отправить уведомление ровно на эту подписку (чтобы проверить всю цепочку).
  if (url.pathname === '/api/test') {
    if (!validSubscription(data.subscription)) return json({ error: 'Invalid push subscription' }, 400, h);
    try {
      const r = await sendWebPush(data.subscription, {
        title: 'REDLINE',
        body: '✅ Уведомления работают, даже когда приложение закрыто.',
        chatId: '',
        url: 'https://k0ugek1.github.io/chat/'
      }, env);
      const d = await describeResponse(r);
      return json({ ok: d.ok, push: d }, 200, h);
    } catch (e) {
      return json({ ok: false, error: String(e && e.message || e) }, 200, h);
    }
  }

  const chatId = String(data.chatId || '');
  const roomToken = String(data.roomToken || '');
  if (!/^[a-f0-9]{24}$/.test(chatId) || !/^[A-Za-z0-9_-]{43}$/.test(roomToken)) {
    return json({ error: 'Invalid chatId or roomToken' }, 400, h);
  }
  const key = 'room:' + roomToken;

  if (url.pathname === '/api/subscribe') {
    const sub = data.subscription;
    if (!validSubscription(sub)) return json({ error: 'Invalid push subscription' }, 400, h);

    let list = [];
    try { list = JSON.parse(await env.PUSH_KV.get(key) || '[]'); } catch (_) {}
    list = list.filter(x => x && x.endpoint !== sub.endpoint);
    list.push({ endpoint: sub.endpoint, keys: sub.keys, chatId, updatedAt: Date.now() });
    if (list.length > 100) list = list.slice(-100);

    await env.PUSH_KV.put(key, JSON.stringify(list), { expirationTtl: 60 * 60 * 24 * 120 });
    return json({ ok: true, devices: list.length }, 200, h);
  }

  if (url.pathname === '/api/notify') {
    let list = [];
    try { list = JSON.parse(await env.PUSH_KV.get(key) || '[]'); } catch (_) {}

    const sender = String(data.senderEndpoint || '');
    const payload = {
      title: 'REDLINE',
      body: 'Новое сообщение. Открой REDLINE.',
      chatId,
      url: 'https://k0ugek1.github.io/chat/?openChat=' + encodeURIComponent(chatId)
    };

    let sent = 0, removed = false;
    const keep = [], results = [];

    for (const sub of list) {
      if (!sub || !sub.endpoint) continue;
      if (sender && sub.endpoint === sender) { keep.push(sub); continue; }

      try {
        const response = await sendWebPush(sub, payload, env);
        const d = await describeResponse(response);
        results.push({ status: d.status, reason: d.reason });
        if (d.status === 404 || d.status === 410) { removed = true; continue; }
        if (d.ok) sent++;
        keep.push(sub);
      } catch (e) {
        results.push({ status: 0, reason: String(e && e.message || e) });
        keep.push(sub);
      }
    }

    if (removed) {
      await env.PUSH_KV.put(key, JSON.stringify(keep), { expirationTtl: 60 * 60 * 24 * 120 });
    }
    return json({ ok: true, sent, devices: list.length, results }, 200, h);
  }

  return json({ error: 'Not found' }, 404, h);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname.startsWith('/api/') || url.pathname === '/health') {
      return handleApi(request, env);
    }
    return new Response('redline-push', { status: 200, headers: { 'content-type': 'text/plain' } });
  }
};
