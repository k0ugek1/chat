
const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      ...headers
    }
  });

const b64u = {
  enc(bytes) {
    let s = '';
    for (const b of bytes) s += String.fromCharCode(b);
    return btoa(s)
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/g, '');
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
    'access-control-allow-origin':
      origin === allowed ? origin : allowed,
    'access-control-allow-methods': 'GET,POST,OPTIONS',
    'access-control-allow-headers': 'content-type',
    'vary': 'Origin'
  };
}

async function readJson(request) {
  try {
    return await request.json();
  } catch (_) {
    return null;
  }
}

function concat(...arrays) {
  const out = new Uint8Array(
    arrays.reduce((n, a) => n + a.length, 0)
  );

  let p = 0;
  for (const a of arrays) {
    out.set(a, p);
    p += a.length;
  }
  return out;
}

function u32(n) {
  return Uint8Array.of(n >>> 24, n >>> 16, n >>> 8, n);
}

async function hmac(keyBytes, data) {
  const key = await crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  return new Uint8Array(
    await crypto.subtle.sign('HMAC', key, data)
  );
}

async function hkdfExpand(prk, info, length) {
  let out = new Uint8Array(0);
  let previous = new Uint8Array(0);
  let counter = 1;

  while (out.length < length) {
    previous = await hmac(
      prk,
      concat(previous, info, Uint8Array.of(counter++))
    );
    out = concat(out, previous);
  }

  return out.slice(0, length);
}

async function vapidAuthorization(endpoint, env) {
  const url = new URL(endpoint);
  const now = Math.floor(Date.now() / 1000);

  const header = b64u.enc(te.encode(JSON.stringify({
    typ: 'JWT',
    alg: 'ES256'
  })));

  const claims = b64u.enc(te.encode(JSON.stringify({
    aud: url.origin,
    exp: now + 12 * 60 * 60,
    sub: env.VAPID_SUBJECT || 'mailto:admin@example.com'
  })));

  const unsigned = header + '.' + claims;
  const pub = b64u.dec(env.VAPID_PUBLIC_KEY);

  if (pub.length !== 65 || pub[0] !== 4) {
    throw new Error('Invalid VAPID public key');
  }

  const jwk = {
    kty: 'EC',
    crv: 'P-256',
    x: b64u.enc(pub.slice(1, 33)),
    y: b64u.enc(pub.slice(33, 65)),
    d: env.VAPID_PRIVATE_KEY,
    ext: true,
    key_ops: ['sign']
  };

  const key = await crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign']
  );

  const sig = new Uint8Array(
    await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      key,
      te.encode(unsigned)
    )
  );

  return 'vapid t=' + unsigned + '.' +
    b64u.enc(sig) + ', k=' + env.VAPID_PUBLIC_KEY;
}

async function encryptPush(payload, subscription) {
  const clientPub = b64u.dec(subscription.keys.p256dh);
  const auth = b64u.dec(subscription.keys.auth);

  if (clientPub.length !== 65 || auth.length < 16) {
    throw new Error('Invalid subscription keys');
  }

  const receiverKey = await crypto.subtle.importKey(
    'raw',
    clientPub,
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    []
  );

  const ephemeral = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits']
  );

  const serverPub = new Uint8Array(
    await crypto.subtle.exportKey('raw', ephemeral.publicKey)
  );

  const shared = new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: 'ECDH', public: receiverKey },
      ephemeral.privateKey,
      256
    )
  );

  const authPrk = await hmac(auth, shared);

  const keyInfo = concat(
    te.encode('WebPush: info\0'),
    clientPub,
    serverPub
  );

  const ikm = await hmac(authPrk, keyInfo);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const prk = await hmac(salt, ikm);

  const cek = await hkdfExpand(
    prk,
    te.encode('Content-Encoding: aes128gcm\0'),
    16
  );

  const nonce = await hkdfExpand(
    prk,
    te.encode('Content-Encoding: nonce\0'),
    12
  );

  const plain = concat(
    te.encode(JSON.stringify(payload)),
    Uint8Array.of(2)
  );

  const aesKey = await crypto.subtle.importKey(
    'raw',
    cek,
    'AES-GCM',
    false,
    ['encrypt']
  );

  const encrypted = new Uint8Array(
    await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: nonce,
        tagLength: 128
      },
      aesKey,
      plain
    )
  );

  return concat(
    salt,
    u32(4096),
    Uint8Array.of(serverPub.length),
    serverPub,
    encrypted
  );
}

async function sendWebPush(subscription, payload, env) {
  const body = await encryptPush(payload, subscription);
  const authorization = await vapidAuthorization(
    subscription.endpoint,
    env
  );

  return fetch(subscription.endpoint, {
    method: 'POST',
    headers: {
      'Authorization': authorization,
      'Content-Type': 'application/octet-stream',
      'Content-Encoding': 'aes128gcm',
      'TTL': '86400',
      'Urgency': 'normal'
    },
    body
  });
}

async function handleApi(request, env) {
  const url = new URL(request.url);

  if (request.method === 'OPTIONS') {
    return new Response(null, {
      status: 204,
      headers: cors(request, env)
    });
  }

  if (request.method === 'GET' && url.pathname === '/health') {
    return json(
      { ok: true, service: 'redline-push' },
      200,
      cors(request, env)
    );
  }

  if (request.method !== 'POST') {
    return json({ error: 'Not found' }, 404, cors(request, env));
  }

  const data = await readJson(request);

  if (!data || typeof data !== 'object') {
    return json({ error: 'Invalid JSON' }, 400, cors(request, env));
  }

  const chatId = String(data.chatId || '');
  const roomToken = String(data.roomToken || '');

  if (
    !/^[a-f0-9]{24}$/.test(chatId) ||
    !/^[A-Za-z0-9_-]{43}$/.test(roomToken)
  ) {
    return json(
      { error: 'Invalid chatId or roomToken' },
      400,
      cors(request, env)
    );
  }

  const key = 'room:' + roomToken;

  if (url.pathname === '/api/subscribe') {
    const sub = data.subscription;

    if (
      !sub ||
      typeof sub.endpoint !== 'string' ||
      !sub.endpoint.startsWith('https://') ||
      !sub.keys ||
      typeof sub.keys.p256dh !== 'string' ||
      typeof sub.keys.auth !== 'string'
    ) {
      return json(
        { error: 'Invalid push subscription' },
        400,
        cors(request, env)
      );
    }

    let list = [];

    try {
      list = JSON.parse(await env.PUSH_KV.get(key) || '[]');
    } catch (_) {}

    list = list.filter(x => x && x.endpoint !== sub.endpoint);

    list.push({
      endpoint: sub.endpoint,
      keys: sub.keys,
      chatId,
      updatedAt: Date.now()
    });

    if (list.length > 100) list = list.slice(-100);

    await env.PUSH_KV.put(key, JSON.stringify(list), {
      expirationTtl: 60 * 60 * 24 * 120
    });

    return json({ ok: true }, 200, cors(request, env));
  }

  if (url.pathname === '/api/notify') {
    let list = [];

    try {
      list = JSON.parse(await env.PUSH_KV.get(key) || '[]');
    } catch (_) {}

    const sender = String(data.senderEndpoint || '');

    const payload = {
      title: 'REDLINE',
      body: 'Новое сообщение. Открой REDLINE.',
      chatId,
      url:
        'https://k0ugek1.github.io/chat/?openChat=' +
        encodeURIComponent(chatId)
    };

    let sent = 0;
    let removed = false;
    const keep = [];

    for (const sub of list) {
      if (!sub || !sub.endpoint) continue;

      if (sender && sub.endpoint === sender) {
        keep.push(sub);
        continue;
      }

      try {
        const response = await sendWebPush(sub, payload, env);

        if (response.status === 404 || response.status === 410) {
          removed = true;
          continue;
        }

        if (response.ok) sent++;
        keep.push(sub);
      } catch (_) {
        keep.push(sub);
      }
    }

    if (removed) {
      await env.PUSH_KV.put(key, JSON.stringify(keep), {
        expirationTtl: 60 * 60 * 24 * 120
      });
    }

    return json({ ok: true, sent }, 200, cors(request, env));
  }

  return json({ error: 'Not found' }, 404, cors(request, env));
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (
      url.pathname.startsWith('/api/') ||
      url.pathname === '/health'
    ) {
      return handleApi(request, env);
    }

    return env.ASSETS.fetch(request);
  }
};
