// REDLINE service worker: принимает Web Push и показывает уведомление, даже когда приложение закрыто.
self.addEventListener('install', event => {
  event.waitUntil(self.skipWaiting());
});

self.addEventListener('activate', event => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener('push', event => {
  let data = {};
  try {
    data = event.data ? event.data.json() : {};
  } catch (_) {}

  const title = String(data.title || 'REDLINE').slice(0, 60);
  const body = String(data.body || 'Новое сообщение. Открой REDLINE.').slice(0, 120);
  const chatId = String(data.chatId || '');
  const target = String(data.url || self.registration.scope);

  // Safari/iOS требует показать уведомление на КАЖДЫЙ push, иначе подписка отзывается.
  event.waitUntil(
    self.registration.showNotification(title, {
      body,
      tag: chatId ? 'rl-' + chatId : 'redline-push',
      renotify: false,
      data: { chatId, url: target }
    })
  );
});

self.addEventListener('notificationclick', event => {
  const data = event.notification.data || {};
  const chatId = data.chatId || '';

  event.notification.close();

  event.waitUntil((async () => {
    const windows = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    const own = windows.filter(c => {
      try { return new URL(c.url).origin === self.location.origin; } catch (_) { return false; }
    });

    // Приложение уже запущено: просто выводим его на экран и открываем нужный чат (без перезагрузки).
    if (own.length) {
      const client = own.find(c => c.focused) || own[0];
      try { await client.focus(); } catch (_) {}
      if (chatId) client.postMessage({ type: 'REDLINE_OPEN_CHAT', chatId });
      return;
    }

    // Приложение закрыто: запускаем его сразу в нужном чате.
    const url = new URL(data.url || self.registration.scope, self.registration.scope);
    if (chatId) url.searchParams.set('openChat', chatId);
    return self.clients.openWindow(url.href);
  })());
});
