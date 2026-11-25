
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
  const body = String(
    data.body || 'Новое сообщение. Открой REDLINE.'
  ).slice(0, 120);

  const chatId = String(data.chatId || '');
  const target = String(data.url || self.registration.scope);

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
  const target = data.url || self.registration.scope;

  event.notification.close();

  event.waitUntil((async () => {
    const windows = await self.clients.matchAll({
      type: 'window',
      includeUncontrolled: true
    });

    const url = new URL(target, self.registration.scope);
    if (chatId) {
      url.searchParams.set('openChat', chatId);
    }

    for (const client of windows) {
      if (new URL(client.url).origin === self.location.origin) {
        const navigated = await client.navigate(url.href);
        return (navigated || client).focus();
      }
    }

    return self.clients.openWindow(url.href);
  })());
});
