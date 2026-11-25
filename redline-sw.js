self.addEventListener('install', event => {
  event.waitUntil(self.skipWaiting());
});

self.addEventListener('activate', event => {
  event.waitUntil(self.clients.claim());
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

    for (const client of windows) {
      if (new URL(client.url).origin === self.location.origin) {
        if (chatId) {
          client.postMessage({
            type: 'REDLINE_OPEN_CHAT',
            chatId
          });
        }
        return client.focus();
      }
    }

    const url = new URL(target, self.registration.scope);
    if (chatId) url.searchParams.set('openChat', chatId);
    return self.clients.openWindow(url.href);
  })());
});
