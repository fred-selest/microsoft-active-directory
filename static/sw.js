// Service Worker for AD Web Interface PWA
const CACHE_NAME = 'ad-web-interface-v1.15.1';
const urlsToCache = [
  '/',
  '/static/css/style.css',
  '/static/js/main.js',
  'https://cdn.jsdelivr.net/npm/chart.js'
];

// Installation du Service Worker
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => {
        console.log('Cache ouvert');
        return cache.addAll(urlsToCache);
      })
  );
});

// Activation et nettoyage des anciens caches
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(cacheNames => {
      return Promise.all(
        cacheNames.map(cacheName => {
          if (cacheName !== CACHE_NAME) {
            console.log('Suppression ancien cache:', cacheName);
            return caches.delete(cacheName);
          }
        })
      );
    })
  );
});

// Strategie de cache: Network First, fallback to cache
self.addEventListener('fetch', event => {
  // Ne pas mettre en cache les requetes POST ou les API
  if (event.request.method !== 'GET' || event.request.url.includes('/api/')) {
    return;
  }

  event.respondWith(
    fetch(event.request)
      .then(response => {
        // Clone la reponse car elle ne peut etre lue qu'une fois
        const responseClone = response.clone();

        // Mettre en cache les fichiers statiques
        if (event.request.url.includes('/static/')) {
          caches.open(CACHE_NAME)
            .then(cache => {
              cache.put(event.request, responseClone);
            });
        }

        return response;
      })
      .catch(() => {
        // En cas d'erreur reseau, retourner le cache
        return caches.match(event.request);
      })
  );
});

// Gestion des notifications push (pour les alertes)
self.addEventListener('push', event => {
  const options = {
    body: event.data ? event.data.text() : 'Nouvelle notification',
    icon: '/static/icons/icon.svg',
    badge: '/static/icons/icon.svg',
    vibrate: [100, 50, 100],
    data: {
      dateOfArrival: Date.now(),
      primaryKey: 1
    },
    actions: [
      {action: 'explore', title: 'Voir'},
      {action: 'close', title: 'Fermer'}
    ]
  };

  event.waitUntil(
    self.registration.showNotification('AD Web Interface', options)
  );
});

// Gestion du clic sur les notifications
self.addEventListener('notificationclick', event => {
  event.notification.close();

  if (event.action === 'explore') {
    event.waitUntil(
      clients.openWindow('/alerts')
    );
  }
});
