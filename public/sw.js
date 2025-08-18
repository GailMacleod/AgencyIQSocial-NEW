/**
 * Service Worker for PWA Session Management
 * Handles session synchronization and cache management for installed app
 */

const CACHE_NAME = 'theagencyiq-v1';
const SESSION_SYNC_INTERVAL = 60000; // 1 minute

// Install event
self.addEventListener('install', (event) => {
  console.log('🔧 Service Worker: Installing...');
  self.skipWaiting();
});

// Activate event
self.addEventListener('activate', (event) => {
  console.log('✅ Service Worker: Activated');
  event.waitUntil(clients.claim());
});

// Fetch event with session validation
self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  
  // Skip session check for non-API requests
  if (!url.pathname.startsWith('/api/')) {
    return;
  }

  event.respondWith(
    fetch(event.request)
      .then(response => {
        // Check for 401 responses (session expired)
        if (response.status === 401) {
          // Notify all clients about session expiry
          self.clients.matchAll().then(clients => {
            clients.forEach(client => {
              client.postMessage({
                type: 'SESSION_EXPIRED',
                url: url.pathname
              });
            });
          });
        }
        
        return response;
      })
      .catch(error => {
        console.error('SW: Fetch error:', error);
        throw error;
      })
  );
});

// Background sync for session validation
self.addEventListener('sync', (event) => {
  if (event.tag === 'session-sync') {
    event.waitUntil(validateSession());
  }
});

// Periodic session validation
self.addEventListener('periodicsync', (event) => {
  if (event.tag === 'session-check') {
    event.waitUntil(validateSession());
  }
});

// Message handling from main thread
self.addEventListener('message', (event) => {
  if (event.data?.type === 'LOGOUT') {
    handleLogout();
  } else if (event.data?.type === 'SESSION_CHECK') {
    validateSession();
  }
});

/**
 * Validate session with server
 */
async function validateSession() {
  try {
    const response = await fetch('/api/auth/session', {
      method: 'GET',
      credentials: 'include',
      headers: {
        'X-SW-Session-Check': 'true'
      }
    });

    const sessionData = await response.json();
    
    if (!sessionData.authenticated) {
      // Session expired - notify clients
      const clients = await self.clients.matchAll();
      clients.forEach(client => {
        client.postMessage({
          type: 'SESSION_EXPIRED',
          timestamp: new Date().toISOString()
        });
      });
    }

  } catch (error) {
    console.error('SW: Session validation failed:', error);
  }
}

/**
 * Handle logout cleanup
 */
async function handleLogout() {
  try {
    // Clear all caches
    const cacheNames = await caches.keys();
    await Promise.all(
      cacheNames.map(cacheName => caches.delete(cacheName))
    );

    // Notify clients
    const clients = await self.clients.matchAll();
    clients.forEach(client => {
      client.postMessage({
        type: 'LOGOUT_COMPLETE',
        timestamp: new Date().toISOString()
      });
    });

    console.log('✅ SW: Logout cleanup complete');

  } catch (error) {
    console.error('SW: Logout cleanup failed:', error);
  }
}

// Periodic session check (every minute)
setInterval(validateSession, SESSION_SYNC_INTERVAL);