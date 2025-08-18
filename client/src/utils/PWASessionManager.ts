/**
 * PWA Session Manager
 * Handles session synchronization between PWA and browser contexts
 * Fixes stale session issues in installed apps
 */

class PWASessionManager {
  private isServiceWorkerRegistered = false;
  private sessionSyncInterval: NodeJS.Timeout | null = null;

  /**
   * Initialize PWA session management
   */
  async init() {
    try {
      // Register service worker for PWA
      if ('serviceWorker' in navigator) {
        const registration = await navigator.serviceWorker.register('/sw.js');
        this.isServiceWorkerRegistered = true;
        console.log('✅ PWA Service Worker registered for session sync');
        
        // Listen for service worker messages
        navigator.serviceWorker.addEventListener('message', this.handleServiceWorkerMessage.bind(this));
      }

      // Start session synchronization
      this.startSessionSync();
      
      // Handle visibility change (app focus/blur)
      document.addEventListener('visibilitychange', this.handleVisibilityChange.bind(this));
      
      // Handle page focus for PWA session refresh
      window.addEventListener('focus', this.handleAppFocus.bind(this));

    } catch (error) {
      console.error('❌ PWA Session Manager initialization failed:', error);
    }
  }

  /**
   * Start periodic session synchronization (every 30 seconds)
   */
  private startSessionSync() {
    this.sessionSyncInterval = setInterval(async () => {
      await this.syncSessionWithServer();
    }, 30000); // 30 seconds
  }

  /**
   * Stop session synchronization
   */
  private stopSessionSync() {
    if (this.sessionSyncInterval) {
      clearInterval(this.sessionSyncInterval);
      this.sessionSyncInterval = null;
    }
  }

  /**
   * Sync session with server to detect cookie expiry
   */
  private async syncSessionWithServer() {
    try {
      const response = await fetch('/api/auth/session', {
        method: 'GET',
        credentials: 'include',
        headers: {
          'X-PWA-Session-Check': 'true'
        }
      });

      const sessionData = await response.json();
      
      // If session is not authenticated but we think we are, clear everything
      if (!sessionData.authenticated) {
        console.log('🔄 PWA: Session expired, clearing stale data');
        await this.clearStaleSession();
      } else {
        // Update local session data
        localStorage.setItem('pwa_session_sync', JSON.stringify({
          userId: sessionData.userId,
          userEmail: sessionData.userEmail,
          lastSync: new Date().toISOString()
        }));
      }

    } catch (error) {
      console.log('⚠️ PWA session sync failed:', error.message);
    }
  }

  /**
   * Clear stale session data (called when cookies are invalid)
   */
  async clearStaleSession() {
    try {
      // Clear all local storage
      localStorage.clear();
      sessionStorage.clear();
      
      // Clear IndexedDB if available
      if ('indexedDB' in window) {
        const databases = await indexedDB.databases();
        for (const db of databases) {
          if (db.name) {
            const deleteReq = indexedDB.deleteDatabase(db.name);
            await new Promise((resolve, reject) => {
              deleteReq.onsuccess = () => resolve(true);
              deleteReq.onerror = () => reject(deleteReq.error);
            });
          }
        }
      }

      // Clear service worker cache
      if (this.isServiceWorkerRegistered && 'caches' in window) {
        const cacheNames = await caches.keys();
        await Promise.all(
          cacheNames.map(cacheName => caches.delete(cacheName))
        );
      }

      // Force page reload to clear any remaining state
      window.location.href = '/';

    } catch (error) {
      console.error('❌ Failed to clear stale session:', error);
    }
  }

  /**
   * Handle logout with PWA-specific cleanup
   */
  async handleLogout() {
    try {
      console.log('🔓 PWA: Processing logout...');
      
      // Call backend logout
      const response = await fetch('/api/auth/logout', {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
          'X-PWA-Logout': 'true'
        }
      });

      const logoutData = await response.json();
      
      // Stop session sync
      this.stopSessionSync();
      
      // Clear all PWA data
      await this.clearStaleSession();
      
      console.log('✅ PWA logout complete');
      return logoutData;

    } catch (error) {
      console.error('❌ PWA logout failed:', error);
      // Force clear even on error
      await this.clearStaleSession();
    }
  }

  /**
   * Handle service worker messages
   */
  private handleServiceWorkerMessage(event: MessageEvent) {
    if (event.data?.type === 'SESSION_EXPIRED') {
      console.log('🔄 PWA: Service worker detected session expiry');
      this.clearStaleSession();
    }
  }

  /**
   * Handle visibility change (app becomes visible/hidden)
   */
  private async handleVisibilityChange() {
    if (!document.hidden) {
      // App became visible - sync session
      await this.syncSessionWithServer();
    }
  }

  /**
   * Handle app focus (user switched back to app)
   */
  private async handleAppFocus() {
    // Check session when app regains focus
    await this.syncSessionWithServer();
  }

  /**
   * Check if running as PWA
   */
  isPWA(): boolean {
    return window.matchMedia('(display-mode: standalone)').matches ||
           window.navigator.standalone === true ||
           document.referrer.includes('android-app://');
  }

  /**
   * Force cookie clearing for PWA (attempts manual deletion)
   */
  async clearPWACookies() {
    try {
      // Try to clear cookies manually (limited in PWA context)
      const cookiesToClear = [
        'connect.sid',
        'theagencyiq.session',
        'sessionId',
        'userId',
        'userEmail',
        'subscriptionStatus',
        'auth_token',
        'pwa_session'
      ];

      for (const cookieName of cookiesToClear) {
        document.cookie = `${cookieName}=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;`;
        document.cookie = `${cookieName}=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/; domain=${window.location.hostname};`;
      }

      console.log('✅ PWA cookies cleared manually');

    } catch (error) {
      console.log('⚠️ PWA cookie clearing limited:', error.message);
    }
  }
}

// Export singleton instance
const pwaSessionManager = new PWASessionManager();

export default pwaSessionManager;
export { PWASessionManager };