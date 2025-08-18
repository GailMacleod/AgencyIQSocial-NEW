/**
 * IndexedDB persistent storage for PWA offline support
 */

interface SessionData {
  id: string;
  userId: string;
  email: string;
  timestamp: number;
  authenticated: boolean;
}

class IndexedDBStorage {
  private dbName = 'TheAgencyIQPWA';
  private version = 1;
  private storeName = 'sessions';

  private async openDB(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(this.dbName, this.version);
      
      request.onerror = () => reject(request.error);
      request.onsuccess = () => resolve(request.result);
      
      request.onupgradeneeded = (event) => {
        const db = (event.target as IDBOpenDBRequest).result;
        
        if (!db.objectStoreNames.contains(this.storeName)) {
          const store = db.createObjectStore(this.storeName, { keyPath: 'id' });
          store.createIndex('userId', 'userId', { unique: false });
          store.createIndex('timestamp', 'timestamp', { unique: false });
        }
      };
    });
  }

  async storeSession(sessionData: SessionData): Promise<void> {
    try {
      const db = await this.openDB();
      const transaction = db.transaction([this.storeName], 'readwrite');
      const store = transaction.objectStore(this.storeName);
      
      await new Promise<void>((resolve, reject) => {
        const request = store.put({
          ...sessionData,
          timestamp: Date.now()
        });
        
        request.onsuccess = () => resolve();
        request.onerror = () => reject(request.error);
      });
      
      console.log('✅ Session stored in IndexedDB for offline PWA support');
    } catch (error) {
      console.warn('⚠️ Failed to store session in IndexedDB:', error);
    }
  }

  async getStoredSession(): Promise<SessionData | null> {
    try {
      const db = await this.openDB();
      const transaction = db.transaction([this.storeName], 'readonly');
      const store = transaction.objectStore(this.storeName);
      
      const sessions = await new Promise<SessionData[]>((resolve, reject) => {
        const request = store.getAll();
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
      });
      
      if (sessions.length === 0) return null;
      
      // Get most recent session
      const latestSession = sessions.sort((a, b) => b.timestamp - a.timestamp)[0];
      
      // Check if session is not too old (7 days)
      const sevenDaysAgo = Date.now() - (7 * 24 * 60 * 60 * 1000);
      if (latestSession.timestamp < sevenDaysAgo) {
        await this.clearOldSessions();
        return null;
      }
      
      return latestSession;
    } catch (error) {
      console.warn('⚠️ Failed to retrieve session from IndexedDB:', error);
      return null;
    }
  }

  async clearOldSessions(): Promise<void> {
    try {
      const db = await this.openDB();
      const transaction = db.transaction([this.storeName], 'readwrite');
      const store = transaction.objectStore(this.storeName);
      
      await new Promise<void>((resolve, reject) => {
        const request = store.clear();
        request.onsuccess = () => resolve();
        request.onerror = () => reject(request.error);
      });
      
      console.log('✅ Old sessions cleared from IndexedDB');
    } catch (error) {
      console.warn('⚠️ Failed to clear old sessions:', error);
    }
  }

  async clearAllSessions(): Promise<void> {
    try {
      await this.clearOldSessions();
      console.log('✅ All sessions cleared from IndexedDB for logout');
    } catch (error) {
      console.warn('⚠️ Failed to clear all sessions:', error);
    }
  }
}

export const indexedDBStorage = new IndexedDBStorage();