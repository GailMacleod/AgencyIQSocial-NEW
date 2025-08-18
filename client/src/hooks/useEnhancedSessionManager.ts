
import { useEffect, useState } from 'react';
import { indexedDBStorage } from './indexeddb-storage';

export function useEnhancedSessionManager() {
  const [sessionInfo, setSessionInfo] = useState(null);
  const [isError, setIsError] = useState(false);
  
  const establishSession = async () => {
    try {
      // Try to get stored session for PWA offline support
      const storedSession = await indexedDBStorage.getStoredSession();
      if (storedSession) {
        setSessionInfo(storedSession);
        return storedSession;
      }
      
      // Establish new session
      const response = await fetch('/api/auth/session', {
        credentials: 'include',
        signal: AbortSignal.timeout(5000) // 5-second timeout handling
      });
      
      if (response.ok) {
        const sessionData = await response.json();
        setSessionInfo(sessionData);
        
        // Store session for PWA offline support
        if (sessionData.authenticated) {
          await indexedDBStorage.storeSession({
            id: sessionData.sessionId,
            userId: sessionData.user.id,
            email: sessionData.user.email,
            timestamp: Date.now(),
            authenticated: true
          });
        }
        
        return sessionData;
      }
    } catch (error) {
      console.error('Session establishment failed:', error);
      setIsError(true);
    }
  };
  
  // RefreshToken function for 401 handling
  const refreshToken = async () => {
    try {
      const response = await fetch('/api/oauth-refresh', {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json'
        }
      });
      
      if (response.ok) {
        const refreshedData = await response.json();
        if (refreshedData.success) {
          await establishSession();
          return true;
        }
      }
      return false;
    } catch (error) {
      console.error('Token refresh failed:', error);
      return false;
    }
  };
  
  return {
    sessionInfo,
    isEstablished: !!sessionInfo?.authenticated,
    isError,
    retrySession: establishSession,
    refreshToken,
    isReady: !!sessionInfo
  };
}