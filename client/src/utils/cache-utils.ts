/**
 * Browser cache clearing utilities for TheAgencyIQ
 * Handles stale authentication and session issues
 */

export const clearBrowserCache = () => {
  try {
    // Clear localStorage
    localStorage.clear();
    
    // Clear sessionStorage
    sessionStorage.clear();
    
    // Clear all cookies
    document.cookie.split(";").forEach((c) => {
      const eqPos = c.indexOf("=");
      const name = eqPos > -1 ? c.substr(0, eqPos) : c;
      document.cookie = name + "=;expires=Thu, 01 Jan 1970 00:00:00 GMT;path=/";
      document.cookie = name + "=;expires=Thu, 01 Jan 1970 00:00:00 GMT;path=/;domain=" + window.location.hostname;
      document.cookie = name + "=;expires=Thu, 01 Jan 1970 00:00:00 GMT;path=/;domain=." + window.location.hostname;
    });
    
    // Clear any cached service worker data
    if ('serviceWorker' in navigator) {
      navigator.serviceWorker.getRegistrations().then((registrations) => {
        registrations.forEach((registration) => {
          registration.unregister();
        });
      });
    }
    
    // Clear any cached API data if using queryClient
    if (window.queryClient) {
      window.queryClient.clear();
    }
    
    console.log('Cache cleared successfully - browser data reset');
    return true;
  } catch (error) {
    console.error('Error clearing cache:', error);
    return false;
  }
};

export const addCacheBustingHeaders = () => {
  // Add meta tags to prevent caching
  const metaTags = [
    { name: 'Cache-Control', content: 'no-cache, no-store, must-revalidate' },
    { name: 'Pragma', content: 'no-cache' },
    { name: 'Expires', content: '0' }
  ];
  
  metaTags.forEach(({ name, content }) => {
    let meta = document.querySelector(`meta[http-equiv="${name}"]`);
    if (!meta) {
      meta = document.createElement('meta');
      meta.setAttribute('http-equiv', name);
      document.head.appendChild(meta);
    }
    meta.setAttribute('content', content);
  });
};

export const forcePageRefresh = (clearCache = true) => {
  if (clearCache) {
    clearBrowserCache();
  }
  
  // Force hard refresh
  window.location.reload();
};

// Auto-initialize cache busting headers
if (typeof document !== 'undefined') {
  addCacheBustingHeaders();
}