// Simple logout handler that clears session and redirects
export const handleLogout = async (): Promise<void> => {
  try {
    // Clear browser storage
    if (typeof window !== 'undefined') {
      localStorage.clear();
      sessionStorage.clear();
    }

    // Use simple logout route that handles everything server-side
    window.location.href = '/logout';
    
  } catch (error) {
    console.error('Logout error:', error);
    
    // Force redirect even if logout failed
    window.location.href = '/logout';
  }
};

// Legacy export for backward compatibility
export const logoutHandler = {
  performLogout: handleLogout
};

export const performSecureLogout = handleLogout;