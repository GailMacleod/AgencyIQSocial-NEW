/**
 * OAuth Manager with Token Refresh and Scope Handling
 * Prevents token expiry during app usage and handles logout failures
 */

import { apiRetry } from './apiRetryWrapper';

interface OAuthToken {
  accessToken: string;
  refreshToken?: string;
  expiresAt: number;
  scope: string[];
  provider: string;
}

interface OAuthState {
  tokens: Map<string, OAuthToken>;
  refreshPromises: Map<string, Promise<OAuthToken>>;
  isRefreshing: boolean;
}

export class OAuthManager {
  private static instance: OAuthManager;
  private state: OAuthState;
  private refreshBuffer = 5 * 60 * 1000; // 5 minutes before expiry

  constructor() {
    this.state = {
      tokens: new Map(),
      refreshPromises: new Map(),
      isRefreshing: false
    };
    
    // Start token monitoring
    this.startTokenMonitoring();
  }

  static getInstance(): OAuthManager {
    if (!OAuthManager.instance) {
      OAuthManager.instance = new OAuthManager();
    }
    return OAuthManager.instance;
  }

  /**
   * Initialize OAuth tokens from backend
   */
  async initializeTokens(): Promise<void> {
    try {
      const response = await apiRetry.get('/api/oauth/tokens');
      const tokenData = response.data;

      for (const [provider, token] of Object.entries(tokenData)) {
        this.state.tokens.set(provider, token as OAuthToken);
      }

      console.log('✅ OAuth tokens initialized for providers:', Array.from(this.state.tokens.keys()));
    } catch (error) {
      console.warn('⚠️ Failed to initialize OAuth tokens:', error);
    }
  }

  /**
   * Get valid token for provider (with automatic refresh)
   */
  async getValidToken(provider: string): Promise<string | null> {
    const token = this.state.tokens.get(provider);
    
    if (!token) {
      console.warn(`No token found for provider: ${provider}`);
      return null;
    }

    // Check if token needs refresh
    const now = Date.now();
    const needsRefresh = token.expiresAt - now < this.refreshBuffer;

    if (needsRefresh) {
      console.log(`🔄 Token for ${provider} needs refresh`);
      return await this.refreshToken(provider);
    }

    return token.accessToken;
  }

  /**
   * Refresh token with deduplication
   */
  private async refreshToken(provider: string): Promise<string | null> {
    // Check if refresh is already in progress
    const existingPromise = this.state.refreshPromises.get(provider);
    if (existingPromise) {
      try {
        const refreshedToken = await existingPromise;
        return refreshedToken.accessToken;
      } catch (error) {
        console.error(`Token refresh failed for ${provider}:`, error);
        return null;
      }
    }

    // Start new refresh
    const refreshPromise = this.performTokenRefresh(provider);
    this.state.refreshPromises.set(provider, refreshPromise);

    try {
      const refreshedToken = await refreshPromise;
      this.state.tokens.set(provider, refreshedToken);
      return refreshedToken.accessToken;
    } catch (error) {
      console.error(`Token refresh failed for ${provider}:`, error);
      // Remove invalid token
      this.state.tokens.delete(provider);
      return null;
    } finally {
      this.state.refreshPromises.delete(provider);
    }
  }

  /**
   * Perform actual token refresh API call
   */
  private async performTokenRefresh(provider: string): Promise<OAuthToken> {
    const currentToken = this.state.tokens.get(provider);
    
    if (!currentToken?.refreshToken) {
      throw new Error(`No refresh token available for ${provider}`);
    }

    const response = await apiRetry.post('/api/oauth/refresh', {
      provider,
      refreshToken: currentToken.refreshToken
    });

    if (!response.data || !response.data.accessToken) {
      throw new Error(`Invalid refresh response for ${provider}`);
    }

    return {
      accessToken: response.data.accessToken,
      refreshToken: response.data.refreshToken || currentToken.refreshToken,
      expiresAt: Date.now() + (response.data.expiresIn * 1000),
      scope: response.data.scope || currentToken.scope,
      provider
    };
  }

  /**
   * Check token scopes for API calls
   */
  hasScope(provider: string, requiredScope: string): boolean {
    const token = this.state.tokens.get(provider);
    return token?.scope.includes(requiredScope) || false;
  }

  /**
   * Safe logout with retry mechanism
   */
  async logout(provider?: string): Promise<boolean> {
    const providers = provider ? [provider] : Array.from(this.state.tokens.keys());
    const results = [];

    for (const p of providers) {
      try {
        // Attempt OAuth token revocation first
        await this.revokeToken(p);
        
        // Remove from local state
        this.state.tokens.delete(p);
        this.state.refreshPromises.delete(p);
        
        console.log(`✅ Successfully logged out from ${p}`);
        results.push(true);
      } catch (error) {
        console.error(`❌ Logout failed for ${p}:`, error);
        
        // Still remove from local state even if server call fails
        this.state.tokens.delete(p);
        this.state.refreshPromises.delete(p);
        
        results.push(false);
      }
    }

    // Attempt backend session cleanup
    try {
      await apiRetry.post('/api/auth/logout', { 
        providers,
        forceCleanup: true 
      });
    } catch (error) {
      console.warn('Backend logout cleanup failed:', error);
    }

    // Force page reload as fallback to clear any remaining state
    if (results.some(r => !r)) {
      console.log('🔄 Forcing page reload due to logout issues');
      setTimeout(() => {
        window.location.href = '/';
      }, 1000);
    }

    return results.every(r => r);
  }

  /**
   * Revoke token at provider
   */
  private async revokeToken(provider: string): Promise<void> {
    const token = this.state.tokens.get(provider);
    
    if (!token) {
      return;
    }

    // Provider-specific revocation
    switch (provider) {
      case 'google':
        await apiRetry.post(`https://oauth2.googleapis.com/revoke`, {
          token: token.accessToken
        });
        break;
      case 'facebook':
        await apiRetry.delete(`https://graph.facebook.com/me/permissions`, {
          params: { access_token: token.accessToken }
        });
        break;
      case 'linkedin':
        await apiRetry.post('/api/oauth/revoke/linkedin', {
          token: token.accessToken
        });
        break;
      default:
        // Generic revocation via backend
        await apiRetry.post('/api/oauth/revoke', {
          provider,
          token: token.accessToken
        });
    }
  }

  /**
   * Start background token monitoring
   */
  private startTokenMonitoring(): void {
    setInterval(() => {
      const now = Date.now();
      
      for (const [provider, token] of this.state.tokens.entries()) {
        const timeToExpiry = token.expiresAt - now;
        
        // Proactive refresh 10 minutes before expiry
        if (timeToExpiry < 10 * 60 * 1000 && timeToExpiry > 0) {
          console.log(`⏰ Proactively refreshing token for ${provider}`);
          this.refreshToken(provider).catch(error => {
            console.error(`Proactive refresh failed for ${provider}:`, error);
          });
        }
        
        // Remove expired tokens
        if (timeToExpiry <= 0) {
          console.warn(`🚫 Token expired for ${provider}, removing`);
          this.state.tokens.delete(provider);
        }
      }
    }, 2 * 60 * 1000); // Check every 2 minutes
  }

  /**
   * Get token status for debugging
   */
  getTokenStatus(): Record<string, any> {
    const status: Record<string, any> = {};
    
    for (const [provider, token] of this.state.tokens.entries()) {
      const now = Date.now();
      const timeToExpiry = token.expiresAt - now;
      
      status[provider] = {
        hasToken: true,
        expiresIn: Math.round(timeToExpiry / 1000 / 60), // minutes
        scopes: token.scope,
        needsRefresh: timeToExpiry < this.refreshBuffer
      };
    }
    
    return status;
  }

  /**
   * Handle API call failures due to token issues
   */
  async handleTokenFailure(provider: string, error: any): Promise<boolean> {
    if (error.response?.status === 401) {
      console.log(`🔄 Handling 401 error for ${provider}, attempting token refresh`);
      
      const newToken = await this.refreshToken(provider);
      return newToken !== null;
    }
    
    return false;
  }
}

// Create singleton instance
export const oauthManager = OAuthManager.getInstance();

// Export convenience functions
export const getValidToken = (provider: string) => oauthManager.getValidToken(provider);
export const hasScope = (provider: string, scope: string) => oauthManager.hasScope(provider, scope);
export const safeLogout = (provider?: string) => oauthManager.logout(provider);
export const handleTokenFailure = (provider: string, error: any) => oauthManager.handleTokenFailure(provider, error);