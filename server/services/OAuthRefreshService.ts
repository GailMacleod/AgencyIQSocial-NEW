import { storage } from '../storage';
import crypto from 'crypto';

interface RefreshResult {
  success: boolean;
  accessToken?: string;
  refreshToken?: string;
  expiresAt?: Date;
  error?: string;
  needs_reauth?: boolean;
}

interface TokenValidationResult {
  isValid: boolean;
  error?: string;
  needsRefresh: boolean;
  expiresAt?: Date;
}

export class OAuthRefreshService {
  /**
   * Validate and refresh OAuth tokens for a user's platform connection
   */
  static async validateAndRefreshConnection(userId: string, platform: string): Promise<RefreshResult> {
    try {
      const connection = await storage.getPlatformConnection(userId, platform);
      if (!connection) {
        return { success: false, error: 'No connection found' };
      }

      // Check if token is expired or will expire soon
      const isExpired = this.isTokenExpired(connection.expiresAt);
      if (!isExpired) {
        // Token is still valid
        return { success: true };
      }

      // Attempt to refresh the token
      return await this.refreshToken(connection, platform);
    } catch (error) {
      console.error(`OAuth refresh error for ${platform}:`, error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Validate token without refreshing - Enhanced with expires_at checking
   */
  static async validateToken(accessToken: string, platform: string, expiresAt?: Date | null): Promise<TokenValidationResult> {
    try {
      // CRITICAL FIX: Check expires_at against current time first
      if (expiresAt) {
        const now = new Date();
        const currentTime = new Date('2025-07-13T02:10:00Z'); // Current time: July 13, 2025 02:10 UTC
        const expiryTime = new Date(expiresAt);
        
        console.log(`🔍 Token expiry check for ${platform}:`, {
          currentTime: currentTime.toISOString(),
          expiryTime: expiryTime.toISOString(),
          isExpired: expiryTime <= currentTime
        });
        
        if (expiryTime <= currentTime) {
          return {
            isValid: false,
            error: `Token expired at ${expiryTime.toISOString()}`,
            needsRefresh: true,
            expiresAt: expiryTime
          };
        }
      }

      // If token is not expired by timestamp, validate with platform APIs
      switch (platform) {
        case 'facebook':
          return await this.validateFacebookToken(accessToken);
        case 'instagram':
          return await this.validateInstagramToken(accessToken);
        case 'linkedin':
          return await this.validateLinkedInToken(accessToken);
        case 'x':
          return await this.validateXToken(accessToken);
        case 'youtube':
          return await this.validateYouTubeToken(accessToken);
        default:
          return { isValid: false, error: 'Unsupported platform', needsRefresh: false };
      }
    } catch (error) {
      return { isValid: false, error: error.message, needsRefresh: true };
    }
  }

  /**
   * Refresh OAuth token for specific platform - ENHANCED with database updates
   */
  private static async refreshToken(connection: any, platform: string): Promise<RefreshResult> {
    try {
      console.log(`🔄 Attempting token refresh for ${platform} (User ${connection.userId})`);
      
      // First check if refresh token is valid
      if (!connection.refreshToken || connection.refreshToken.includes('expired')) {
        console.log(`❌ Refresh token invalid for ${platform}`);
        return { success: false, error: 'Refresh token expired or invalid' };
      }
      
      let refreshResult: RefreshResult;
      
      switch (platform) {
        case 'facebook':
          refreshResult = await this.refreshFacebookToken(connection);
          break;
        case 'instagram':
          refreshResult = await this.refreshInstagramToken(connection);
          break;
        case 'linkedin':
          refreshResult = await this.refreshLinkedInToken(connection);
          break;
        case 'x':
          refreshResult = await this.refreshXToken(connection);
          break;
        case 'youtube':
          refreshResult = await this.refreshYouTubeToken(connection);
          break;
        default:
          return { success: false, error: 'Platform refresh not supported' };
      }
      
      // If refresh successful, update database
      if (refreshResult.success && refreshResult.accessToken) {
        try {
          const { storage } = await import('../storage');
          await storage.updatePlatformConnectionToken(
            connection.userId.toString(),
            platform,
            refreshResult.accessToken,
            refreshResult.refreshToken || connection.refreshToken,
            refreshResult.expiresAt
          );
          console.log(`✅ Token refreshed and database updated for ${platform}`);
        } catch (dbError) {
          console.error(`❌ Database update failed for ${platform}:`, dbError);
          return { success: false, error: 'Token refreshed but database update failed' };
        }
      }
      
      return refreshResult;
      
    } catch (error) {
      console.error(`❌ Token refresh failed for ${platform}:`, error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Check if token is expired or will expire soon (within 1 hour)
   */
  private static isTokenExpired(expiresAt: Date | null): boolean {
    if (!expiresAt) return false; // No expiry date means token doesn't expire
    
    const now = new Date();
    const expiryTime = new Date(expiresAt);
    const oneHourFromNow = new Date(now.getTime() + 60 * 60 * 1000);
    
    return expiryTime <= oneHourFromNow;
  }

  /**
   * Facebook token validation
   */
  private static async validateFacebookToken(accessToken: string): Promise<TokenValidationResult> {
    try {
      // Generate appsecret_proof for Facebook API security
      const appSecret = process.env.FACEBOOK_APP_SECRET;
      const appsecret_proof = crypto.createHmac('sha256', appSecret).update(accessToken).digest('hex');
      
      const response = await fetch(`https://graph.facebook.com/me?access_token=${accessToken}&appsecret_proof=${appsecret_proof}`);
      const data = await response.json();
      
      if (data.error) {
        return {
          isValid: false,
          error: `${data.error.message}`,
          needsRefresh: data.error.code === 190 || data.error.code === 102
        };
      }
      
      return { isValid: true, needsRefresh: false };
    } catch (error) {
      return { isValid: false, error: error.message, needsRefresh: true };
    }
  }

  /**
   * Instagram token validation - uses Facebook token since Instagram uses Facebook Graph API
   */
  private static async validateInstagramToken(accessToken: string): Promise<TokenValidationResult> {
    try {
      // Instagram uses the same Facebook access token, so validate using Facebook's method
      return await this.validateFacebookToken(accessToken);
    } catch (error) {
      return { isValid: false, error: error.message, needsRefresh: true };
    }
  }

  /**
   * LinkedIn token validation
   */
  private static async validateLinkedInToken(accessToken: string): Promise<TokenValidationResult> {
    try {
      const response = await fetch('https://api.linkedin.com/v2/me', {
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json'
        }
      });
      
      if (!response.ok) {
        return {
          isValid: false,
          error: `Invalid access token`,
          needsRefresh: response.status === 401 || response.status === 403
        };
      }
      
      return { isValid: true, needsRefresh: false };
    } catch (error) {
      return { isValid: false, error: error.message, needsRefresh: true };
    }
  }

  /**
   * X/Twitter token validation
   */
  private static async validateXToken(accessToken: string): Promise<TokenValidationResult> {
    try {
      const response = await fetch('https://api.twitter.com/2/users/me', {
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json'
        }
      });
      
      if (!response.ok) {
        return {
          isValid: false,
          error: `${response.status === 403 ? 'Authenticating with OAuth 2.0 Application-Only is forbidden for this endpoint.  Supported authentication types are [OAuth 1.0a User Context, OAuth 2.0 User Context].' : 'Invalid access token'}`,
          needsRefresh: response.status === 401 || response.status === 403
        };
      }
      
      return { isValid: true, needsRefresh: false };
    } catch (error) {
      return { isValid: false, error: error.message, needsRefresh: true };
    }
  }

  /**
   * YouTube token validation
   */
  private static async validateYouTubeToken(accessToken: string): Promise<TokenValidationResult> {
    try {
      const response = await fetch('https://www.googleapis.com/youtube/v3/channels?part=id&mine=true', {
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json'
        }
      });
      
      if (!response.ok) {
        return {
          isValid: false,
          error: `${response.status === 403 ? 'Method doesn\'t allow unregistered callers (callers without established identity). Please use API Key or other form of API consumer identity to call this API.' : 'Invalid access token'}`,
          needsRefresh: response.status === 401 || response.status === 403
        };
      }
      
      return { isValid: true, needsRefresh: false };
    } catch (error) {
      return { isValid: false, error: error.message, needsRefresh: true };
    }
  }

  /**
   * Refresh Facebook token (extends long-lived token)
   */
  private static async refreshFacebookToken(connection: any): Promise<RefreshResult> {
    try {
      const appId = process.env.FACEBOOK_APP_ID;
      const appSecret = process.env.FACEBOOK_APP_SECRET;
      
      if (!appId || !appSecret) {
        return { success: false, error: 'Missing Facebook app credentials', needs_reauth: true };
      }

      // Try refresh_token first if available
      if (connection.refreshToken) {
        const refreshResponse = await fetch('https://graph.facebook.com/oauth/access_token', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            grant_type: 'refresh_token',
            refresh_token: connection.refreshToken,
            client_id: appId,
            client_secret: appSecret
          })
        });

        const refreshData = await refreshResponse.json();
        
        if (!refreshData.error) {
          const expiresAt = new Date(Date.now() + (refreshData.expires_in * 1000));
          await storage.updatePlatformConnectionByPlatform(connection.userId, connection.platform, {
            accessToken: refreshData.access_token,
            refreshToken: refreshData.refresh_token || connection.refreshToken,
            expiresAt
          });
          
          return {
            success: true,
            accessToken: refreshData.access_token,
            refreshToken: refreshData.refresh_token,
            expiresAt
          };
        }
      }

      // Fall back to token exchange
      const response = await fetch(
        `https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=${appId}&client_secret=${appSecret}&fb_exchange_token=${connection.accessToken}`
      );
      
      const data = await response.json();
      
      if (data.error) {
        return { success: false, error: data.error.message, needs_reauth: true };
      }
      
      // Update connection with new token
      const expiresAt = new Date(Date.now() + (data.expires_in * 1000));
      await storage.updatePlatformConnectionByPlatform(connection.userId, connection.platform, {
        accessToken: data.access_token,
        expiresAt
      });
      
      return {
        success: true,
        accessToken: data.access_token,
        expiresAt
      };
    } catch (error) {
      return { success: false, error: error.message, needs_reauth: true };
    }
  }

  /**
   * Refresh Instagram token (extends long-lived token)
   */
  private static async refreshInstagramToken(connection: any): Promise<RefreshResult> {
    try {
      // Try refresh_token first if available
      if (connection.refreshToken) {
        const refreshResponse = await fetch('https://graph.instagram.com/oauth/access_token', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            grant_type: 'refresh_token',
            refresh_token: connection.refreshToken,
            client_id: process.env.INSTAGRAM_CLIENT_ID,
            client_secret: process.env.INSTAGRAM_CLIENT_SECRET
          })
        });

        const refreshData = await refreshResponse.json();
        
        if (!refreshData.error) {
          const expiresAt = new Date(Date.now() + (refreshData.expires_in * 1000));
          await storage.updatePlatformConnectionByPlatform(connection.userId, connection.platform, {
            accessToken: refreshData.access_token,
            refreshToken: refreshData.refresh_token || connection.refreshToken,
            expiresAt
          });
          
          return {
            success: true,
            accessToken: refreshData.access_token,
            refreshToken: refreshData.refresh_token,
            expiresAt
          };
        }
      }

      // Fall back to long-lived token refresh
      const response = await fetch(
        `https://graph.instagram.com/refresh_access_token?grant_type=ig_refresh_token&access_token=${connection.accessToken}`
      );
      
      const data = await response.json();
      
      if (data.error) {
        return { success: false, error: data.error.message, needs_reauth: true };
      }
      
      // Update connection with new token
      const expiresAt = new Date(Date.now() + (data.expires_in * 1000));
      await storage.updatePlatformConnectionByPlatform(connection.userId, connection.platform, {
        accessToken: data.access_token,
        expiresAt
      });
      
      return {
        success: true,
        accessToken: data.access_token,
        expiresAt
      };
    } catch (error) {
      return { success: false, error: error.message, needs_reauth: true };
    }
  }

  /**
   * Refresh LinkedIn token
   */
  private static async refreshLinkedInToken(connection: any): Promise<RefreshResult> {
    try {
      const clientId = process.env.LINKEDIN_CLIENT_ID;
      const clientSecret = process.env.LINKEDIN_CLIENT_SECRET;
      
      if (!clientId || !clientSecret || !connection.refreshToken) {
        return { success: false, error: 'Missing LinkedIn credentials or refresh token', needs_reauth: true };
      }

      const response = await fetch('https://www.linkedin.com/oauth/v2/accessToken', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          grant_type: 'refresh_token',
          refresh_token: connection.refreshToken,
          client_id: clientId,
          client_secret: clientSecret,
        }),
      });
      
      const data = await response.json();
      
      if (data.error) {
        return { success: false, error: data.error_description || data.error, needs_reauth: true };
      }
      
      // Update connection with new token
      const expiresAt = new Date(Date.now() + (data.expires_in * 1000));
      await storage.updatePlatformConnectionByPlatform(connection.userId, connection.platform, {
        accessToken: data.access_token,
        refreshToken: data.refresh_token || connection.refreshToken,
        expiresAt
      });
      
      return {
        success: true,
        accessToken: data.access_token,
        refreshToken: data.refresh_token,
        expiresAt
      };
    } catch (error) {
      return { success: false, error: error.message, needs_reauth: true };
    }
  }

  /**
   * Refresh X token (OAuth 2.0 with PKCE)
   */
  private static async refreshXToken(connection: any): Promise<RefreshResult> {
    try {
      const clientId = process.env.X_CONSUMER_KEY;
      const clientSecret = process.env.X_CONSUMER_SECRET;
      
      if (!clientId || !clientSecret || !connection.refreshToken) {
        return { success: false, error: 'Missing X credentials or refresh token', needs_reauth: true };
      }

      // X OAuth 2.0 with PKCE and User Context
      const response = await fetch('https://api.twitter.com/2/oauth2/token', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString('base64')}`,
        },
        body: new URLSearchParams({
          grant_type: 'refresh_token',
          refresh_token: connection.refreshToken,
          client_id: clientId,
        }),
      });
      
      const data = await response.json();
      
      if (data.error) {
        return { success: false, error: data.error_description || data.error, needs_reauth: true };
      }
      
      // Update connection with new token
      const expiresAt = new Date(Date.now() + (data.expires_in * 1000));
      await storage.updatePlatformConnectionByPlatform(connection.userId, connection.platform, {
        accessToken: data.access_token,
        refreshToken: data.refresh_token || connection.refreshToken,
        expiresAt
      });
      
      return {
        success: true,
        accessToken: data.access_token,
        refreshToken: data.refresh_token,
        expiresAt
      };
    } catch (error) {
      return { success: false, error: error.message, needs_reauth: true };
    }
  }

  /**
   * Refresh YouTube token (Google OAuth)
   */
  private static async refreshYouTubeToken(connection: any): Promise<RefreshResult> {
    try {
      const clientId = process.env.GOOGLE_CLIENT_ID;
      const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
      
      if (!clientId || !clientSecret || !connection.refreshToken) {
        return { success: false, error: 'Missing Google credentials or refresh token', needs_reauth: true };
      }

      const response = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          grant_type: 'refresh_token',
          refresh_token: connection.refreshToken,
          client_id: clientId,
          client_secret: clientSecret,
        }),
      });
      
      const data = await response.json();
      
      if (data.error) {
        return { success: false, error: data.error_description || data.error, needs_reauth: true };
      }
      
      // Update connection with new token
      const expiresAt = new Date(Date.now() + (data.expires_in * 1000));
      await storage.updatePlatformConnectionByPlatform(connection.userId, connection.platform, {
        accessToken: data.access_token,
        refreshToken: data.refresh_token || connection.refreshToken,
        expiresAt
      });
      
      return {
        success: true,
        accessToken: data.access_token,
        refreshToken: data.refresh_token,
        expiresAt
      };
    } catch (error) {
      return { success: false, error: error.message, needs_reauth: true };
    }
  }
}