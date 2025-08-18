import axios from 'axios';
import crypto from 'crypto';

interface RefreshResult {
  success: boolean;
  newAccessToken?: string;
  newRefreshToken?: string;
  expiresAt?: Date;
  error?: string;
  requiresReauth?: boolean;
}

export class OAuthRefreshService {
  
  static async validateAndRefreshConnection(platform: string, userId: number): Promise<RefreshResult> {
    try {
      const { storage } = await import('./storage');
      const connections = await storage.getPlatformConnectionsByUser(userId);
      const connection = connections.find(c => c.platform === platform);
      
      if (!connection) {
        return {
          success: false,
          error: `No ${platform} connection found`,
          requiresReauth: true
        };
      }

      // First validate current token
      const { OAuthStatusChecker } = await import('./oauth-status-checker');
      let validation;
      
      switch (platform) {
        case 'facebook':
          validation = await OAuthStatusChecker.validateFacebookToken(connection.accessToken);
          break;
        case 'instagram':
          validation = await OAuthStatusChecker.validateInstagramToken(connection.accessToken);
          break;
        case 'youtube':
          validation = await OAuthStatusChecker.validateYouTubeToken(connection.accessToken);
          break;
        case 'x':
          validation = await OAuthStatusChecker.validateXToken(connection.accessToken, connection.refreshToken);
          break;
        case 'linkedin':
          validation = await OAuthStatusChecker.validateLinkedInToken(connection.accessToken);
          break;
        default:
          return {
            success: false,
            error: `Unsupported platform: ${platform}`,
            requiresReauth: true
          };
      }

      // If token is valid, no refresh needed
      if (validation.isValid) {
        return {
          success: true,
          newAccessToken: connection.accessToken,
          newRefreshToken: connection.refreshToken
        };
      }

      // Token is invalid, attempt refresh
      console.log(`[OAUTH-REFRESH] Token validation failed for ${platform}, attempting refresh...`);
      
      switch (platform) {
        case 'facebook':
          return await this.refreshFacebookToken(connection, userId);
        case 'instagram':
          return await this.refreshInstagramToken(connection, userId);
        case 'youtube':
          return await this.refreshYouTubeToken(connection, userId);
        case 'x':
          return await this.refreshXToken(connection, userId);
        case 'linkedin':
          return await this.refreshLinkedInToken(connection, userId);
        default:
          return {
            success: false,
            error: `Refresh not implemented for ${platform}`,
            requiresReauth: true
          };
      }
      
    } catch (error: any) {
      console.error(`[OAUTH-REFRESH] Error for ${platform}:`, error);
      return {
        success: false,
        error: error.message,
        requiresReauth: true
      };
    }
  }

  private static async refreshFacebookToken(connection: any, userId: number): Promise<RefreshResult> {
    try {
      console.log(`[OAUTH-REFRESH] Attempting Facebook token refresh for user ${userId}`);
      
      // Check if we have the required environment variables
      if (!process.env.FACEBOOK_APP_ID || !process.env.FACEBOOK_APP_SECRET) {
        console.error('[OAUTH-REFRESH] Facebook credentials not configured');
        return {
          success: false,
          error: 'Facebook app credentials not configured in environment',
          requiresReauth: true
        };
      }

      // FIXED: Remove appsecret_proof requirement for Facebook token refresh
      // First try to get a fresh Page Access Token
      // This handles the "Token requires regeneration" error
      const pageResponse = await axios.get(
        `https://graph.facebook.com/v18.0/me/accounts`,
        {
          params: {
            access_token: connection.accessToken
            // REMOVED: appsecret_proof requirement
          }
        }
      );

      if (pageResponse.data.data && pageResponse.data.data.length > 0) {
        // Use the first page's access token (should be a Page Access Token)
        const pageAccessToken = pageResponse.data.data[0].access_token;
        
        // Exchange for long-lived token
        const response = await axios.get(
          `https://graph.facebook.com/v18.0/oauth/access_token`,
          {
            params: {
              grant_type: 'fb_exchange_token',
              client_id: process.env.FACEBOOK_APP_ID,
              client_secret: process.env.FACEBOOK_APP_SECRET,
              fb_exchange_token: pageAccessToken
            }
          }
        );

        const { access_token, expires_in } = response.data;
        const expiresAt = new Date(Date.now() + (expires_in * 1000));

        // Update database
        const { storage } = await import('./storage');
        await storage.updatePlatformConnection(connection.id, {
          accessToken: access_token,
          expiresAt: expiresAt
        });

        console.log(`[OAUTH-REFRESH] Facebook token refreshed successfully, expires: ${expiresAt.toISOString()}`);
        
        return {
          success: true,
          newAccessToken: access_token,
          expiresAt: expiresAt
        };
      } else {
        // No pages found, need full reauth
        return {
          success: false,
          error: 'No Facebook pages found. Please ensure your Facebook account manages a page.',
          requiresReauth: true
        };
      }
      
    } catch (error: any) {
      console.error('[OAUTH-REFRESH] Facebook refresh failed:', error.response?.data || error.message);
      
      // Enhanced error handling for specific Facebook errors
      if (error.response?.data?.error) {
        const fbError = error.response.data.error;
        if (fbError.code === 190) {
          return {
            success: false,
            error: 'Facebook token expired. Please reconnect your Facebook account.',
            requiresReauth: true
          };
        } else if (fbError.code === 102) {
          return {
            success: false,
            error: 'Facebook API session key invalid. Please reconnect your Facebook account.',
            requiresReauth: true
          };
        }
      }
      
      return {
        success: false,
        error: 'Facebook token refresh failed. Please reconnect your Facebook account.',
        requiresReauth: true
      };
    }
  }

  private static async refreshInstagramToken(connection: any, userId: number): Promise<RefreshResult> {
    try {
      console.log(`[OAUTH-REFRESH] Attempting Instagram token refresh for user ${userId}`);
      
      // First try Instagram-specific refresh
      const response = await axios.get(
        `https://graph.instagram.com/refresh_access_token`,
        {
          params: {
            grant_type: 'ig_refresh_token',
            access_token: connection.accessToken
          }
        }
      );

      const { access_token, expires_in } = response.data;
      const expiresAt = new Date(Date.now() + (expires_in * 1000));

      // Update database
      const { storage } = await import('./storage');
      await storage.updatePlatformConnection(connection.id, {
        accessToken: access_token,
        expiresAt: expiresAt
      });

      console.log(`[OAUTH-REFRESH] Instagram token refreshed successfully, expires: ${expiresAt.toISOString()}`);
      
      return {
        success: true,
        newAccessToken: access_token,
        expiresAt: expiresAt
      };
      
    } catch (error: any) {
      console.error('[OAUTH-REFRESH] Instagram refresh failed:', error.response?.data || error.message);
      
      // Enhanced error handling for Instagram-specific errors
      if (error.response?.data?.error) {
        const igError = error.response.data.error;
        if (igError.code === 190) {
          return {
            success: false,
            error: 'Instagram token expired. Please reconnect your Instagram account.',
            requiresReauth: true
          };
        } else if (igError.message && igError.message.includes('Cannot parse access token')) {
          return {
            success: false,
            error: 'Instagram token format invalid. Please reconnect your Instagram account.',
            requiresReauth: true
          };
        }
      }
      
      return {
        success: false,
        error: 'Instagram token refresh failed. Please reconnect your Instagram account.',
        requiresReauth: true
      };
    }
  }

  private static async refreshYouTubeToken(connection: any, userId: number): Promise<RefreshResult> {
    try {
      if (!connection.refreshToken) {
        return {
          success: false,
          error: 'No refresh token available',
          requiresReauth: true
        };
      }

      const response = await axios.post(
        'https://oauth2.googleapis.com/token',
        {
          client_id: process.env.YOUTUBE_CLIENT_ID,
          client_secret: process.env.YOUTUBE_CLIENT_SECRET,
          refresh_token: connection.refreshToken,
          grant_type: 'refresh_token'
        }
      );

      const { access_token, expires_in, refresh_token } = response.data;
      const expiresAt = new Date(Date.now() + (expires_in * 1000));

      // Update database
      const { storage } = await import('./storage');
      await storage.updatePlatformConnection(connection.id, {
        accessToken: access_token,
        refreshToken: refresh_token || connection.refreshToken, // Keep existing if not provided
        expiresAt: expiresAt
      });

      console.log(`[OAUTH-REFRESH] YouTube token refreshed successfully, expires: ${expiresAt.toISOString()}`);
      
      return {
        success: true,
        newAccessToken: access_token,
        newRefreshToken: refresh_token || connection.refreshToken,
        expiresAt: expiresAt
      };
      
    } catch (error: any) {
      console.error('[OAUTH-REFRESH] YouTube refresh failed:', error.response?.data || error.message);
      return {
        success: false,
        error: 'YouTube token refresh failed',
        requiresReauth: true
      };
    }
  }

  private static async refreshXToken(connection: any, userId: number): Promise<RefreshResult> {
    try {
      console.log(`[OAUTH-REFRESH] Attempting X token refresh for user ${userId}`);
      
      const consumerKey = process.env.X_CONSUMER_KEY;
      const consumerSecret = process.env.X_CONSUMER_SECRET;
      
      if (!consumerKey || !consumerSecret) {
        console.log(`[OAUTH-REFRESH] X consumer credentials status: KEY=${!!consumerKey}, SECRET=${!!consumerSecret}`);
        return {
          success: false,
          error: 'X consumer credentials not configured in environment',
          requiresReauth: true
        };
      }

      if (!connection.refreshToken) {
        return {
          success: false,
          error: 'No refresh token available for X',
          requiresReauth: true
        };
      }

      console.log(`[OAUTH-REFRESH] X credentials available, attempting refresh with consumer key: ${consumerKey.substring(0, 10)}...`);
      
      // X OAuth 2.0 refresh token request using URLSearchParams
      const refreshData = new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: connection.refreshToken,
        client_id: consumerKey
      });

      // X OAuth 2.0 token refresh
      const response = await axios.post(
        'https://api.twitter.com/2/oauth2/token',
        refreshData,
        {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': `Basic ${Buffer.from(`${consumerKey}:${consumerSecret}`).toString('base64')}`
          }
        }
      );

      const { access_token, refresh_token, expires_in } = response.data;
      const expiresAt = new Date(Date.now() + (expires_in * 1000));

      // Update database
      const { storage } = await import('./storage');
      await storage.updatePlatformConnection(connection.id, {
        accessToken: access_token,
        refreshToken: refresh_token,
        expiresAt: expiresAt
      });

      console.log(`[OAUTH-REFRESH] X token refreshed successfully, expires: ${expiresAt.toISOString()}`);
      
      return {
        success: true,
        newAccessToken: access_token,
        newRefreshToken: refresh_token,
        expiresAt: expiresAt
      };
      
    } catch (error: any) {
      console.error('[OAUTH-REFRESH] X refresh failed:', {
        status: error.response?.status,
        data: error.response?.data,
        message: error.message
      });
      return {
        success: false,
        error: error.response?.data?.error_description || error.message,
        requiresReauth: true
      };
    }
  }

  private static async refreshLinkedInToken(connection: any, userId: number): Promise<RefreshResult> {
    try {
      console.log(`[OAUTH-REFRESH] Attempting LinkedIn token refresh for user ${userId}`);
      
      // Check if we have the required environment variables
      if (!process.env.LINKEDIN_CLIENT_ID || !process.env.LINKEDIN_CLIENT_SECRET) {
        console.error('[OAUTH-REFRESH] LinkedIn credentials not configured');
        return {
          success: false,
          error: 'LinkedIn app credentials not configured in environment',
          requiresReauth: true
        };
      }

      if (!connection.refreshToken) {
        return {
          success: false,
          error: 'No refresh token available for LinkedIn. Please reconnect your LinkedIn account.',
          requiresReauth: true
        };
      }

      // LinkedIn OAuth 2.0 token refresh
      const refreshData = new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: connection.refreshToken,
        client_id: process.env.LINKEDIN_CLIENT_ID,
        client_secret: process.env.LINKEDIN_CLIENT_SECRET
      });

      const response = await axios.post(
        'https://www.linkedin.com/oauth/v2/accessToken',
        refreshData,
        {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
          }
        }
      );

      const { access_token, refresh_token, expires_in } = response.data;
      const expiresAt = new Date(Date.now() + (expires_in * 1000));

      // Update database
      const { storage } = await import('./storage');
      await storage.updatePlatformConnection(connection.id, {
        accessToken: access_token,
        refreshToken: refresh_token || connection.refreshToken,
        expiresAt: expiresAt
      });

      console.log(`[OAUTH-REFRESH] LinkedIn token refreshed successfully, expires: ${expiresAt.toISOString()}`);
      
      return {
        success: true,
        newAccessToken: access_token,
        newRefreshToken: refresh_token || connection.refreshToken,
        expiresAt: expiresAt
      };
      
    } catch (error: any) {
      console.error('[OAUTH-REFRESH] LinkedIn refresh failed:', error.response?.data || error.message);
      
      // Enhanced error handling for LinkedIn-specific errors
      if (error.response?.data?.error) {
        const linkedInError = error.response.data.error;
        if (linkedInError === 'invalid_grant') {
          return {
            success: false,
            error: 'LinkedIn refresh token expired. Please reconnect your LinkedIn account.',
            requiresReauth: true
          };
        } else if (linkedInError === 'invalid_client') {
          return {
            success: false,
            error: 'LinkedIn app credentials invalid. Please check app configuration.',
            requiresReauth: true
          };
        }
      }
      
      return {
        success: false,
        error: 'LinkedIn token refresh failed. Please reconnect your LinkedIn account.',
        requiresReauth: true
      };
    }
  }
}