import { db } from '../db';
import { platformConnections, oauthTokens } from '@shared/schema';
import { eq, and } from 'drizzle-orm';

interface TokenRefreshResult {
  success: boolean;
  accessToken?: string;
  refreshToken?: string;
  expiresAt?: number;
  error?: string;
}

export default class TokenManager {
  private async refreshFacebookToken(refreshToken: string): Promise<TokenRefreshResult> {
    try {
      const response = await fetch('https://graph.facebook.com/oauth/access_token', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          grant_type: 'refresh_token',
          refresh_token: refreshToken,
          client_id: process.env.FACEBOOK_CLIENT_ID || '',
          client_secret: process.env.FACEBOOK_CLIENT_SECRET || ''
        })
      });

      const data = await response.json();

      if (response.ok && data.access_token) {
        return {
          success: true,
          accessToken: data.access_token,
          refreshToken: data.refresh_token || refreshToken,
          expiresAt: data.expires_in ? Date.now() + (data.expires_in * 1000) : undefined
        };
      } else {
        return {
          success: false,
          error: data.error?.message || 'Facebook token refresh failed'
        };
      }
    } catch (error: any) {
      return {
        success: false,
        error: error.message
      };
    }
  }

  private async refreshLinkedInToken(refreshToken: string): Promise<TokenRefreshResult> {
    try {
      const response = await fetch('https://www.linkedin.com/oauth/v2/accessToken', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          grant_type: 'refresh_token',
          refresh_token: refreshToken,
          client_id: process.env.LINKEDIN_CLIENT_ID || '',
          client_secret: process.env.LINKEDIN_CLIENT_SECRET || ''
        })
      });

      const data = await response.json();

      if (response.ok && data.access_token) {
        return {
          success: true,
          accessToken: data.access_token,
          refreshToken: data.refresh_token || refreshToken,
          expiresAt: data.expires_in ? Date.now() + (data.expires_in * 1000) : undefined
        };
      } else {
        return {
          success: false,
          error: data.error_description || 'LinkedIn token refresh failed'
        };
      }
    } catch (error: any) {
      return {
        success: false,
        error: error.message
      };
    }
  }

  private async refreshGoogleToken(refreshToken: string): Promise<TokenRefreshResult> {
    try {
      const response = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          grant_type: 'refresh_token',
          refresh_token: refreshToken,
          client_id: process.env.GOOGLE_CLIENT_ID || '',
          client_secret: process.env.GOOGLE_CLIENT_SECRET || ''
        })
      });

      const data = await response.json();

      if (response.ok && data.access_token) {
        return {
          success: true,
          accessToken: data.access_token,
          refreshToken: data.refresh_token || refreshToken,
          expiresAt: data.expires_in ? Date.now() + (data.expires_in * 1000) : undefined
        };
      } else {
        return {
          success: false,
          error: data.error_description || 'Google token refresh failed'
        };
      }
    } catch (error: any) {
      return {
        success: false,
        error: error.message
      };
    }
  }

  private async refreshTwitterToken(refreshToken: string): Promise<TokenRefreshResult> {
    try {
      // Twitter OAuth 2.0 token refresh
      const response = await fetch('https://api.twitter.com/2/oauth2/token', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': `Basic ${Buffer.from(`${process.env.TWITTER_CLIENT_ID}:${process.env.TWITTER_CLIENT_SECRET}`).toString('base64')}`
        },
        body: new URLSearchParams({
          grant_type: 'refresh_token',
          refresh_token: refreshToken
        })
      });

      const data = await response.json();

      if (response.ok && data.access_token) {
        return {
          success: true,
          accessToken: data.access_token,
          refreshToken: data.refresh_token || refreshToken,
          expiresAt: data.expires_in ? Date.now() + (data.expires_in * 1000) : undefined
        };
      } else {
        return {
          success: false,
          error: data.error_description || 'Twitter token refresh failed'
        };
      }
    } catch (error: any) {
      return {
        success: false,
        error: error.message
      };
    }
  }

  async refreshToken(userId: number, platform: string, refreshToken: string): Promise<TokenRefreshResult> {
    if (!refreshToken) {
      return {
        success: false,
        error: 'No refresh token available'
      };
    }

    let result: TokenRefreshResult;

    switch (platform.toLowerCase()) {
      case 'facebook':
      case 'instagram': // Instagram uses Facebook tokens
        result = await this.refreshFacebookToken(refreshToken);
        break;
      case 'linkedin':
        result = await this.refreshLinkedInToken(refreshToken);
        break;
      case 'youtube':
        result = await this.refreshGoogleToken(refreshToken);
        break;
      case 'x':
      case 'twitter':
        result = await this.refreshTwitterToken(refreshToken);
        break;
      default:
        return {
          success: false,
          error: `Token refresh not implemented for platform: ${platform}`
        };
    }

    // Log the refresh attempt
    console.log(`🔄 Token refresh for ${platform}: ${result.success ? 'success' : 'failed'} - ${result.error || 'token updated'}`);

    return result;
  }

  async getValidToken(userId: number, platform: string): Promise<string | null> {
    try {
      // Get connection from database
      const [connection] = await db
        .select()
        .from(platformConnections)
        .where(and(
          eq(platformConnections.userId, userId),
          eq(platformConnections.platform, platform),
          eq(platformConnections.isActive, true)
        ));

      if (!connection) {
        console.log(`❌ No active connection found for ${platform}`);
        return null;
      }

      // Check if token is expired
      if (connection.expiresAt && new Date(connection.expiresAt) <= new Date(Date.now() + 300000)) { // 5 minutes buffer
        console.log(`🔄 Token expiring soon for ${platform}, attempting refresh...`);
        
        const refreshResult = await this.refreshToken(userId, platform, connection.refreshToken || '');
        
        if (refreshResult.success && refreshResult.accessToken) {
          // Update connection with new token
          await db
            .update(platformConnections)
            .set({
              accessToken: refreshResult.accessToken,
              refreshToken: refreshResult.refreshToken || connection.refreshToken,
              expiresAt: refreshResult.expiresAt ? new Date(refreshResult.expiresAt) : undefined
            })
            .where(and(
              eq(platformConnections.userId, userId),
              eq(platformConnections.platform, platform)
            ));

          return refreshResult.accessToken;
        } else {
          console.error(`❌ Failed to refresh token for ${platform}: ${refreshResult.error}`);
          return null;
        }
      }

      return connection.accessToken;
    } catch (error) {
      console.error(`❌ Error getting valid token for ${platform}:`, error);
      return null;
    }
  }

  async revokeToken(userId: number, platform: string): Promise<boolean> {
    try {
      const token = await this.getValidToken(userId, platform);
      if (!token) {
        return false;
      }

      let revokeUrl: string;
      let method = 'POST';
      let headers: Record<string, string> = {};
      let body: any;

      switch (platform.toLowerCase()) {
        case 'facebook':
        case 'instagram':
          revokeUrl = `https://graph.facebook.com/me/permissions?access_token=${token}`;
          method = 'DELETE';
          break;
        case 'linkedin':
          revokeUrl = 'https://www.linkedin.com/oauth/v2/revoke';
          headers['Content-Type'] = 'application/x-www-form-urlencoded';
          body = new URLSearchParams({
            token: token,
            client_id: process.env.LINKEDIN_CLIENT_ID || ''
          });
          break;
        case 'youtube':
          revokeUrl = `https://oauth2.googleapis.com/revoke?token=${token}`;
          break;
        case 'x':
        case 'twitter':
          revokeUrl = 'https://api.twitter.com/2/oauth2/revoke';
          headers['Content-Type'] = 'application/x-www-form-urlencoded';
          headers['Authorization'] = `Basic ${Buffer.from(`${process.env.TWITTER_CLIENT_ID}:${process.env.TWITTER_CLIENT_SECRET}`).toString('base64')}`;
          body = new URLSearchParams({ token });
          break;
        default:
          console.log(`⚠️ Token revocation not implemented for ${platform}`);
          return false;
      }

      const response = await fetch(revokeUrl, {
        method,
        headers,
        body
      });

      const success = response.ok;
      console.log(`🔄 Token revocation for ${platform}: ${success ? 'success' : 'failed'}`);

      // Mark connection as inactive regardless of revoke success
      await db
        .update(platformConnections)
        .set({ isActive: false })
        .where(and(
          eq(platformConnections.userId, userId),
          eq(platformConnections.platform, platform)
        ));

      return success;
    } catch (error) {
      console.error(`❌ Error revoking token for ${platform}:`, error);
      return false;
    }
  }
}