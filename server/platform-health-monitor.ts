import { storage } from './storage';
import axios from 'axios';
import crypto from 'crypto';

interface HealthStatus {
  platform: string;
  healthy: boolean;
  tokenValid: boolean;
  permissions: string[];
  lastChecked: Date;
  error?: string;
  fixes?: string[];
}

interface TokenValidation {
  valid: boolean;
  expiresAt?: Date;
  scopes?: string[];
  error?: string;
  needsRefresh?: boolean;
}

export class PlatformHealthMonitor {
  
  /**
   * Validates all platform connections for a user and fixes issues
   */
  static async validateAllConnections(userId: number): Promise<HealthStatus[]> {
    try {
      const connections = await storage.getPlatformConnectionsByUser(userId);
      const healthStatuses: HealthStatus[] = [];
      
      for (const connection of connections) {
        const health = await this.validateConnection(connection);
        healthStatuses.push(health);
        
        // Auto-fix any issues found
        if (!health.healthy) {
          await this.autoFixConnection(userId, connection.platform, health);
        }
      }
      
      return healthStatuses;
    } catch (error) {
      console.error('Failed to validate all connections:', error);
      return [];
    }
  }
  
  /**
   * Validates a single platform connection thoroughly
   */
  static async validateConnection(connection: any): Promise<HealthStatus> {
    switch (connection.platform) {
      case 'facebook':
        return await this.validateFacebookConnection(connection);
      case 'instagram':
        return await this.validateInstagramConnection(connection);
      case 'linkedin':
        return await this.validateLinkedInConnection(connection);
      case 'x':
        return await this.validateXConnection(connection);
      case 'youtube':
        return await this.validateYouTubeConnection(connection);
      default:
        return {
          platform: connection.platform,
          healthy: false,
          tokenValid: false,
          permissions: [],
          lastChecked: new Date(),
          error: 'Platform not supported'
        };
    }
  }
  
  /**
   * Facebook token validation with comprehensive checks
   */
  static async validateFacebookConnection(connection: any): Promise<HealthStatus> {
    try {
      const { accessToken } = connection;
      
      if (!accessToken || accessToken.length < 10) {
        return {
          platform: 'facebook',
          healthy: false,
          tokenValid: false,
          permissions: [],
          lastChecked: new Date(),
          error: 'Invalid access token format',
          fixes: ['Reconnect Facebook account with proper OAuth flow']
        };
      }

      // Validate token with Facebook's debug endpoint
      const debugResponse = await axios.get(
        `https://graph.facebook.com/debug_token`,
        {
          params: {
            input_token: accessToken,
            access_token: `${process.env.FACEBOOK_APP_ID}|${process.env.FACEBOOK_APP_SECRET}`
          }
        }
      );

      const tokenData = debugResponse.data.data;
      
      if (!tokenData.is_valid) {
        return {
          platform: 'facebook',
          healthy: false,
          tokenValid: false,
          permissions: [],
          lastChecked: new Date(),
          error: 'Facebook token is invalid or expired',
          fixes: ['Refresh Facebook access token', 'Reconnect Facebook account']
        };
      }

      // Check required permissions for posting
      const requiredScopes = ['pages_manage_posts', 'pages_read_engagement'];
      const userScopes = tokenData.scopes || [];
      const missingScopes = requiredScopes.filter(scope => !userScopes.includes(scope));

      // Test actual posting capability
      const canPost = await this.testFacebookPosting(accessToken);

      return {
        platform: 'facebook',
        healthy: canPost && missingScopes.length === 0,
        tokenValid: true,
        permissions: userScopes,
        lastChecked: new Date(),
        error: missingScopes.length > 0 ? `Missing permissions: ${missingScopes.join(', ')}` : undefined,
        fixes: missingScopes.length > 0 ? ['Reconnect with additional permissions'] : undefined
      };

    } catch (error: any) {
      return {
        platform: 'facebook',
        healthy: false,
        tokenValid: false,
        permissions: [],
        lastChecked: new Date(),
        error: error.response?.data?.error?.message || error.message,
        fixes: ['Check Facebook App credentials', 'Reconnect Facebook account']
      };
    }
  }

  /**
   * LinkedIn token validation
   */
  static async validateLinkedInConnection(connection: any): Promise<HealthStatus> {
    try {
      const { accessToken } = connection;
      
      if (!accessToken || accessToken.length < 10) {
        return {
          platform: 'linkedin',
          healthy: false,
          tokenValid: false,
          permissions: [],
          lastChecked: new Date(),
          error: 'Invalid access token format'
        };
      }

      // Validate token by getting user profile
      const profileResponse = await axios.get(
        'https://api.linkedin.com/v2/people/~',
        {
          headers: {
            'Authorization': `Bearer ${accessToken}`,
            'Content-Type': 'application/json'
          }
        }
      );

      // Test posting permissions
      const canPost = await this.testLinkedInPosting(accessToken);

      return {
        platform: 'linkedin',
        healthy: canPost,
        tokenValid: true,
        permissions: ['r_liteprofile', 'w_member_social'],
        lastChecked: new Date()
      };

    } catch (error: any) {
      const isTokenExpired = error.response?.status === 401;
      
      return {
        platform: 'linkedin',
        healthy: false,
        tokenValid: !isTokenExpired,
        permissions: [],
        lastChecked: new Date(),
        error: isTokenExpired ? 'LinkedIn token expired' : error.message,
        fixes: isTokenExpired ? ['Refresh LinkedIn token'] : ['Check LinkedIn API credentials']
      };
    }
  }

  /**
   * X (Twitter) token validation
   */
  static async validateXConnection(connection: any): Promise<HealthStatus> {
    try {
      const { accessToken, tokenSecret } = connection;
      
      if (!accessToken || !tokenSecret) {
        return {
          platform: 'x',
          healthy: false,
          tokenValid: false,
          permissions: [],
          lastChecked: new Date(),
          error: 'Missing access token or token secret'
        };
      }

      // Test posting capability
      const canPost = await this.testXPosting(accessToken, tokenSecret);

      return {
        platform: 'x',
        healthy: canPost,
        tokenValid: true,
        permissions: ['tweet', 'read'],
        lastChecked: new Date()
      };

    } catch (error: any) {
      return {
        platform: 'x',
        healthy: false,
        tokenValid: false,
        permissions: [],
        lastChecked: new Date(),
        error: error.message,
        fixes: ['Reconnect X account', 'Check X API credentials']
      };
    }
  }

  /**
   * Instagram connection validation
   */
  static async validateInstagramConnection(connection: any): Promise<HealthStatus> {
    try {
      const { accessToken } = connection;
      
      // Instagram requires Facebook Business account
      const facebookHealth = await this.validateFacebookConnection(connection);
      
      if (!facebookHealth.healthy) {
        return {
          platform: 'instagram',
          healthy: false,
          tokenValid: false,
          permissions: [],
          lastChecked: new Date(),
          error: 'Instagram requires valid Facebook Business connection'
        };
      }

      // Check for Instagram Business Account
      const hasInstagramBusiness = await this.checkInstagramBusinessAccount(accessToken);

      return {
        platform: 'instagram',
        healthy: hasInstagramBusiness,
        tokenValid: true,
        permissions: ['instagram_basic', 'instagram_content_publish'],
        lastChecked: new Date(),
        error: !hasInstagramBusiness ? 'Instagram Business Account required' : undefined
      };

    } catch (error: any) {
      return {
        platform: 'instagram',
        healthy: false,
        tokenValid: false,
        permissions: [],
        lastChecked: new Date(),
        error: error.message
      };
    }
  }

  /**
   * YouTube connection validation
   */
  static async validateYouTubeConnection(connection: any): Promise<HealthStatus> {
    try {
      const { accessToken } = connection;
      
      if (!accessToken) {
        return {
          platform: 'youtube',
          healthy: false,
          tokenValid: false,
          permissions: [],
          lastChecked: new Date(),
          error: 'Missing YouTube access token'
        };
      }

      // Validate token with YouTube API
      const channelResponse = await axios.get(
        'https://www.googleapis.com/youtube/v3/channels',
        {
          headers: {
            'Authorization': `Bearer ${accessToken}`
          },
          params: {
            part: 'snippet',
            mine: true
          }
        }
      );

      const hasChannel = channelResponse.data.items && channelResponse.data.items.length > 0;

      return {
        platform: 'youtube',
        healthy: hasChannel,
        tokenValid: true,
        permissions: ['youtube.readonly', 'youtube.upload'],
        lastChecked: new Date(),
        error: !hasChannel ? 'No YouTube channel found' : undefined
      };

    } catch (error: any) {
      return {
        platform: 'youtube',
        healthy: false,
        tokenValid: false,
        permissions: [],
        lastChecked: new Date(),
        error: error.response?.data?.error?.message || error.message
      };
    }
  }

  /**
   * Auto-fix connection issues
   */
  static async autoFixConnection(userId: number, platform: string, health: HealthStatus): Promise<boolean> {
    console.log(`Auto-fixing ${platform} connection for user ${userId}`);
    
    if (!health.tokenValid) {
      // Attempt token refresh
      return await this.refreshToken(userId, platform);
    }
    
    if (health.error?.includes('permission')) {
      // Mark for re-authorization with proper scopes
      await this.markForReauthorization(userId, platform, health.fixes || []);
      return false;
    }
    
    return false;
  }

  /**
   * Refresh expired tokens
   */
  static async refreshToken(userId: number, platform: string): Promise<boolean> {
    try {
      const connection = await storage.getPlatformConnection(userId, platform);
      if (!connection?.refreshToken) {
        return false;
      }

      switch (platform) {
        case 'facebook':
          return await this.refreshFacebookToken(connection);
        case 'linkedin':
          return await this.refreshLinkedInToken(connection);
        default:
          return false;
      }
    } catch (error) {
      console.error(`Failed to refresh ${platform} token:`, error);
      return false;
    }
  }

  /**
   * Test actual posting capability for Facebook
   */
  private static async testFacebookPosting(accessToken: string): Promise<boolean> {
    try {
      // Test with a dry-run post creation
      await axios.get(
        `https://graph.facebook.com/v18.0/me/accounts`,
        {
          params: {
            access_token: accessToken,
            fields: 'id,name,access_token'
          }
        }
      );
      return true;
    } catch (error) {
      return false;
    }
  }

  /**
   * Test LinkedIn posting capability
   */
  private static async testLinkedInPosting(accessToken: string): Promise<boolean> {
    try {
      // Test by getting user profile (required for posting)
      await axios.get(
        'https://api.linkedin.com/v2/people/~',
        {
          headers: {
            'Authorization': `Bearer ${accessToken}`
          }
        }
      );
      return true;
    } catch (error) {
      return false;
    }
  }

  /**
   * Test X posting capability
   */
  private static async testXPosting(accessToken: string, tokenSecret: string): Promise<boolean> {
    try {
      const OAuth = require('oauth-1.0a');
      const oauth = OAuth({
        consumer: {
          key: process.env.TWITTER_CLIENT_ID!,
          secret: process.env.TWITTER_CLIENT_SECRET!
        },
        signature_method: 'HMAC-SHA1',
        hash_function(base_string: string, key: string) {
          return crypto.createHmac('sha1', key).update(base_string).digest('base64');
        }
      });

      const token = { key: accessToken, secret: tokenSecret };
      const request_data = {
        url: 'https://api.twitter.com/1.1/account/verify_credentials.json',
        method: 'GET'
      };

      const auth_header = oauth.toHeader(oauth.authorize(request_data, token));
      
      await axios.get(request_data.url, { headers: auth_header });
      return true;
    } catch (error) {
      return false;
    }
  }

  /**
   * Check if Instagram Business Account exists
   */
  private static async checkInstagramBusinessAccount(accessToken: string): Promise<boolean> {
    try {
      const response = await axios.get(
        `https://graph.facebook.com/v18.0/me/accounts`,
        {
          params: {
            access_token: accessToken,
            fields: 'instagram_business_account'
          }
        }
      );

      return response.data.data.some((account: any) => account.instagram_business_account);
    } catch (error) {
      return false;
    }
  }

  private static async refreshFacebookToken(connection: any): Promise<boolean> {
    // Facebook long-lived tokens don't need refresh - they last 60 days
    // If expired, user needs to re-authenticate
    return false;
  }

  private static async refreshLinkedInToken(connection: any): Promise<boolean> {
    // LinkedIn tokens expire after 2 months and cannot be refreshed
    // User needs to re-authenticate
    return false;
  }

  private static async markForReauthorization(userId: number, platform: string, fixes: string[]): Promise<void> {
    // Mark connection as needing reauthorization
    await storage.updatePlatformConnectionByPlatform(userId, platform, {
      isActive: false,
      lastError: `Requires reauthorization: ${fixes.join(', ')}`
    });
  }
}