import axios from 'axios';
import crypto from 'crypto';

interface TokenValidationResult {
  platform: string;
  isValid: boolean;
  error?: string;
  scopes?: string[];
  expiresAt?: string;
  needsRefresh: boolean;
  requiredScopes?: string[];
}

export class OAuthStatusChecker {
  
  static async validateFacebookToken(accessToken: string): Promise<TokenValidationResult> {
    try {
      const appSecret = process.env.FACEBOOK_APP_SECRET;
      const appsecretProof = crypto.createHmac('sha256', appSecret!).update(accessToken).digest('hex');
      
      // Check token validity and get permissions
      const response = await axios.get(
        `https://graph.facebook.com/v18.0/me`,
        {
          params: {
            access_token: accessToken,
            appsecret_proof: appsecretProof,
            fields: 'id,name'
          }
        }
      );

      // Get token info including scopes
      const tokenInfo = await axios.get(
        `https://graph.facebook.com/v18.0/debug_token`,
        {
          params: {
            input_token: accessToken,
            access_token: `${process.env.FACEBOOK_APP_ID}|${process.env.FACEBOOK_APP_SECRET}`
          }
        }
      );

      const scopes = tokenInfo.data.data.scopes || [];
      const requiredScopes = ['pages_manage_posts', 'pages_read_engagement', 'public_profile'];
      const hasRequiredScopes = requiredScopes.every(scope => scopes.includes(scope));

      return {
        platform: 'facebook',
        isValid: true,
        scopes,
        expiresAt: tokenInfo.data.data.expires_at ? new Date(tokenInfo.data.data.expires_at * 1000).toISOString() : 'Never',
        needsRefresh: !hasRequiredScopes,
        requiredScopes
      };
    } catch (error: any) {
      return {
        platform: 'facebook',
        isValid: false,
        error: error.response?.data?.error?.message || error.message,
        needsRefresh: true,
        requiredScopes: ['pages_manage_posts', 'pages_read_engagement', 'public_profile']
      };
    }
  }

  static async validateInstagramToken(accessToken: string): Promise<TokenValidationResult> {
    try {
      // Check Instagram token validity
      const response = await axios.get(
        `https://graph.instagram.com/v18.0/me`,
        {
          params: {
            access_token: accessToken,
            fields: 'id,username'
          }
        }
      );

      return {
        platform: 'instagram',
        isValid: true,
        scopes: ['instagram_basic', 'instagram_content_publish'],
        needsRefresh: false,
        requiredScopes: ['instagram_basic', 'instagram_content_publish']
      };
    } catch (error: any) {
      return {
        platform: 'instagram',
        isValid: false,
        error: error.response?.data?.error?.message || error.message,
        needsRefresh: true,
        requiredScopes: ['instagram_basic', 'instagram_content_publish']
      };
    }
  }

  static async validateYouTubeToken(accessToken: string): Promise<TokenValidationResult> {
    try {
      // Check YouTube token validity
      const response = await axios.get(
        `https://www.googleapis.com/youtube/v3/channels`,
        {
          params: {
            access_token: accessToken,
            part: 'snippet',
            mine: true
          }
        }
      );

      return {
        platform: 'youtube',
        isValid: true,
        scopes: ['https://www.googleapis.com/auth/youtube.upload'],
        needsRefresh: false,
        requiredScopes: ['https://www.googleapis.com/auth/youtube.upload']
      };
    } catch (error: any) {
      return {
        platform: 'youtube',
        isValid: false,
        error: error.response?.data?.error?.message || error.message,
        needsRefresh: true,
        requiredScopes: ['https://www.googleapis.com/auth/youtube.upload']
      };
    }
  }

  static async validateXToken(accessToken: string, tokenSecret?: string): Promise<TokenValidationResult> {
    if (!process.env.X_CONSUMER_KEY || !process.env.X_CONSUMER_SECRET) {
      return {
        platform: 'x',
        isValid: false,
        error: 'X API credentials not configured',
        needsRefresh: true,
        requiredScopes: ['tweet.write', 'users.read']
      };
    }

    try {
      // For OAuth 2.0 Bearer token
      if (!tokenSecret) {
        const response = await axios.get(
          `https://api.twitter.com/2/users/me`,
          {
            headers: {
              'Authorization': `Bearer ${accessToken}`
            }
          }
        );

        return {
          platform: 'x',
          isValid: true,
          scopes: ['tweet.write', 'users.read'],
          needsRefresh: false,
          requiredScopes: ['tweet.write', 'users.read']
        };
      }

      // For OAuth 1.0a (legacy)
      return {
        platform: 'x',
        isValid: false,
        error: 'OAuth 1.0a tokens need migration to OAuth 2.0',
        needsRefresh: true,
        requiredScopes: ['tweet.write', 'users.read']
      };
    } catch (error: any) {
      return {
        platform: 'x',
        isValid: false,
        error: error.response?.data?.detail || error.message,
        needsRefresh: true,
        requiredScopes: ['tweet.write', 'users.read']
      };
    }
  }

  static async validateLinkedInToken(accessToken: string): Promise<TokenValidationResult> {
    try {
      // Check LinkedIn token validity
      const response = await axios.get(
        `https://api.linkedin.com/v2/me`,
        {
          headers: {
            'Authorization': `Bearer ${accessToken}`
          }
        }
      );

      return {
        platform: 'linkedin',
        isValid: true,
        scopes: ['w_member_social', 'r_liteprofile'],
        needsRefresh: false,
        requiredScopes: ['w_member_social', 'r_liteprofile']
      };
    } catch (error: any) {
      return {
        platform: 'linkedin',
        isValid: false,
        error: error.response?.data?.message || error.message,
        needsRefresh: true,
        requiredScopes: ['w_member_social', 'r_liteprofile']
      };
    }
  }

  static async validateAllUserTokens(userId: number): Promise<TokenValidationResult[]> {
    const { storage } = await import('./storage');
    const connections = await storage.getPlatformConnectionsByUser(userId);
    const results: TokenValidationResult[] = [];

    for (const connection of connections) {
      let result: TokenValidationResult;

      switch (connection.platform) {
        case 'facebook':
          result = await this.validateFacebookToken(connection.accessToken);
          break;
        case 'instagram':
          result = await this.validateInstagramToken(connection.accessToken);
          break;
        case 'youtube':
          result = await this.validateYouTubeToken(connection.accessToken);
          break;
        case 'x':
          result = await this.validateXToken(connection.accessToken, connection.refreshToken);
          break;
        case 'linkedin':
          result = await this.validateLinkedInToken(connection.accessToken);
          break;
        default:
          result = {
            platform: connection.platform,
            isValid: false,
            error: 'Unknown platform',
            needsRefresh: true,
            requiredScopes: []
          };
      }

      results.push(result);
    }

    return results;
  }
}