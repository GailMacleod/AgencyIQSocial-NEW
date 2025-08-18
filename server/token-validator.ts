import axios from 'axios';

export class TokenValidator {
  
  static async validateAllUserTokens(userId: number, connections: any[]): Promise<{
    [platform: string]: {
      valid: boolean;
      error?: string;
      needsReconnection: boolean;
      permissions?: string[];
    }
  }> {
    
    const results: any = {};
    
    for (const conn of connections) {
      try {
        switch (conn.platform) {
          case 'facebook':
            results.facebook = await this.validateFacebookToken(conn.accessToken);
            break;
          case 'linkedin':
            results.linkedin = await this.validateLinkedInToken(conn.accessToken);
            break;
          case 'x':
          case 'twitter':
            results.twitter = await this.validateTwitterToken(conn.accessToken);
            break;
          case 'instagram':
            results.instagram = await this.validateInstagramToken(conn.accessToken);
            break;
          default:
            results[conn.platform] = { valid: false, needsReconnection: true, error: 'Platform not supported' };
        }
      } catch (error: any) {
        results[conn.platform] = { 
          valid: false, 
          needsReconnection: true, 
          error: error.message 
        };
      }
    }
    
    return results;
  }

  private static async validateFacebookToken(accessToken: string): Promise<{
    valid: boolean; error?: string; needsReconnection: boolean; permissions?: string[];
  }> {
    
    try {
      // Check token validity and permissions
      const response = await axios.get(`https://graph.facebook.com/me/permissions?access_token=${accessToken}`);
      
      const permissions = response.data.data || [];
      const grantedPermissions = permissions
        .filter((p: any) => p.status === 'granted')
        .map((p: any) => p.permission);
      
      const requiredPermissions = ['pages_manage_posts', 'pages_read_engagement'];
      const hasRequiredPermissions = requiredPermissions.every(perm => 
        grantedPermissions.includes(perm)
      );
      
      if (!hasRequiredPermissions) {
        return {
          valid: false,
          needsReconnection: true,
          error: `Missing required permissions: ${requiredPermissions.filter(p => !grantedPermissions.includes(p)).join(', ')}`,
          permissions: grantedPermissions
        };
      }
      
      return {
        valid: true,
        needsReconnection: false,
        permissions: grantedPermissions
      };
      
    } catch (error: any) {
      return {
        valid: false,
        needsReconnection: true,
        error: error.response?.data?.error?.message || 'Token validation failed'
      };
    }
  }

  private static async validateLinkedInToken(accessToken: string): Promise<{
    valid: boolean; error?: string; needsReconnection: boolean;
  }> {
    
    try {
      const response = await axios.get('https://api.linkedin.com/v2/me', {
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'X-Restli-Protocol-Version': '2.0.0'
        }
      });
      
      if (response.status === 200 && response.data.id) {
        return { valid: true, needsReconnection: false };
      }
      
      return {
        valid: false,
        needsReconnection: true,
        error: 'LinkedIn token invalid or expired'
      };
      
    } catch (error: any) {
      return {
        valid: false,
        needsReconnection: true,
        error: error.response?.data?.message || 'LinkedIn token expired'
      };
    }
  }

  private static async validateTwitterToken(accessToken: string): Promise<{
    valid: boolean; error?: string; needsReconnection: boolean;
  }> {
    
    // Twitter OAuth 1.0a tokens are incompatible with current API v2
    if (accessToken.includes('twitter_token') || accessToken.length < 50) {
      return {
        valid: false,
        needsReconnection: true,
        error: 'OAuth 1.0a token incompatible with Twitter API v2'
      };
    }
    
    try {
      const response = await axios.get('https://api.twitter.com/2/users/me', {
        headers: {
          'Authorization': `Bearer ${accessToken}`
        }
      });
      
      if (response.status === 200 && response.data.data?.id) {
        return { valid: true, needsReconnection: false };
      }
      
      return {
        valid: false,
        needsReconnection: true,
        error: 'Twitter token invalid'
      };
      
    } catch (error: any) {
      return {
        valid: false,
        needsReconnection: true,
        error: 'Requires OAuth 2.0 upgrade'
      };
    }
  }

  private static async validateInstagramToken(accessToken: string): Promise<{
    valid: boolean; error?: string; needsReconnection: boolean;
  }> {
    
    // Demo tokens cannot post to real Instagram
    if (accessToken.includes('demo')) {
      return {
        valid: false,
        needsReconnection: true,
        error: 'Demo token cannot post to real Instagram accounts'
      };
    }
    
    return { valid: true, needsReconnection: false };
  }
}