import axios from 'axios';
import { storage } from './storage';
import crypto from 'crypto';

interface TokenRefreshResult {
  success: boolean;
  newAccessToken?: string;
  newRefreshToken?: string;
  expiresAt?: Date;
  error?: string;
}

export class OAuthRefreshService {
  
  static async refreshFacebookToken(refreshToken: string): Promise<TokenRefreshResult> {
    try {
      const response = await axios.get('https://graph.facebook.com/v18.0/oauth/access_token', {
        params: {
          grant_type: 'fb_exchange_token',
          client_id: process.env.FACEBOOK_APP_ID,
          client_secret: process.env.FACEBOOK_APP_SECRET,
          fb_exchange_token: refreshToken
        }
      });

      const { access_token, expires_in } = response.data;
      const expiresAt = new Date(Date.now() + (expires_in * 1000));

      return {
        success: true,
        newAccessToken: access_token,
        expiresAt
      };
    } catch (error: any) {
      console.error('Facebook token refresh error:', error.response?.data || error.message);
      return {
        success: false,
        error: error.response?.data?.error?.message || error.message
      };
    }
  }

  static async refreshLinkedInToken(refreshToken: string): Promise<TokenRefreshResult> {
    try {
      const response = await axios.post('https://www.linkedin.com/oauth/v2/accessToken', 
        new URLSearchParams({
          grant_type: 'refresh_token',
          refresh_token: refreshToken,
          client_id: process.env.LINKEDIN_CLIENT_ID!,
          client_secret: process.env.LINKEDIN_CLIENT_SECRET!
        }),
        {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
          }
        }
      );

      const { access_token, refresh_token, expires_in } = response.data;
      const expiresAt = new Date(Date.now() + (expires_in * 1000));

      return {
        success: true,
        newAccessToken: access_token,
        newRefreshToken: refresh_token,
        expiresAt
      };
    } catch (error: any) {
      console.error('LinkedIn token refresh error:', error.response?.data || error.message);
      return {
        success: false,
        error: error.response?.data?.error_description || error.message
      };
    }
  }

  static async validateAndRefreshConnection(connectionId: number): Promise<boolean> {
    try {
      // Get all users' connections and find the specific one
      const users = await storage.getAllUsers();
      let connection: any = null;
      
      for (const user of users) {
        const userConnections = await storage.getPlatformConnectionsByUser(user.id);
        const found = userConnections.find((c: any) => c.id === connectionId);
        if (found) {
          connection = found;
          break;
        }
      }
      
      if (!connection || !connection.isActive) {
        return false;
      }

      // Check if token is expired
      if (connection.expiresAt && new Date() >= connection.expiresAt) {
        console.log(`Token expired for ${connection.platform} connection ${connectionId}, attempting refresh...`);
        
        let refreshResult: TokenRefreshResult = { success: false };
        
        switch (connection.platform) {
          case 'facebook':
            if (connection.refreshToken) {
              refreshResult = await this.refreshFacebookToken(connection.refreshToken);
            }
            break;
          case 'linkedin':
            if (connection.refreshToken) {
              refreshResult = await this.refreshLinkedInToken(connection.refreshToken);
            }
            break;
          default:
            console.log(`Token refresh not implemented for ${connection.platform}`);
            return false;
        }

        if (refreshResult.success) {
          // Update connection with new tokens
          await storage.updatePlatformConnection(connectionId, {
            accessToken: refreshResult.newAccessToken!,
            refreshToken: refreshResult.newRefreshToken || connection.refreshToken,
            expiresAt: refreshResult.expiresAt
          });
          
          console.log(`Successfully refreshed ${connection.platform} token for connection ${connectionId}`);
          return true;
        } else {
          // Mark connection as inactive if refresh failed
          await storage.updatePlatformConnection(connectionId, {
            isActive: false
          });
          
          console.error(`Failed to refresh ${connection.platform} token: ${refreshResult.error}`);
          return false;
        }
      }

      return true; // Token is still valid
    } catch (error: any) {
      console.error('Token validation error:', error);
      return false;
    }
  }

  static async validateAllUserConnections(userId: number): Promise<{
    validConnections: string[];
    expiredConnections: string[];
    refreshedConnections: string[];
  }> {
    const connections = await storage.getPlatformConnectionsByUser(userId);
    const validConnections: string[] = [];
    const expiredConnections: string[] = [];
    const refreshedConnections: string[] = [];

    for (const connection of connections) {
      if (!connection.isActive) {
        expiredConnections.push(connection.platform);
        continue;
      }

      const isValid = await this.validateAndRefreshConnection(connection.id);
      
      if (isValid) {
        // Check if token was refreshed by comparing timestamps
        const updatedConnection = await storage.getPlatformConnectionsByUser(userId);
        const updated = updatedConnection.find(c => c.id === connection.id);
        
        if (updated && updated.accessToken !== connection.accessToken) {
          refreshedConnections.push(connection.platform);
        } else {
          validConnections.push(connection.platform);
        }
      } else {
        expiredConnections.push(connection.platform);
      }
    }

    return {
      validConnections,
      expiredConnections,
      refreshedConnections
    };
  }
}