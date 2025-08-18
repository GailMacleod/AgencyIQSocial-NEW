/**
 * LinkedIn Token Validator
 * Validates LinkedIn OAuth tokens using LinkedIn API
 */
import axios from 'axios';
import { storage } from './storage';

interface LinkedInTokenValidationResult {
  isValid: boolean;
  error?: string;
  userInfo?: any;
  expiresIn?: number;
}

export class LinkedInTokenValidator {
  
  /**
   * Validate LinkedIn token using LinkedIn API
   * Uses the API endpoint: https://api.linkedin.com/v1/people/~?oauth2_access_token=TOKEN
   * Success means live token; Error means expired token
   * Access tokens last 60 days
   */
  async validateToken(accessToken: string): Promise<LinkedInTokenValidationResult> {
    try {
      console.log('🔍 Validating LinkedIn token...');
      
      // Use LinkedIn API to validate token
      const response = await axios.get(`https://api.linkedin.com/v1/people/~?oauth2_access_token=${accessToken}`, {
        headers: {
          'Accept': 'application/json',
          'User-Agent': 'TheAgencyIQ/1.0'
        },
        timeout: 10000
      });
      
      console.log('✅ LinkedIn token is VALID');
      return {
        isValid: true,
        userInfo: response.data,
        expiresIn: 60 * 24 * 60 * 60 * 1000 // 60 days in milliseconds
      };
      
    } catch (error: any) {
      console.log('❌ LinkedIn token validation failed:', error.message);
      
      if (error.response?.status === 401) {
        return {
          isValid: false,
          error: 'Token expired or invalid'
        };
      }
      
      return {
        isValid: false,
        error: error.message || 'Token validation failed'
      };
    }
  }
  
  /**
   * Check and refresh LinkedIn connection token if needed
   */
  async checkAndRefreshLinkedInConnection(userId: number): Promise<boolean> {
    try {
      // Get user's LinkedIn connection
      const connections = await storage.getPlatformConnectionsByUser(userId);
      const linkedinConnection = connections.find(conn => conn.platform === 'linkedin');
      
      if (!linkedinConnection) {
        console.log('❌ No LinkedIn connection found for user:', userId);
        return false;
      }
      
      if (!linkedinConnection.accessToken) {
        console.log('❌ No access token found for LinkedIn connection');
        return false;
      }
      
      // Validate the token
      const validation = await this.validateToken(linkedinConnection.accessToken);
      
      if (validation.isValid) {
        console.log('✅ LinkedIn token is valid');
        return true;
      } else {
        console.log('❌ LinkedIn token is invalid:', validation.error);
        
        // Mark connection as inactive
        await storage.updatePlatformConnection(linkedinConnection.id, {
          isActive: false
        });
        
        return false;
      }
      
    } catch (error: any) {
      console.error('Error checking LinkedIn connection:', error);
      return false;
    }
  }
  
  /**
   * Get LinkedIn connection status for user
   */
  async getLinkedInConnectionStatus(userId: number): Promise<{
    connected: boolean;
    tokenValid: boolean;
    username?: string;
    error?: string;
  }> {
    try {
      const connections = await storage.getPlatformConnectionsByUser(userId);
      const linkedinConnection = connections.find(conn => conn.platform === 'linkedin');
      
      if (!linkedinConnection) {
        return {
          connected: false,
          tokenValid: false,
          error: 'No LinkedIn connection found'
        };
      }
      
      if (!linkedinConnection.accessToken) {
        return {
          connected: true,
          tokenValid: false,
          username: linkedinConnection.platformUsername,
          error: 'No access token found'
        };
      }
      
      // Validate token
      const validation = await this.validateToken(linkedinConnection.accessToken);
      
      return {
        connected: true,
        tokenValid: validation.isValid,
        username: linkedinConnection.platformUsername,
        error: validation.error
      };
      
    } catch (error: any) {
      return {
        connected: false,
        tokenValid: false,
        error: error.message
      };
    }
  }
}

export const linkedinTokenValidator = new LinkedInTokenValidator();