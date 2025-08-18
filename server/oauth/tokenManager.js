/**
 * OAuth Token Manager with PostgreSQL Storage and Refresh Logic
 * Handles token storage, validation, and automatic refresh for all platforms
 */

import axios from 'axios';
import { db } from '../db.js';
import { oauthTokens } from '@shared/schema';
import { eq, and } from 'drizzle-orm';

class OAuthTokenManager {
  constructor() {
    this.refreshEndpoints = {
      facebook: 'https://graph.facebook.com/v18.0/oauth/access_token',
      google: 'https://oauth2.googleapis.com/token',
      linkedin: 'https://www.linkedin.com/oauth/v2/accessToken',
      // Twitter OAuth 1.1 doesn't use refresh tokens
    };
  }

  /**
   * Store OAuth tokens in PostgreSQL database
   */
  async storeTokens({
    userId,
    platform,
    accessToken,
    refreshToken,
    expiresIn = 3600,
    scopes = [],
    platformUserId,
    platformUsername
  }) {
    try {
      console.log(`💾 Storing OAuth tokens for user ${userId}, platform ${platform}`);

      const expiresAt = new Date();
      expiresAt.setSeconds(expiresAt.getSeconds() + expiresIn);

      // Check if token already exists
      const [existingToken] = await db
        .select()
        .from(oauthTokens)
        .where(and(
          eq(oauthTokens.userId, userId),
          eq(oauthTokens.provider, platform)
        ));

      const tokenData = {
        userId,
        provider: platform,
        accessToken,
        refreshToken,
        expiresAt,
        scope: scopes,
        profileId: platformUserId
      };

      if (existingToken) {
        console.log(`🔄 Updating existing ${platform} token for user ${userId}`);
        await db
          .update(oauthTokens)
          .set({
            ...tokenData,
            updatedAt: new Date()
          })
          .where(eq(oauthTokens.id, existingToken.id));
      } else {
        console.log(`➕ Creating new ${platform} token for user ${userId}`);
        await db
          .insert(oauthTokens)
          .values(tokenData);
      }

      console.log(`✅ OAuth tokens stored successfully for ${platform}`);
      return tokenData;
    } catch (error) {
      console.error(`❌ Error storing OAuth tokens for ${platform}:`, error);
      throw error;
    }
  }

  /**
   * Get valid access token (refresh if necessary)
   */
  async getValidToken(userId, platform) {
    try {
      console.log(`🔍 Getting valid token for user ${userId}, platform ${platform}`);

      const [tokenRecord] = await db
        .select()
        .from(oauthTokens)
        .where(and(
          eq(oauthTokens.userId, userId),
          eq(oauthTokens.provider, platform)
        ));

      if (!tokenRecord) {
        throw new Error(`No OAuth token found for platform ${platform}`);
      }

      // Check if token is expired (with 5 minute buffer)
      const now = new Date();
      const expiryBuffer = new Date(tokenRecord.expiresAt);
      expiryBuffer.setMinutes(expiryBuffer.getMinutes() - 5);

      if (now > expiryBuffer && tokenRecord.refreshToken) {
        console.log(`🔄 Token expired, refreshing for ${platform}`);
        return await this.refreshToken(userId, platform, tokenRecord);
      }

      console.log(`✅ Valid token found for ${platform}`);
      return {
        accessToken: tokenRecord.accessToken,
        platform,
        expiresAt: tokenRecord.expiresAt,
        scopes: tokenRecord.scope
      };
    } catch (error) {
      console.error(`❌ Error getting valid token for ${platform}:`, error);
      throw error;
    }
  }

  /**
   * Refresh expired OAuth token
   */
  async refreshToken(userId, platform, tokenRecord) {
    try {
      console.log(`🔄 Refreshing OAuth token for ${platform}`);

      if (!tokenRecord.refreshToken) {
        throw new Error(`No refresh token available for ${platform}`);
      }

      let refreshResponse;

      switch (platform) {
        case 'facebook':
          refreshResponse = await this.refreshFacebookToken(tokenRecord);
          break;
        case 'google':
        case 'youtube':
          refreshResponse = await this.refreshGoogleToken(tokenRecord);
          break;
        case 'linkedin':
          refreshResponse = await this.refreshLinkedInToken(tokenRecord);
          break;
        default:
          throw new Error(`Token refresh not supported for platform: ${platform}`);
      }

      // Update token in database
      const expiresAt = new Date();
      expiresAt.setSeconds(expiresAt.getSeconds() + (refreshResponse.expires_in || 3600));

      await db
        .update(oauthTokens)
        .set({
          accessToken: refreshResponse.access_token,
          refreshToken: refreshResponse.refresh_token || tokenRecord.refreshToken,
          expiresAt,
          updatedAt: new Date()
        })
        .where(eq(oauthTokens.id, tokenRecord.id));

      console.log(`✅ Token refreshed successfully for ${platform}`);
      return {
        accessToken: refreshResponse.access_token,
        platform,
        expiresAt,
        scopes: tokenRecord.scope
      };
    } catch (error) {
      console.error(`❌ Error refreshing token for ${platform}:`, error);
      throw error;
    }
  }

  /**
   * Refresh Facebook token
   */
  async refreshFacebookToken(tokenRecord) {
    const response = await axios.post(this.refreshEndpoints.facebook, {
      grant_type: 'fb_exchange_token',
      client_id: process.env.FACEBOOK_APP_ID,
      client_secret: process.env.FACEBOOK_APP_SECRET,
      fb_exchange_token: tokenRecord.accessToken
    });
    return response.data;
  }

  /**
   * Refresh Google/YouTube token
   */
  async refreshGoogleToken(tokenRecord) {
    const response = await axios.post(this.refreshEndpoints.google, {
      grant_type: 'refresh_token',
      client_id: process.env.GOOGLE_CLIENT_ID,
      client_secret: process.env.GOOGLE_CLIENT_SECRET,
      refresh_token: tokenRecord.refreshToken
    });
    return response.data;
  }

  /**
   * Refresh LinkedIn token
   */
  async refreshLinkedInToken(tokenRecord) {
    const response = await axios.post(this.refreshEndpoints.linkedin, {
      grant_type: 'refresh_token',
      refresh_token: tokenRecord.refreshToken,
      client_id: process.env.LINKEDIN_CLIENT_ID,
      client_secret: process.env.LINKEDIN_CLIENT_SECRET
    });
    return response.data;
  }

  /**
   * Revoke OAuth token (logout)
   */
  async revokeToken(userId, platform) {
    try {
      console.log(`🗑️ Revoking OAuth token for user ${userId}, platform ${platform}`);

      const [tokenRecord] = await db
        .select()
        .from(oauthTokens)
        .where(and(
          eq(oauthTokens.userId, userId),
          eq(oauthTokens.provider, platform)
        ));

      if (!tokenRecord) {
        console.log(`⚠️ No token found to revoke for ${platform}`);
        return;
      }

      // Revoke at provider level
      try {
        switch (platform) {
          case 'facebook':
            await axios.delete(`https://graph.facebook.com/v18.0/${tokenRecord.profileId}/permissions`, {
              params: { access_token: tokenRecord.accessToken }
            });
            break;
          case 'google':
          case 'youtube':
            await axios.post(`https://oauth2.googleapis.com/revoke`, {
              token: tokenRecord.accessToken
            });
            break;
          case 'linkedin':
            await axios.post(`https://www.linkedin.com/oauth/v2/revoke`, {
              token: tokenRecord.accessToken,
              client_id: process.env.LINKEDIN_CLIENT_ID,
              client_secret: process.env.LINKEDIN_CLIENT_SECRET
            });
            break;
        }
      } catch (revokeError) {
        console.warn(`⚠️ Provider revocation failed for ${platform}, continuing with database cleanup:`, revokeError.message);
      }

      // Remove from database
      await db
        .delete(oauthTokens)
        .where(eq(oauthTokens.id, tokenRecord.id));

      console.log(`✅ OAuth token revoked successfully for ${platform}`);
    } catch (error) {
      console.error(`❌ Error revoking token for ${platform}:`, error);
      throw error;
    }
  }

  /**
   * Check token validity with scope verification
   */
  async validateTokenScopes(userId, platform, requiredScopes = []) {
    try {
      const tokenData = await this.getValidToken(userId, platform);
      
      if (requiredScopes.length === 0) {
        return { valid: true, scopes: tokenData.scopes };
      }

      const hasAllScopes = requiredScopes.every(scope => 
        tokenData.scopes && tokenData.scopes.includes(scope)
      );

      if (!hasAllScopes) {
        const missingScopes = requiredScopes.filter(scope => 
          !tokenData.scopes || !tokenData.scopes.includes(scope)
        );
        
        return {
          valid: false,
          missingScopes,
          currentScopes: tokenData.scopes
        };
      }

      return { valid: true, scopes: tokenData.scopes };
    } catch (error) {
      return { valid: false, error: error.message };
    }
  }
}

export default OAuthTokenManager;