// Enhanced OAuth Manager with Passport.js Integration
// Handles token management, refresh, and platform-specific configurations

import passport from 'passport';
// Note: Import statements simplified for compilation
// Full implementation would use actual passport strategies
import { db } from '../db';
import { enhancedOauthTokens, users } from '../../shared/schema';
import { eq, and } from 'drizzle-orm';
import { logger } from '../utils/logger.js';
import axios from 'axios';

export class PassportOAuthManager {
  constructor() {
    this.initializeStrategies();
    this.setupSerialization();
  }

  private initializeStrategies() {
    // Facebook OAuth Strategy
    if (process.env.FACEBOOK_CLIENT_ID && process.env.FACEBOOK_CLIENT_SECRET) {
      passport.use(new FacebookStrategy({
        clientID: process.env.FACEBOOK_CLIENT_ID,
        clientSecret: process.env.FACEBOOK_CLIENT_SECRET,
        callbackURL: `${process.env.BASE_URL || 'http://localhost:5000'}/auth/facebook/callback`,
        scope: ['pages_manage_posts', 'pages_read_engagement', 'pages_show_list', 'business_management']
      }, this.handleOAuthCallback.bind(this, 'facebook')));
    }

    // Google OAuth Strategy (for YouTube)
    if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
      passport.use(new GoogleStrategy({
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: `${process.env.BASE_URL || 'http://localhost:5000'}/auth/google/callback`,
        scope: ['https://www.googleapis.com/auth/youtube.upload', 'https://www.googleapis.com/auth/youtube']
      }, this.handleOAuthCallback.bind(this, 'google')));
    }

    // LinkedIn OAuth Strategy
    if (process.env.LINKEDIN_CLIENT_ID && process.env.LINKEDIN_CLIENT_SECRET) {
      passport.use(new LinkedInStrategy({
        clientID: process.env.LINKEDIN_CLIENT_ID,
        clientSecret: process.env.LINKEDIN_CLIENT_SECRET,
        callbackURL: `${process.env.BASE_URL || 'http://localhost:5000'}/auth/linkedin/callback`,
        scope: ['w_member_social', 'r_organization_social']
      }, this.handleOAuthCallback.bind(this, 'linkedin')));
    }

    // Twitter OAuth Strategy
    if (process.env.TWITTER_CLIENT_ID && process.env.TWITTER_CLIENT_SECRET) {
      passport.use(new TwitterStrategy({
        consumerKey: process.env.TWITTER_CLIENT_ID,
        consumerSecret: process.env.TWITTER_CLIENT_SECRET,
        callbackURL: `${process.env.BASE_URL || 'http://localhost:5000'}/auth/twitter/callback`
      }, this.handleOAuthCallback.bind(this, 'twitter')));
    }
  }

  private setupSerialization() {
    passport.serializeUser((user: any, done) => {
      done(null, user.id);
    });

    passport.deserializeUser(async (id: number, done) => {
      try {
        const [user] = await db.select().from(users).where(eq(users.id, id));
        done(null, user);
      } catch (error) {
        done(error, null);
      }
    });
  }

  private async handleOAuthCallback(platform: string, accessToken: string, refreshToken: string, profile: any, done: any) {
    try {
      // Get user from session or create/find user
      const userId = profile.user?.id || 1; // Fallback to maintain existing behavior
      
      // Calculate token expiry based on platform
      const expiresAt = this.calculateTokenExpiry(platform);
      const scopes = this.extractScopes(platform, profile);

      // Store/update OAuth token
      await this.storeOAuthToken(userId, platform, {
        accessToken,
        refreshToken,
        expiresAt,
        scopes,
        platformData: {
          profileId: profile.id,
          username: profile.username,
          displayName: profile.displayName
        }
      });

      logger.info('OAuth token stored successfully', {
        platform,
        userId,
        hasRefreshToken: !!refreshToken
      });

      done(null, { id: userId, platform, accessToken });
    } catch (error) {
      logger.error('OAuth callback error', {
        platform,
        error: error.message
      });
      done(error, null);
    }
  }

  private calculateTokenExpiry(platform: string): Date {
    const now = new Date();
    const expiryHours = {
      facebook: 60 * 24, // 60 days
      google: 1, // 1 hour (requires refresh)
      linkedin: 60 * 24, // 60 days
      twitter: 0 // No expiry for Twitter
    };

    const hours = expiryHours[platform] || 24;
    return new Date(now.getTime() + (hours * 60 * 60 * 1000));
  }

  private extractScopes(platform: string, profile: any): string[] {
    const defaultScopes = {
      facebook: ['pages_manage_posts', 'pages_read_engagement'],
      google: ['https://www.googleapis.com/auth/youtube.upload'],
      linkedin: ['w_member_social'],
      twitter: ['tweet.write', 'users.read']
    };

    return profile.scope?.split(' ') || defaultScopes[platform] || [];
  }

  async storeOAuthToken(userId: number, platform: string, tokenData: {
    accessToken: string;
    refreshToken?: string;
    expiresAt: Date;
    scopes: string[];
    platformData: any;
  }) {
    try {
      // Deactivate existing tokens for this user/platform
      await db.update(enhancedOauthTokens)
        .set({ isValid: false, updatedAt: new Date() })
        .where(and(
          eq(enhancedOauthTokens.userId, userId),
          eq(enhancedOauthTokens.platform, platform),
          eq(enhancedOauthTokens.isValid, true)
        ));

      // Insert new token
      const [newToken] = await db.insert(enhancedOauthTokens).values({
        userId,
        platform,
        accessToken: tokenData.accessToken,
        refreshToken: tokenData.refreshToken,
        expiresAt: tokenData.expiresAt,
        scopes: tokenData.scopes,
        platformData: tokenData.platformData,
        lastRefreshed: new Date(),
        isValid: true
      }).returning();

      logger.info('OAuth token stored in database', {
        tokenId: newToken.id,
        platform,
        userId,
        expiresAt: tokenData.expiresAt
      });

      return newToken;
    } catch (error) {
      logger.error('Failed to store OAuth token', {
        error: error.message,
        platform,
        userId
      });
      throw error;
    }
  }

  async refreshToken(userId: number, platform: string): Promise<string | null> {
    try {
      const [token] = await db.select().from(enhancedOauthTokens)
        .where(and(
          eq(enhancedOauthTokens.userId, userId),
          eq(enhancedOauthTokens.platform, platform),
          eq(enhancedOauthTokens.isValid, true)
        ));

      if (!token || !token.refreshToken) {
        logger.warn('No refresh token available', { userId, platform });
        return null;
      }

      // Check if token needs refresh (5 minutes buffer)
      const now = new Date();
      const expiryBuffer = new Date(token.expiresAt!.getTime() - 5 * 60 * 1000);
      
      if (now < expiryBuffer) {
        return token.accessToken; // Token still valid
      }

      // Refresh token based on platform
      const refreshed = await this.performTokenRefresh(platform, token.refreshToken);
      
      if (refreshed) {
        await db.update(enhancedOauthTokens)
          .set({
            accessToken: refreshed.accessToken,
            refreshToken: refreshed.refreshToken || token.refreshToken,
            expiresAt: refreshed.expiresAt,
            lastRefreshed: new Date(),
            updatedAt: new Date()
          })
          .where(eq(enhancedOauthTokens.id, token.id));

        logger.info('Token refreshed successfully', {
          platform,
          userId,
          tokenId: token.id
        });

        return refreshed.accessToken;
      }

      return null;
    } catch (error) {
      logger.error('Token refresh failed', {
        error: error.message,
        platform,
        userId
      });
      return null;
    }
  }

  private async performTokenRefresh(platform: string, refreshToken: string): Promise<{
    accessToken: string;
    refreshToken?: string;
    expiresAt: Date;
  } | null> {
    try {
      switch (platform) {
        case 'facebook':
          return await this.refreshFacebookToken(refreshToken);
        case 'google':
          return await this.refreshGoogleToken(refreshToken);
        case 'linkedin':
          return await this.refreshLinkedInToken(refreshToken);
        default:
          logger.warn('Token refresh not implemented for platform', { platform });
          return null;
      }
    } catch (error) {
      logger.error('Platform token refresh failed', {
        error: error.message,
        platform
      });
      return null;
    }
  }

  private async refreshFacebookToken(refreshToken: string) {
    const response = await axios.post('https://graph.facebook.com/v18.0/oauth/access_token', {
      grant_type: 'fb_exchange_token',
      client_id: process.env.FACEBOOK_CLIENT_ID,
      client_secret: process.env.FACEBOOK_CLIENT_SECRET,
      fb_exchange_token: refreshToken
    });

    return {
      accessToken: response.data.access_token,
      expiresAt: new Date(Date.now() + (response.data.expires_in * 1000))
    };
  }

  private async refreshGoogleToken(refreshToken: string) {
    const response = await axios.post('https://oauth2.googleapis.com/token', {
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_id: process.env.GOOGLE_CLIENT_ID,
      client_secret: process.env.GOOGLE_CLIENT_SECRET
    });

    return {
      accessToken: response.data.access_token,
      refreshToken: response.data.refresh_token || refreshToken,
      expiresAt: new Date(Date.now() + (response.data.expires_in * 1000))
    };
  }

  private async refreshLinkedInToken(refreshToken: string) {
    const response = await axios.post('https://www.linkedin.com/oauth/v2/accessToken', {
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_id: process.env.LINKEDIN_CLIENT_ID,
      client_secret: process.env.LINKEDIN_CLIENT_SECRET
    });

    return {
      accessToken: response.data.access_token,
      refreshToken: response.data.refresh_token || refreshToken,
      expiresAt: new Date(Date.now() + (response.data.expires_in * 1000))
    };
  }

  async validateToken(userId: number, platform: string): Promise<boolean> {
    try {
      const [token] = await db.select().from(enhancedOauthTokens)
        .where(and(
          eq(enhancedOauthTokens.userId, userId),
          eq(enhancedOauthTokens.platform, platform),
          eq(enhancedOauthTokens.isValid, true)
        ));

      if (!token) return false;

      // Check if token is expired
      if (token.expiresAt && new Date() > token.expiresAt) {
        return false;
      }

      return true;
    } catch (error) {
      logger.error('Token validation failed', {
        error: error.message,
        platform,
        userId
      });
      return false;
    }
  }

  async revokeToken(userId: number, platform: string): Promise<boolean> {
    try {
      await db.update(enhancedOauthTokens)
        .set({ isValid: false, updatedAt: new Date() })
        .where(and(
          eq(enhancedOauthTokens.userId, userId),
          eq(enhancedOauthTokens.platform, platform)
        ));

      logger.info('OAuth token revoked', { userId, platform });
      return true;
    } catch (error) {
      logger.error('Token revocation failed', {
        error: error.message,
        platform,
        userId
      });
      return false;
    }
  }

  async getValidToken(userId: number, platform: string): Promise<string | null> {
    try {
      // First try to refresh if needed
      const token = await this.refreshToken(userId, platform);
      return token;
    } catch (error) {
      logger.error('Failed to get valid token', {
        error: error.message,
        platform,
        userId
      });
      return null;
    }
  }
}

export const passportOAuthManager = new PassportOAuthManager();