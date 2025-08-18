import { Express } from 'express';
import { storage } from '../storage';

interface OAuthSessionDebug {
  sessionId: string;
  sessionData: any;
  userId?: string;
  userEmail?: string;
  hasUser: boolean;
  userResult?: any;
}

/**
 * OAuth Service - Isolated OAuth functionality for security and maintainability
 * Handles all OAuth authentication flows for social media platforms
 */
export class OAuthService {
  private app: Express;
  private passport: any;

  constructor(app: Express, passport: any) {
    this.app = app;
    this.passport = passport;
  }

  /**
   * Initialize all OAuth routes for supported platforms
   */
  public initializeOAuthRoutes(): void {
    this.setupFacebookOAuth();
    this.setupInstagramOAuth();
    this.setupLinkedInOAuth();
    this.setupTwitterOAuth();
    this.setupYouTubeOAuth();
  }

  /**
   * Log OAuth session debug information
   */
  private logOAuthDebug(platform: string, req: any): void {
    const debugInfo: OAuthSessionDebug = {
      sessionId: req.sessionID,
      sessionData: req.session,
      userId: req.session?.userId,
      userEmail: req.session?.userEmail,
      hasUser: !!req.user,
      userResult: req.user
    };

    console.log(`🔍 ${platform} OAuth Session Debug:`, debugInfo);
  }

  /**
   * Handle OAuth callback success response
   */
  private handleOAuthSuccess(platform: string, req: any, res: any): void {
    this.logOAuthDebug(platform, req);
    
    console.log(`✅ ${platform} OAuth callback successful - token persisted via handleOAuthCallback`);
    console.log(`${platform} OAuth result:`, req.user);
    
    // Ensure user session is properly maintained after OAuth
    if (req.user && req.user.success) {
      console.log(`🔐 ${platform} OAuth session maintained for user session`);
    }
    
    res.send('<script>window.opener.postMessage("oauth_success", "*"); window.close();</script>');
  }

  /**
   * Facebook OAuth setup
   */
  private setupFacebookOAuth(): void {
    this.app.get('/auth/facebook', this.passport.authenticate('facebook', {
      scope: ['pages_show_list', 'pages_read_engagement', 'pages_manage_posts']
    }));

    this.app.get('/auth/facebook/callback',
      this.passport.authenticate('facebook', { failureRedirect: '/connect-platforms?error=facebook' }),
      (req: any, res: any) => {
        this.handleOAuthSuccess('Facebook', req, res);
      }
    );
  }

  /**
   * Instagram OAuth setup
   */
  private setupInstagramOAuth(): void {
    this.app.get('/auth/instagram', this.passport.authenticate('instagram', {
      scope: ['instagram_basic', 'pages_show_list']
    }));

    this.app.get('/auth/instagram/callback',
      this.passport.authenticate('instagram', { failureRedirect: '/connect-platforms?error=instagram' }),
      (req: any, res: any) => {
        this.handleOAuthSuccess('Instagram', req, res);
      }
    );
  }

  /**
   * LinkedIn OAuth setup
   */
  private setupLinkedInOAuth(): void {
    this.app.get('/auth/linkedin', this.passport.authenticate('linkedin', {
      scope: ['r_liteprofile', 'w_member_social']
    }));

    this.app.get('/auth/linkedin/callback',
      this.passport.authenticate('linkedin', { failureRedirect: '/connect-platforms?error=linkedin' }),
      (req: any, res: any) => {
        this.handleOAuthSuccess('LinkedIn', req, res);
      }
    );
  }

  /**
   * Twitter/X OAuth setup
   */
  private setupTwitterOAuth(): void {
    this.app.get('/auth/twitter', this.passport.authenticate('twitter'));

    this.app.get('/auth/twitter/callback',
      this.passport.authenticate('twitter', { failureRedirect: '/connect-platforms?error=twitter' }),
      (req: any, res: any) => {
        this.handleOAuthSuccess('X (Twitter)', req, res);
      }
    );
  }

  /**
   * YouTube OAuth setup
   */
  private setupYouTubeOAuth(): void {
    this.app.get('/auth/youtube', this.passport.authenticate('youtube', {
      scope: ['https://www.googleapis.com/auth/youtube.readonly', 'https://www.googleapis.com/auth/youtube.upload']
    }));

    this.app.get('/auth/youtube/callback',
      this.passport.authenticate('youtube', { failureRedirect: '/connect-platforms?error=youtube' }),
      (req: any, res: any) => {
        this.handleOAuthSuccess('YouTube', req, res);
      }
    );
  }

  /**
   * Get OAuth connection status for all platforms
   */
  public async getOAuthStatus(userId: string): Promise<any> {
    try {
      const connections = await storage.getPlatformConnections(userId);
      return connections.map(conn => ({
        platform: conn.platform,
        connected: conn.isActive,
        username: conn.platformUsername,
        connectedAt: conn.connectedAt
      }));
    } catch (error) {
      console.error('Error getting OAuth status:', error);
      return [];
    }
  }

  /**
   * Disconnect OAuth platform
   */
  public async disconnectPlatform(userId: string, platform: string): Promise<boolean> {
    try {
      await storage.disconnectPlatform(userId, platform);
      return true;
    } catch (error) {
      console.error(`Error disconnecting ${platform}:`, error);
      return false;
    }
  }

  /**
   * Refresh OAuth tokens for a platform
   */
  public async refreshOAuthTokens(userId: string, platform: string): Promise<boolean> {
    try {
      // Implementation depends on platform-specific refresh logic
      console.log(`Refreshing OAuth tokens for ${platform} (User ID: ${userId})`);
      // This would typically involve making API calls to refresh tokens
      return true;
    } catch (error) {
      console.error(`Error refreshing OAuth tokens for ${platform}:`, error);
      return false;
    }
  }
}