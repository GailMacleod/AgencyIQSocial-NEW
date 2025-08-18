/**
 * CRITICAL FIX: OAuth Route Consolidation - HIGH SEVERITY  
 * 
 * Problem: Multiple /callback routes causing inconsistent flows and token leaks
 * Solution: Single consolidated callback with platform switching and S256 PKCE
 */

import { Request, Response } from 'express';
import crypto from 'crypto';
import { db } from '../db';
import { eq } from 'drizzle-orm';
import { platformConnections, users } from '../../shared/schema';

interface OAuthState {
  platform: string;
  timestamp: number;
  userId: number;
  codeVerifier?: string;
}

export class OAuthConsolidationManager {
  private static instance: OAuthConsolidationManager;
  private codeVerifiers: Map<string, string> = new Map();

  public static getInstance(): OAuthConsolidationManager {
    if (!OAuthConsolidationManager.instance) {
      OAuthConsolidationManager.instance = new OAuthConsolidationManager();
    }
    return OAuthConsolidationManager.instance;
  }

  /**
   * CRITICAL: Generate S256 PKCE challenge (2025 OWASP requirement)
   */
  public generatePKCEChallenge(): { codeVerifier: string; codeChallenge: string } {
    const codeVerifier = crypto.randomBytes(32).toString('base64url');
    const codeChallenge = crypto
      .createHash('sha256')
      .update(codeVerifier)
      .digest('base64url');

    return { codeVerifier, codeChallenge };
  }

  /**
   * CRITICAL: Consolidated OAuth initiation with S256 PKCE
   */
  public initiateOAuth(platform: string, userId: number, baseUrl: string): string {
    const { codeVerifier, codeChallenge } = this.generatePKCEChallenge();
    
    const state = Buffer.from(JSON.stringify({
      platform,
      timestamp: Date.now(),
      userId,
      codeVerifier // Store for callback verification
    })).toString('base64');

    // Store code verifier for callback
    this.codeVerifiers.set(state, codeVerifier);

    const callbackUri = `${baseUrl}/auth/callback`;
    
    const oauthUrls: { [key: string]: string } = {
      facebook: `https://www.facebook.com/v18.0/dialog/oauth?client_id=${process.env.FACEBOOK_APP_ID}&redirect_uri=${encodeURIComponent(callbackUri)}&scope=pages_show_list,pages_manage_posts,pages_read_engagement&response_type=code&state=${state}`,
      
      instagram: `https://api.instagram.com/oauth/authorize?client_id=${process.env.INSTAGRAM_CLIENT_ID}&redirect_uri=${encodeURIComponent(callbackUri)}&scope=user_profile,user_media&response_type=code&state=${state}`,
      
      linkedin: `https://www.linkedin.com/oauth/v2/authorization?response_type=code&client_id=${process.env.LINKEDIN_CLIENT_ID}&redirect_uri=${encodeURIComponent(callbackUri)}&scope=r_liteprofile%20w_member_social&state=${state}`,
      
      x: `https://twitter.com/i/oauth2/authorize?response_type=code&client_id=${process.env.X_CLIENT_ID}&redirect_uri=${encodeURIComponent(callbackUri)}&scope=tweet.read%20tweet.write%20users.read&state=${state}&code_challenge=${codeChallenge}&code_challenge_method=S256`,
      
      youtube: `https://accounts.google.com/o/oauth2/v2/auth?response_type=code&client_id=${process.env.GOOGLE_CLIENT_ID}&redirect_uri=${encodeURIComponent(callbackUri)}&scope=https://www.googleapis.com/auth/youtube.upload&state=${state}&code_challenge=${codeChallenge}&code_challenge_method=S256`
    };

    const url = oauthUrls[platform];
    if (!url) {
      throw new Error(`Unsupported OAuth platform: ${platform}`);
    }

    console.log('✅ [OAUTH_INIT] S256 PKCE OAuth initiated:', {
      platform,
      userId,
      codeChallenge: codeChallenge.substring(0, 10) + '...',
      callbackUri
    });

    return url;
  }

  /**
   * CRITICAL: Consolidated OAuth callback handler with platform switching
   */
  public async handleCallback(req: Request, res: Response): Promise<void> {
    try {
      const { code, state, error } = req.query;

      if (error) {
        console.error('🚨 [OAUTH_CALLBACK] OAuth error:', error);
        return this.sendErrorResponse(res, 'OAuth authorization failed');
      }

      if (!code || !state) {
        console.error('🚨 [OAUTH_CALLBACK] Missing code or state');
        return this.sendErrorResponse(res, 'Invalid OAuth callback');
      }

      // Parse and validate state
      let parsedState: OAuthState;
      try {
        parsedState = JSON.parse(Buffer.from(state as string, 'base64').toString());
      } catch {
        console.error('🚨 [OAUTH_CALLBACK] Invalid state parameter');
        return this.sendErrorResponse(res, 'Invalid OAuth state');
      }

      const { platform, userId, timestamp } = parsedState;

      // Validate state timestamp (prevent replay attacks)
      if (Date.now() - timestamp > 10 * 60 * 1000) { // 10 minutes
        console.error('🚨 [OAUTH_CALLBACK] Expired OAuth state:', { platform, userId });
        return this.sendErrorResponse(res, 'OAuth state expired');
      }

      // Get code verifier for PKCE
      const codeVerifier = this.codeVerifiers.get(state as string);
      this.codeVerifiers.delete(state as string); // Use once

      // Exchange code for token based on platform
      const tokenData = await this.exchangeCodeForToken(platform, code as string, codeVerifier);
      
      if (!tokenData) {
        console.error('🚨 [OAUTH_CALLBACK] Token exchange failed:', { platform, userId });
        return this.sendErrorResponse(res, 'Token exchange failed');
      }

      // Store token in database
      await this.storeOAuthToken(userId, platform, tokenData);

      console.log('✅ [OAUTH_CALLBACK] OAuth completed successfully:', {
        platform,
        userId,
        tokenExpiry: tokenData.expires_at ? new Date(tokenData.expires_at) : 'N/A'
      });

      // Send success response with proper window closing
      res.send(`
        <script>
          if (window.opener) {
            window.opener.postMessage({
              type: 'oauth_success',
              platform: '${platform}',
              userId: ${userId}
            }, '*');
          }
          window.close();
        </script>
      `);

    } catch (error: any) {
      console.error('🚨 [OAUTH_CALLBACK] Callback error:', error);
      this.sendErrorResponse(res, 'OAuth callback failed');
    }
  }

  /**
   * Platform-specific token exchange
   */
  private async exchangeCodeForToken(platform: string, code: string, codeVerifier?: string): Promise<any> {
    const baseUrl = process.env.NODE_ENV === 'production' 
      ? 'https://app.theagencyiq.ai'
      : `https://${process.env.REPLIT_DEV_DOMAIN}`;
    const callbackUri = `${baseUrl}/auth/callback`;

    switch (platform) {
      case 'facebook':
        return this.exchangeFacebookToken(code, callbackUri);
      case 'instagram':
        return this.exchangeInstagramToken(code, callbackUri);
      case 'linkedin':
        return this.exchangeLinkedInToken(code, callbackUri);
      case 'x':
        return this.exchangeXToken(code, callbackUri, codeVerifier);
      case 'youtube':
        return this.exchangeYouTubeToken(code, callbackUri, codeVerifier);
      default:
        throw new Error(`Unsupported platform: ${platform}`);
    }
  }

  private async exchangeFacebookToken(code: string, redirectUri: string): Promise<any> {
    const response = await fetch('https://graph.facebook.com/v18.0/oauth/access_token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: process.env.FACEBOOK_APP_ID!,
        client_secret: process.env.FACEBOOK_APP_SECRET!,
        redirect_uri: redirectUri,
        code
      })
    });

    return response.json();
  }

  private async exchangeLinkedInToken(code: string, redirectUri: string): Promise<any> {
    const response = await fetch('https://www.linkedin.com/oauth/v2/accessToken', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: redirectUri,
        client_id: process.env.LINKEDIN_CLIENT_ID!,
        client_secret: process.env.LINKEDIN_CLIENT_SECRET!
      })
    });

    return response.json();
  }

  private async exchangeXToken(code: string, redirectUri: string, codeVerifier?: string): Promise<any> {
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: redirectUri,
      client_id: process.env.X_CLIENT_ID!
    });

    if (codeVerifier) {
      body.append('code_verifier', codeVerifier);
    }

    const response = await fetch('https://api.twitter.com/2/oauth2/token', {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': `Basic ${Buffer.from(`${process.env.X_CLIENT_ID}:${process.env.X_CLIENT_SECRET}`).toString('base64')}`
      },
      body
    });

    return response.json();
  }

  private async exchangeInstagramToken(code: string, redirectUri: string): Promise<any> {
    const response = await fetch('https://api.instagram.com/oauth/access_token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: process.env.INSTAGRAM_CLIENT_ID!,
        client_secret: process.env.INSTAGRAM_CLIENT_SECRET!,
        grant_type: 'authorization_code',
        redirect_uri: redirectUri,
        code
      })
    });

    return response.json();
  }

  private async exchangeYouTubeToken(code: string, redirectUri: string, codeVerifier?: string): Promise<any> {
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: redirectUri,
      client_id: process.env.GOOGLE_CLIENT_ID!,
      client_secret: process.env.GOOGLE_CLIENT_SECRET!
    });

    if (codeVerifier) {
      body.append('code_verifier', codeVerifier);
    }

    const response = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body
    });

    return response.json();
  }

  /**
   * Store OAuth token in database
   */
  private async storeOAuthToken(userId: number, platform: string, tokenData: any): Promise<void> {
    const expiresAt = tokenData.expires_in 
      ? new Date(Date.now() + tokenData.expires_in * 1000)
      : null;

    await db.insert(platformConnections)
      .values({
        userId: userId.toString(), 
        platform,
        token: tokenData.access_token,
        refreshToken: tokenData.refresh_token || null,
        expiresAt,
        isActive: true,
        scope: tokenData.scope || '',
        createdAt: new Date(),
        updatedAt: new Date()
      })
      .onConflictDoUpdate({
        target: [platformConnections.userId, platformConnections.platform],
        set: {
          token: tokenData.access_token,
          refreshToken: tokenData.refresh_token || null,
          expiresAt,
          isActive: true,
          scope: tokenData.scope || '',
          updatedAt: new Date()
        }
      });
  }

  private sendErrorResponse(res: Response, message: string): void {
    res.send(`
      <script>
        if (window.opener) {
          window.opener.postMessage({
            type: 'oauth_error',
            message: '${message}'
          }, '*');
        }
        window.close();
      </script>
    `);
  }
}