/**
 * Platform Authentication Manager
 * Handles proper OAuth flows and token management for all social platforms
 */

import crypto from 'crypto';

export interface PlatformStatus {
  platform: string;
  authenticated: boolean;
  ready_to_post: boolean;
  error?: string;
  setup_required?: string;
  setup_url?: string;
}

export interface PostingCredentials {
  url: string;
  headers: Record<string, string>;
  payload: any;
  method: 'POST' | 'PUT';
}

export class PlatformAuthManager {
  
  /**
   * Get authentication status for all platforms
   */
  static async getAllPlatformStatus(): Promise<PlatformStatus[]> {
    const platforms = ['facebook', 'linkedin', 'instagram', 'twitter'];
    const results = await Promise.all(
      platforms.map(platform => this.getPlatformStatus(platform))
    );
    return results;
  }

  /**
   * Get specific platform authentication status
   */
  static async getPlatformStatus(platform: string): Promise<PlatformStatus> {
    switch (platform.toLowerCase()) {
      case 'facebook':
        return await this.getFacebookStatus();
      case 'linkedin':
        return await this.getLinkedInStatus();
      case 'instagram':
        return await this.getInstagramStatus();
      case 'twitter':
        return await this.getTwitterStatus();
      default:
        return {
          platform,
          authenticated: false,
          ready_to_post: false,
          error: 'Platform not supported'
        };
    }
  }

  /**
   * Get posting credentials for authenticated platform
   */
  static async getPostingCredentials(platform: string, content: string): Promise<PostingCredentials | null> {
    const status = await this.getPlatformStatus(platform);
    if (!status.ready_to_post) {
      throw new Error(status.error || `${platform} not ready for posting`);
    }

    switch (platform.toLowerCase()) {
      case 'facebook':
        return await this.getFacebookPostingCredentials(content);
      case 'linkedin':
        return await this.getLinkedInPostingCredentials(content);
      case 'instagram':
        return await this.getInstagramPostingCredentials(content);
      case 'twitter':
        return await this.getTwitterPostingCredentials(content);
      default:
        return null;
    }
  }

  // Facebook Implementation
  private static async getFacebookStatus(): Promise<PlatformStatus> {
    const userToken = process.env.FACEBOOK_PAGE_ACCESS_TOKEN;
    const appSecret = process.env.FACEBOOK_APP_SECRET;

    if (!userToken || !appSecret) {
      return {
        platform: 'facebook',
        authenticated: false,
        ready_to_post: false,
        error: 'Facebook credentials not configured',
        setup_required: 'Add Facebook app credentials to environment'
      };
    }

    try {
      const proof = crypto.createHmac('sha256', appSecret).update(userToken).digest('hex');
      
      // Check user authentication
      const userResponse = await fetch(`https://graph.facebook.com/v20.0/me?access_token=${userToken}&appsecret_proof=${proof}&fields=id,name`);
      const userData = await userResponse.json();

      if (userData.error) {
        return {
          platform: 'facebook',
          authenticated: false,
          ready_to_post: false,
          error: `Facebook auth failed: ${userData.error.message}`
        };
      }

      // Check for managed pages
      const pagesResponse = await fetch(`https://graph.facebook.com/v20.0/me/accounts?access_token=${userToken}&appsecret_proof=${proof}`);
      const pagesData = await pagesResponse.json();

      if (pagesData.error) {
        return {
          platform: 'facebook',
          authenticated: true,
          ready_to_post: false,
          error: `Facebook pages check failed: ${pagesData.error.message}`
        };
      }

      const hasPages = pagesData.data && pagesData.data.length > 0;

      return {
        platform: 'facebook',
        authenticated: true,
        ready_to_post: hasPages,
        error: hasPages ? undefined : 'No Facebook business pages found',
        setup_required: hasPages ? undefined : 'Create a Facebook business page',
        setup_url: hasPages ? undefined : 'https://www.facebook.com/pages/create'
      };

    } catch (error: any) {
      return {
        platform: 'facebook',
        authenticated: false,
        ready_to_post: false,
        error: `Facebook test failed: ${error.message}`
      };
    }
  }

  private static async getFacebookPostingCredentials(content: string): Promise<PostingCredentials> {
    const userToken = process.env.FACEBOOK_PAGE_ACCESS_TOKEN!;
    const appSecret = process.env.FACEBOOK_APP_SECRET!;
    const userProof = crypto.createHmac('sha256', appSecret).update(userToken).digest('hex');

    // Get first available page
    const pagesResponse = await fetch(`https://graph.facebook.com/v20.0/me/accounts?access_token=${userToken}&appsecret_proof=${userProof}`);
    const pagesData = await pagesResponse.json();
    
    if (!pagesData.data || pagesData.data.length === 0) {
      throw new Error('No Facebook pages available for posting');
    }

    const page = pagesData.data[0];
    const pageProof = crypto.createHmac('sha256', appSecret).update(page.access_token).digest('hex');

    return {
      url: `https://graph.facebook.com/v20.0/${page.id}/feed`,
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      payload: {
        message: content,
        access_token: page.access_token,
        appsecret_proof: pageProof
      }
    };
  }

  // LinkedIn Implementation
  private static async getLinkedInStatus(): Promise<PlatformStatus> {
    const clientSecret = process.env.LINKEDIN_CLIENT_SECRET;

    if (!clientSecret) {
      return {
        platform: 'linkedin',
        authenticated: false,
        ready_to_post: false,
        error: 'LinkedIn credentials not configured',
        setup_required: 'Add LinkedIn OAuth credentials'
      };
    }

    // LinkedIn requires user OAuth token, not client secret
    return {
      platform: 'linkedin',
      authenticated: false,
      ready_to_post: false,
      error: 'LinkedIn requires user OAuth token',
      setup_required: 'Complete LinkedIn OAuth flow for user access token'
    };
  }

  private static async getLinkedInPostingCredentials(content: string): Promise<PostingCredentials> {
    throw new Error('LinkedIn posting requires OAuth user token - not implemented');
  }

  // Instagram Implementation  
  private static async getInstagramStatus(): Promise<PlatformStatus> {
    const clientSecret = process.env.INSTAGRAM_CLIENT_SECRET;

    if (!clientSecret) {
      return {
        platform: 'instagram',
        authenticated: false,
        ready_to_post: false,
        error: 'Instagram credentials not configured',
        setup_required: 'Add Instagram Business API credentials'
      };
    }

    // Instagram requires Facebook Business API token
    return {
      platform: 'instagram',
      authenticated: false,
      ready_to_post: false,
      error: 'Instagram requires Facebook Business API integration',
      setup_required: 'Set up Instagram Business account via Facebook'
    };
  }

  private static async getInstagramPostingCredentials(content: string): Promise<PostingCredentials> {
    throw new Error('Instagram posting requires Facebook Business API integration - not implemented');
  }

  // Twitter Implementation
  private static async getTwitterStatus(): Promise<PlatformStatus> {
    const clientSecret = process.env.TWITTER_CLIENT_SECRET;

    if (!clientSecret) {
      return {
        platform: 'twitter',
        authenticated: false,
        ready_to_post: false,
        error: 'Twitter credentials not configured',
        setup_required: 'Add Twitter API credentials'
      };
    }

    // Twitter requires Bearer token for API v2
    return {
      platform: 'twitter',
      authenticated: false,
      ready_to_post: false,
      error: 'Twitter requires OAuth Bearer token',
      setup_required: 'Generate Twitter API Bearer token'
    };
  }

  private static async getTwitterPostingCredentials(content: string): Promise<PostingCredentials> {
    throw new Error('Twitter posting requires OAuth Bearer token - not implemented');
  }
}