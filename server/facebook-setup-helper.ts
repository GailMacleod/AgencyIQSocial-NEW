/**
 * Facebook Setup Helper
 * Provides comprehensive Facebook business page setup and authentication
 */

import crypto from 'crypto';

export interface FacebookPageInfo {
  id: string;
  name: string;
  access_token: string;
  category: string;
  can_post: boolean;
}

export interface FacebookSetupResult {
  success: boolean;
  pages: FacebookPageInfo[];
  error?: string;
  setup_url?: string;
}

export class FacebookSetupHelper {
  private appSecret: string;
  private userToken: string;

  constructor() {
    this.appSecret = process.env.FACEBOOK_APP_SECRET || '';
    this.userToken = process.env.FACEBOOK_PAGE_ACCESS_TOKEN || '';
  }

  /**
   * Check Facebook setup and return available pages
   */
  async checkSetup(): Promise<FacebookSetupResult> {
    if (!this.appSecret || !this.userToken) {
      return {
        success: false,
        pages: [],
        error: 'Facebook credentials not configured'
      };
    }

    try {
      const proof = crypto.createHmac('sha256', this.appSecret).update(this.userToken).digest('hex');
      
      // Get user's managed pages
      const pagesResponse = await fetch(
        `https://graph.facebook.com/v20.0/me/accounts?access_token=${this.userToken}&appsecret_proof=${proof}&fields=id,name,category,access_token,can_post`
      );
      
      const pagesData = await pagesResponse.json();
      
      if (pagesData.error) {
        return {
          success: false,
          pages: [],
          error: `Facebook API error: ${pagesData.error.message}`,
          setup_url: 'https://www.facebook.com/pages/create'
        };
      }

      const pages: FacebookPageInfo[] = pagesData.data?.map((page: any) => ({
        id: page.id,
        name: page.name,
        access_token: page.access_token,
        category: page.category,
        can_post: page.can_post !== false
      })) || [];

      if (pages.length === 0) {
        return {
          success: false,
          pages: [],
          error: 'No Facebook business pages found. Create a Facebook page to enable posting.',
          setup_url: 'https://www.facebook.com/pages/create'
        };
      }

      return {
        success: true,
        pages: pages.filter(p => p.can_post)
      };
      
    } catch (error: any) {
      return {
        success: false,
        pages: [],
        error: `Setup check failed: ${error.message}`
      };
    }
  }

  /**
   * Test posting to a specific Facebook page
   */
  async testPagePosting(pageId: string, pageToken: string, testMessage: string): Promise<{ success: boolean; postId?: string; error?: string }> {
    try {
      const proof = crypto.createHmac('sha256', this.appSecret).update(pageToken).digest('hex');
      
      const response = await fetch(`https://graph.facebook.com/v20.0/${pageId}/feed`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          message: testMessage,
          access_token: pageToken,
          appsecret_proof: proof
        }).toString()
      });

      const result = await response.json();

      if (result.error) {
        return { success: false, error: result.error.message };
      }

      // Clean up test post
      if (result.id) {
        setTimeout(async () => {
          await fetch(`https://graph.facebook.com/v20.0/${result.id}?access_token=${pageToken}&appsecret_proof=${proof}`, {
            method: 'DELETE'
          });
        }, 5000); // Delete after 5 seconds
      }

      return { success: true, postId: result.id };
      
    } catch (error: any) {
      return { success: false, error: error.message };
    }
  }

  /**
   * Get the best page for posting (most recent with posting permissions)
   */
  async getBestPageForPosting(): Promise<FacebookPageInfo | null> {
    const setup = await this.checkSetup();
    if (!setup.success || setup.pages.length === 0) {
      return null;
    }

    // Return first page that can post
    return setup.pages.find(p => p.can_post) || null;
  }
}