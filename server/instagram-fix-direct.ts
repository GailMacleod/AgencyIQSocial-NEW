import { storage } from './storage';

export class InstagramFixDirect {
  
  static async generateWorkingInstagramAuth(userId: number): Promise<{
    authUrl: string;
    instructions: string[];
    bypass: boolean;
  }> {
    
    // Use production redirect URI for Instagram OAuth
    const redirectUri = 'https://app.theagencyiq.ai/api/auth/instagram/callback';

    // Instagram Business API requires Facebook App with Instagram permissions
    const instagramParams = new URLSearchParams({
      client_id: process.env.FACEBOOK_APP_ID!, // Instagram uses Facebook App ID
      redirect_uri: redirectUri,
      scope: 'instagram_basic pages_show_list instagram_manage_posts', // Space-delimited format
      response_type: 'code',
      state: `user_${userId}_instagram_business`
    });
    
    const instagramUrl = `https://www.facebook.com/v18.0/dialog/oauth?${instagramParams.toString()}`;

    return {
      authUrl: instagramUrl,
      instructions: [
        '1. This will connect Instagram via Facebook Business API',
        '2. You need an Instagram Business or Creator account',
        '3. Your Instagram must be connected to a Facebook Page',
        '4. Grant all requested permissions for posting',
        '5. After connection, Instagram posts will work immediately'
      ],
      bypass: true
    };
  }

  static async createDirectInstagramConnection(userId: number, accessToken: string, profileData: any): Promise<void> {
    
    // Validate this is a real Instagram business token
    if (!accessToken || accessToken.includes('demo') || accessToken.length < 50) {
      throw new Error('Invalid Instagram business token - only real accounts supported');
    }

    // Get Instagram business account info
    try {
      const response = await fetch(`https://graph.facebook.com/v18.0/me/accounts?access_token=${accessToken}`);
      const data = await response.json();
      
      if (data.error) {
        throw new Error(`Instagram API error: ${data.error.message}`);
      }

      // Find Instagram business account
      const instagramPage = data.data?.find((page: any) => page.instagram_business_account);
      
      if (!instagramPage) {
        throw new Error('No Instagram Business account found. Connect your Instagram to a Facebook Page first.');
      }

      // Store Instagram business connection
      await storage.createPlatformConnection({
        userId,
        platform: 'instagram',
        platformUserId: instagramPage.instagram_business_account.id,
        platformUsername: instagramPage.name,
        accessToken,
        refreshToken: null,
        isActive: true
      });

      console.log('Instagram Business connection successful:', {
        pageId: instagramPage.id,
        pageName: instagramPage.name,
        instagramId: instagramPage.instagram_business_account.id
      });

    } catch (error: any) {
      console.error('Instagram connection error:', error);
      throw new Error(`Failed to establish Instagram connection: ${error.message}`);
    }
  }

  static async testInstagramPosting(userId: number): Promise<{
    canPost: boolean;
    error?: string;
    accountType?: string;
  }> {
    
    const connections = await storage.getPlatformConnectionsByUser(userId);
    const instagramConnection = connections.find(c => c.platform === 'instagram');
    
    if (!instagramConnection?.accessToken) {
      return {
        canPost: false,
        error: 'No Instagram connection found'
      };
    }

    try {
      // Test Instagram Graph API access
      const response = await fetch(`https://graph.facebook.com/v18.0/me?access_token=${instagramConnection.accessToken}`);
      const data = await response.json();
      
      if (data.error) {
        return {
          canPost: false,
          error: `Instagram API error: ${data.error.message}`
        };
      }

      // Check for Instagram business account
      const accountsResponse = await fetch(`https://graph.facebook.com/v18.0/me/accounts?access_token=${instagramConnection.accessToken}`);
      const accountsData = await accountsResponse.json();
      
      const hasInstagramBusiness = accountsData.data?.some((page: any) => page.instagram_business_account);
      
      if (!hasInstagramBusiness) {
        return {
          canPost: false,
          error: 'Instagram Business account required for posting',
          accountType: 'personal'
        };
      }

      return {
        canPost: true,
        accountType: 'business'
      };

    } catch (error: any) {
      return {
        canPost: false,
        error: `Instagram test failed: ${error.message}`
      };
    }
  }

  static async fixInstagramCompletely(userId: number): Promise<{
    success: boolean;
    authUrl: string;
    currentStatus: any;
    message: string;
  }> {
    
    const authData = await this.generateWorkingInstagramAuth(userId);
    const testResult = await this.testInstagramPosting(userId);
    
    return {
      success: true,
      authUrl: authData.authUrl,
      currentStatus: testResult,
      message: testResult.canPost 
        ? 'Instagram Business connection working - posts will publish successfully'
        : 'Click the auth URL to connect Instagram Business account for posting'
    };
  }
}