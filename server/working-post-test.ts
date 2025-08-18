import { storage } from './storage';

export class WorkingPostTest {
  
  static async testPostPublishingWithCurrentTokens(userId: number): Promise<{
    facebook: { working: boolean; error?: string; fix?: string };
    linkedin: { working: boolean; error?: string; fix?: string };
    twitter: { working: boolean; error?: string; fix?: string };
    summary: string;
  }> {
    
    const results = {
      facebook: { working: false, error: '', fix: '' },
      linkedin: { working: false, error: '', fix: '' },
      twitter: { working: false, error: '', fix: '' },
      summary: ''
    };

    // Test Facebook posting
    try {
      const fbResult = await this.testFacebookPost(userId);
      results.facebook = fbResult;
    } catch (error: any) {
      results.facebook = {
        working: false,
        error: error.message,
        fix: 'Reconnect Facebook with pages_manage_posts permission'
      };
    }

    // Test LinkedIn posting
    try {
      const liResult = await this.testLinkedInPost(userId);
      results.linkedin = liResult;
    } catch (error: any) {
      results.linkedin = {
        working: false,
        error: error.message,
        fix: 'Reconnect LinkedIn with w_member_social permission'
      };
    }

    // Test Twitter posting
    try {
      const twResult = await this.testTwitterPost(userId);
      results.twitter = twResult;
    } catch (error: any) {
      results.twitter = {
        working: false,
        error: error.message,
        fix: 'Upgrade to OAuth 2.0 with tweet.write permission'
      };
    }

    const workingCount = [results.facebook, results.linkedin, results.twitter]
      .filter(r => r.working).length;
    
    results.summary = `${workingCount}/3 platforms working. ${3 - workingCount} require OAuth reconnection.`;

    return results;
  }

  private static async testFacebookPost(userId: number): Promise<{
    working: boolean; error?: string; fix?: string;
  }> {
    
    // Get Facebook connection
    const connections = await storage.getPlatformConnectionsByUser(userId);
    const fbConnection = connections.find(c => c.platform === 'facebook');
    
    if (!fbConnection || !fbConnection.accessToken) {
      return {
        working: false,
        error: 'No Facebook connection found',
        fix: 'Connect Facebook account with proper permissions'
      };
    }

    // Test actual Facebook Graph API call
    try {
      const response = await fetch('https://graph.facebook.com/me/feed', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          message: 'Test post from TheAgencyIQ - checking OAuth permissions',
          access_token: fbConnection.accessToken
        })
      });

      const data = await response.json();

      if (response.ok && data.id) {
        return { working: true };
      } else {
        return {
          working: false,
          error: data.error?.message || 'Unknown Facebook API error',
          fix: 'Reconnect Facebook with pages_manage_posts permission'
        };
      }
    } catch (error: any) {
      return {
        working: false,
        error: error.message,
        fix: 'Check Facebook API connectivity and permissions'
      };
    }
  }

  private static async testLinkedInPost(userId: number): Promise<{
    working: boolean; error?: string; fix?: string;
  }> {
    
    const connections = await storage.getPlatformConnectionsByUser(userId);
    const liConnection = connections.find(c => c.platform === 'linkedin');
    
    if (!liConnection || !liConnection.accessToken) {
      return {
        working: false,
        error: 'No LinkedIn connection found',
        fix: 'Connect LinkedIn account with w_member_social permission'
      };
    }

    // Test LinkedIn API call
    try {
      const response = await fetch('https://api.linkedin.com/v2/ugcPosts', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${liConnection.accessToken}`,
          'Content-Type': 'application/json',
          'X-Restli-Protocol-Version': '2.0.0'
        },
        body: JSON.stringify({
          author: `urn:li:person:${liConnection.platformUserId}`,
          lifecycleState: 'PUBLISHED',
          specificContent: {
            'com.linkedin.ugc.ShareContent': {
              shareCommentary: {
                text: 'Test post from TheAgencyIQ - checking OAuth permissions'
              },
              shareMediaCategory: 'NONE'
            }
          },
          visibility: {
            'com.linkedin.ugc.MemberNetworkVisibility': 'PUBLIC'
          }
        })
      });

      const data = await response.json();

      if (response.ok && data.id) {
        return { working: true };
      } else {
        return {
          working: false,
          error: data.message || 'LinkedIn API error',
          fix: 'Reconnect LinkedIn with w_member_social permission'
        };
      }
    } catch (error: any) {
      return {
        working: false,
        error: error.message,
        fix: 'Check LinkedIn API connectivity and token validity'
      };
    }
  }

  private static async testTwitterPost(userId: number): Promise<{
    working: boolean; error?: string; fix?: string;
  }> {
    
    const connections = await storage.getPlatformConnectionsByUser(userId);
    const twConnection = connections.find(c => c.platform === 'x' || c.platform === 'twitter');
    
    if (!twConnection || !twConnection.accessToken) {
      return {
        working: false,
        error: 'No X/Twitter connection found',
        fix: 'Connect X account with OAuth 2.0 and tweet.write permission'
      };
    }

    // Twitter/X requires OAuth 2.0 for API v2
    try {
      const response = await fetch('https://api.twitter.com/2/tweets', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${twConnection.accessToken}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          text: 'Test post from TheAgencyIQ - checking OAuth permissions'
        })
      });

      const data = await response.json();

      if (response.ok && data.data?.id) {
        return { working: true };
      } else {
        return {
          working: false,
          error: data.detail || data.title || 'Twitter API error',
          fix: 'Upgrade to OAuth 2.0 with tweet.write permission'
        };
      }
    } catch (error: any) {
      return {
        working: false,
        error: error.message,
        fix: 'Check X/Twitter API connectivity and OAuth 2.0 setup'
      };
    }
  }

  static async simulateWorkingPostAfterReconnection(): Promise<{
    facebook: { success: boolean; postId: string };
    linkedin: { success: boolean; postId: string };
    twitter: { success: boolean; postId: string };
    message: string;
  }> {
    
    // Simulate what would happen with proper OAuth connections
    return {
      facebook: {
        success: true,
        postId: 'fb_demo_12345_working'
      },
      linkedin: {
        success: true,
        postId: 'li_demo_67890_working'
      },
      twitter: {
        success: true,
        postId: 'tw_demo_54321_working'
      },
      message: 'All 50 posts would publish successfully with proper OAuth reconnection'
    };
  }
}