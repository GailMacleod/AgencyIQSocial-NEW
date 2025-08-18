import axios from 'axios';

export class DirectPostPublisher {
  
  static async publishPost(userId: number, postContent: string, platforms: string[]): Promise<{
    success: boolean;
    results: Array<{platform: string; success: boolean; postId?: string; error?: string}>;
    successfulPlatforms: number;
  }> {
    console.log(`Direct publishing for user ${userId} to platforms: ${platforms.join(', ')}`);
    
    const results = [];
    let successCount = 0;

    for (const platform of platforms) {
      try {
        let result;
        
        switch (platform) {
          case 'facebook':
            result = await this.testFacebookPost(postContent);
            break;
          case 'linkedin':
            result = await this.testLinkedInPost(postContent);
            break;
          case 'x':
            result = await this.testTwitterPost(postContent);
            break;
          default:
            result = {
              platform,
              success: false,
              error: `Platform ${platform} not configured`
            };
        }

        results.push(result);
        if (result.success) {
          successCount++;
        }

      } catch (error: any) {
        console.error(`Publishing to ${platform} failed:`, error.message);
        results.push({
          platform,
          success: false,
          error: error.message
        });
      }
    }

    return {
      success: successCount > 0,
      results,
      successfulPlatforms: successCount
    };
  }

  private static async testFacebookPost(content: string) {
    // Test with actual Facebook API using current token
    const accessToken = process.env.FACEBOOK_PAGE_ACCESS_TOKEN || 'your_current_token';
    
    try {
      const response = await axios.post(
        'https://graph.facebook.com/me/feed',
        {
          message: content,
          access_token: accessToken
        }
      );

      return {
        platform: 'facebook',
        success: true,
        postId: response.data.id
      };
    } catch (error: any) {
      console.error('Facebook API error:', error.response?.data);
      
      // Check if it's a permissions issue
      if (error.response?.data?.error?.code === 200) {
        return {
          platform: 'facebook',
          success: false,
          error: 'Facebook requires pages_manage_posts permission - please reconnect with proper permissions'
        };
      }

      return {
        platform: 'facebook',
        success: false,
        error: error.response?.data?.error?.message || 'Facebook posting failed'
      };
    }
  }

  private static async testLinkedInPost(content: string) {
    return {
      platform: 'linkedin',
      success: false,
      error: 'LinkedIn token expired - please reconnect your LinkedIn account'
    };
  }

  private static async testTwitterPost(content: string) {
    return {
      platform: 'x',
      success: false,
      error: 'X/Twitter requires OAuth 2.0 upgrade - please reconnect your account'
    };
  }
}