import { storage } from './storage';
import axios from 'axios';
import crypto from 'crypto';

interface PublishAttempt {
  platform: string;
  success: boolean;
  postId?: string;
  error?: string;
}

export class PostFixService {
  
  static async publishPostWithFallbacks(userId: number, postId: number, platforms: string[]): Promise<{
    success: boolean;
    results: PublishAttempt[];
    successfulPlatforms: number;
  }> {
    
    const user = await storage.getUser(userId);
    if (!user) {
      throw new Error('User not found');
    }

    const connections = await storage.getPlatformConnectionsByUser(userId);
    const post = (await storage.getPostsByUser(userId)).find(p => p.id === postId);
    
    if (!post) {
      throw new Error('Post not found');
    }

    const results: PublishAttempt[] = [];
    let successfulPlatforms = 0;

    for (const platform of platforms) {
      const connection = connections.find(c => c.platform === platform && c.isActive);
      
      if (!connection) {
        results.push({
          platform,
          success: false,
          error: `${platform} not connected`
        });
        continue;
      }

      let publishResult: PublishAttempt;

      try {
        switch (platform) {
          case 'facebook':
            publishResult = await this.publishToFacebookWithFallback(connection.accessToken, post.content);
            break;
          case 'linkedin':
            publishResult = await this.publishToLinkedInWithValidation(connection.accessToken, post.content);
            break;
          case 'x':
            publishResult = await this.publishToXWithCorrectAuth(connection.accessToken, connection.refreshToken || '', post.content);
            break;
          case 'instagram':
            publishResult = await this.publishToInstagramBasic(connection.accessToken, post.content);
            break;
          case 'youtube':
            publishResult = await this.publishToYouTubeCommunity(connection.accessToken, post.content);
            break;
          default:
            publishResult = {
              platform,
              success: false,
              error: `Platform ${platform} not supported`
            };
        }
      } catch (error: any) {
        publishResult = {
          platform,
          success: false,
          error: error.message
        };
      }

      results.push(publishResult);
      if (publishResult.success) {
        successfulPlatforms++;
      }
    }

    // Update post status
    if (successfulPlatforms > 0) {
      const allSuccessful = successfulPlatforms === platforms.length;
      await storage.updatePost(postId, {
        status: allSuccessful ? "published" : "partial",
        publishedAt: new Date(),
        analytics: { results }
      });

      // Decrement user post allocation
      const newRemaining = Math.max(0, (user.remainingPosts || 0) - 1);
      await storage.updateUser(userId, { remainingPosts: newRemaining });
    } else {
      await storage.updatePost(postId, {
        status: "failed",
        errorLog: results.map(r => `${r.platform}: ${r.error}`).join('; ')
      });
    }

    return {
      success: successfulPlatforms > 0,
      results,
      successfulPlatforms
    };
  }

  private static async publishToFacebookWithFallback(accessToken: string, content: string): Promise<PublishAttempt> {
    const appSecret = process.env.FACEBOOK_APP_SECRET;
    if (!appSecret) {
      return { platform: 'facebook', success: false, error: 'Facebook App Secret not configured' };
    }

    const appsecretProof = crypto.createHmac('sha256', appSecret).update(accessToken).digest('hex');

    // Try user feed directly (this usually works)
    try {
      const response = await axios.post(
        `https://graph.facebook.com/v18.0/me/feed`,
        {
          message: content,
          access_token: accessToken,
          appsecret_proof: appsecretProof
        }
      );

      console.log(`Facebook user feed post successful: ${response.data.id}`);
      return {
        platform: 'facebook',
        success: true,
        postId: response.data.id
      };
    } catch (error: any) {
      console.error('Facebook publish error:', error.response?.data || error.message);
      return {
        platform: 'facebook',
        success: false,
        error: error.response?.data?.error?.message || error.message
      };
    }
  }

  private static async publishToLinkedInWithValidation(accessToken: string, content: string): Promise<PublishAttempt> {
    try {
      // First validate the token by getting user info
      const userResponse = await axios.get(
        'https://api.linkedin.com/v2/people/~',
        {
          headers: {
            'Authorization': `Bearer ${accessToken}`
          }
        }
      );

      const userId = userResponse.data.id;

      // Post using the validated user ID
      const response = await axios.post(
        'https://api.linkedin.com/v2/ugcPosts',
        {
          author: `urn:li:person:${userId}`,
          lifecycleState: 'PUBLISHED',
          specificContent: {
            'com.linkedin.ugc.ShareContent': {
              shareCommentary: {
                text: content
              },
              shareMediaCategory: 'NONE'
            }
          },
          visibility: {
            'com.linkedin.ugc.MemberNetworkVisibility': 'PUBLIC'
          }
        },
        {
          headers: {
            'Authorization': `Bearer ${accessToken}`,
            'Content-Type': 'application/json',
            'X-Restli-Protocol-Version': '2.0.0'
          }
        }
      );

      console.log(`LinkedIn post successful: ${response.data.id}`);
      return {
        platform: 'linkedin',
        success: true,
        postId: response.data.id
      };
    } catch (error: any) {
      console.error('LinkedIn publish error:', error.response?.data || error.message);
      return {
        platform: 'linkedin',
        success: false,
        error: error.response?.data?.message || 'LinkedIn token expired - please reconnect'
      };
    }
  }

  private static async publishToXWithCorrectAuth(accessToken: string, tokenSecret: string, content: string): Promise<PublishAttempt> {
    try {
      // For now, use simpler approach - X API v2 with user context
      const response = await axios.post(
        'https://api.twitter.com/2/tweets',
        {
          text: content.length > 280 ? content.substring(0, 277) + '...' : content
        },
        {
          headers: {
            'Authorization': `Bearer ${process.env.TWITTER_BEARER_TOKEN || accessToken}`,
            'Content-Type': 'application/json'
          }
        }
      );

      console.log(`X/Twitter post successful: ${response.data.data.id}`);
      return {
        platform: 'x',
        success: true,
        postId: response.data.data.id
      };
    } catch (error: any) {
      console.error('X/Twitter publish error:', error.response?.data || error.message);
      
      // If Bearer token fails, provide specific guidance
      return {
        platform: 'x',
        success: false,
        error: 'X/Twitter posting requires valid OAuth 2.0 user context - please reconnect your X account'
      };
    }
  }

  private static async publishToInstagramBasic(accessToken: string, content: string): Promise<PublishAttempt> {
    // Instagram Basic Display API doesn't support posting
    // This would require Instagram Graph API with business account
    return {
      platform: 'instagram',
      success: false,
      error: 'Instagram posting requires business account and Graph API access'
    };
  }

  private static async publishToYouTubeCommunity(accessToken: string, content: string): Promise<PublishAttempt> {
    try {
      // YouTube community posts
      const response = await axios.post(
        'https://www.googleapis.com/youtube/v3/communityPosts?part=snippet',
        {
          snippet: {
            text: content
          }
        },
        {
          headers: {
            'Authorization': `Bearer ${accessToken}`,
            'Content-Type': 'application/json'
          }
        }
      );

      console.log(`YouTube community post successful: ${response.data.id}`);
      return {
        platform: 'youtube',
        success: true,
        postId: response.data.id
      };
    } catch (error: any) {
      console.error('YouTube publish error:', error.response?.data || error.message);
      return {
        platform: 'youtube',
        success: false,
        error: error.response?.data?.error?.message || 'YouTube posting failed'
      };
    }
  }
}