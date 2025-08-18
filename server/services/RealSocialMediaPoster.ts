// Real Social Media Posting Service with OAuth Integration
// Replaces mock posting with authentic API calls and exponential backoff

import axios, { AxiosResponse } from 'axios';
import { db } from '../db';
import { enhancedPostLogs, enhancedOauthTokens } from '../../shared/schema';
import { eq, and } from 'drizzle-orm';
import { logger } from '../utils/logger.js';
import { PassportOAuthManager } from './PassportOAuthManager';
import { notificationService } from './NotificationService';

export interface PostData {
  id: string;
  content: string;
  platform: string;
  userId: number;
  mediaUrls?: string[];
  scheduledAt?: Date;
}

export interface PostResult {
  success: boolean;
  postId?: string;
  platformId?: string;
  errorCode?: string;
  errorMessage?: string;
  shouldRetry?: boolean;
  retryAfter?: number;
}

export class RealSocialMediaPoster {
  private oauthManager: PassportOAuthManager;
  private maxRetries = 3;
  private baseDelay = 1000; // 1 second

  constructor() {
    this.oauthManager = new PassportOAuthManager();
  }

  async postToSocialMedia(postData: PostData, attemptNumber: number = 1): Promise<PostResult> {
    const startTime = Date.now();
    
    try {
      // Log attempt
      await this.logPostAttempt(postData, attemptNumber, 'attempt');

      // Get valid OAuth token
      const accessToken = await this.oauthManager.getValidToken(postData.userId, postData.platform);
      if (!accessToken) {
        const error = 'No valid OAuth token available';
        await this.logPostAttempt(postData, attemptNumber, 'failure', {
          errorCode: 'NO_TOKEN',
          errorMessage: error
        });
        return {
          success: false,
          errorCode: 'NO_TOKEN',
          errorMessage: error,
          shouldRetry: false
        };
      }

      // Post to specific platform
      const result = await this.postToPlatform(postData, accessToken);
      
      const processingTime = Date.now() - startTime;

      if (result.success) {
        // Log success
        await this.logPostAttempt(postData, attemptNumber, 'success', {
          platformResponse: { postId: result.platformId },
          processingTime,
          oauthTokenUsed: accessToken.substring(0, 10) + '***'
        });

        // Send confirmation notification
        await notificationService.sendPostConfirmation(postData.userId, {
          platform: postData.platform,
          content: postData.content,
          postId: result.platformId || postData.id
        });

        logger.info('Post published successfully', {
          postId: postData.id,
          platform: postData.platform,
          platformId: result.platformId,
          processingTime
        });
      } else {
        // Log failure
        await this.logPostAttempt(postData, attemptNumber, 'failure', {
          errorCode: result.errorCode,
          errorMessage: result.errorMessage,
          processingTime,
          retryAfter: result.retryAfter ? new Date(Date.now() + result.retryAfter) : undefined
        });

        // Send error notification
        await notificationService.sendErrorNotification(postData.userId, {
          platform: postData.platform,
          errorMessage: result.errorMessage || 'Unknown error',
          postId: postData.id,
          attemptNumber
        });

        // Determine if should retry
        if (result.shouldRetry && attemptNumber < this.maxRetries) {
          const delay = this.calculateBackoffDelay(attemptNumber);
          logger.info('Scheduling retry for failed post', {
            postId: postData.id,
            attemptNumber,
            nextAttempt: attemptNumber + 1,
            delay
          });

          // Schedule retry with exponential backoff
          setTimeout(() => {
            this.postToSocialMedia(postData, attemptNumber + 1);
          }, delay);
        }
      }

      return result;
    } catch (error) {
      const processingTime = Date.now() - startTime;
      
      await this.logPostAttempt(postData, attemptNumber, 'failure', {
        errorCode: 'SYSTEM_ERROR',
        errorMessage: error.message,
        processingTime
      });

      logger.error('Unexpected error during posting', {
        postId: postData.id,
        platform: postData.platform,
        error: error.message,
        attemptNumber
      });

      return {
        success: false,
        errorCode: 'SYSTEM_ERROR',
        errorMessage: error.message,
        shouldRetry: attemptNumber < this.maxRetries
      };
    }
  }

  private async postToPlatform(postData: PostData, accessToken: string): Promise<PostResult> {
    switch (postData.platform.toLowerCase()) {
      case 'facebook':
        return await this.postToFacebook(postData, accessToken);
      case 'instagram':
        return await this.postToInstagram(postData, accessToken);
      case 'linkedin':
        return await this.postToLinkedIn(postData, accessToken);
      case 'twitter':
      case 'x':
        return await this.postToTwitter(postData, accessToken);
      case 'youtube':
        return await this.postToYouTube(postData, accessToken);
      default:
        return {
          success: false,
          errorCode: 'UNSUPPORTED_PLATFORM',
          errorMessage: `Platform ${postData.platform} not supported`,
          shouldRetry: false
        };
    }
  }

  private async postToFacebook(postData: PostData, accessToken: string): Promise<PostResult> {
    try {
      const response: AxiosResponse = await axios.post(
        'https://graph.facebook.com/v18.0/me/feed',
        {
          message: postData.content,
          access_token: accessToken
        }
      );

      return {
        success: true,
        platformId: response.data.id
      };
    } catch (error) {
      return this.handlePlatformError(error, 'facebook');
    }
  }

  private async postToInstagram(postData: PostData, accessToken: string): Promise<PostResult> {
    try {
      // Instagram requires image for posts
      if (!postData.mediaUrls || postData.mediaUrls.length === 0) {
        return {
          success: false,
          errorCode: 'MISSING_MEDIA',
          errorMessage: 'Instagram posts require at least one image',
          shouldRetry: false
        };
      }

      // Create media container
      const containerResponse: AxiosResponse = await axios.post(
        'https://graph.facebook.com/v18.0/me/media',
        {
          image_url: postData.mediaUrls[0],
          caption: postData.content,
          access_token: accessToken
        }
      );

      // Publish the container
      const publishResponse: AxiosResponse = await axios.post(
        'https://graph.facebook.com/v18.0/me/media_publish',
        {
          creation_id: containerResponse.data.id,
          access_token: accessToken
        }
      );

      return {
        success: true,
        platformId: publishResponse.data.id
      };
    } catch (error) {
      return this.handlePlatformError(error, 'instagram');
    }
  }

  private async postToLinkedIn(postData: PostData, accessToken: string): Promise<PostResult> {
    try {
      const response: AxiosResponse = await axios.post(
        'https://api.linkedin.com/v2/ugcPosts',
        {
          author: 'urn:li:person:me',
          lifecycleState: 'PUBLISHED',
          specificContent: {
            'com.linkedin.ugc.ShareContent': {
              shareCommentary: {
                text: postData.content
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

      return {
        success: true,
        platformId: response.data.id
      };
    } catch (error) {
      return this.handlePlatformError(error, 'linkedin');
    }
  }

  private async postToTwitter(postData: PostData, accessToken: string): Promise<PostResult> {
    try {
      const response: AxiosResponse = await axios.post(
        'https://api.twitter.com/2/tweets',
        {
          text: postData.content
        },
        {
          headers: {
            'Authorization': `Bearer ${accessToken}`,
            'Content-Type': 'application/json'
          }
        }
      );

      return {
        success: true,
        platformId: response.data.data.id
      };
    } catch (error) {
      return this.handlePlatformError(error, 'twitter');
    }
  }

  private async postToYouTube(postData: PostData, accessToken: string): Promise<PostResult> {
    try {
      // YouTube requires video upload, not just text posts
      if (!postData.mediaUrls || postData.mediaUrls.length === 0) {
        return {
          success: false,
          errorCode: 'MISSING_VIDEO',
          errorMessage: 'YouTube posts require a video file',
          shouldRetry: false
        };
      }

      // This is a simplified example - actual YouTube upload requires multipart form data
      const response: AxiosResponse = await axios.post(
        'https://www.googleapis.com/youtube/v3/videos',
        {
          snippet: {
            title: postData.content.substring(0, 100),
            description: postData.content,
            categoryId: '22' // People & Blogs
          },
          status: {
            privacyStatus: 'public'
          }
        },
        {
          headers: {
            'Authorization': `Bearer ${accessToken}`,
            'Content-Type': 'application/json'
          },
          params: {
            part: 'snippet,status'
          }
        }
      );

      return {
        success: true,
        platformId: response.data.id
      };
    } catch (error) {
      return this.handlePlatformError(error, 'youtube');
    }
  }

  private handlePlatformError(error: any, platform: string): PostResult {
    const status = error.response?.status;
    const errorData = error.response?.data;

    // Handle rate limiting
    if (status === 429) {
      const retryAfter = error.response?.headers['retry-after'];
      return {
        success: false,
        errorCode: 'RATE_LIMITED',
        errorMessage: `Rate limited by ${platform}`,
        shouldRetry: true,
        retryAfter: retryAfter ? parseInt(retryAfter) * 1000 : 60000 // Default 1 minute
      };
    }

    // Handle token errors
    if (status === 401) {
      return {
        success: false,
        errorCode: 'INVALID_TOKEN',
        errorMessage: 'OAuth token invalid or expired',
        shouldRetry: false
      };
    }

    // Handle temporary errors
    if (status >= 500) {
      return {
        success: false,
        errorCode: 'SERVER_ERROR',
        errorMessage: `${platform} server error: ${status}`,
        shouldRetry: true
      };
    }

    // Handle client errors
    return {
      success: false,
      errorCode: 'CLIENT_ERROR',
      errorMessage: errorData?.error?.message || error.message,
      shouldRetry: false
    };
  }

  private calculateBackoffDelay(attemptNumber: number): number {
    // Exponential backoff with jitter: base * 2^attempt + random(0, 1000)
    const exponentialDelay = this.baseDelay * Math.pow(2, attemptNumber - 1);
    const jitter = Math.random() * 1000;
    return Math.min(exponentialDelay + jitter, 60000); // Max 60 seconds
  }

  private async logPostAttempt(
    postData: PostData,
    attemptNumber: number,
    action: string,
    details?: {
      errorCode?: string;
      errorMessage?: string;
      platformResponse?: any;
      processingTime?: number;
      oauthTokenUsed?: string;
      retryAfter?: Date;
    }
  ) {
    try {
      await db.insert(enhancedPostLogs).values({
        postId: postData.id,
        userId: postData.userId,
        platform: postData.platform,
        action,
        attemptNumber,
        statusCode: details?.platformResponse ? 200 : (details?.errorCode ? 400 : null),
        errorCode: details?.errorCode,
        errorMessage: details?.errorMessage,
        platformResponse: details?.platformResponse,
        oauthTokenUsed: details?.oauthTokenUsed,
        processingTime: details?.processingTime,
        retryAfter: details?.retryAfter
      });
    } catch (error) {
      logger.error('Failed to log post attempt', {
        error: error.message,
        postId: postData.id,
        attemptNumber
      });
    }
  }

  // Get posting history for a specific post
  async getPostHistory(postId: string) {
    try {
      const logs = await db.select()
        .from(enhancedPostLogs)
        .where(eq(enhancedPostLogs.postId, postId))
        .orderBy(enhancedPostLogs.createdAt);
      
      return logs;
    } catch (error) {
      logger.error('Failed to get post history', {
        error: error.message,
        postId
      });
      return [];
    }
  }

  // Retry failed posts
  async retryFailedPost(postId: string): Promise<PostResult> {
    // This would need to be implemented based on how posts are stored
    // For now, return not implemented
    return {
      success: false,
      errorCode: 'NOT_IMPLEMENTED',
      errorMessage: 'Manual retry not implemented yet',
      shouldRetry: false
    };
  }
}

export const realSocialMediaPoster = new RealSocialMediaPoster();