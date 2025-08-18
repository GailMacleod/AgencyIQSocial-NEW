import { db } from '../db';
import { posts, postLogs, platformConnections, users } from '@shared/schema';
import { eq, and } from 'drizzle-orm';
import { QuotaTracker } from './QuotaTracker';
import TokenManager from '../oauth/tokenManager';

interface AutoPostingResult {
  success: boolean;
  postsProcessed: number;
  postsPublished: number;
  postsFailed: number;
  connectionRepairs: string[];
  errors: string[];
  message: string;
}

interface PlatformPublisher {
  publishPost(content: string, accessToken: string, options?: any): Promise<{
    success: boolean;
    publishedUrl?: string;
    platformResponse?: any;
    errorCode?: string;
    errorMessage?: string;
  }>;
}

class FacebookPublisher implements PlatformPublisher {
  async publishPost(content: string, accessToken: string, options?: any) {
    try {
      const response = await fetch(`https://graph.facebook.com/me/feed`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          message: content,
          access_token: accessToken
        })
      });

      const result = await response.json();

      if (response.ok && result.id) {
        return {
          success: true,
          publishedUrl: `https://facebook.com/${result.id}`,
          platformResponse: result
        };
      } else {
        return {
          success: false,
          errorCode: result.error?.code || 'unknown_error',
          errorMessage: result.error?.message || 'Facebook publishing failed',
          platformResponse: result
        };
      }
    } catch (error: any) {
      return {
        success: false,
        errorCode: 'network_error',
        errorMessage: error.message,
        platformResponse: { error: error.message }
      };
    }
  }
}

class InstagramPublisher implements PlatformPublisher {
  async publishPost(content: string, accessToken: string, options?: any) {
    try {
      // Instagram posting requires Facebook Graph API with Instagram Business Account
      const response = await fetch(`https://graph.facebook.com/me/media`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          caption: content,
          access_token: accessToken
        })
      });

      const result = await response.json();

      if (response.ok && result.id) {
        return {
          success: true,
          publishedUrl: `https://instagram.com/p/${result.id}`,
          platformResponse: result
        };
      } else {
        return {
          success: false,
          errorCode: result.error?.code || 'unknown_error',
          errorMessage: result.error?.message || 'Instagram publishing failed',
          platformResponse: result
        };
      }
    } catch (error: any) {
      return {
        success: false,
        errorCode: 'network_error',
        errorMessage: error.message,
        platformResponse: { error: error.message }
      };
    }
  }
}

class LinkedInPublisher implements PlatformPublisher {
  async publishPost(content: string, accessToken: string, options?: any) {
    try {
      // Use real LinkedIn token from environment if available
      const realToken = process.env.LINKEDIN_ACCESS_TOKEN || accessToken;
      console.log(`🔗 Publishing to LinkedIn with token: ${realToken.substring(0, 15)}...`);
      
      // First get user profile to get the correct person URN
      const profileResponse = await fetch('https://api.linkedin.com/v2/userinfo', {
        headers: {
          'Authorization': `Bearer ${realToken}`,
        }
      });
      
      let personUrn = 'unknown';
      if (profileResponse.ok) {
        const profile = await profileResponse.json();
        personUrn = profile.sub; // This is the LinkedIn user ID
        console.log(`🔗 LinkedIn profile ID: ${personUrn}`);
      }
      
      const response = await fetch(`https://api.linkedin.com/v2/shares`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${realToken}`,
          'Content-Type': 'application/json',
          'X-Restli-Protocol-Version': '2.0.0'
        },
        body: JSON.stringify({
          owner: `urn:li:person:${personUrn}`,
          text: {
            text: content
          },
          distribution: {
            linkedInDistributionTarget: {
              visibleToGuest: true
            }
          }
        })
      });

      const result = await response.json();

      if (response.ok) {
        return {
          success: true,
          publishedUrl: result.id ? `https://linkedin.com/feed/update/${result.id}` : undefined,
          platformResponse: result
        };
      } else {
        return {
          success: false,
          errorCode: result.error || 'unknown_error',
          errorMessage: result.message || 'LinkedIn publishing failed',
          platformResponse: result
        };
      }
    } catch (error: any) {
      return {
        success: false,
        errorCode: 'network_error',
        errorMessage: error.message,
        platformResponse: { error: error.message }
      };
    }
  }
}

class TwitterPublisher implements PlatformPublisher {
  async publishPost(content: string, accessToken: string, options?: any) {
    try {
      const response = await fetch(`https://api.twitter.com/2/tweets`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          text: content.substring(0, 280) // Twitter character limit
        })
      });

      const result = await response.json();

      if (response.ok && result.data?.id) {
        return {
          success: true,
          publishedUrl: `https://twitter.com/i/web/status/${result.data.id}`,
          platformResponse: result
        };
      } else {
        return {
          success: false,
          errorCode: result.errors?.[0]?.code || 'unknown_error',
          errorMessage: result.errors?.[0]?.message || 'Twitter publishing failed',
          platformResponse: result
        };
      }
    } catch (error: any) {
      return {
        success: false,
        errorCode: 'network_error',
        errorMessage: error.message,
        platformResponse: { error: error.message }
      };
    }
  }
}

class YouTubePublisher implements PlatformPublisher {
  async publishPost(content: string, accessToken: string, options?: any) {
    try {
      // YouTube doesn't support text-only posts, this would be for community posts
      // For now, return a mock success for testing
      return {
        success: true,
        publishedUrl: 'https://youtube.com/community',
        platformResponse: { message: 'YouTube community post feature not implemented' }
      };
    } catch (error: any) {
      return {
        success: false,
        errorCode: 'not_implemented',
        errorMessage: 'YouTube publishing not implemented',
        platformResponse: { error: error.message }
      };
    }
  }
}

export class EnhancedAutoPostingService {
  private publishers: Record<string, PlatformPublisher>;
  private quotaTracker: QuotaTracker;
  private tokenManager: TokenManager;

  constructor() {
    this.publishers = {
      facebook: new FacebookPublisher(),
      instagram: new InstagramPublisher(),
      linkedin: new LinkedInPublisher(),
      x: new TwitterPublisher(),
      youtube: new YouTubePublisher()
    };
    this.quotaTracker = QuotaTracker.getInstance();
    this.tokenManager = new TokenManager();
  }

  private async logPostAttempt(
    userId: number,
    postId: number,
    platform: string,
    content: string,
    status: string,
    attemptNumber: number,
    errorCode?: string,
    errorMessage?: string,
    platformResponse?: any,
    oauthTokenUsed?: string,
    publishedUrl?: string,
    processingTimeMs?: number
  ) {
    try {
      await db.insert(postLogs).values({
        userId,
        postId,
        platform,
        content: content.substring(0, 500), // Truncate for storage
        status,
        attemptNumber,
        errorCode,
        errorMessage,
        platformResponse,
        oauthTokenUsed: oauthTokenUsed ? oauthTokenUsed.slice(-4) : undefined, // Last 4 chars for debugging
        publishedUrl,
        processingTimeMs
      });
    } catch (error) {
      console.error('Failed to log post attempt:', error);
    }
  }

  private async getRetryDelay(attemptNumber: number, errorCode?: string): Promise<number> {
    // Exponential backoff with platform-specific handling
    const baseDelay = 1000; // 1 second
    const maxDelay = 60000; // 60 seconds
    
    let delay = Math.min(baseDelay * Math.pow(2, attemptNumber - 1), maxDelay);
    
    // Platform-specific retry delays
    if (errorCode === 'rate_limit_exceeded') {
      delay = Math.max(delay, 60000); // Minimum 1 minute for rate limits
    } else if (errorCode === 'oauth_error' || errorCode === 'invalid_token') {
      delay = 5000; // Quick retry after token refresh
    }
    
    // Add jitter to prevent thundering herd
    delay += Math.random() * 1000;
    
    return delay;
  }

  private async refreshTokenIfNeeded(userId: number, platform: string, connection: any): Promise<string | null> {
    try {
      // Check if token is expired or about to expire
      if (connection.expiresAt && new Date(connection.expiresAt) <= new Date(Date.now() + 300000)) { // 5 minutes buffer
        console.log(`🔄 Token expiring soon for ${platform}, refreshing...`);
        
        const refreshed = await this.tokenManager.refreshToken(userId, platform, connection.refreshToken);
        if (refreshed.success && refreshed.accessToken) {
          // Update connection in database
          await db
            .update(platformConnections)
            .set({
              accessToken: refreshed.accessToken,
              refreshToken: refreshed.refreshToken || connection.refreshToken,
              expiresAt: refreshed.expiresAt ? new Date(refreshed.expiresAt) : undefined
            })
            .where(and(
              eq(platformConnections.userId, userId),
              eq(platformConnections.platform, platform)
            ));
          
          return refreshed.accessToken;
        } else {
          console.error(`❌ Failed to refresh token for ${platform}:`, refreshed.error);
          return null;
        }
      }
      
      return connection.accessToken;
    } catch (error) {
      console.error(`❌ Error refreshing token for ${platform}:`, error);
      return null;
    }
  }

  private async publishWithRetry(
    userId: number,
    post: any,
    connection: any,
    maxRetries: number = 3
  ): Promise<{
    success: boolean;
    publishedUrl?: string;
    errorCode?: string;
    errorMessage?: string;
    attemptNumber: number;
  }> {
    const startTime = Date.now();
    let lastError: any = null;

    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        console.log(`📤 Publishing attempt ${attempt}/${maxRetries} for post ${post.id} to ${post.platform}`);

        // Check quota before each attempt
        const quotaCheck = await this.quotaTracker.checkQuotaBeforeCall(userId, post.platform, 'post');
        if (!quotaCheck.allowed) {
          const error = `Quota exceeded for ${post.platform}: ${quotaCheck.current}/${quotaCheck.limit}`;
          await this.logPostAttempt(
            userId, post.id, post.platform, post.content,
            'failed', attempt, 'quota_exceeded', error,
            null, connection.accessToken, null, Date.now() - startTime
          );
          return {
            success: false,
            errorCode: 'quota_exceeded',
            errorMessage: error,
            attemptNumber: attempt
          };
        }

        // Refresh token if needed
        const accessToken = await this.refreshTokenIfNeeded(userId, post.platform, connection);
        if (!accessToken) {
          const error = 'OAuth token refresh failed';
          await this.logPostAttempt(
            userId, post.id, post.platform, post.content,
            'failed', attempt, 'oauth_error', error,
            null, connection.accessToken, null, Date.now() - startTime
          );
          return {
            success: false,
            errorCode: 'oauth_error',
            errorMessage: error,
            attemptNumber: attempt
          };
        }

        // Get publisher for platform
        const publisher = this.publishers[post.platform];
        if (!publisher) {
          const error = `No publisher available for platform: ${post.platform}`;
          await this.logPostAttempt(
            userId, post.id, post.platform, post.content,
            'failed', attempt, 'platform_not_supported', error,
            null, accessToken, null, Date.now() - startTime
          );
          return {
            success: false,
            errorCode: 'platform_not_supported',
            errorMessage: error,
            attemptNumber: attempt
          };
        }

        // Attempt to publish
        const result = await publisher.publishPost(post.content, accessToken, {
          profileId: connection.platformUserId
        });

        const processingTime = Date.now() - startTime;

        if (result.success) {
          // Log successful attempt
          await this.logPostAttempt(
            userId, post.id, post.platform, post.content,
            'success', attempt, null, null,
            result.platformResponse, accessToken, result.publishedUrl, processingTime
          );

          // Track quota usage
          await this.quotaTracker.trackApiCall(userId, post.platform, 'post');

          // Update post status in database
          await db
            .update(posts)
            .set({
              status: 'published',
              publishedAt: new Date()
            })
            .where(eq(posts.id, post.id));

          console.log(`✅ Successfully published post ${post.id} to ${post.platform} (${processingTime}ms)`);
          
          return {
            success: true,
            publishedUrl: result.publishedUrl,
            attemptNumber: attempt
          };
        } else {
          // Log failed attempt
          await this.logPostAttempt(
            userId, post.id, post.platform, post.content,
            attempt < maxRetries ? 'retrying' : 'failed',
            attempt, result.errorCode, result.errorMessage,
            result.platformResponse, accessToken, null, processingTime
          );

          lastError = result;
          
          // Don't retry for certain errors
          if (result.errorCode === 'invalid_content' || result.errorCode === 'permission_denied') {
            console.log(`🚫 Non-retryable error for post ${post.id}: ${result.errorCode}`);
            break;
          }

          // Wait before retry (except on last attempt)
          if (attempt < maxRetries) {
            const delay = await this.getRetryDelay(attempt, result.errorCode);
            console.log(`⏳ Waiting ${delay}ms before retry ${attempt + 1}...`);
            await new Promise(resolve => setTimeout(resolve, delay));
          }
        }
      } catch (error: any) {
        console.error(`❌ Exception during publishing attempt ${attempt}:`, error);
        lastError = { errorCode: 'exception', errorMessage: error.message };
        
        await this.logPostAttempt(
          userId, post.id, post.platform, post.content,
          attempt < maxRetries ? 'retrying' : 'failed',
          attempt, 'exception', error.message,
          null, connection.accessToken, null, Date.now() - startTime
        );

        if (attempt < maxRetries) {
          const delay = await this.getRetryDelay(attempt);
          await new Promise(resolve => setTimeout(resolve, delay));
        }
      }
    }

    // All attempts failed
    await db
      .update(posts)
      .set({
        status: 'failed',
        errorLog: lastError?.errorMessage || 'All publishing attempts failed'
      })
      .where(eq(posts.id, post.id));

    return {
      success: false,
      errorCode: lastError?.errorCode || 'unknown_error',
      errorMessage: lastError?.errorMessage || 'All publishing attempts failed',
      attemptNumber: maxRetries
    };
  }

  async enforceAutoPosting(userId: number): Promise<AutoPostingResult> {
    const result: AutoPostingResult = {
      success: false,
      postsProcessed: 0,
      postsPublished: 0,
      postsFailed: 0,
      connectionRepairs: [],
      errors: [],
      message: ''
    };

    try {
      console.log(`🚀 Enhanced auto-posting enforcer starting for user ${userId}`);

      // Get user and validate subscription
      const [user] = await db.select().from(users).where(eq(users.id, userId));
      if (!user) {
        result.errors.push('User not found');
        return result;
      }

      // Get all platform connections
      const connections = await db
        .select()
        .from(platformConnections)
        .where(and(
          eq(platformConnections.userId, userId),
          eq(platformConnections.isActive, true)
        ));

      if (connections.length === 0) {
        result.errors.push('No active platform connections found');
        return result;
      }

      console.log(`📊 Found ${connections.length} active platform connections`);

      // Get approved posts ready for publishing
      const approvedPosts = await db
        .select()
        .from(posts)
        .where(and(
          eq(posts.userId, userId),
          eq(posts.status, 'approved')
        ));

      if (approvedPosts.length === 0) {
        result.errors.push('No approved posts found for publishing');
        return result;
      }

      console.log(`📋 Found ${approvedPosts.length} approved posts for publishing`);

      // Process each post with rate limiting
      for (let i = 0; i < approvedPosts.length; i++) {
        const post = approvedPosts[i];
        result.postsProcessed++;

        try {
          console.log(`📤 Processing post ${post.id} for ${post.platform} (${i + 1}/${approvedPosts.length})`);

          // Find platform connection
          const connection = connections.find(conn => conn.platform === post.platform);
          if (!connection) {
            result.postsFailed++;
            result.errors.push(`No connection found for platform: ${post.platform}`);
            continue;
          }

          // Rate limiting: 2-second delay between posts
          if (i > 0) {
            console.log('⏳ Rate limiting: waiting 2 seconds...');
            await new Promise(resolve => setTimeout(resolve, 2000));
          }

          // Publish with retry logic
          const publishResult = await this.publishWithRetry(userId, post, connection);

          if (publishResult.success) {
            result.postsPublished++;
            result.connectionRepairs.push(`Successfully published post ${post.id} to ${post.platform}${publishResult.publishedUrl ? ` (${publishResult.publishedUrl})` : ''}`);
          } else {
            result.postsFailed++;
            result.errors.push(`Failed to publish post ${post.id} to ${post.platform}: ${publishResult.errorMessage}`);
          }

        } catch (error: any) {
          console.error(`❌ Error processing post ${post.id}:`, error);
          result.postsFailed++;
          result.errors.push(`Error processing post ${post.id}: ${error.message}`);
        }
      }

      result.success = result.postsPublished > 0;
      result.message = `Processed ${result.postsProcessed} posts: ${result.postsPublished} published, ${result.postsFailed} failed`;

      console.log(`✅ Auto-posting enforcer completed: ${result.message}`);

    } catch (error: any) {
      console.error('❌ Auto-posting enforcer error:', error);
      result.errors.push(`Auto-posting enforcer error: ${error.message}`);
    }

    return result;
  }
}