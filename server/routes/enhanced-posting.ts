// Enhanced Social Media Posting Routes
// Real posting with OAuth integration and comprehensive error handling

import { Router } from 'express';
import { requireAuth, requireActiveSubscription } from '../middleware/auth-validation';
import { postingRateLimit, enforceQuota } from '../middleware/enhanced-security';
import { realSocialMediaPoster } from '../services/RealSocialMediaPoster';
import { notificationService } from '../services/NotificationService';
import { db } from '../db';
import { posts } from '../../shared/schema';
import { eq } from 'drizzle-orm';

const router = Router();

// Enhanced post publishing with real OAuth integration
router.post('/api/posts/:postId/publish', 
  requireAuth,
  requireActiveSubscription,
  postingRateLimit,
  enforceQuota('social_media', 'post', 20), // 20 posts per hour
  async (req, res) => {
    try {
      const { postId } = req.params;
      const userId = req.user!.id;

      // Get post from database
      const [post] = await db.select()
        .from(posts)
        .where(eq(posts.id, parseInt(postId)));

      if (!post) {
        return res.status(404).json({
          error: 'Post not found',
          code: 'POST_NOT_FOUND'
        });
      }

      if (post.userId !== userId) {
        return res.status(403).json({
          error: 'Unauthorized access to post',
          code: 'UNAUTHORIZED_POST'
        });
      }

      if (post.status === 'published') {
        return res.status(400).json({
          error: 'Post already published',
          code: 'ALREADY_PUBLISHED'
        });
      }

      // Prepare post data for publishing
      const postData = {
        id: post.id.toString(),
        content: post.content,
        platform: post.platform,
        userId: post.userId,
        scheduledAt: post.scheduledFor
      };

      // Attempt to publish
      const result = await realSocialMediaPoster.postToSocialMedia(postData);

      if (result.success) {
        // Update post status
        await db.update(posts)
          .set({
            status: 'published',
            publishedAt: new Date()
          })
          .where(eq(posts.id, post.id));

        res.json({
          success: true,
          message: 'Post published successfully',
          platformId: result.platformId,
          postId: post.id
        });
      } else {
        // Update post status to failed
        await db.update(posts)
          .set({
            status: 'failed',
            errorLog: result.errorMessage
          })
          .where(eq(posts.id, post.id));

        res.status(400).json({
          success: false,
          error: result.errorMessage,
          code: result.errorCode,
          shouldRetry: result.shouldRetry
        });
      }
    } catch (error) {
      console.error('Post publishing failed:', error);
      res.status(500).json({
        error: 'Publishing failed',
        code: 'PUBLISH_ERROR'
      });
    }
  }
);

// Bulk publishing with rate limiting
router.post('/api/posts/publish-batch',
  requireAuth,
  requireActiveSubscription,
  postingRateLimit,
  async (req, res) => {
    try {
      const { postIds } = req.body;
      const userId = req.user!.id;

      if (!Array.isArray(postIds) || postIds.length === 0) {
        return res.status(400).json({
          error: 'Post IDs array required',
          code: 'INVALID_POST_IDS'
        });
      }

      if (postIds.length > 10) {
        return res.status(400).json({
          error: 'Maximum 10 posts per batch',
          code: 'BATCH_LIMIT_EXCEEDED'
        });
      }

      const results = [];
      
      for (const postId of postIds) {
        try {
          const [post] = await db.select()
            .from(posts)
            .where(eq(posts.id, parseInt(postId)));

          if (post && post.userId === userId && post.status === 'approved') {
            const postData = {
              id: post.id.toString(),
              content: post.content,
              platform: post.platform,
              userId: post.userId
            };

            const result = await realSocialMediaPoster.postToSocialMedia(postData);
            
            if (result.success) {
              await db.update(posts)
                .set({
                  status: 'published',
                  publishedAt: new Date()
                })
                .where(eq(posts.id, post.id));
            }

            results.push({
              postId: post.id,
              success: result.success,
              platformId: result.platformId,
              error: result.errorMessage
            });

            // Add delay between posts to prevent platform bans
            await new Promise(resolve => setTimeout(resolve, 2000));
          }
        } catch (error) {
          results.push({
            postId,
            success: false,
            error: error.message
          });
        }
      }

      const successCount = results.filter(r => r.success).length;
      const failureCount = results.length - successCount;

      res.json({
        success: failureCount === 0,
        message: `Published ${successCount} posts, ${failureCount} failures`,
        results,
        summary: {
          total: results.length,
          successful: successCount,
          failed: failureCount
        }
      });
    } catch (error) {
      console.error('Batch publishing failed:', error);
      res.status(500).json({
        error: 'Batch publishing failed',
        code: 'BATCH_PUBLISH_ERROR'
      });
    }
  }
);

// Get posting history
router.get('/api/posts/:postId/history',
  requireAuth,
  async (req, res) => {
    try {
      const { postId } = req.params;
      const history = await realSocialMediaPoster.getPostHistory(postId);
      
      res.json({
        success: true,
        postId,
        history
      });
    } catch (error) {
      console.error('Failed to get post history:', error);
      res.status(500).json({
        error: 'Failed to get post history',
        code: 'HISTORY_ERROR'
      });
    }
  }
);

// Retry failed post
router.post('/api/posts/:postId/retry',
  requireAuth,
  postingRateLimit,
  async (req, res) => {
    try {
      const { postId } = req.params;
      const userId = req.user!.id;

      const [post] = await db.select()
        .from(posts)
        .where(eq(posts.id, parseInt(postId)));

      if (!post || post.userId !== userId) {
        return res.status(404).json({
          error: 'Post not found',
          code: 'POST_NOT_FOUND'
        });
      }

      if (post.status !== 'failed') {
        return res.status(400).json({
          error: 'Only failed posts can be retried',
          code: 'INVALID_STATUS'
        });
      }

      const postData = {
        id: post.id.toString(),
        content: post.content,
        platform: post.platform,
        userId: post.userId
      };

      const result = await realSocialMediaPoster.postToSocialMedia(postData);

      if (result.success) {
        await db.update(posts)
          .set({
            status: 'published',
            publishedAt: new Date(),
            errorLog: null
          })
          .where(eq(posts.id, post.id));

        res.json({
          success: true,
          message: 'Post published successfully on retry',
          platformId: result.platformId
        });
      } else {
        res.status(400).json({
          success: false,
          error: result.errorMessage,
          code: result.errorCode
        });
      }
    } catch (error) {
      console.error('Post retry failed:', error);
      res.status(500).json({
        error: 'Retry failed',
        code: 'RETRY_ERROR'
      });
    }
  }
);

export default router;