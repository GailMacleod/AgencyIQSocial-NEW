import { storage } from './storage';
import { OAuthRefreshService } from './oauth-refresh';
import PostPublisher from './post-publisher';

interface DiagnosticResult {
  userId: number;
  userEmail: string;
  platformConnections: {
    platform: string;
    status: 'connected' | 'expired' | 'invalid' | 'missing_permissions';
    error?: string;
    lastTested: Date;
  }[];
  postStatus: {
    total: number;
    draft: number;
    approved: number;
    published: number;
    failed: number;
  };
  publishingErrors: string[];
  recommendations: string[];
  fixesApplied: string[];
}

export class PostDiagnosticsService {
  
  static async runComprehensiveDiagnostic(userId: number): Promise<DiagnosticResult> {
    console.log(`🔍 Running comprehensive post diagnostic for user ${userId}...`);
    
    const user = await storage.getUser(userId);
    if (!user) {
      throw new Error('User not found');
    }

    const result: DiagnosticResult = {
      userId,
      userEmail: user.email,
      platformConnections: [],
      postStatus: { total: 0, draft: 0, approved: 0, published: 0, failed: 0 },
      publishingErrors: [],
      recommendations: [],
      fixesApplied: []
    };

    // 1. Analyze platform connections
    await this.analyzePlatformConnections(userId, result);
    
    // 2. Analyze post status
    await this.analyzePostStatus(userId, result);
    
    // 3. Test publishing capabilities
    await this.testPublishingCapabilities(userId, result);
    
    // 4. Generate recommendations
    this.generateRecommendations(result);
    
    console.log(`✅ Diagnostic complete for ${user.email}:`, {
      connections: result.platformConnections.length,
      posts: result.postStatus.total,
      errors: result.publishingErrors.length,
      recommendations: result.recommendations.length
    });

    return result;
  }

  private static async analyzePlatformConnections(userId: number, result: DiagnosticResult): Promise<void> {
    const connections = await storage.getPlatformConnectionsByUser(userId);
    
    // Validate and refresh tokens
    const validation = await OAuthRefreshService.validateAllUserConnections(userId);
    
    for (const connection of connections) {
      let status: 'connected' | 'expired' | 'invalid' | 'missing_permissions' = 'connected';
      let error: string | undefined;

      if (!connection.isActive) {
        status = 'expired';
        error = 'Connection marked as inactive';
      } else if (validation.expiredConnections.includes(connection.platform)) {
        status = 'expired';
        error = 'OAuth token expired and refresh failed';
      } else if (connection.accessToken.includes('demo') || connection.accessToken.includes('mock')) {
        status = 'invalid';
        error = 'Using demo/mock token - not suitable for real publishing';
      } else if (validation.refreshedConnections.includes(connection.platform)) {
        result.fixesApplied.push(`Refreshed ${connection.platform} OAuth token`);
      }

      result.platformConnections.push({
        platform: connection.platform,
        status,
        error,
        lastTested: new Date()
      });
    }
  }

  private static async analyzePostStatus(userId: number, result: DiagnosticResult): Promise<void> {
    const posts = await storage.getPostsByUser(userId);
    
    result.postStatus = {
      total: posts.length,
      draft: posts.filter(p => p.status === 'draft').length,
      approved: posts.filter(p => p.status === 'approved').length,
      published: posts.filter(p => p.status === 'published').length,
      failed: posts.filter(p => p.status === 'failed').length
    };

    // Analyze failed posts for common errors
    const failedPosts = posts.filter(p => p.status === 'failed');
    for (const post of failedPosts) {
      if (post.errorLog) {
        result.publishingErrors.push(`${post.platform}: ${post.errorLog}`);
      }
    }
  }

  private static async testPublishingCapabilities(userId: number, result: DiagnosticResult): Promise<void> {
    // Test each platform's publishing capability with a test post
    const testContent = "🔧 The AgencyIQ - Connection Test Post (This is a system diagnostic - please ignore)";
    
    for (const connInfo of result.platformConnections) {
      if (connInfo.status !== 'connected') {
        continue;
      }

      try {
        // Create a temporary test post
        const testPost = await storage.createPost({
          userId,
          platform: connInfo.platform,
          content: testContent,
          status: 'draft',
          scheduledFor: new Date(),
          subscriptionCycle: '2025-06-16'
        });

        // Attempt to publish (this will reveal actual API issues)
        const publishResult = await PostPublisher.publishPost(userId, testPost.id, [connInfo.platform]);
        
        if (!publishResult.success) {
          const platformResult = publishResult.results[connInfo.platform];
          if (platformResult && platformResult.error) {
            result.publishingErrors.push(`${connInfo.platform}: ${platformResult.error}`);
            
            // Update connection info with specific error
            connInfo.error = platformResult.error;
            if (platformResult.error.includes('expired') || platformResult.error.includes('invalid')) {
              connInfo.status = 'expired';
            } else if (platformResult.error.includes('permission') || platformResult.error.includes('scope')) {
              connInfo.status = 'missing_permissions';
            }
          }
        } else {
          result.fixesApplied.push(`✅ ${connInfo.platform} publishing test successful`);
        }

        // Clean up test post
        await storage.deletePost(testPost.id);

      } catch (error: any) {
        result.publishingErrors.push(`${connInfo.platform} test failed: ${error.message}`);
      }
    }
  }

  private static generateRecommendations(result: DiagnosticResult): void {
    // Connection-based recommendations
    const expiredConnections = result.platformConnections.filter(c => c.status === 'expired');
    const invalidConnections = result.platformConnections.filter(c => c.status === 'invalid');
    const permissionIssues = result.platformConnections.filter(c => c.status === 'missing_permissions');

    if (expiredConnections.length > 0) {
      result.recommendations.push(
        `🔄 Reconnect expired platforms: ${expiredConnections.map(c => c.platform).join(', ')}`
      );
    }

    if (invalidConnections.length > 0) {
      result.recommendations.push(
        `🚫 Replace demo/mock tokens with real OAuth connections: ${invalidConnections.map(c => c.platform).join(', ')}`
      );
    }

    if (permissionIssues.length > 0) {
      result.recommendations.push(
        `🔐 Grant additional permissions during OAuth: ${permissionIssues.map(c => c.platform).join(', ')}`
      );
    }

    // Post-based recommendations
    if (result.postStatus.failed > 0) {
      result.recommendations.push(
        `🔧 ${result.postStatus.failed} failed posts need attention - check platform connections`
      );
    }

    if (result.postStatus.approved > 0 && result.platformConnections.filter(c => c.status === 'connected').length > 0) {
      result.recommendations.push(
        `📤 ${result.postStatus.approved} approved posts ready for publishing`
      );
    }

    // Error-based recommendations
    const facebookPageErrors = result.publishingErrors.filter(e => e.includes('Facebook') && e.includes('pages'));
    if (facebookPageErrors.length > 0) {
      result.recommendations.push(
        `📄 Facebook requires page management permissions - reconnect with 'pages_manage_posts' scope`
      );
    }

    const linkedinTokenErrors = result.publishingErrors.filter(e => e.includes('LinkedIn') && e.includes('expired'));
    if (linkedinTokenErrors.length > 0) {
      result.recommendations.push(
        `🔗 LinkedIn token expired - automatic refresh attempted, may need manual reconnection`
      );
    }

    const twitterAuthErrors = result.publishingErrors.filter(e => e.includes('Twitter') || e.includes('Unsupported Authentication'));
    if (twitterAuthErrors.length > 0) {
      result.recommendations.push(
        `🐦 X/Twitter authentication method updated - test posting should now work`
      );
    }
  }

  static async autoFixCommonIssues(userId: number): Promise<string[]> {
    const fixesApplied: string[] = [];
    
    try {
      // 1. Refresh expired tokens
      const validation = await OAuthRefreshService.validateAllUserConnections(userId);
      fixesApplied.push(...validation.refreshedConnections.map(p => `Refreshed ${p} token`));
      
      // 2. Clean up failed posts older than 24 hours
      const posts = await storage.getPostsByUser(userId);
      const oldFailedPosts = posts.filter(p => 
        p.status === 'failed' && 
        p.createdAt && 
        new Date().getTime() - new Date(p.createdAt).getTime() > 24 * 60 * 60 * 1000
      );
      
      for (const post of oldFailedPosts) {
        await storage.updatePost(post.id, { status: 'draft' });
      }
      
      if (oldFailedPosts.length > 0) {
        fixesApplied.push(`Reset ${oldFailedPosts.length} old failed posts to draft status`);
      }

      // 3. Validate subscription quota accuracy
      const user = await storage.getUser(userId);
      if (user) {
        const publishedPosts = posts.filter(p => p.status === 'published').length;
        const expectedRemaining = (user.totalPosts || 30) - publishedPosts;
        
        if (user.remainingPosts !== expectedRemaining) {
          await storage.updateUser(userId, { remainingPosts: expectedRemaining });
          fixesApplied.push(`Corrected post quota: ${expectedRemaining} remaining`);
        }
      }

    } catch (error: any) {
      console.error('Auto-fix error:', error);
      fixesApplied.push(`Auto-fix error: ${error.message}`);
    }

    return fixesApplied;
  }
}