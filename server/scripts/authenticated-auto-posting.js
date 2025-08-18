#!/usr/bin/env node
// Authenticated Auto-Posting Script
// Ensures all database operations require valid session authentication

import { AutoPostingAuth } from '../middleware/database-auth.js';
import { logger } from '../utils/logger.js';

class AuthenticatedAutoPosting {
  constructor() {
    this.requiredCookies = ['theagencyiq.session'];
    this.authenticatedDB = null;
  }

  // Validate session cookies before any database operations
  validateEnvironment() {
    const sessionCookie = process.env.SESSION_COOKIE;
    const userId = process.env.USER_ID;

    if (!sessionCookie) {
      throw new Error('SESSION_COOKIE environment variable required for authenticated auto-posting');
    }

    if (!userId) {
      throw new Error('USER_ID environment variable required for authenticated auto-posting');
    }

    // Validate cookie format
    if (!sessionCookie.includes('theagencyiq.session=')) {
      throw new Error('Invalid session cookie format. Must include theagencyiq.session=');
    }

    logger.info('Environment validation passed for authenticated auto-posting', {
      userId,
      hasSessionCookie: true,
      timestamp: new Date().toISOString()
    });

    return { sessionCookie, userId };
  }

  // Initialize authenticated database connection
  async initialize() {
    try {
      const { sessionCookie, userId } = this.validateEnvironment();
      
      // Validate posting request with authentication
      await AutoPostingAuth.validatePostingRequest(sessionCookie, userId);
      
      // Create authenticated auto-posting service
      this.authenticatedService = await AutoPostingAuth.createAuthenticatedAutoPosting(sessionCookie);
      
      logger.info('Authenticated auto-posting service initialized', {
        userId,
        authenticated: this.authenticatedService.authenticated,
        timestamp: new Date().toISOString()
      });

      return true;
    } catch (error) {
      logger.error('Failed to initialize authenticated auto-posting', {
        error: error.message,
        timestamp: new Date().toISOString()
      });
      throw error;
    }
  }

  // Execute authenticated auto-posting
  async executeAutoPosting(postData) {
    if (!this.authenticatedService) {
      throw new Error('Auto-posting service not initialized. Call initialize() first.');
    }

    try {
      logger.info('Starting authenticated auto-posting execution', {
        postId: postData.id,
        platform: postData.platform,
        authenticated: true
      });

      const result = await this.authenticatedService.executePost(postData);
      
      logger.info('Authenticated auto-posting completed successfully', {
        postId: postData.id,
        platform: postData.platform,
        success: result.success,
        timestamp: new Date().toISOString()
      });

      return result;
    } catch (error) {
      logger.error('Authenticated auto-posting failed', {
        error: error.message,
        postId: postData.id,
        platform: postData.platform,
        timestamp: new Date().toISOString()
      });
      throw error;
    }
  }

  // Validate session before any database query
  async executeAuthenticatedQuery(query, params = []) {
    if (!this.authenticatedService) {
      throw new Error('Database service not authenticated. Call initialize() first.');
    }

    try {
      logger.info('Executing authenticated database query', {
        query: query.substring(0, 50) + '...',
        authenticated: true,
        timestamp: new Date().toISOString()
      });

      // Execute query with authenticated database connection
      const result = await this.authenticatedService.db.execute(query, params);
      
      return result;
    } catch (error) {
      logger.error('Authenticated database query failed', {
        error: error.message,
        query: query.substring(0, 50) + '...',
        timestamp: new Date().toISOString()
      });
      throw error;
    }
  }
}

// Command-line interface for authenticated auto-posting
async function main() {
  if (import.meta.url === `file://${process.argv[1]}`) {
    try {
      const autoPosting = new AuthenticatedAutoPosting();
      
      // Initialize with session authentication
      await autoPosting.initialize();
      
      console.log('✅ Authenticated auto-posting service ready');
      console.log('📋 Session validation: PASSED');
      console.log('🔐 Database access: AUTHENTICATED');
      
      // Example usage - replace with actual post data
      const examplePost = {
        id: 'test-post-' + Date.now(),
        platform: 'facebook',
        content: 'Test authenticated post',
        userId: process.env.USER_ID
      };
      
      const result = await autoPosting.executeAutoPosting(examplePost);
      
      console.log('✅ Auto-posting execution completed:', result);
      
    } catch (error) {
      console.error('❌ Authenticated auto-posting failed:', error.message);
      process.exit(1);
    }
  }
}

// Usage instructions
if (import.meta.url === `file://${process.argv[1]}`) {
  console.log('🔐 Authenticated Auto-Posting Script');
  console.log('📋 Required environment variables:');
  console.log('   SESSION_COOKIE="theagencyiq.session=your_session_id"');
  console.log('   USER_ID="your_user_id"');
  console.log('');
  
  main().catch(console.error);
}

export { AuthenticatedAutoPosting };