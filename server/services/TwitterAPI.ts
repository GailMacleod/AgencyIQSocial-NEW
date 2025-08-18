/**
 * TWITTER/X API INTEGRATION 
 * Production-ready tweepy-style integration with OAuth 1.0a for posting queue
 */

import OAuth from 'oauth-1.0a';
import crypto from 'crypto';
import fetch from 'node-fetch';

interface TwitterCredentials {
  consumerKey: string;
  consumerSecret: string;
  accessToken: string;
  accessTokenSecret: string;
}

interface TweetResponse {
  success: boolean;
  tweetId?: string;
  error?: string;
  rateLimited?: boolean;
}

export class TwitterAPI {
  private oauth: any;
  private credentials: TwitterCredentials;

  constructor(credentials: TwitterCredentials) {
    this.credentials = credentials;
    
    this.oauth = new OAuth({
      consumer: {
        key: credentials.consumerKey,
        secret: credentials.consumerSecret
      },
      signature_method: 'HMAC-SHA1',
      hash_function: (baseString: string, key: string) => {
        return crypto.createHmac('sha1', key).update(baseString).digest('base64');
      }
    });
  }

  /**
   * Post tweet with OAuth 1.0a authentication
   */
  async postTweet(content: string): Promise<TweetResponse> {
    try {
      // Ensure content is within Twitter's character limit
      if (content.length > 280) {
        content = content.substring(0, 277) + '...';
      }

      const requestData = {
        url: 'https://api.twitter.com/2/tweets',
        method: 'POST',
        data: { text: content }
      };

      const token = {
        key: this.credentials.accessToken,
        secret: this.credentials.accessTokenSecret
      };

      // Generate OAuth headers
      const authHeader = this.oauth.toHeader(this.oauth.authorize(requestData, token));

      console.log(`🐦 Posting to X: "${content.substring(0, 50)}..."`);

      const response = await fetch(requestData.url, {
        method: 'POST',
        headers: {
          'Authorization': authHeader.Authorization,
          'Content-Type': 'application/json',
          'User-Agent': 'TheAgencyIQ/1.0'
        },
        body: JSON.stringify(requestData.data)
      });

      const responseData = await response.json();

      if (response.ok && responseData.data?.id) {
        console.log(`✅ X post successful: ${responseData.data.id}`);
        return {
          success: true,
          tweetId: responseData.data.id
        };
      } else if (response.status === 429) {
        // Rate limited
        console.log(`⏳ X API rate limited`);
        return {
          success: false,
          error: 'Rate limited',
          rateLimited: true
        };
      } else {
        const errorMsg = responseData.errors?.[0]?.message || responseData.detail || 'Unknown error';
        console.log(`❌ X post failed: ${errorMsg}`);
        return {
          success: false,
          error: errorMsg
        };
      }

    } catch (error: any) {
      console.error('❌ X API error:', error.message);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Test connection and credentials
   */
  async testConnection(): Promise<{ success: boolean; error?: string }> {
    try {
      const requestData = {
        url: 'https://api.twitter.com/2/users/me',
        method: 'GET'
      };

      const token = {
        key: this.credentials.accessToken,
        secret: this.credentials.accessTokenSecret
      };

      const authHeader = this.oauth.toHeader(this.oauth.authorize(requestData, token));

      const response = await fetch(requestData.url, {
        method: 'GET',
        headers: {
          'Authorization': authHeader.Authorization,
          'User-Agent': 'TheAgencyIQ/1.0'
        }
      });

      if (response.ok) {
        const data = await response.json();
        console.log(`✅ X API connection test successful for @${data.data?.username}`);
        return { success: true };
      } else {
        const errorData = await response.json();
        const errorMsg = errorData.errors?.[0]?.message || 'Connection test failed';
        return { success: false, error: errorMsg };
      }

    } catch (error: any) {
      return { success: false, error: error.message };
    }
  }

  /**
   * Get rate limit status
   */
  async getRateLimitStatus(): Promise<{ 
    remaining: number; 
    resetTime: Date; 
    limit: number; 
  } | null> {
    try {
      const requestData = {
        url: 'https://api.twitter.com/1.1/application/rate_limit_status.json?resources=statuses',
        method: 'GET'
      };

      const token = {
        key: this.credentials.accessToken,
        secret: this.credentials.accessTokenSecret
      };

      const authHeader = this.oauth.toHeader(this.oauth.authorize(requestData, token));

      const response = await fetch(requestData.url, {
        method: 'GET',
        headers: {
          'Authorization': authHeader.Authorization,
          'User-Agent': 'TheAgencyIQ/1.0'
        }
      });

      if (response.ok) {
        const data = await response.json();
        const statusUpdate = data.resources?.statuses?.['/statuses/update'];
        
        if (statusUpdate) {
          return {
            remaining: statusUpdate.remaining,
            resetTime: new Date(statusUpdate.reset * 1000),
            limit: statusUpdate.limit
          };
        }
      }

      return null;
    } catch (error) {
      console.error('Failed to get rate limit status:', error);
      return null;
    }
  }

  /**
   * Create from environment variables
   */
  static fromEnvironment(): TwitterAPI | null {
    const consumerKey = process.env.X_CONSUMER_KEY;
    const consumerSecret = process.env.X_CONSUMER_SECRET;
    const accessToken = process.env.X_ACCESS_TOKEN;
    const accessTokenSecret = process.env.X_ACCESS_TOKEN_SECRET;

    if (!consumerKey || !consumerSecret || !accessToken || !accessTokenSecret) {
      console.log('❌ Missing X/Twitter API credentials in environment variables');
      return null;
    }

    return new TwitterAPI({
      consumerKey,
      consumerSecret,
      accessToken,
      accessTokenSecret
    });
  }

  /**
   * Create from platform connection
   */
  static fromPlatformConnection(connection: any): TwitterAPI | null {
    try {
      // Parse OAuth tokens from connection
      const credentials = {
        consumerKey: process.env.X_CONSUMER_KEY || '',
        consumerSecret: process.env.X_CONSUMER_SECRET || '',
        accessToken: connection.accessToken || '',
        accessTokenSecret: connection.refreshToken || connection.accessTokenSecret || ''
      };

      if (!credentials.consumerKey || !credentials.consumerSecret || 
          !credentials.accessToken || !credentials.accessTokenSecret) {
        console.log('❌ Incomplete X/Twitter credentials in platform connection');
        return null;
      }

      return new TwitterAPI(credentials);
    } catch (error) {
      console.error('❌ Failed to create TwitterAPI from platform connection:', error);
      return null;
    }
  }
}