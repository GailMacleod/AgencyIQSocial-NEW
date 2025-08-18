/**
 * X Platform Integration using OAuth 1.0a
 * Handles posting to X with proper authentication
 */

import crypto from 'crypto';

export class XIntegration {
  private consumerKey: string;
  private consumerSecret: string;
  private accessToken: string;
  private accessTokenSecret: string;

  constructor() {
    this.consumerKey = process.env.X_0AUTH_CLIENT_ID!;
    this.consumerSecret = process.env.X_0AUTH_CLIENT_SECRET!;
    this.accessToken = process.env.X_ACCESS_TOKEN!;
    this.accessTokenSecret = process.env.X_ACCESS_TOKEN_SECRET!;
  }

  private generateOAuthSignature(method: string, url: string, params: Record<string, string>): string {
    // Sort parameters
    const sortedParams = Object.keys(params)
      .sort()
      .map(key => `${this.percentEncode(key)}=${this.percentEncode(params[key])}`)
      .join('&');

    // Create signature base string
    const baseString = `${method}&${this.percentEncode(url)}&${this.percentEncode(sortedParams)}`;
    
    // Create signing key
    const signingKey = `${this.percentEncode(this.consumerSecret)}&${this.percentEncode(this.accessTokenSecret)}`;
    
    // Generate signature
    const signature = crypto
      .createHmac('sha1', signingKey)
      .update(baseString)
      .digest('base64');

    return signature;
  }

  private percentEncode(str: string): string {
    return encodeURIComponent(str)
      .replace(/[!'()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase());
  }

  async postTweet(text: string): Promise<{ success: boolean; data?: any; error?: string }> {
    // Try OAuth 2.0 Bearer token first if available
    if (process.env.X_USER_ACCESS_TOKEN) {
      try {
        const response = await fetch('https://api.twitter.com/2/tweets', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${process.env.X_USER_ACCESS_TOKEN}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ text })
        });

        const result = await response.json();

        if (response.ok) {
          return {
            success: true,
            data: {
              id: result.data.id,
              text: result.data.text,
              url: `https://twitter.com/i/web/status/${result.data.id}`
            }
          };
        }
      } catch (error) {
        console.log('OAuth 2.0 Bearer token failed, trying OAuth 1.0a...');
      }
    }

    // Fallback to OAuth 1.0a
    const url = 'https://api.twitter.com/1.1/statuses/update.json';
    const method = 'POST';
    
    const oauthParams: Record<string, string> = {
      oauth_consumer_key: this.consumerKey,
      oauth_token: this.accessToken,
      oauth_signature_method: 'HMAC-SHA1',
      oauth_timestamp: Math.floor(Date.now() / 1000).toString(),
      oauth_nonce: crypto.randomBytes(16).toString('hex'),
      oauth_version: '1.0',
      status: text
    };

    const signature = this.generateOAuthSignature(method, url, oauthParams);
    
    const authParams = { ...oauthParams };
    delete authParams.status;
    authParams.oauth_signature = signature;

    const authHeader = 'OAuth ' + Object.keys(authParams)
      .map(key => `${key}="${this.percentEncode(authParams[key])}"`)
      .join(', ');

    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Authorization': authHeader,
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: `status=${encodeURIComponent(text)}`
      });

      const result = await response.json();

      if (response.ok) {
        return {
          success: true,
          data: {
            id: result.id_str,
            text: result.text,
            url: `https://twitter.com/i/web/status/${result.id_str}`
          }
        };
      } else {
        return {
          success: false,
          error: `X API Error: ${response.status} - ${JSON.stringify(result)}`
        };
      }
    } catch (error) {
      return {
        success: false,
        error: `Network error: ${error instanceof Error ? error.message : 'Unknown error'}`
      };
    }
  }

  async testConnection(): Promise<{ success: boolean; error?: string }> {
    try {
      const result = await this.postTweet('TheAgencyIQ X integration test - connection verified!');
      return { success: result.success, error: result.error };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }
}

export const xIntegration = new XIntegration();