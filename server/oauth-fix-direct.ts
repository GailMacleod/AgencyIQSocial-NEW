import { storage } from './storage';

export class DirectOAuthFix {
  
  static async generateWorkingAuthUrls(userId: number): Promise<{
    facebook: string;
    linkedin: string;
    twitter: string;
    status: string;
  }> {
    
    const baseUrl = process.env.REPLIT_DOMAINS 
      ? `https://${process.env.REPLIT_DOMAINS.split(',')[0]}` 
      : 'http://localhost:5000';

    // Facebook OAuth URL with correct permissions for posting
    const facebookParams = new URLSearchParams({
      client_id: process.env.FACEBOOK_APP_ID!,
      redirect_uri: `${baseUrl}/auth/facebook/callback`,
      scope: 'pages_manage_posts,pages_read_engagement,publish_to_groups,pages_show_list,email',
      response_type: 'code',
      state: `user_${userId}_facebook`
    });
    
    const facebookUrl = `https://www.facebook.com/v18.0/dialog/oauth?${facebookParams.toString()}`;

    // LinkedIn OAuth URL with posting permissions
    const linkedinParams = new URLSearchParams({
      response_type: 'code',
      client_id: process.env.LINKEDIN_CLIENT_ID!,
      redirect_uri: `${baseUrl}/auth/linkedin/callback`,
      state: `user_${userId}_linkedin`,
      scope: 'w_member_social,r_liteprofile,r_emailaddress'
    });
    
    const linkedinUrl = `https://www.linkedin.com/oauth/v2/authorization?${linkedinParams.toString()}`;

    // Twitter OAuth 2.0 URL with tweet permissions
    const twitterParams = new URLSearchParams({
      response_type: 'code',
      client_id: process.env.TWITTER_CLIENT_ID!,
      redirect_uri: `${baseUrl}/auth/twitter/callback`,
      scope: 'tweet.read tweet.write users.read offline.access',
      state: `user_${userId}_twitter`,
      code_challenge: 'challenge',
      code_challenge_method: 'plain'
    });
    
    const twitterUrl = `https://twitter.com/i/oauth2/authorize?${twitterParams.toString()}`;

    return {
      facebook: facebookUrl,
      linkedin: linkedinUrl,
      twitter: twitterUrl,
      status: 'Direct OAuth URLs generated with proper posting permissions'
    };
  }

  static async testCurrentTokenStatus(userId: number): Promise<{
    facebook: { working: boolean; error: string; needsFix: boolean };
    linkedin: { working: boolean; error: string; needsFix: boolean };
    twitter: { working: boolean; error: string; needsFix: boolean };
    summary: string;
  }> {
    
    const connections = await storage.getPlatformConnectionsByUser(userId);
    
    const results = {
      facebook: { working: false, error: '', needsFix: true },
      linkedin: { working: false, error: '', needsFix: true },
      twitter: { working: false, error: '', needsFix: true },
      summary: ''
    };

    // Test Facebook token
    const fbConnection = connections.find(c => c.platform === 'facebook');
    if (fbConnection?.accessToken) {
      try {
        const response = await fetch(`https://graph.facebook.com/me?access_token=${fbConnection.accessToken}`);
        const data = await response.json();
        
        if (data.error) {
          results.facebook.error = data.error.message;
          results.facebook.needsFix = true;
        } else {
          results.facebook.working = true;
          results.facebook.needsFix = false;
        }
      } catch (error: any) {
        results.facebook.error = 'Facebook API connection failed';
      }
    } else {
      results.facebook.error = 'No Facebook token found';
    }

    // Test LinkedIn token
    const liConnection = connections.find(c => c.platform === 'linkedin');
    if (liConnection?.accessToken) {
      try {
        const response = await fetch('https://api.linkedin.com/v2/me', {
          headers: { 'Authorization': `Bearer ${liConnection.accessToken}` }
        });
        
        if (response.ok) {
          results.linkedin.working = true;
          results.linkedin.needsFix = false;
        } else {
          results.linkedin.error = 'LinkedIn token expired or invalid';
        }
      } catch (error: any) {
        results.linkedin.error = 'LinkedIn API connection failed';
      }
    } else {
      results.linkedin.error = 'No LinkedIn token found';
    }

    // Test Twitter token
    const twConnection = connections.find(c => c.platform === 'x' || c.platform === 'twitter');
    if (twConnection?.accessToken) {
      if (twConnection.accessToken.includes('twitter_token') || twConnection.accessToken.length < 50) {
        results.twitter.error = 'OAuth 1.0a token incompatible with API v2';
      } else {
        try {
          const response = await fetch('https://api.twitter.com/2/users/me', {
            headers: { 'Authorization': `Bearer ${twConnection.accessToken}` }
          });
          
          if (response.ok) {
            results.twitter.working = true;
            results.twitter.needsFix = false;
          } else {
            results.twitter.error = 'Twitter token invalid or expired';
          }
        } catch (error: any) {
          results.twitter.error = 'Twitter API connection failed';
        }
      }
    } else {
      results.twitter.error = 'No Twitter token found';
    }

    const workingCount = [results.facebook, results.linkedin, results.twitter]
      .filter(r => r.working).length;
    
    results.summary = `${workingCount}/3 platforms working. ${3 - workingCount} need OAuth reconnection.`;

    return results;
  }

  static async fixAllConnections(userId: number): Promise<{
    action: string;
    authUrls: any;
    instructions: string[];
  }> {
    
    const authUrls = await this.generateWorkingAuthUrls(userId);
    
    return {
      action: 'OAuth Reconnection Required',
      authUrls,
      instructions: [
        '1. Click the Facebook URL to reconnect with pages_manage_posts permission',
        '2. Click the LinkedIn URL to reconnect with w_member_social permission', 
        '3. Click the Twitter URL to upgrade to OAuth 2.0 with tweet.write permission',
        '4. After reconnecting, your 50 posts will publish successfully'
      ]
    };
  }
}