// oauth-service.ts
export const oauthService = {
  async revokeTokens(userId: number, platform: string) {
    const revokeUrls = {
      facebook: 'https://graph.facebook.com/v20.0/me/permissions?access_token={token}',
      instagram: 'https://graph.facebook.com/v20.0/me/permissions?access_token={token}',
      linkedin: 'https://api.linkedin.com/v2/accessToken',
      x: 'https://api.twitter.com/2/oauth2/revoke',
      youtube: 'https://accounts.google.com/o/oauth2/revoke'
    };
    console.log(`Revoking ${platform} token at ${revokeUrls[platform]}`);
  },
};