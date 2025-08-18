// Deployment-specific build configuration
export const deploymentConfig = {
  // Environment detection for production
  isProd: process.env.NODE_ENV === 'production' || process.env.REPLIT_DEPLOYED === 'true',
  
  // Build settings
  build: {
    target: 'node18',
    platform: 'node',
    format: 'esm' as const,
    bundle: true,
    external: ['sharp', '@node-rs/*']
  },
  
  // Session configuration for production
  session: {
    cookie: {
      secure: true, // HTTPS only in production
      httpOnly: true,
      maxAge: 72 * 60 * 60 * 1000, // 72 hours
      sameSite: 'lax' as const
    }
  },
  
  // Production OAuth callback URLs  
  oauth: {
    callbackUrls: {
      facebook: 'https://app.theagencyiq.ai/auth/facebook/callback',
      google: 'https://app.theagencyiq.ai/auth/google/callback', 
      linkedin: 'https://app.theagencyiq.ai/auth/linkedin/callback'
    }
  }
};

export function getDeploymentMode() {
  return deploymentConfig.isProd ? 'production' : 'development';
}