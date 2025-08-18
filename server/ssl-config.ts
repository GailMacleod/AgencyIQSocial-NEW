// SSL and domain configuration for https://app.theagencyiq.ai
export const SSL_CONFIG = {
  production: {
    domain: 'app.theagencyiq.ai',
    protocol: 'https',
    port: 443,
    enforceHttps: true,
    hstsMaxAge: 31536000, // 1 year
    hstsIncludeSubdomains: true,
    hstsPreload: true
  },
  development: {
    domain: 'localhost',
    protocol: 'http',
    port: 5000,
    enforceHttps: false
  }
};

export const ALLOWED_ORIGINS = [
  'https://app.theagencyiq.ai',
  'https://theagencyiq.ai',
  'https://www.theagencyiq.ai',
  'https://agency-iq-social-GailMac.replit.app',
  'https://*.replit.app',
  'http://localhost:5000',
  'http://localhost:3000'
];

export const SECURITY_HEADERS = {
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'X-XSS-Protection': '1; mode=block',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://checkout.stripe.com https://js.stripe.com https://www.googletagmanager.com https://www.google-analytics.com https://replit.com https://*.replit.app; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com https://fonts.googleapis.com data:; img-src 'self' data: https: blob:; connect-src 'self' https://api.stripe.com https://api.x.ai https://api.xai.com https://checkout.stripe.com https://www.google-analytics.com https://www.googletagmanager.com https://graph.facebook.com https://api.instagram.com https://api.linkedin.com https://api.twitter.com https://www.googleapis.com https://oauth2.googleapis.com https://accounts.google.com https://*.replit.app wss://app.theagencyiq.ai wss://*.replit.app; frame-src https://checkout.stripe.com https://js.stripe.com https://accounts.google.com; worker-src 'self' blob:;",
  'Permissions-Policy': 'camera=(), fullscreen=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), sync-xhr=(), usb=(), screen-wake-lock=(), web-share=()'
};

export function validateDomain(hostname: string): boolean {
  const allowedDomains = [
    'app.theagencyiq.ai',
    'theagencyiq.ai',
    'www.theagencyiq.ai',
    'agency-iq-social-GailMac.replit.app',
    'localhost'
  ];
  
  // Allow any .replit.app subdomain
  const isReplitDomain = hostname.endsWith('.replit.app');
  
  return allowedDomains.includes(hostname) || isReplitDomain;
}

export function isSecureContext(req: any): boolean {
  return req.secure || req.header('x-forwarded-proto') === 'https';
}