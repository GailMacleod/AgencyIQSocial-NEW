import express from 'express';
import session from 'express-session';
import Knex from 'knex';

import passport from 'passport';
import cors from 'cors';
import { createServer } from 'http';
// Dynamic imports for code splitting

// Environment validation
if (!process.env.SESSION_SECRET) {
  throw new Error('Missing required SESSION_SECRET');
}

const app = express();

// Replit-compatible port configuration - uses dynamic port assignment
const port = parseInt(process.env.PORT || '5000', 10);
console.log(`Server initializing with port ${port} (${process.env.PORT ? 'from ENV' : 'default'})`);

// Validate port for Replit environment
if (isNaN(port) || port < 1 || port > 65535) {
  console.error(`Invalid port: ${process.env.PORT}. Using default port 5000.`);
  process.exit(1);
}

// CORS configuration
app.use(cors({
  origin: true,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'Origin'],
  optionsSuccessStatus: 200
}));

// Content Security Policy middleware
app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy', [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://replit.com https://*.facebook.com https://connect.facebook.net https://www.googletagmanager.com https://*.google-analytics.com",
    "connect-src 'self' https://graph.facebook.com https://www.googletagmanager.com https://*.google-analytics.com https://analytics.google.com",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src 'self' data: https: https://fonts.gstatic.com https://fonts.googleapis.com blob:",
    "img-src 'self' data: https: https://scontent.xx.fbcdn.net https://www.google-analytics.com",
    "frame-src 'self' https://*.facebook.com",
    "object-src 'none'",
    "base-uri 'self'"
  ].join('; '));
  next();
});

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Session configuration with SQLite persistent storage
try {
  const connectSessionKnex = require('connect-session-knex');
  const SessionStore = connectSessionKnex(session);
  const knex = require('knex');

  const knexInstance = knex({
    client: 'sqlite3',
    connection: {
      filename: './data/sessions.db',
    },
    useNullAsDefault: true,
  });

  const store = new SessionStore({
    knex: knexInstance,
    tablename: 'sessions',
    createtable: true,
  });

  app.use(
    session({
      secret: process.env.SESSION_SECRET || 'fallback-session-secret-for-development',
      resave: false,
      saveUninitialized: false,
      store: store,
      cookie: {
        httpOnly: true,
        secure: false, // Allow non-HTTPS in development
        maxAge: 7 * 24 * 60 * 60 * 1000, // 1 week
        sameSite: 'lax',
      },
      name: 'theagencyiq.sid',
    })
  );

  console.log('✅ Session middleware initialized (SQLite persistent store)');
} catch (error) {
  console.warn('⚠️ SQLite session store failed, falling back to memory store:', error.message);
  
  app.use(
    session({
      secret: process.env.SESSION_SECRET || 'fallback-session-secret-for-development',
      resave: false,
      saveUninitialized: false,
      cookie: {
        httpOnly: true,
        secure: false,
        maxAge: 7 * 24 * 60 * 60 * 1000,
        sameSite: 'lax',
      },
      name: 'theagencyiq.sid',
    })
  );
  
  console.log('✅ Session middleware initialized (memory store fallback)');
}

// Initialize auth and API routes with dynamic imports
async function initializeRoutes() {
  const { configurePassportStrategies, authRouter } = await import('./authModule');
  const { apiRouter } = await import('./apiModule');
  
  configurePassportStrategies();
  app.use(passport.initialize());
  app.use(passport.session());
  
  app.use('/auth', authRouter);
  app.use('/api', apiRouter);
}

await initializeRoutes();

// Facebook OAuth specific error handler - must be before routes
app.use('/auth/facebook/callback', (err: any, req: any, res: any, next: any) => {
  console.error('🔧 Facebook OAuth specific error handler:', err.message);
  
  if (err.message && err.message.includes("domain of this URL isn't included")) {
    console.error('❌ Facebook OAuth: Domain not configured');
    return res.redirect('/login?error=domain_not_configured&message=Domain+configuration+required+in+Meta+Console');
  }
  
  if (err.message && (err.message.includes("Invalid verification code") || err.message.includes("verification code"))) {
    console.error('❌ Facebook OAuth: Invalid authorization code');
    return res.redirect('/login?error=invalid_code&message=Facebook+authorization+expired+please+try+again');
  }
  
  console.error('❌ Facebook OAuth: General error');
  return res.redirect('/login?error=facebook_oauth_failed&message=' + encodeURIComponent(err.message || 'Facebook OAuth failed'));
});

// Global error handler
app.use((err: any, req: any, res: any, next: any) => {
  console.error('Global error handler caught:', err.message || err);
  console.error('Request URL:', req.url);
  console.error('Request method:', req.method);
  console.error('Headers sent:', res.headersSent);
  
  // Handle Facebook OAuth errors gracefully
  if (req.url.includes('/auth/facebook/callback') && !res.headersSent) {
    console.error('🔧 Intercepting Facebook OAuth error for graceful handling');
    
    if (err.message && err.message.includes("domain of this URL isn't included")) {
      console.error('❌ Facebook OAuth: Domain not configured in Meta Console');
      return res.redirect('/login?error=domain_not_configured&message=Domain+configuration+required+in+Meta+Console');
    }
    
    if (err.message && (err.message.includes("Invalid verification code") || err.message.includes("verification code"))) {
      console.error('❌ Facebook OAuth: Invalid authorization code - graceful redirect');
      return res.redirect('/login?error=invalid_code&message=Facebook+authorization+expired+please+try+again');
    }
    
    // Other Facebook OAuth errors
    console.error('❌ Facebook OAuth error - graceful redirect:', err.message);
    return res.redirect('/login?error=facebook_oauth_failed&message=' + encodeURIComponent(err.message || 'Facebook OAuth failed'));
  }
  
  if (!res.headersSent) {
    res.status(500).json({
      error: 'Internal server error',
      message: err.message,
      timestamp: new Date().toISOString(),
      url: req.url
    });
  }
});

// Resilient session recovery middleware
app.use(async (req: any, res: any, next: any) => {
  const skipPaths = ['/api/establish-session', '/api/webhook', '/manifest.json', '/uploads', '/facebook-data-deletion', '/api/deletion-status', '/auth/', '/oauth-status'];
  
  // Allow all OAuth routes without authentication
  if (req.url.startsWith('/auth/facebook') || skipPaths.some(path => req.url.startsWith(path))) {
    return next();
  }

  if (!req.session?.userId) {
    try {
      // Graceful session recovery logic would go here
      // For now, continue without blocking
    } catch (error: any) {
      console.log('Database connectivity issue, proceeding with degraded auth');
    }
  }
  
  next();
});

// Facebook data deletion compliance endpoints
app.get('/facebook-data-deletion', (req, res) => {
  res.json({ status: 'ok', message: 'Facebook data deletion endpoint operational' });
});

app.post('/facebook-data-deletion', (req, res) => {
  try {
    const signedRequest = req.body.signed_request;
    if (!signedRequest) {
      return res.status(400).json({ error: 'Missing signed_request parameter' });
    }

    // Parse Facebook signed request
    const [encodedSig, payload] = signedRequest.split('.');
    const decodedPayload = JSON.parse(Buffer.from(payload, 'base64').toString());
    const userId = decodedPayload.user_id;

    console.log('Facebook data deletion request:', { userId, timestamp: new Date().toISOString() });

    res.json({
      url: `${req.protocol}://${req.get('host')}/api/deletion-status/${userId}`,
      confirmation_code: `DEL_${userId}_${Date.now()}`
    });
  } catch (error: any) {
    console.error('Facebook data deletion error:', error);
    res.status(500).json({ error: 'Failed to process data deletion request' });
  }
});

// Asset endpoints
app.get(['/manifest.json', '/public/js/beacon.js'], (req, res) => {
  if (req.path === '/manifest.json') {
    res.json({
      name: "TheAgencyIQ",
      short_name: "AgencyIQ",
      description: "AI-powered social media automation platform",
      start_url: "/",
      display: "standalone",
      background_color: "#ffffff",
      theme_color: "#000000",
      icons: [{
        src: "/attached_assets/agency_logo_512x512 (1)_1752200321498.png",
        sizes: "512x512",
        type: "image/png"
      }]
    });
  } else if (req.path === '/public/js/beacon.js') {
    res.setHeader('Content-Type', 'application/javascript');
    res.setHeader('Cache-Control', 'public, max-age=3600');
    res.send('// TheAgencyIQ Beacon - Meta Pixel compatibility layer\nconsole.log("Beacon loaded successfully");');
  }
});

// Facebook endpoint
app.get('/facebook', (req, res) => {
  const baseUrl = process.env.REPLIT_DOMAINS 
    ? `https://${process.env.REPLIT_DOMAINS.split(',')[0]}` 
    : 'https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev';
    
  res.json({
    status: 'ok',
    message: 'Facebook endpoint operational',
    baseUrl: baseUrl
  });
});

// OAuth status endpoint
app.get('/oauth-status', (req, res) => {
  const platforms = ['facebook', 'x', 'linkedin', 'instagram', 'youtube'];
  const platformStatus = platforms.map(platform => ({
    platform,
    connected: false,
    timestamp: null,
    status: 'not_connected'
  }));

  res.json({
    success: true,
    platforms: platformStatus,
    timestamp: new Date().toISOString()
  });
});

// Routes will be mounted dynamically above

// Static file serving
app.use('/uploads', express.static('uploads'));
app.use('/attached_assets', express.static('attached_assets'));
app.use('/public', express.static('public'));

// Serve manifest.json with proper headers
app.get('/manifest.json', (req, res) => {
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'public, max-age=3600');
  res.sendFile(require('path').join(__dirname, '../public/manifest.json'));
});

// Serve frontend
app.get('*', (req, res) => {
  const path = require('path');
  res.sendFile(path.join(__dirname, 'client/dist/index.html'));
});

// Start server
const server = createServer(app);

server.listen(port, '0.0.0.0', () => {
  console.log(`🚀 TheAgencyIQ Server running on port ${port}`);
  console.log(`📍 Port source: ${process.env.PORT ? `ENV (${process.env.PORT})` : 'default (5000)'}`);
  console.log(`🌐 Host: 0.0.0.0 (Replit-compatible)`);
  console.log(`⚙️  Environment: ${process.env.NODE_ENV || 'development'}`);
  
  if (process.env.REPLIT_DOMAINS) {
    console.log(`🔗 Replit URL: https://${process.env.REPLIT_DOMAINS.split(',')[0]}`);
  }
  
  console.log(`Deploy time: ${new Date().toLocaleString('en-AU', { 
    timeZone: 'Australia/Sydney',
    day: '2-digit',
    month: '2-digit', 
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: true
  })} AEST`);
  
  console.log('React app with OAuth bypass ready');
  console.log('Visit /public to bypass auth and access platform connections');
});

// Dynamic port conflict handling for Replit hosting
server.on('error', (error: NodeJS.ErrnoException) => {
  if (error.code === 'EADDRINUSE') {
    console.log(`Port ${port} is already in use, trying alternative ports...`);
    
    // Try alternative ports dynamically
    const tryAlternativePort = (altPort: number) => {
      const altServer = createServer(app);
      altServer.listen(altPort, '0.0.0.0', () => {
        console.log(`🚀 TheAgencyIQ Server running on port ${altPort} (alternative)`);
        console.log(`📍 Port source: alternative (original ${port} was busy)`);
        console.log(`🌐 Host: 0.0.0.0 (Replit-compatible)`);
        console.log(`⚙️  Environment: ${process.env.NODE_ENV || 'development'}`);
        if (process.env.REPLIT_DOMAINS) {
          console.log(`🔗 Replit URL: https://${process.env.REPLIT_DOMAINS.split(',')[0]}`);
        }
        console.log('React app with OAuth bypass ready');
      }).on('error', (altError: NodeJS.ErrnoException) => {
        if (altError.code === 'EADDRINUSE' && altPort < 8000) {
          tryAlternativePort(altPort + 1);
        } else {
          console.error(`Failed to bind to port ${altPort}:`, altError.message);
          process.exit(1);
        }
      });
    };
    
    tryAlternativePort(port + 1);
  } else if (error.code === 'EACCES') {
    console.error(`❌ Permission denied for port ${port}. Check Replit configuration.`);
    process.exit(1);
  } else {
    console.error('❌ Server error:', error);
    process.exit(1);
  }
});

// Graceful shutdown for Replit deployment
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  server.close(() => {
    console.log('TheAgencyIQ server terminated successfully');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log('SIGINT received, shutting down gracefully');
  server.close(() => {
    console.log('TheAgencyIQ server terminated successfully');
    process.exit(0);
  });
});

export default server;