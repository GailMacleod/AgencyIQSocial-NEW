import express from 'express';
import { createServer } from 'http';
import session from 'express-session';
import cors from 'cors';
import helmet from 'helmet';
import path from 'path';

// Import routes and services
import { registerRoutes } from './routes';
import { db } from './db';

// CommonJS-compatible __dirname
const __dirname = process.cwd();

const app = express();
const httpServer = createServer(app);

// Port configuration
const PORT = process.env.PORT || 5000;

// Environment configuration
const isDevelopment = process.env.NODE_ENV === 'development';
const baseUrl = isDevelopment 
  ? `https://${process.env.REPL_SLUG}.${process.env.REPL_OWNER}.repl.co`
  : 'https://app.theagencyiq.ai';

console.log('🌍 Server Environment:', {
  NODE_ENV: process.env.NODE_ENV,
  baseUrl,
  port: process.env.PORT,
  hasDatabase: !!process.env.DATABASE_URL
});

// Session configuration
const sessionConfig = {
  secret: process.env.SESSION_SECRET || 'your-secret-key-here',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: !isDevelopment,
    httpOnly: true,
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    sameSite: 'lax' as const
  }
};

// Middleware setup
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://connect.facebook.net", "https://www.googletagmanager.com"],
      imgSrc: ["'self'", "data:", "https:", "blob:"],
      fontSrc: ["'self'", "https://fonts.gstatic.com", "data:"],
      connectSrc: ["'self'", "https://api.x.ai", "https://graph.facebook.com"],
      frameSrc: ["'self'", "https://www.facebook.com"],
      frameAncestors: ["'self'", "https://www.facebook.com"]
    }
  }
}));

app.use(cors({
  origin: true,
  credentials: true
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Session middleware
app.use(session(sessionConfig));

// Static file serving
app.use('/public', express.static(path.join(__dirname, '../public')));
app.use('/attached_assets', express.static(path.join(__dirname, '../attached_assets')));

// API routes
console.log('📡 Loading routes...');
registerRoutes(app);
console.log('✅ Routes registered successfully');

// Production static file serving (minimal - API only)
if (!isDevelopment) {
  console.log('🏭 Setting up production API server...');
  
  // Catch-all for frontend routes (send simple response instead of missing file)
  app.get('*', (req, res) => {
    // If it's an API route, let it fall through to 404
    if (req.path.startsWith('/api/') || req.path.startsWith('/auth/')) {
      return res.status(404).json({ error: 'API endpoint not found' });
    }
    
    // For all other routes, send simple HTML response
    res.send(`<!DOCTYPE html>
<html>
<head>
    <title>TheAgencyIQ API Server</title>
</head>
<body>
    <h1>TheAgencyIQ API Server</h1>
    <p>CommonJS server running on port ${PORT}</p>
    <p>Facebook OAuth: <a href="/auth/facebook">Test Facebook OAuth</a></p>
    <p>Server Time: ${new Date().toISOString()}</p>
</body>
</html>`);
  });
  console.log('✅ Production API server setup complete');
}

// Global error handler
app.use((error: any, req: any, res: any, next: any) => {
  console.error('🚨 Global Error Handler:', {
    message: error.message,
    stack: error.stack,
    url: req.url,
    method: req.method,
    timestamp: new Date().toISOString()
  });
  
  res.status(500).json({
    error: 'Internal server error',
    message: isDevelopment ? error.message : 'Something went wrong'
  });
});

// Start server
async function startServer() {
  try {
    // Initialize database connection
    console.log('🗄️  Database connection initialized');
    
    httpServer.listen(Number(PORT), '0.0.0.0', () => {
      console.log(`🚀 TheAgencyIQ Server running on port ${PORT}`);
      console.log(`📍 Port source: ${process.env.PORT ? 'ENV' : 'default'} (${PORT})`);
      console.log(`🌐 Host: 0.0.0.0 (Replit-compatible)`);
      console.log(`⚙️  Environment: ${process.env.NODE_ENV || 'production'}`);
      console.log(`🔗 Replit URL: ${baseUrl}`);
      console.log(`Deploy time: ${new Date().toLocaleString('en-AU', { 
        timeZone: 'Australia/Brisbane',
        day: '2-digit',
        month: '2-digit', 
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
      })} AEST`);
      console.log('React app with OAuth bypass ready');
      console.log('Visit /public to bypass auth and access platform connections');
    });
  } catch (error) {
    console.error('❌ Server startup failed:', error);
    process.exit(1);
  }
}

startServer();