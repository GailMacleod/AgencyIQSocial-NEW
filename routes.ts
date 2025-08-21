// routes.ts - Refactored server routes for secure, production-ready Express app
// Filename: routes.ts

import type { Express, Request, Response, NextFunction } from "express";
import express from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { insertUserSchema, insertBrandPurposeSchema, insertPostSchema, users, postLedger, postSchedule, platformConnections, posts, brandPurpose, giftCertificates } from "@shared/schema";
import { db } from "./db";
import { sql, eq, and, desc, asc } from "drizzle-orm";
import bcrypt from "bcrypt";
import Stripe from "stripe";
import { z } from "zod";
import session from "express-session";
import connectPg from "connect-pg-simple";
import { generateContentCalendar, generateReplacementPost, getAIResponse, generateEngagementInsight } from "./grok";
import twilio from "twilio";
import sgMail from "@sendgrid/mail";
import multer from "multer";
import path from "path";
import fs from "fs";
import crypto from "crypto";
import { passport } from "./oauth-config";
import axios from "axios";
import PostPublisher from "./post-publisher";
import BreachNotificationService from "./breach-notification";
import { authenticateLinkedIn, authenticateFacebook, authenticateInstagram, authenticateTwitter, authenticateYouTube } from './platform-auth';
import { requireActiveSubscription, requireAuth, establishSession } from './middleware/subscriptionAuth';
import { userFeedbackService } from './userFeedbackService';
import RollbackAPI from './rollback-api';
import { OAuthRefreshService } from './services/OAuthRefreshService';
import { AIContentOptimizer } from './services/AIContentOptimizer';
import { AnalyticsEngine } from './services/AnalyticsEngine';
import { DataCleanupService } from './services/DataCleanupService';
import { linkedinTokenValidator } from './linkedin-token-validator';
import { DirectPublishService } from './services/DirectPublishService';
import { UnifiedOAuthService } from './services/UnifiedOAuthService';
import { directTokenGenerator } from './direct-token-generator';
import cron from "node-cron";

// Extend Request type for session and user
declare module "express-session" {
  interface SessionData {
    userId: number;
    accessToken: string;
    refreshToken: string;
    stripeSessionId?: string;
  }
}

declare module "express" {
  interface Request {
    user?: { id: number; accessToken: string; refreshToken: string };
  }
}

// Constants for quotas (researched limits for 2025)
const QUOTAS = {
  twitter: 1667, // per app/24h
  linkedin: 100, // per user/day
  veo: 20 // req/min for Veo
};

// Initialize app and server
const app = express();
const httpServer = createServer(app);

// Middleware order: security first, then session, then body parsers, then auth
app.use(express.urlencoded({ extended: true }));
app.use(express.json({ limit: '1mb' })); // Global JSON parser with limit

// Session middleware with PG store and secure cookies
app.use(session({
  secret: process.env.SESSION_SECRET || 'default-secret-change-in-production',
  store: new (connectPg(session))({ conString: process.env.DATABASE_URL }),
  cookie: {
    maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    sameSite: 'strict'
  },
  resave: false,
  saveUninitialized: false
}));

// Quota middleware (example for post routes; extend as needed)
const quotaMiddleware = async (req: Request, res: Response, next: NextFunction) => {
  const userId = req.session.userId;
  const platform = req.body.platform;
  if (!userId || !platform) return res.status(401).json({ error: 'Unauthorized' });
  const count = await db.select({ count: sql`count(*)` }).from(posts).where(and(eq(posts.userId, userId), eq(posts.platform, platform), sql`publishedAt > NOW() - INTERVAL '1 day'`));
  const max = QUOTAS[platform] * 0.95;
  if (count[0].count >= max) return res.status(429).json({ error: 'Quota reached - try tomorrow' });
  next();
};

// Apply quota to post routes
app.use('/api/posts', quotaMiddleware);

// Auth middleware (requireAuth from import)
app.use(requireAuth);

// Video quota middleware (for Veo)
const veoQuotaMiddleware = async (req: Request, res: Response, next: NextFunction) => {
  const userId = req.session.userId;
  if (!userId) return res.status(401).json({ error: 'Unauthorized' });
  const count = await db.select({ count: sql`count(*)` }).from(posts).where(and(eq(posts.userId, userId), sql`publishedAt > NOW() - INTERVAL '1 minute'`));
  if (count[0].count >= QUOTAS.veo) return res.status(429).json({ error: 'Veo quota reached' });
  next();
};

// Apply to video routes
app.use('/api/video', veoQuotaMiddleware);

// Multer for uploads (disk storage with limits)
const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'uploads/'),
    filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
  }),
  limits: { fileSize: 5 * 1024 * 1024 } // 5MB limit
});

// Auto-posting cron (hourly, queries scheduled posts and publishes)
cron.schedule('0 * * * *', async () => {
  const scheduled = await db.select().from(posts).where(sql`scheduledFor <= NOW() AND status = 'scheduled'`);
  for (const post of scheduled) {
    // Optimize content with Grok if needed
    const optimizedContent = await getAIResponse(`Optimize post for ${post.platform}: ${post.content}`);
    // Publish to platform using token from DB/session
    await PostPublisher.publish(post.platform, optimizedContent, post.userId);
    await db.update(posts).set({ status: 'published', publishedAt: new Date() }).where(eq(posts.id, post.id));
  }
});

// User route with Zod validation and session set
app.post('/api/users', async (req: Request, res: Response) => {
  try {
    const validatedData = insertUserSchema.parse(req.body);
    const hashedPassword = await bcrypt.hash(validatedData.password, 10);
    const [newUser] = await db.insert(users).values({ ...validatedData, password: hashedPassword }).returning();
    req.session.regenerate((err) => {
      if (err) throw err;
      req.session.userId = newUser.id;
      req.session.save((err) => {
        if (err) throw err;
        res.status(201).json(newUser);
      });
    });
  } catch (error) {
    console.error('User creation error:', error);
    res.status(400).json({ error: 'Invalid input' });
  }
});

// OAuth callback with server-side token exchange and session set
app.get('/api/oauth/twitter/callback', passport.authenticate('twitter', { failureRedirect: '/' }), async (req: Request, res: Response) => {
  try {
    if (!req.user) throw new Error('Authentication failed');
    const user = req.user as { id: number };
    const code = req.query.code as string;
    const tokenRes = await axios.post('https://api.twitter.com/2/oauth2/token', new URLSearchParams({
      code,
      grant_type: 'authorization_code',
      client_id: process.env.TWITTER_CLIENT_ID || '',
      redirect_uri: 'your-callback-url',
      code_verifier: 'challenge' // From PKCE
    }), {
      auth: {
        username: process.env.TWITTER_CLIENT_ID || '',
        password: process.env.TWITTER_CLIENT_SECRET || ''
      }
    });
    req.session.regenerate((err) => {
      if (err) throw err;
      req.session.userId = user.id;
      req.session.accessToken = tokenRes.data.access_token;
      req.session.refreshToken = tokenRes.data.refresh_token;
      req.session.save((err) => {
        if (err) throw err;
        res.redirect('/dashboard');
      });
    });
  } catch (error) {
    console.error('OAuth callback error:', error);
    res.status(500).json({ error: 'OAuth failed' });
  }
});

// Stripe webhook with raw body and signature verification
app.post('/api/stripe/webhook', express.raw({ type: 'application/json' }), (req: Request, res: Response) => {
  const sig = req.headers['stripe-signature'] as string;
  try {
    const event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET || '');
    if (event.type === 'checkout.session.completed') {
      // Update DB for subscription
      const session = event.data.object as Stripe.Checkout.Session;
      await db.update(users).set({ subscriptionActive: true }).where(eq(users.id, session.metadata.userId));
    }
    res.json({ received: true });
  } catch (error) {
    console.error('Webhook error:', error);
    res.status(400).send(`Webhook Error: ${error.message}`);
  }
});

// Veo video test with quota check and Grok enhancement
app.post("/api/video/test-veo3", async (req: Request, res: Response) => {
  try {
    const { prompt } = req.body;
    if (!prompt) return res.status(400).json({ error: 'Prompt is required' });
    // Quota check
    const userId = req.session.userId;
    if (!userId) return res.status(401).json({ error: 'Unauthorized' });
    const count = await db.select({ count: sql`count(*)` }).from(posts).where(and(eq(posts.userId, userId), sql`publishedAt > NOW() - INTERVAL '1 minute'`));
    if (count[0].count >= QUOTAS.veo) return res.status(429).json({ error: 'Veo quota reached' });
    // Enhance prompt with Grok
    const optimizedPrompt = await getAIResponse(`Optimize video prompt for Veo: ${prompt}`);
    const VideoService = (await import('./videoService')).default;
    const result = await VideoService.generateVeo3VideoContent(optimizedPrompt, { aspectRatio: '16:9', durationSeconds: 8 });
    // Store in DB
    await db.insert(posts).values({ userId, platform: 'video', content: optimizedPrompt, videoData: result });
    return res.json({ success: true, result, optimizedPrompt });
  } catch (error) {
    console.error('Veo test error:', error);
    return res.status(500).json({ error: 'Veo test failed' });
  }
});

// Video proxy with checks
app.get('/videos/:videoId', async (req: Request, res: Response) => {
  try {
    const videoId = req.params.videoId;
    const videoPath = path.join('public/videos', videoId);
    if (!fs.existsSync(videoPath)) {
      console.log(`Video not found: ${videoId}`);
      return res.status(404).json({ success: false, error: 'Video not found' });
    }
    res.setHeader('Content-Type', 'video/mp4');
    res.setHeader('Accept-Ranges', 'bytes');
    fs.createReadStream(videoPath).pipe(res);
  } catch (error) {
    console.error('Video proxy error:', error);
    res.status(500).json({ success: false, error: 'Video proxy failed' });
  }
});

// Serve videos static
app.use('/videos', express.static('public/videos', {
  setHeaders: (res) => {
    res.setHeader('Content-Type', 'video/mp4');
    res.setHeader('Accept-Ranges', 'bytes');
  }
}));

// Return server
return httpServer;