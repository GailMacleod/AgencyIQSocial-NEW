import express, { Router, Request, Response, NextFunction } from 'express';
import session from 'express-session';
import passport from 'passport';
import bcrypt from 'bcryptjs';
import stripe from 'stripe';
import cookieParser from 'cookie-parser';
import crypto from 'crypto';
import { storage } from './storage';
import quotaManager from './quota-manager';
import postScheduler from './post-scheduler';
import twilioService from './twilio-service';
import { oauthService } from './oauth-service';
import grokService from './grok-service';
import veoService from './veo-service';
import { eq } from 'drizzle-orm';

interface MyRequest extends Request {
  session: session.Session & { userId?: string };
  user?: any;
}

const apiRouter: Router = express.Router();

require('./routes/auth')(apiRouter);

apiRouter.use(async (req: MyRequest, res: Response, next: NextFunction) => {
  if (req.session.userId && (req.path.startsWith('/post') || req.path.startsWith('/generate-content'))) {
    const quota = await quotaManager.checkQuota(req.session.userId);
    if (quota.remaining < 1) return res.status(403).json({ error: 'Quota exceeded - upgrade subscription' });
    const now = new Date();
    const cycleEnd = new Date(quota.cycleStart);
    cycleEnd.setDate(cycleEnd.getDate() + 30);
    if (now > cycleEnd) await quotaManager.resetQuotaCycle(req.session.userId);
  }
  next();
});

apiRouter.use(async (req: MyRequest, res: Response, next: NextFunction) => {
  if (req.path.startsWith('/post')) {
    const platform = req.body.platform;
    const limits = { facebook: 35, instagram: 50, linkedin: 50, x: 100, youtube: 6 };
    const dailyPosts = await storage.countDailyPosts(req.session.userId, platform);
    if (dailyPosts >= limits[platform]) return res.status(429).json({ error: 'Daily limit reached for ' + platform });
    let attempts = 0;
    while (attempts < 3) {
      try {
        await postScheduler.postToPlatform(req.session.userId, req.body.content, platform);
        break;
      } catch (error) {
        attempts++;
        await new Promise(r => setTimeout(r, 2 ** attempts * 1000));
      }
    }
    if (attempts === 3) return res.status(500).json({ error: 'Posting failed after retries' });
  }
  next();
});

apiRouter.use('/post', async (req: MyRequest, res: Response, next: NextFunction) => {
  const platform = req.body.platform;
  const tokens = await storage.getOAuthTokens(req.session.userId, platform);
  if (tokens.expired) {
    const refreshed = await oauthService.refreshTokens(tokens.refreshToken, platform);
    await storage.updateOAuthTokens(req.session.userId, platform, refreshed);
  }
  next();
});

apiRouter.post('/onboarding', async (req: MyRequest, res: Response) => {
  try {
    const { email, password, phone } = req.body;
    const existing = await storage.getUserByEmail(email);
    if (existing) return res.status(400).json({ error: 'Email in use' });
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await storage.createUser({ email, hashedPassword, phone });
    await twilioService.sendVerification(phone);
    req.session.userId = user.id;
    const stripeInstance = stripe(process.env.STRIPE_SECRET_KEY);
    const stripeSession = await stripeInstance.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: [{
        price_data: {
          currency: 'usd',
          product_data: { name: 'AgencyIQ Subscription' },
          unit_amount: 1000,
        },
        quantity: 1,
      }],
      mode: 'subscription',
      success_url: `${req.headers.origin}/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${req.headers.origin}/cancel`,
      metadata: { userId: user.id },
    });
    res.json({ success: true, stripeSessionUrl: stripeSession.url });
  } catch (error: unknown) {
    const e = error as Error;
    res.status(500).json({ error: 'Onboarding failed: ' + e.message });
  }
});

apiRouter.post('/deactivate-platform', async (req: MyRequest, res: Response) => {
  try {
    if (!req.session.userId) return res.status(401).json({ error: 'Unauthorized' });
    const { platform } = req.body;
    await oauthService.revokeTokens(req.session.userId, platform);
    res.json({ success: true });
  } catch (error: unknown) {
    const e = error as Error;
    res.status(500).json({ error: 'Deactivation failed: ' + e.message });
  }
});

apiRouter.post('/generate-content', async (req: MyRequest, res: Response) => {
  try {
    if (!req.session.userId) return res.status(401).json({ error: 'Unauthorized' });
    const quota = await quotaManager.checkQuota(req.session.userId);
    if (quota.remaining < 1) return res.status(403).json({ error: 'Quota exceeded' });
    const userPlan = await storage.getUserPlan(req.session.userId);
    if (userPlan !== 'professional') return res.status(403).json({ error: 'Veo 3.0 exclusive to Professional' });
    const prompt = req.body.prompt + ', JTBD-aligned, animal casting, cinematic';
    const content = await grokService.generateContent(prompt);
    const veoInit = await veoService.initiateVeoGeneration(content, { cinematic: true });
    await quotaManager.deductQuota(req.session.userId, 1);
    if (req.body.platform) {
      await postScheduler.postToPlatform(req.session.userId, content, req.body.platform);
    }
    res.json({ content, video: { isAsync: true, operationId: veoInit.operationId, pollEndpoint: `/api/video/operation/${veoInit.operationId}`, message: 'VEO 3.0 generation initiated - use operation ID to check status', pollInterval: 5000, estimatedTime: '115s to 6 minutes', status: 'processing' } });
  } catch (error: unknown) {
    const e = error as Error;
    res.status(500).json({ error: 'Content generation failed: ' + e.message });
  }
});

const rateLimit = require('express-rate-limit');
apiRouter.get('/video/operation/:opId', rateLimit({ windowMs: 5000, max: 1 }), async (req: MyRequest, res: Response) => {
  try {
    const status = await veoService.pollOperationStatus(req.params.opId, req.session.userId);
    if (status.status === 'completed') await quotaManager.deductQuota(req.session.userId, 1);
    res.json(status);
  } catch (error: unknown) {
    const e = error as Error;
    res.status(500).json({ error: 'Poll failed: ' + e.message });
  }
});

apiRouter.post('/stripe-webhook', express.raw({ type: 'application/json' }), async (req: Request, res: Response) => {
  try {
    const sig = req.headers['stripe-signature'] as string;
    const stripeInstance = stripe(process.env.STRIPE_SECRET_KEY);
    const event = stripeInstance.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
    let userId;
    if (event.type === 'checkout.session.completed') {
      userId = event.data.object.metadata.userId;
      await storage.activateSubscription(userId, event.data.object.id);
    } else if (event.type === 'customer.subscription.created' || event.type === 'customer.subscription.updated') {
      userId = event.data.object.metadata.userId;
      const priceId = event.data.object.items.data[0].price.id;
      const plan = priceId.includes('starter') ? 'starter' : priceId.includes('growth') ? 'growth' : 'professional';
      const quotas = { starter: 10, growth: 20, professional: 30 };
      await quotaManager.updateQuotaFromStripe(userId, quotas[plan]);
    } else if (event.type === 'customer.subscription.deleted') {
      userId = event.data.object.metadata.userId;
      await quotaManager.updateQuotaFromStripe(userId, 0);
    }
    res.json({ received: true });
  } catch (error: unknown) {
    const e = error as Error;
    res.status(400).json({ error: 'Webhook failed: ' + e.message });
  }
});

apiRouter.post('/data-deletion/facebook', async (req: MyRequest, res: Response) => {
  const { signed_request } = req.body;
  if (!signed_request) return res.status(400).json({ error: 'Missing signed_request' });
  try {
    const parsed = parseSignedRequest(signed_request, process.env.FACEBOOK_APP_SECRET);
    const fbUserId = parsed.user_id;
    await storage.deleteUserData(fbUserId);
    const deletionId = Date.now().toString();
    res.json({ url: `https://${req.headers.host}/api/deletion-status/${deletionId}`, confirmation_code: deletionId });
  } catch (error: unknown) {
    const e = error as Error;
    res.status(500).json({ error: 'Deletion failed: ' + e.message });
  }
});

function parseSignedRequest(signedRequest: string, secret: string) {
  const [encodedSig, payload] = signedRequest.split('.');
  const sig = Buffer.from(encodedSig.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('hex');
  const data = JSON.parse(Buffer.from(payload.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'));
  const expectedSig = crypto.createHmac('sha256', secret).update(payload).digest('hex');
  if (sig !== expectedSig) throw new Error('Invalid signature');
  return data;
}

apiRouter.get('/deletion-status/:id', (req: MyRequest, res: Response) => {
  const deletionId = req.params.id;
  res.json({ status: 'Deletion complete', confirmation_code: deletionId });
});

export { apiRouter };