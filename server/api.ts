// server/api.ts (or client/src/lib/server/api.ts if you must keep it inside client)
// Express API router (server-only). Do NOT include this file in the Vite client build.

import express, {
  Router,
  Request,
  Response,
  NextFunction,
  RequestHandler,
} from 'express';
import session from 'express-session';
import bcrypt from 'bcryptjs';
import Stripe from 'stripe';
import crypto from 'crypto';
import rateLimit from 'express-rate-limit';

// --- Server-side services (must exist in your server codebase) ---
import { storage } from './storage';
import quotaManager from './quota-manager';
import postScheduler from './post-scheduler';
import twilioService from './twilio-service';
import { oauthService } from './oauth-service';
import grokService from './grok-service';
import veoService from './veo-service';

// --- Augment express-session to add userId on SessionData ---
declare module 'express-session' {
  // This is the safe way to type req.session.userId
  interface SessionData {
    userId?: string;
  }
}

const apiRouter: Router = express.Router();

// If your routes/auth module is CommonJS (module.exports = fn) or ESM default export,
// this will call it either way. If you have a TS ESM module with named export,
// change accordingly.
try {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const maybeRegister = require('./routes/auth');
  const registerAuth =
    typeof maybeRegister === 'function'
      ? maybeRegister
      : typeof maybeRegister?.default === 'function'
      ? maybeRegister.default
      : null;
  if (registerAuth) registerAuth(apiRouter);
} catch {
  // routes/auth is optional here; ignore if absent
}

// Small helper: wrap async handlers to forward errors to Express
const wrap =
  (fn: (req: Request, res: Response, next: NextFunction) => Promise<void>): RequestHandler =>
  (req, res, next) => {
    fn(req, res, next).catch(next);
  };

// ---------------------------------------------
// Quota cycle check middleware (server-only)
// ---------------------------------------------
apiRouter.use(
  wrap(async (req, res, next) => {
    const userId = req.session?.userId;
    if (
      userId &&
      (req.path.startsWith('/post') || req.path.startsWith('/generate-content'))
    ) {
      const quota = await quotaManager.checkQuota(userId);
      if (quota.remaining < 1) {
        res
          .status(403)
          .json({ error: 'Quota exceeded - upgrade subscription' });
        return;
      }
      const cycleEnd = new Date(quota.cycleStart);
      cycleEnd.setDate(cycleEnd.getDate() + 30);
      if (new Date() > cycleEnd) {
        await quotaManager.resetQuotaCycle(userId);
      }
    }
    next();
  })
);

// ---------------------------------------------
// Posting guard + retry + per-platform daily limits
// ---------------------------------------------
apiRouter.use(
  '/post',
  wrap(async (req, res, next) => {
    const userId = req.session?.userId;
    const platform: string | undefined = req.body?.platform;
    if (!userId || !platform) {
      next();
      return;
    }

    const limits: Record<string, number> = {
      facebook: 35,
      instagram: 50,
      linkedin: 50,
      x: 100,
      youtube: 6,
    };

    const dailyPosts = await storage.countDailyPosts(userId, platform);
    if (dailyPosts >= (limits[platform] ?? 0)) {
      res.status(429).json({ error: `Daily limit reached for ${platform}` });
      return;
    }

    let attempts = 0;
    while (attempts < 3) {
      try {
        await postScheduler.postToPlatform(
          userId,
          req.body.content,
          platform
        );
        break;
      } catch {
        attempts++;
        await new Promise((r) => setTimeout(r, 2 ** attempts * 1000));
      }
    }

    if (attempts === 3) {
      res.status(500).json({ error: 'Posting failed after retries' });
      return;
    }

    next();
  })
);

// ---------------------------------------------
// Refresh tokens if expired for /post requests
// ---------------------------------------------
apiRouter.use(
  '/post',
  wrap(async (req, res, next) => {
    const userId = req.session?.userId;
    const platform: string | undefined = req.body?.platform;
    if (userId && platform) {
      const tokens = await storage.getOAuthTokens(userId, platform);
      if (tokens?.expired) {
        const refreshed = await oauthService.refreshTokens(
          tokens.refreshToken,
          platform
        );
        await storage.updateOAuthTokens(userId, platform, refreshed);
      }
    }
    next();
  })
);

// ---------------------------------------------
// Onboarding
// ---------------------------------------------
apiRouter.post(
  '/onboarding',
  wrap(async (req, res) => {
    const { email, password, phone } = req.body || {};
    if (!email || !password || !phone) {
      res.status(400).json({ error: 'Missing email, password or phone' });
      return;
    }

    const existing = await storage.getUserByEmail(email);
    if (existing) {
      res.status(400).json({ error: 'Email in use' });
      return;
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await storage.createUser({ email, hashedPassword, phone });

    await twilioService.sendVerification(phone);
    req.session.userId = user.id;

    const stripeSecret = process.env.STRIPE_SECRET_KEY as string | undefined;
    if (!stripeSecret) {
      res.status(500).json({ error: 'Stripe is not configured' });
      return;
    }
    const stripe = new Stripe(stripeSecret);

    const origin =
      (req.headers.origin as string | undefined) ??
      `${req.protocol}://${req.get('host')}`;

    const stripeSession = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: [
        {
          price_data: {
            currency: 'usd',
            product_data: { name: 'AgencyIQ Subscription' },
            unit_amount: 1000,
          },
          quantity: 1,
        },
      ],
      mode: 'subscription',
      success_url: `${origin}/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${origin}/cancel`,
      metadata: { userId: String(user.id) },
    });

    res.json({ success: true, stripeSessionUrl: stripeSession.url });
  })
);

// ---------------------------------------------
// Deactivate platform
// ---------------------------------------------
apiRouter.post(
  '/deactivate-platform',
  wrap(async (req, res) => {
    const userId = req.session?.userId;
    if (!userId) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }
    const { platform } = req.body || {};
    if (!platform) {
      res.status(400).json({ error: 'Missing platform' });
      return;
    }
    await oauthService.revokeTokens(userId, platform);
    res.json({ success: true });
  })
);

// ---------------------------------------------
// Content generation (grok + VEO kickoff)
// ---------------------------------------------
apiRouter.post(
  '/generate-content',
  wrap(async (req, res) => {
    const userId = req.session?.userId;
    if (!userId) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }
    const quota = await quotaManager.checkQuota(userId);
    if (quota.remaining < 1) {
      res.status(403).json({ error: 'Quota exceeded' });
      return;
    }
    const userPlan = await storage.getUserPlan(userId);
    if (userPlan !== 'professional') {
      res
        .status(403)
        .json({ error: 'Veo 3.0 is exclusive to Professional plan' });
      return;
    }

    const basePrompt = String(req.body?.prompt ?? '');
    const prompt =
      basePrompt.trim().length > 0
        ? `${basePrompt}, JTBD-aligned, animal casting, cinematic`
        : 'JTBD-aligned, animal casting, cinematic';

    const content = await grokService.generateContent(prompt);
    const veoInit = await veoService.initiateVeoGeneration(content, {
      cinematic: true,
    });

    await quotaManager.deductQuota(userId, 1);

    if (req.body?.platform) {
      await postScheduler.postToPlatform(userId, content, req.body.platform);
    }

    res.json({
      content,
      video: {
        isAsync: true,
        operationId: veoInit.operationId,
        pollEndpoint: `/api/video/operation/${veoInit.operationId}`,
        message:
          'VEO 3.0 generation initiated - use operation ID to check status',
        pollInterval: 5000,
        estimatedTime: '115s to 6 minutes',
        status: 'processing',
      },
    });
  })
);

// ---------------------------------------------
// VEO poll endpoint (rate limited)
// ---------------------------------------------
apiRouter.get(
  '/video/operation/:opId',
  rateLimit({ windowMs: 5000, max: 1 }),
  wrap(async (req, res) => {
    const userId = req.session?.userId;
    const opId = req.params?.opId as string;
    const status = await veoService.pollOperationStatus(opId, userId);
    if (status.status === 'completed' && userId) {
      await quotaManager.deductQuota(userId, 1);
    }
    res.json(status);
  })
);

// ---------------------------------------------
// Stripe webhook
// ---------------------------------------------
apiRouter.post(
  '/stripe-webhook',
  express.raw({ type: 'application/json' }),
  wrap(async (req, res) => {
    const stripeSecret = process.env.STRIPE_SECRET_KEY as string | undefined;
    const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET as
      | string
      | undefined;

    if (!stripeSecret || !webhookSecret) {
      res.status(500).json({ error: 'Stripe is not configured' });
      return;
    }

    const stripe = new Stripe(stripeSecret);
    const sig = req.headers['stripe-signature'] as string;

    const event = stripe.webhooks.constructEvent(
      req.body,
      sig,
      webhookSecret
    );

    let userId: string | undefined;

    if (event.type === 'checkout.session.completed') {
      const obj: any = event.data.object;
      userId = String(obj?.metadata?.userId ?? '');
      if (userId) {
        await storage.activateSubscription(userId, obj.id);
      }
    } else if (
      event.type === 'customer.subscription.created' ||
      event.type === 'customer.subscription.updated'
    ) {
      const obj: any = event.data.object;
      userId = String(obj?.metadata?.userId ?? '');
      const priceId: string | undefined = obj?.items?.data?.[0]?.price?.id;
      if (userId && priceId) {
        const plan = priceId.includes('starter')
          ? 'starter'
          : priceId.includes('growth')
          ? 'growth'
          : 'professional';
        const quotas: Record<string, number> = {
          starter: 10,
          growth: 20,
          professional: 30,
        };
        await quotaManager.updateQuotaFromStripe(userId, quotas[plan]);
      }
    } else if (event.type === 'customer.subscription.deleted') {
      const obj: any = event.data.object;
      userId = String(obj?.metadata?.userId ?? '');
      if (userId) {
        await quotaManager.updateQuotaFromStripe(userId, 0);
      }
    }

    res.json({ received: true });
  })
);

// ---------------------------------------------
// Facebook Data Deletion
// ---------------------------------------------
apiRouter.post(
  '/data-deletion/facebook',
  wrap(async (req, res) => {
    const signed_request = req.body?.signed_request as string | undefined;
    if (!signed_request) {
      res.status(400).json({ error: 'Missing signed_request' });
      return;
    }
    const appSecret = process.env.FACEBOOK_APP_SECRET as string | undefined;
    if (!appSecret) {
      res.status(500).json({ error: 'Facebook app secret not configured' });
      return;
    }
    const parsed = parseSignedRequest(signed_request, appSecret);
    const fbUserId = parsed.user_id;
    await storage.deleteUserData(fbUserId);
    const deletionId = Date.now().toString();
    res.json({
      url: `https://${req.headers.host}/api/deletion-status/${deletionId}`,
      confirmation_code: deletionId,
    });
  })
);

function parseSignedRequest(signedRequest: string, secret: string) {
  const [encodedSig, payload] = signedRequest.split('.');
  const sig = Buffer.from(
    encodedSig.replace(/-/g, '+').replace(/_/g, '/'),
    'base64'
  ).toString('hex');

  const data = JSON.parse(
    Buffer.from(payload.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString(
      'utf8'
    )
  );

  const expectedSig = crypto
    .createHmac('sha256', secret)
    .update(payload)
    .digest('hex');

  if (sig !== expectedSig) throw new Error('Invalid signature');
  return data;
}

// ---------------------------------------------
// Deletion status
// ---------------------------------------------
apiRouter.get('/deletion-status/:id', (req: Request, res: Response) => {
  const deletionId = req.params.id;
  res.json({ status: 'Deletion complete', confirmation_code: deletionId });
});

export { apiRouter };
