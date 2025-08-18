declare module 'express-session' {
  interface SessionData {
    userId: number;
    oauthTokens: any;
    deviceInfo: any;
    lastSyncAt: string;
    lastActivity: string;
    dailyApiCalls: number;
    quotaResetDate: string;
    lastIP: string;
    lastUA: string;
  }
}

declare module 'express-serve-static-core' {
  interface Request {
    sessionID: string;
  }
}