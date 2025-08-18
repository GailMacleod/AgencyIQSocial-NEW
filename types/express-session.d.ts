import 'express-session';

declare module 'express-session' {
  interface SessionData {
    userId?: number;
    userEmail?: string;
    isAuthenticated?: boolean;
  }
}

export interface CustomRequest extends Express.Request {
  session: Express.Session & {
    userId?: number;
    userEmail?: string;
    isAuthenticated?: boolean;
  };
}