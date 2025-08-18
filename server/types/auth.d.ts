declare interface AuthRequest extends Express.Request {
  session: import('express-session').Session & {
    userId?: string;
    userEmail?: string;
    authenticated?: boolean;
    sessionId?: string;
    platformTokens?: Record<string, any>;
    subscription?: {
      plan: string;
      active: boolean;
      remainingPosts: number;
      totalPosts: number;
    };
    lastActivity?: Date;
    regeneratedAt?: Date;
  };
}

declare module 'morgan' {
  function morgan(format: string, options?: any): any;
  export = morgan;
}

declare module 'connect-pg-simple' {
  function connectPgSimple(session: any): any;
  export = connectPgSimple;
}