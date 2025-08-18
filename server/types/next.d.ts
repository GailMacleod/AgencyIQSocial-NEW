import { NextRequest } from 'next/server';
import { Session, User } from 'next-auth'; // Adjust if using next-auth v5

declare module 'next/server' {
  export interface NextRequest {
    user?: User; // Extend with your User type (e.g., { id: string; email: string; })
    session?: Session; // For auth sessions
    json: () => Promise<any>; // If json() is errored (though standard Request has it; override if conflict)
  }
}