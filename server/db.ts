import { Pool, neonConfig } from '@neondatabase/serverless';
import { drizzle } from 'drizzle-orm/neon-serverless';
import ws from "ws";
import * as schema from "@shared/schema";

// Fix WebSocket constructor for Neon serverless - critical for database integrity  
try {
  // Ensure WebSocket is properly configured for serverless environment
  if (typeof WebSocket !== 'undefined') {
    neonConfig.webSocketConstructor = WebSocket;
  } else if (ws && typeof ws === 'function') {
    neonConfig.webSocketConstructor = ws;
  } else {
    // Import ws dynamically for Node.js environment
    const { default: WebSocketNode } = await import('ws');
    neonConfig.webSocketConstructor = WebSocketNode;
  }
  console.log('✅ WebSocket constructor configured for Neon database');
} catch (error) {
  console.warn('⚠️ WebSocket configuration failed, using fallback:', error?.message);
  neonConfig.webSocketConstructor = ws;
}

if (!process.env.DATABASE_URL) {
  throw new Error(
    "DATABASE_URL must be set. Did you forget to provision a database?",
  );
}

export const pool = new Pool({ connectionString: process.env.DATABASE_URL });
export const db = drizzle({ client: pool, schema });