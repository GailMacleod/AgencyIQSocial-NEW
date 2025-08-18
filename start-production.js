#!/usr/bin/env node

// Production server startup script for app.theagencyiq.ai
const { spawn } = require('child_process');
const path = require('path');

// Set production environment variables
process.env.NODE_ENV = 'production';
process.env.PORT = process.env.PORT || '8080';

console.log('🚀 Starting TheAgencyIQ Production Server');
console.log('📍 Domain: app.theagencyiq.ai');
console.log('🌍 Environment:', process.env.NODE_ENV);
console.log('🔌 Port:', process.env.PORT);

// Check required environment variables
const requiredEnvVars = [
  'DATABASE_URL',
  'FB_CLIENT_ID',
  'FB_CLIENT_SECRET',
  'SESSION_SECRET'
];

const missingVars = requiredEnvVars.filter(varName => !process.env[varName]);
if (missingVars.length > 0) {
  console.error('❌ Missing required environment variables:', missingVars);
  console.error('Please set these variables in your production environment');
  process.exit(1);
}

// Start the server with proper TypeScript support
const serverProcess = spawn('npx', ['tsx', 'server/index.ts'], {
  stdio: 'inherit',
  env: process.env,
  cwd: process.cwd()
});

serverProcess.on('error', (error) => {
  console.error('❌ Server process error:', error);
  process.exit(1);
});

serverProcess.on('close', (code) => {
  console.log(`Server process exited with code ${code}`);
  process.exit(code);
});

// Handle graceful shutdown
process.on('SIGTERM', () => {
  console.log('📨 Received SIGTERM, shutting down gracefully');
  serverProcess.kill('SIGTERM');
});

process.on('SIGINT', () => {
  console.log('📨 Received SIGINT, shutting down gracefully');
  serverProcess.kill('SIGINT');
});