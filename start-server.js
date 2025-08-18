/**
 * Emergency server startup script
 * Bypasses tsx dependency issues
 */

import { spawn } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

console.log('🚀 Starting TheAgencyIQ server...');

// Try different startup methods
const startupMethods = [
  ['npx', 'tsx', 'server/index.ts'],
  ['node', '--loader', 'tsx/esm', 'server/index.ts'],
  ['node', 'server/index.js'], // If compiled
];

let currentMethod = 0;

function tryStartup() {
  if (currentMethod >= startupMethods.length) {
    console.error('❌ All startup methods failed');
    process.exit(1);
  }

  const [command, ...args] = startupMethods[currentMethod];
  console.log(`🔧 Trying method ${currentMethod + 1}: ${command} ${args.join(' ')}`);

  const server = spawn(command, args, {
    cwd: __dirname,
    stdio: 'inherit',
    env: {
      ...process.env,
      NODE_ENV: 'development'
    }
  });

  server.on('error', (error) => {
    console.error(`❌ Method ${currentMethod + 1} failed:`, error.message);
    currentMethod++;
    setTimeout(tryStartup, 1000);
  });

  server.on('exit', (code) => {
    if (code !== 0) {
      console.error(`❌ Method ${currentMethod + 1} exited with code ${code}`);
      currentMethod++;
      setTimeout(tryStartup, 1000);
    }
  });
}

tryStartup();