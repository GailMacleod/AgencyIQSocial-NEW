#!/usr/bin/env node

import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 5000;

// Serve static files
app.use(express.static(path.join(__dirname, 'dist/public')));
app.use('/attached_assets', express.static(path.join(__dirname, 'attached_assets')));

// Health check
app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    build: 'vite-free-production'
  });
});

// API status endpoint
app.get('/api/status', (req, res) => {
  res.json({
    status: 'TheAgencyIQ Production Server',
    version: '1.0.0',
    deployment: 'vite-free',
    features: [
      'Multi-platform OAuth integration',
      'AI-powered content generation',
      'Professional quota management',
      'Queensland event scheduling',
      'Secure session management',
      'PostgreSQL database integration'
    ]
  });
});

// Catch all - serve index.html for SPA routing
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'dist/public/index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 TheAgencyIQ Production Server running on port ${PORT}`);
  console.log(`📍 Server URL: http://localhost:${PORT}`);
  console.log(`⚡ Build: Vite-free production deployment`);
  console.log(`✅ Ready for Replit deployment`);
});