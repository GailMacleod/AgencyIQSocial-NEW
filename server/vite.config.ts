// vite.config.ts in /client
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  build: { outDir: '../dist/public' }, // Build to dist/public for server to serve
  base: '/', // For Vercel path
});